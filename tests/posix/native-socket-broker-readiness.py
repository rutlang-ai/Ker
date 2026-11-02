#!/usr/bin/env python3
"""TAP proof for the opt-in socket-broker READY/STOP control path."""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

WIRE_PATH = Path(__file__).resolve().parents[2] / 'tools' / 'broker_readiness_wire.py'
WIRE_SPEC = importlib.util.spec_from_file_location('_c34_broker_wire', WIRE_PATH)
wire = importlib.util.module_from_spec(WIRE_SPEC)
WIRE_SPEC.loader.exec_module(wire)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def start_ticks(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = text.rfind(')')
    require(close >= 0, f'cannot parse /proc/{pid}/stat for {pid}')
    fields = text[close + 2:].split()
    require(len(fields) > 19, f'incomplete /proc/{pid}/stat for {pid}')
    return int(fields[19], 10)


def process_alive(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    return not poller.poll(0)


def receive_record(endpoint, expected_size, timeout):
    endpoint.settimeout(timeout)
    packet, ancillary, flags, _ = endpoint.recvmsg(
        expected_size + 1, socket.CMSG_SPACE(struct.calcsize('3i')) +
        socket.CMSG_SPACE(16 * struct.calcsize('i')))
    creds = []
    rights = []
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET:
            continue
        if kind == socket.SCM_CREDENTIALS:
            if len(data) == struct.calcsize('3i'):
                creds.append(struct.unpack('3i', data))
        elif kind == socket.SCM_RIGHTS:
            fds = struct.unpack(f'{len(data) // struct.calcsize("i")}i', data)
            rights.extend(fds)
    for fd in rights:
        os.close(fd)
    require(not rights, f'broker control packet unexpectedly carried descriptors: {rights!r}')
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
        f'broker control packet was truncated: flags={flags}')
    require(len(creds) == 1, f'expected exactly one SCM_CREDENTIALS, got {creds!r}')
    return packet, creds[0]


def send_test_packet(endpoint, packet, rights=()):
    ancillary = []
    if rights:
        values = struct.pack(f'{len(rights)}i', *rights)
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, values))
    sent = endpoint.sendmsg([packet], ancillary, getattr(socket, 'MSG_NOSIGNAL', 0))
    require(sent == len(packet), f'short test STOP send: {sent} of {len(packet)}')


def load_ker_run(path):
    spec = importlib.util.spec_from_file_location('_c34_test_ker_run', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_eal(args):
    cpu = min(os.sched_getaffinity(0))
    plugin = args.dpdk_plugin_dir / 'librte_net_tap.so'
    return (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
        f'--iova-mode=va -m 64 -d {shlex.quote(str(plugin))} '
        '--vdev=net_tap0,iface=kerpeer,remote=kerlink')


def supervisor(args, notify_fd=-1, retain_endpoint=False):
    ker_run = load_ker_run(args.launcher)
    supervisor_pid = os.getpid()
    supervisor_start = start_ticks(supervisor_pid)
    nonce = os.urandom(16)
    epoch = int.from_bytes(os.urandom(8), 'little') or 1
    app_endpoint, control_endpoint = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | getattr(socket, 'SOCK_CLOEXEC', 0))
    control_endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    control_endpoint.settimeout(20)

    retainer_pid = -1
    if retain_endpoint:
        retainer_pid = os.fork()
        if retainer_pid == 0:
            try:
                app_endpoint.close()
                if notify_fd >= 0:
                    os.close(notify_fd)
                time.sleep(60)
            finally:
                os._exit(0)

    state = {'app': None, 'profile': None, 'start_ticks': None}
    original_popen = subprocess.Popen

    def test_popen(command, *popen_args, **kwargs):
        values = [str(item) for item in command] if isinstance(command, (list, tuple)) else [str(command)]
        if str(args.broker.resolve()) not in values:
            return original_popen(command, *popen_args, **kwargs)
        env = dict(kwargs.get('env') or os.environ)
        worker_profile = env.get('KER_RUNTIME_SERVICE_WORKER_PROFILE')
        require(worker_profile and len(worker_profile) == 64,
            'runtime-service launcher did not provide the actual worker profile hash')
        env.update({
            'KER_BROKER_READINESS_FD': str(app_endpoint.fileno()),
            'KER_BROKER_RUN_NONCE': nonce.hex(),
            'KER_BROKER_WORKER_EPOCH': str(epoch),
            'KER_BROKER_WORKER_PROFILE_SHA256': worker_profile,
            'KER_BROKER_SUPERVISOR_START_TICKS': str(supervisor_start),
        })
        kwargs['env'] = env
        kwargs['pass_fds'] = tuple(sorted(set(kwargs.get('pass_fds', ())) |
                                           {app_endpoint.fileno()}))
        broker_log_path = Path(args.stats).with_suffix('.broker.log')
        broker_log = broker_log_path.open('wb', buffering=0)
        state['broker_log'] = broker_log
        kwargs['stdout'] = broker_log
        kwargs['stderr'] = subprocess.STDOUT
        process = original_popen(command, *popen_args, **kwargs)
        state['app'] = process
        state['profile'] = bytes.fromhex(worker_profile)
        state['start_ticks'] = start_ticks(process.pid)
        app_endpoint.close()
        if notify_fd >= 0:
            message = {'event': 'APP', 'pid': process.pid,
                'start_ticks': state['start_ticks'], 'retainer_pid': retainer_pid}
            os.write(notify_fd, (json.dumps(message) + '\n').encode())
        return process

    control_errors = []
    control_result = {}

    def control_thread():
        try:
            process = None
            deadline = time.monotonic() + 25
            while process is None and time.monotonic() < deadline:
                process = state['app']
                time.sleep(0.001)
            require(process is not None, 'broker Popen was not observed before READY deadline')
            if args.mode == 'no-bootstrap':
                control_endpoint.settimeout(15)
                packet = control_endpoint.recv(121)
                require(packet == b'', f'expected no READY and broker endpoint close, got {packet!r}')
                control_result['no_ready'] = True
                return
            packet, credentials = receive_record(control_endpoint, 120, 20)
            nonce_value, epoch_value, profile, broker_start, count, manifest = wire.unpack_ready(packet)
            broker_pid, broker_uid, broker_gid = credentials
            require(broker_pid == process.pid and broker_uid == os.getuid() and
                    broker_gid == os.getgid(),
                f'READY SCM credentials do not identify exact broker Popen: {credentials!r}')
            broker_pidfd = os.pidfd_open(broker_pid, 0)
            try:
                require(process_alive(broker_pidfd), 'broker exited before READY was accepted')
                require(start_ticks(broker_pid) == broker_start == state['start_ticks'],
                    'READY start ticks do not match exact broker Popen')
                require(os.path.realpath(f'/proc/{broker_pid}/exe') == str(args.broker.resolve()),
                    'READY sender executable is not the pinned broker fixture')
                require(nonce_value == nonce and epoch_value == epoch and
                    profile == state['profile'] and count == 0 and
                    manifest == wire.EMPTY_MANIFEST_SHA256,
                    'READY fields do not match supervisor run/profile and empty bootstrap')
                control_result['ready'] = True
                if notify_fd >= 0:
                    os.write(notify_fd, (json.dumps({'event': 'READY', 'pid': broker_pid,
                        'start_ticks': broker_start, 'retainer_pid': retainer_pid}) + '\n').encode())
                if args.mode == 'parent-death':
                    return
                if args.mode == 'bad-stop':
                    bad = wire.pack_stop(wire.STOP, bytes([nonce[0] ^ 1]) + nonce[1:],
                        epoch, supervisor_pid, os.getuid(), os.getgid(), supervisor_start)
                    send_test_packet(control_endpoint, bad)
                    control_endpoint.settimeout(15)
                    require(control_endpoint.recv(1) == b'',
                        'invalid STOP must fail closed without STOP_ACK')
                    control_result['bad_stop_rejected'] = True
                    return
                if args.mode == 'rights-stop':
                    bad = wire.pack_stop(wire.STOP, nonce, epoch, supervisor_pid,
                        os.getuid(), os.getgid(), supervisor_start)
                    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                    try:
                        send_test_packet(control_endpoint, bad, (read_fd,))
                    finally:
                        os.close(read_fd)
                        os.close(write_fd)
                    control_endpoint.settimeout(15)
                    require(control_endpoint.recv(1) == b'',
                        'STOP carrying SCM_RIGHTS must fail closed without ACK')
                    control_result['rights_stop_rejected'] = True
                    return
                if args.mode == 'truncated-stop':
                    send_test_packet(control_endpoint,
                        wire.pack_stop(wire.STOP, nonce, epoch, supervisor_pid,
                            os.getuid(), os.getgid(), supervisor_start) + b'\0')
                    control_endpoint.settimeout(15)
                    require(control_endpoint.recv(1) == b'',
                        'truncated STOP must fail closed without ACK')
                    control_result['truncated_stop_rejected'] = True
                    return
                stop = wire.pack_stop(wire.STOP, nonce, epoch, supervisor_pid,
                    os.getuid(), os.getgid(), supervisor_start)
                send_test_packet(control_endpoint, stop)
                ack, ack_credentials = receive_record(control_endpoint, 104, 10)
                require(ack_credentials[0] == process.pid and
                    ack_credentials[1:] == (os.getuid(), os.getgid()),
                    f'STOP_ACK credentials do not identify broker: {ack_credentials!r}')
                expected = (nonce, epoch, wire.EMPTY_MANIFEST_SHA256, supervisor_pid,
                    os.getuid(), os.getgid(), supervisor_start, wire.STOP_ID)
                require(wire.unpack_stop(ack, wire.STOP_ACK) == expected,
                    'STOP_ACK does not match the one-shot supervisor request')
                control_result['ack'] = True
            finally:
                os.close(broker_pidfd)
        except BaseException as error:
            control_errors.append(error)
            process = state.get('app')
            if process is not None and process.poll() is None:
                process.kill()

    thread = threading.Thread(target=control_thread, name='broker-readiness-test-control')
    thread.start()
    arguments = [str(args.launcher), '--library', str(args.library),
        '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
        '--port', 'net_tap0', '--eal', build_eal(args), '--runtime-service',
        '--stats', str(args.stats), '--', str(args.broker), str(args.rpc_path)]
    if args.mode == 'no-bootstrap':
        arguments.append('--skip-bootstrap')
    old_argv = sys.argv
    subprocess.Popen = test_popen
    try:
        sys.argv = arguments
        launcher_result = ker_run.main()
    finally:
        sys.argv = old_argv
        subprocess.Popen = original_popen
        control_endpoint.close()
        if app_endpoint.fileno() >= 0:
            app_endpoint.close()
    thread.join(timeout=25)
    if thread.is_alive():
        raise RuntimeError('broker readiness controller did not terminate')
    if control_errors:
        raise RuntimeError(f'broker readiness controller failed: {control_errors[0]!r}')
    broker_log = state.get('broker_log')
    if broker_log is not None:
        broker_log.close()
    if args.mode == 'parent-death':
        # This mode remains alive until its outer harness kills the parent; it
        # must not signal STOP or close the retained endpoint first.
        raise RuntimeError('parent-death supervisor unexpectedly returned')
    stats = json.loads(Path(args.stats).read_text()) if Path(args.stats).exists() else None
    result = {'event': 'RESULT', 'mode': args.mode, 'launcher_result': launcher_result,
        'control': control_result, 'stats': stats}
    if notify_fd >= 0:
        os.write(notify_fd, (json.dumps(result) + '\n').encode())
    if args.mode == 'healthy':
        require(launcher_result == 0 and control_result.get('ack') and
            stats and stats.get('outstanding') == 0,
            f'healthy READY/STOP did not clean up: {result!r}')
    elif args.mode in ('bad-stop', 'rights-stop', 'truncated-stop'):
        expected_key = {'bad-stop': 'bad_stop_rejected',
            'rights-stop': 'rights_stop_rejected',
            'truncated-stop': 'truncated_stop_rejected'}[args.mode]
        require(launcher_result != 0 and control_result.get(expected_key) and
            stats and stats.get('outstanding') == 0,
            f'{args.mode} was not rejected with worker cleanup: {result!r}')
    elif args.mode == 'no-bootstrap':
        require(launcher_result == 0 and control_result.get('no_ready') and
            stats and stats.get('outstanding') == 0,
            f'no-bootstrap path did not fail before READY and clean up: {result!r}')
    return 0


def enable_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER failed')


def read_line_bounded(stream, timeout, description, max_bytes=4096):
    deadline = time.monotonic() + timeout
    result = bytearray()
    while len(result) < max_bytes:
        remaining = deadline - time.monotonic()
        require(remaining > 0, f'timed out waiting for {description}')
        readable, _, _ = select.select([stream], [], [], remaining)
        require(readable, f'timed out waiting for {description}')
        chunk = os.read(stream.fileno(), 1)
        require(chunk, f'EOF waiting for {description}')
        result.extend(chunk)
        if chunk == b'\n':
            return bytes(result)
    raise RuntimeError(f'{description} exceeded {max_bytes}-byte line bound')


def spawn_supervisor(args, mode, timeout=45):
    notify_read, notify_write = os.pipe2(os.O_CLOEXEC)
    command = [sys.executable, str(Path(__file__).resolve()), '--supervisor',
        '--mode', mode, '--notify-fd', str(notify_write)]
    for name in ('launcher', 'library', 'worker', 'broker', 'dpdk-plugin-dir'):
        command += ['--' + name,
            str(getattr(args, name.replace('-', '_')).resolve())]
    command += ['--stats', str(args.root / f'{mode}.json'),
        '--rpc-path', str(args.root / f'{mode}.sock')]
    retain = mode == 'parent-death'
    log_path = args.root / f'{mode}.supervisor.log'
    log_file = log_path.open('wb')
    process = subprocess.Popen(command, pass_fds=(notify_write,), stdout=log_file,
        stderr=subprocess.STDOUT, start_new_session=True)
    os.close(notify_write)
    try:
        with os.fdopen(notify_read, 'rb', buffering=0) as stream:
            first_record = json.loads(read_line_bounded(stream, 10,
                f'{mode} supervisor startup report'))
            if retain:
                require(first_record.get('event') == 'APP',
                    f'parent-death helper did not publish broker identity: {first_record!r}')
                ready_record = json.loads(read_line_bounded(stream, 20,
                    'parent-death broker READY'))
                require(ready_record.get('event') == 'READY',
                    f'parent-death helper did not reach authenticated READY: {ready_record!r}')
                broker_pid = ready_record['pid']
                broker_pidfd = os.pidfd_open(broker_pid, 0)
                retainer_pid = ready_record['retainer_pid']
                require(retainer_pid > 0, 'endpoint retainer did not retain supervisor endpoint')
                try:
                    os.kill(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    require(process.returncode == -signal.SIGKILL,
                        f'supervisor did not die as requested: {process.returncode}')
                    require(os.path.exists(f'/proc/{retainer_pid}'),
                        'endpoint retainer exited before broker parent-death observation')
                    poller = select.poll()
                    poller.register(broker_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                    require(poller.poll(10_000),
                        'broker did not exit after pinned parent death while channel endpoint remained open')
                    broker_status = None
                    wait_deadline = time.monotonic() + 3
                    while time.monotonic() < wait_deadline:
                        try:
                            waited_pid, status = os.waitpid(broker_pid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if waited_pid == broker_pid:
                            broker_status = status
                            break
                        time.sleep(0.01)
                    broker_log_path = args.root / 'parent-death.broker.log'
                    diagnostic = broker_log_path.read_text(errors='replace')
                    require('BROKER_PARENT_CHECK_ERROR=3' in diagnostic,
                        f'broker did not record ESRCH from pinned parent check: {diagnostic!r}')
                    require(broker_status is not None and
                            ((os.WIFEXITED(broker_status) and os.WEXITSTATUS(broker_status) != 0) or
                             os.WIFSIGNALED(broker_status)),
                        f'broker did not fail after parent-death ESRCH: {broker_status!r}')
                finally:
                    os.close(broker_pidfd)
                return
            output_tail = []
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                readable, _, _ = select.select([stream], [], [],
                    max(0, deadline - time.monotonic()))
                if not readable:
                    break
                line = stream.readline()
                if not line:
                    break
                record = json.loads(line)
                output_tail.append(record)
                if record.get('event') == 'RESULT':
                    break
            else:
                raise RuntimeError(f'{mode} helper timed out; records={output_tail!r}')
        process.wait(timeout=10)
        log_file.flush()
        diagnostics = log_path.read_text(errors='replace')
        require(process.returncode == 0,
            f'{mode} helper failed: records={output_tail!r}; diagnostics={diagnostics!r}')
    finally:
        try:
            os.close(notify_read)
        except OSError:
            pass
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        log_file.close()

def set_up_network():
    for command in (
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', 'link', 'set', 'kerhost', 'up'],
        ['ip', 'link', 'set', 'kerlink', 'up'],
        ['ip', 'link', 'set', 'kerpeer', 'up'],
    ):
        subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'broker', 'dpdk-plugin-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--stats', type=Path,
        default=Path('/dev/shm/ker-broker-readiness-stats.json'))
    parser.add_argument('--rpc-path', type=Path,
        default=Path('/dev/shm/ker-broker-readiness-rpc.sock'))
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--supervisor', action='store_true')
    parser.add_argument('--mode', choices=('healthy', 'bad-stop', 'rights-stop',
        'truncated-stop',
        'no-bootstrap', 'parent-death'), default='healthy')
    parser.add_argument('--notify-fd', type=int, default=-1)
    args = parser.parse_args()
    if args.supervisor:
        return supervisor(args, args.notify_fd,
            retain_endpoint=args.mode == 'parent-death')
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside',
            '--launcher', str(args.launcher.resolve()), '--library', str(args.library.resolve()),
            '--worker', str(args.worker.resolve()), '--broker', str(args.broker.resolve()),
            '--dpdk-plugin-dir', str(args.dpdk_plugin_dir.resolve()),
            '--stats', str(args.stats.resolve()), '--rpc-path', str(args.rpc_path.resolve())]
        subprocess.run(command, check=True)
        return 0
    set_up_network()
    enable_subreaper()
    with tempfile.TemporaryDirectory(prefix='ker-broker-readiness-') as directory:
        args.root = Path(directory)
        for mode in ('healthy', 'bad-stop', 'rights-stop', 'truncated-stop',
                     'no-bootstrap'):
            spawn_supervisor(args, mode)
        spawn_supervisor(args, 'parent-death')
    print('BROKER_READINESS_TAP_OK authenticated_READY_STOP no-bootstrap malformed_STOP parent_pidfd_death')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'broker readiness TAP failed: {error}', file=sys.stderr)
        raise
