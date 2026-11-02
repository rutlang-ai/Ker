#!/usr/bin/env python3
"""TAP proof for the opt-in socket-broker READY/STOP control path."""
import argparse
import ctypes
import importlib.machinery
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
    loader = importlib.machinery.SourceFileLoader('_c34_test_ker_run', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot load ker-run Python source from {path}')
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
    state = {'manager': None, 'app': None, 'retainer_pid': -1}
    original_manager = ker_run.broker_readiness.BrokerReadiness

    # The retainer is forked before ker-run starts worker/runtime threads. It
    # receives only a duplicate of the real readiness endpoint later.
    retainer_channel = None
    if retain_endpoint:
        retainer_parent, retainer_child = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | getattr(socket, 'SOCK_CLOEXEC', 0))
        retainer_pid = os.fork()
        if retainer_pid == 0:
            try:
                retainer_parent.close()
                packet, ancillary, _, _ = retainer_child.recvmsg(1,
                    socket.CMSG_SPACE(struct.calcsize('i')))
                fds = []
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        fds.extend(struct.unpack(f'{len(data) // struct.calcsize("i")}i', data))
                require(packet == b'R' and len(fds) == 1,
                    'retainer did not receive exactly one readiness endpoint')
                held_endpoint_fd = fds[0]
                fds.clear()
                retainer_child.send(b'H')
                time.sleep(60)
            finally:
                if 'held_endpoint_fd' in locals():
                    os.close(held_endpoint_fd)
                for fd in locals().get('fds', []):
                    os.close(fd)
                os._exit(0)
        retainer_child.close()
        retainer_channel = retainer_parent
        retainer_channel.settimeout(5)
        state['retainer_pid'] = retainer_pid

    supervisor_pid = os.getpid()

    def observed_manager(*manager_args, **manager_kwargs):
        manager = original_manager(*manager_args, **manager_kwargs)
        state['manager'] = manager
        if retainer_channel is not None:
            values = struct.pack('i', manager.parent.fileno())
            retainer_channel.sendmsg([b'R'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, values)])
            require(retainer_channel.recv(1) == b'H',
                'retainer did not acknowledge holding the readiness endpoint')
            retainer_channel.close()
            state['retainer_held'] = True
        original_child_started = manager.child_started

        def child_started(process, expected_executable_hash):
            result = original_child_started(process, expected_executable_hash)
            state['app'] = process
            if notify_fd >= 0:
                message = {'event': 'APP', 'pid': process.pid,
                    'start_ticks': manager.app[3], 'retainer_pid': state['retainer_pid'],
                    'retainer_held': state.get('retainer_held', False)}
                os.write(notify_fd, (json.dumps(message) + '\n').encode())
            return result

        manager.child_started = child_started
        return manager

    ker_run.broker_readiness.BrokerReadiness = observed_manager
    control_errors = []
    control_result = {}

    def control_thread():
        try:
            manager = None
            deadline = time.monotonic() + 25
            while manager is None and time.monotonic() < deadline:
                manager = state['manager']
                if manager is None:
                    time.sleep(0.001)
            require(manager is not None, 'broker readiness manager was not created')
            app = None
            while app is None and time.monotonic() < deadline:
                app = state['app']
                if app is None:
                    time.sleep(0.001)
            require(app is not None, 'broker application Popen did not complete')
            if args.mode == 'no-bootstrap':
                wait_deadline = time.monotonic() + 15
                while app.poll() is None and time.monotonic() < wait_deadline:
                    time.sleep(0.005)
                require(app.poll() is not None and not manager.ready,
                    'missing bootstrap unexpectedly reached READY')
                control_result['no_ready'] = True
                return

            ready_deadline = time.monotonic() + 20
            while not manager.ready and time.monotonic() < ready_deadline:
                if app.poll() is not None:
                    break
                time.sleep(0.001)
            require(manager.ready,
                f'ker-run did not accept authenticated READY; app_status={app.poll()}')
            if notify_fd >= 0:
                os.write(notify_fd, (json.dumps({'event': 'READY', 'pid': manager.app[0],
                    'start_ticks': manager.app[3],
                    'retainer_pid': state['retainer_pid'],
                    'retainer_held': state.get('retainer_held', False)}) + '\n').encode())
            if args.mode == 'parent-death':
                return
            if args.mode in ('bad-stop', 'rights-stop', 'truncated-stop'):
                if args.mode == 'bad-stop':
                    bad = wire.pack_stop(wire.STOP,
                        bytes([manager.nonce[0] ^ 1]) + manager.nonce[1:], manager.epoch,
                        supervisor_pid, os.getuid(), os.getgid(), manager.supervisor[3])
                elif args.mode == 'rights-stop':
                    bad = wire.pack_stop(wire.STOP, manager.nonce, manager.epoch,
                        supervisor_pid, os.getuid(), os.getgid(), manager.supervisor[3])
                    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                    try:
                        send_test_packet(manager.parent, bad, (read_fd,))
                    finally:
                        os.close(read_fd)
                        os.close(write_fd)
                    bad = None
                else:
                    bad = wire.pack_stop(wire.STOP, manager.nonce, manager.epoch,
                        supervisor_pid, os.getuid(), os.getgid(), manager.supervisor[3]) + b'\0'
                if bad is not None:
                    send_test_packet(manager.parent, bad)
                wait_deadline = time.monotonic() + 15
                while app.poll() is None and time.monotonic() < wait_deadline:
                    time.sleep(0.005)
                require(app.poll() is not None,
                    'malformed STOP did not terminate the broker application')
                key = {'bad-stop': 'bad_stop_rejected', 'rights-stop': 'rights_stop_rejected',
                    'truncated-stop': 'truncated_stop_rejected'}[args.mode]
                control_result[key] = True
                return

            os.kill(supervisor_pid, signal.SIGTERM)
            stop_deadline = time.monotonic() + 15
            while not manager.stopped and time.monotonic() < stop_deadline:
                time.sleep(0.001)
            require(manager.stopped,
                'ker-run SIGTERM path did not complete authenticated STOP/ACK')
            control_result['ack'] = True
        except BaseException as error:
            control_errors.append(error)
            app = state.get('app')
            if app is not None and app.poll() is None:
                app.kill()

    thread = threading.Thread(target=control_thread, name='broker-readiness-test-control')
    thread.start()
    arguments = [str(args.launcher), '--library', str(args.library),
        '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
        '--port', 'net_tap0', '--eal', build_eal(args), '--runtime-service',
        '--broker-readiness', '--stats', str(args.stats), '--',
        str(args.broker), str(args.rpc_path)]
    if args.mode == 'no-bootstrap':
        arguments.append('--skip-bootstrap')
    old_argv = sys.argv
    try:
        sys.argv = arguments
        launcher_result = ker_run.main()
    finally:
        sys.argv = old_argv
        ker_run.broker_readiness.BrokerReadiness = original_manager
        if retainer_channel is not None:
            retainer_channel.close()
    thread.join(timeout=25)
    if thread.is_alive():
        raise RuntimeError('broker readiness controller did not terminate')
    if control_errors:
        raise RuntimeError(f'broker readiness controller failed: {control_errors[0]!r}')
    if args.mode == 'parent-death':
        raise RuntimeError('parent-death supervisor unexpectedly returned')
    stats = json.loads(Path(args.stats).read_text()) if Path(args.stats).exists() else None
    result = {'event': 'RESULT', 'mode': args.mode, 'launcher_result': launcher_result,
        'control': control_result, 'stats': stats}
    if notify_fd >= 0:
        os.write(notify_fd, (json.dumps(result) + '\n').encode())
    if args.mode == 'healthy':
        require(launcher_result == 143 and control_result.get('ack') and
            stats and stats.get('outstanding') == 0,
            f'healthy READY/STOP did not clean up through ker-run: {result!r}')
    elif args.mode in ('bad-stop', 'rights-stop', 'truncated-stop'):
        expected_key = {'bad-stop': 'bad_stop_rejected',
            'rights-stop': 'rights_stop_rejected',
            'truncated-stop': 'truncated_stop_rejected'}[args.mode]
        require(launcher_result != 0 and control_result.get(expected_key) and
            stats and stats.get('outstanding') == 0,
            f'{args.mode} was not rejected with worker cleanup: {result!r}')
    elif args.mode == 'no-bootstrap':
        require(launcher_result != 0 and control_result.get('no_ready') and
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
                require(first_record.get('retainer_held') is True,
                    'endpoint retainer did not acknowledge the held descriptor')
                ready_record = json.loads(read_line_bounded(stream, 20,
                    'parent-death broker READY'))
                require(ready_record.get('event') == 'READY',
                    f'parent-death helper did not reach authenticated READY: {ready_record!r}')
                require(ready_record.get('retainer_held') is True,
                    'parent-death READY was published before endpoint retention')
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
                    broker_log_path = args.root / 'parent-death.supervisor.log'
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
                     'parent-death', 'no-bootstrap'):
            spawn_supervisor(args, mode)
    print('BROKER_READINESS_TAP_OK authenticated_READY_STOP no-bootstrap malformed_STOP parent_pidfd_death')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'broker readiness TAP failed: {error}', file=sys.stderr)
        raise
