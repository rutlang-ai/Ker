#!/usr/bin/env python3
"""Broker-process/LKL and separate FF owner admission smoke over TAP."""
import argparse
import errno
import json
import os
from pathlib import Path
import re
import resource
import select
import shlex
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_line(process, expected, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, errors = process.communicate()
            raise RuntimeError(f'process exited before {expected}: rc={process.returncode}; '
                f'stdout={output!r}; stderr={errors!r}')
        ready, _, _ = select.select([process.stdout], [], [], 0.05)
        if ready:
            line = process.stdout.readline()
            if not line:
                continue
            if expected in line:
                return line
    raise RuntimeError(f'timed out waiting for {expected}')


def run_progress_client(path, rpc_path):
    progress = subprocess.run([str(path), str(rpc_path)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=10, env=os.environ | {'TMPDIR': os.environ.get('TMPDIR', '/dev/shm')})
    require(progress.returncode == 0 and 'C16_RPC_PROGRESS_OK' in progress.stdout and
        'history=EBUSY' in progress.stdout,
        f'unrelated broker RPC did not complete: rc={progress.returncode}; '
        f'stdout={progress.stdout!r}; stderr={progress.stderr!r}')


def require_zero_requests(line, label, inserted=None):
    require('status=0' in line and 'count=0' in line and
        (inserted is None or f'inserted={inserted}' in line),
        f'{label}: original-Linux request census did not reach zero: {line!r}')


def trace_times(line, event, port):
    match = re.search(r'now_ns=(\d+) deadline_ns=(\d+)', line)
    require(match is not None and f'C16_ADMISSION {event} remote_port={port}' in line,
        f'malformed task timing trace: {line!r}')
    return int(match.group(1)), int(match.group(2))


def disable_core_dumps():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def captured_synacks(capture, destination_ports):
    matches = []
    while True:
        try:
            packet = capture.recv(65535)
        except TimeoutError:
            break
        if len(packet) < 14 + 20 + 20 or packet[12:14] != b'\x08\x00':
            continue
        ip_offset = 14
        if packet[ip_offset + 9] != socket.IPPROTO_TCP:
            continue
        tcp_offset = ip_offset + (packet[ip_offset] & 0xf) * 4
        if len(packet) < tcp_offset + 20:
            continue
        source_port, destination_port = struct.unpack_from('!HH', packet, tcp_offset)
        flags = packet[tcp_offset + 13]
        if (source_port == 8080 and destination_port in destination_ports and
            flags & 0x12 == 0x12):
            matches.append(destination_port)
    return matches


def inside(args):
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
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
        f'--iova-mode=va -m 64 -d {shlex.quote(str(args.dpdk_plugin_dir / "librte_net_tap.so"))} '
        '--vdev=net_tap0,iface=kerpeer,remote=kerlink')
    root_parent = Path(os.environ.get('TMPDIR', '/dev/shm'))
    broker = app = None
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind(('kerhost', 0))
    capture.settimeout(0.01)
    with tempfile.TemporaryDirectory(prefix='ker-c16-admission-', dir=root_parent) as temp:
        root = Path(temp)
        rpc_path = root / 'broker.sock'
        stop_path = root / 'stop.sock'
        stats = root / 'stats.json'
        command = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal, '--stats', str(stats), '--',
            str(args.broker), str(rpc_path), str(stop_path)]
        environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
            'RUNTIME_DIRECTORY': str(root), 'TMPDIR': str(root)}
        try:
            broker = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=environment, bufsize=1, start_new_session=True)
            wait_line(broker, 'C16_BROKER_READY', 45)
            app_env = os.environ | {
                'KER_SOCKET_BROKER_PATH': str(rpc_path),
                'LD_PRELOAD': str(args.preload),
                'RUNTIME_DIRECTORY': str(root), 'TMPDIR': str(root),
            }
            if not args.pump_failure_only:
                app_env |= {'KER_C16_TEST_PUMP_DELAY_US': '80000',
                    'KER_C16_TEST_RECURSIVE_WAIT': '1'}
            if args.registration_negative_only:
                app_env |= {'KER_C16_TEST_PAUSE_AFTER_PREPARE': '1',
                    'KER_C16_TEST_PREPARE_ONCE': '1'}
            if args.malformed_owner_hello_only:
                app_env |= {'KER_C16_TEST_PAUSE_AFTER_PREPARE': '1',
                    'KER_C16_TEST_BAD_HELLO_RIGHTS': '1'}
            if args.owner_death_only:
                app_env['KER_C16_TEST_PAUSE_AFTER_PREPARE'] = '1'
            if args.listener_close_only:
                app_env['KER_C16_TEST_PAUSE_AFTER_PREPARE'] = '1'
            app_argument = ('pump-failure' if args.pump_failure_only else
                'owner-probe' if (args.registration_negative_only or
                    args.malformed_owner_hello_only or args.owner_death_only or
                    args.listener_close_only) else '16')
            flow_ports = (1132, 1354, 2031, 3027, 3769, 4125, 5963, 6537,
                6708, 7356, 7512, 8925, 9382, 9604, 10735, 10970, 11392)
            peers = []
            app = subprocess.Popen([str(args.client), app_argument], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env=app_env, bufsize=1, preexec_fn=disable_core_dumps)
            if args.registration_negative_only:
                marker = wait_line(app, 'C16_ATTACH_ENDPOINT path=', 20)
                endpoint = Path(marker.split('path=', 1)[1].strip())
                directory_info = endpoint.parent.stat()
                require(stat.S_IMODE(directory_info.st_mode) == 0o700 and
                    directory_info.st_uid == os.geteuid() and endpoint.is_socket(),
                    f'owner registration endpoint was not private: {endpoint!s}')
                outsider = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                outsider.settimeout(2)
                outsider.connect(str(endpoint))
                passed_fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
                try:
                    try:
                        outsider.sendmsg([b'not-a-valid-owner-HELLO'],
                            [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                              struct.pack('i', passed_fd))])
                    except BrokenPipeError:
                        pass
                    try:
                        unauthorized = outsider.recv(64)
                    except (ConnectionResetError, BrokenPipeError):
                        unauthorized = b''
                    require(unauthorized == b'',
                        f'foreign actor received registration data: {unauthorized!r}')
                finally:
                    os.close(passed_fd)
                    outsider.close()
                app_ready = wait_line(app, 'C16_APP_READY', 10)
                require('C16_APP_READY' in app_ready and 'one_use=ealready' in app_ready and
                    endpoint.exists(),
                    f'valid owner did not obtain READY after foreign peer rejection: '
                    f'{app_ready!r}')
                os.kill(app.pid, signal.SIGUSR2)
                app_done = wait_line(app, 'C16_APP_DONE', 5)
                require('accepted=0' in app_done and 'inserted=0' in app_done,
                    f'owner probe touched the admission map: {app_done!r}')
                output, errors = app.communicate(timeout=5)
                require(app.returncode == 0,
                    f'authenticated owner did not exit cleanly: rc={app.returncode}; '
                    f'stdout={output!r}; stderr={errors!r}')
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after rejected owner HELLO: '
                    f'rc={broker.returncode}; stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'wrong-actor registration leaked broker I/O state: {report!r}')
                print('C16_OWNER_AUTH_PASS wrong_actor=no_ready valid_actor=ready '
                    'one_use=ok fd_cleanup=ok')
                return 0
            if args.malformed_owner_hello_only:
                marker = wait_line(app, 'C16_ATTACH_ENDPOINT path=', 20)
                endpoint = Path(marker.split('path=', 1)[1].strip())
                output, errors = app.communicate(timeout=10)
                require(app.returncode == 2 and 'C16_APP_READY' not in output and
                    'broker admission attach' in errors and not endpoint.exists(),
                    f'authenticated malformed HELLO with SCM_RIGHTS was not rejected '
                    f'and cleaned up: rc={app.returncode}; stdout={output!r}; '
                    f'stderr={errors!r}; path_exists={endpoint.exists()}')
                rights_closed = wait_line(broker, 'C16_HELLO_RIGHTS_CLOSED fd=', 5)
                require(re.search(r'C16_HELLO_RIGHTS_CLOSED fd=\d+', rights_closed),
                    f'broker did not confirm closing the received SCM_RIGHTS fd: '
                    f'{rights_closed!r}')
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after malformed authenticated HELLO: '
                    f'rc={broker.returncode}; stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'malformed HELLO leaked broker I/O state: {report!r}')
                print('C16_OWNER_AUTH_MALFORMED_PASS valid_peer=1 unexpected_rights=rejected '
                    'no_ready=1 endpoint_cleanup=ok pool=0')
                return 0
            if args.owner_death_only:
                marker = wait_line(app, 'C16_ATTACH_ENDPOINT path=', 20)
                endpoint = Path(marker.split('path=', 1)[1].strip())
                require('C16_APP_READY' in wait_line(app, 'C16_APP_READY', 10),
                    'owner did not attach before death-cleanup check')
                os.kill(app.pid, signal.SIGKILL)
                require(app.wait(timeout=5) == -signal.SIGKILL,
                    'owner fixture did not die from SIGKILL')
                deadline = time.monotonic() + 5
                while endpoint.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                require(not endpoint.exists(),
                    'broker did not unlink the dead owner registration endpoint')
                run_progress_client(args.progress_client, rpc_path)
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after owner death: rc={broker.returncode}; '
                    f'stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'owner death leaked broker I/O state: {report!r}')
                print('C16_OWNER_DEATH_CLEANUP_PASS endpoint_unlinked=1 '
                    'broker_progress=1 pool=0')
                return 0
            if args.listener_close_only:
                marker = wait_line(app, 'C16_ATTACH_ENDPOINT path=', 20)
                endpoint = Path(marker.split('path=', 1)[1].strip())
                app_ready = wait_line(app, 'C16_APP_READY', 20)
                require('C16_APP_READY' in app_ready,
                    'owner did not attach before listener-close check')
                os.kill(app.pid, signal.SIGUSR1)
                require('C16_LISTENER_CLOSED owner_alive=1' in
                    wait_line(app, 'C16_LISTENER_CLOSED', 5),
                    'FF listener close did not complete on the owner loop')
                output, errors = app.communicate(timeout=5)
                deadline = time.monotonic() + 3
                while endpoint.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                require(app.returncode == 3 and
                    'ker owner pump callback status=-104' in errors and
                    not endpoint.exists(),
                    f'listener-close did not fail closed and release the endpoint: '
                    f'rc={app.returncode}; path_exists={endpoint.exists()}; '
                    f'stdout={output!r}; stderr={errors!r}')
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after listener close: rc={broker.returncode}; '
                    f'stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'listener close leaked broker I/O state: {report!r}')
                print('C16_LISTENER_CLOSE_CLEANUP_PASS owner_alive=1 '
                    'fail_closed=ECONNRESET endpoint_unlinked=1 pool=0')
                return 0
            app_ready = wait_line(app, 'C16_APP_READY', 20)
            if args.pump_failure_only:
                retained = wait_line(app, 'C16_PUMP_FAILURE_EVENT_RETAINED', 5)
                require('sticky=ECONNRESET' in retained,
                    f'pump failure did not return the already-observed event: {retained!r}')
                output, errors = app.communicate(timeout=5)
                require(app.returncode == -signal.SIGABRT,
                    f'owner pump failure did not remain sticky/quarantined: '
                    f'rc={app.returncode}; stdout={output!r}; stderr={errors!r}')
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after pump-failure quarantine: '
                    f'rc={broker.returncode}; stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'pump-failure quarantine leaked I/O pool objects: {report!r}')
                print('C16_OWNER_PUMP_FAILURE_PASS observed=ET_ONESHOT_NEXT_WAIT=sticky_error pool=0')
                return 0
            require('pump_timeout=retained' in app_ready and
                'host_only=eopnotsupp' in app_ready,
                f'owner pump timeout/host-only checks did not pass: {app_ready!r}')
            try:
                for index, source_port in enumerate(flow_ports[:16]):
                    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer.settimeout(8)
                    peer.bind(('198.18.0.1', source_port))
                    peer.connect(('198.18.0.2', 8080))
                    peers.append(peer)
                    if index == 0:
                        require('C16_RECURSIVE_WAIT_EDEADLK' in
                            wait_line(app, 'C16_RECURSIVE_WAIT_EDEADLK', 5),
                            'recursive owner wait did not fail with EDEADLK')

                overflow = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                overflow.setblocking(False)
                overflow.bind(('198.18.0.1', flow_ports[16]))
                pending_status = overflow.connect_ex(('198.18.0.2', 8080))
                require(pending_status in (errno.EINPROGRESS, errno.EALREADY),
                    f'seventeenth colliding flow did not remain pending: {pending_status}')
                _, writable, exceptional = select.select(
                    [], [overflow], [overflow], 0.4)
                require(not writable and not exceptional,
                    'map-full flow unexpectedly completed or failed before an admission decision')
                synacks = captured_synacks(capture, {flow_ports[16], 12001})
                require(not synacks,
                    f'timed-out or map-full flow emitted SYN-ACK on wire: {synacks!r}')

                map_identity = wait_line(broker,
                    f'C16_ADMISSION identity-ready remote_port={flow_ports[16]}', 5)
                identity_ns, packet_deadline_ns = trace_times(map_identity,
                    'identity-ready', flow_ports[16])
                map_revoke = wait_line(broker,
                    f'C16_ADMISSION request-revoked remote_port={flow_ports[16]}', 5)
                revoke_ns, revoke_deadline_ns = trace_times(map_revoke,
                    'request-revoked', flow_ports[16])
                require(identity_ns < packet_deadline_ns == revoke_deadline_ns and
                    revoke_ns < packet_deadline_ns,
                    f'map-full request identity/revoke missed packet deadline: '
                    f'{map_identity!r}; {map_revoke!r}')

                # The 17th SYN was observed while the listener remained live.
                # A zero owner-scoped reqsk census is the direct proof that the
                # exact rejected request was revoked, not merely hidden from wire.
                os.kill(app.pid, signal.SIGUSR1)
                require_zero_requests(wait_line(app, 'C16_REQUESTS', 5),
                    'map-full exact request cleanup', inserted=16)
                overflow.close()
                del overflow

                for index, peer in enumerate(peers):
                    peer.sendall(bytes((0x43, 0x31, index)))
                    received = bytearray()
                    while len(received) < 3:
                        chunk = peer.recv(3 - len(received))
                        require(bool(chunk), 'FF owner closed a completed admitted stream early')
                        received.extend(chunk)
                    require(bytes(received) == bytes((0x43, 0x31, index)),
                        f'admitted flow {index} echo mismatch: {bytes(received)!r}')
                # Now test the independent deadline with the genuine map full
                # but otherwise stable. No map callback can run while stopped.
                os.kill(app.pid, signal.SIGSTOP)
                stopped = os.waitid(os.P_PID, app.pid,
                    os.WSTOPPED | os.WEXITED | os.WNOWAIT)
                require(stopped.si_code == os.CLD_STOPPED and
                    stopped.si_status == signal.SIGSTOP,
                    f'FF owner did not acknowledge SIGSTOP before probe: {stopped!r}')
                deadline_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                deadline_probe.setblocking(False)
                deadline_probe.bind(('198.18.0.1', 12001))
                pending_status = deadline_probe.connect_ex(('198.18.0.2', 8080))
                require(pending_status in (errno.EINPROGRESS, errno.EALREADY),
                    f'stopped-owner probe did not remain pending: {pending_status}')
                deadline_identity = wait_line(broker,
                    'C16_ADMISSION identity-ready remote_port=12001', 5)
                identity_ns, packet_deadline_ns = trace_times(deadline_identity,
                    'identity-ready', 12001)
                require(identity_ns < packet_deadline_ns,
                    f'stopped-owner request identity was not resolved before deadline: '
                    f'{deadline_identity!r}')
                run_progress_client(args.progress_client, rpc_path)
                deadline_timeout = wait_line(broker,
                    'C16_ADMISSION owner-timeout remote_port=12001', 5)
                timeout_ns, timeout_deadline_ns = trace_times(deadline_timeout,
                    'owner-timeout', 12001)
                deadline_revoke = wait_line(broker,
                    'C16_ADMISSION request-revoked remote_port=12001', 5)
                revoke_ns, revoke_deadline_ns = trace_times(deadline_revoke,
                    'request-revoked', 12001)
                require(timeout_ns >= packet_deadline_ns == timeout_deadline_ns ==
                    revoke_deadline_ns and revoke_ns >= timeout_ns,
                    f'stopped-owner decision/revoke timestamps do not prove the '
                    f'250ms deadline: {deadline_timeout!r}; {deadline_revoke!r}')
                deadline_synacks = captured_synacks(capture, {12001})
                require(not deadline_synacks,
                    f'stopped-owner deadline probe emitted SYN-ACK before resume: '
                    f'{deadline_synacks!r}')
                os.kill(app.pid, signal.SIGUSR1)
                os.kill(app.pid, signal.SIGUSR2)
                os.kill(app.pid, signal.SIGCONT)
                require_zero_requests(wait_line(app, 'C16_REQUESTS', 5),
                    'stopped-owner deadline cleanup', inserted=16)
                deadline_probe.close()
                app_done = wait_line(app, 'C16_APP_DONE', 10)
            finally:
                if 'overflow' in locals():
                    overflow.close()
                for peer in peers:
                    peer.close()
            require('accepted=16' in app_done and 'inserted=16' in app_done and
                'full=' in app_done and int(app_done.split('full=')[1].split()[0]) >= 1,
                f'original flow-map full/admit accounting is missing: {app_done!r}')
            output, errors = app.communicate(timeout=10)
            require((app.returncode == 0 or
                (app.returncode == -signal.SIGABRT and
                 'ker owner pump callback status=-104' in errors)),
                f'FF owner did not exit cleanly or through the expected quarantined '
                f'deadline path: rc={app.returncode}; stdout={output!r}; stderr={errors!r}')
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                stop.sendto(b'STOP', str(stop_path))
            bout, berr = broker.communicate(timeout=35)
            require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                f'broker failed to stop cleanly: rc={broker.returncode}; '
                f'stdout={bout!r}; stderr={berr!r}')
            report = json.loads(stats.read_text())
            native = report.get('native', {})
            require(report.get('outstanding') == 0 and report.get('tx', 0) > 0 and
                report.get('rx', 0) > 0 and native.get('passive_opens', 0) >= 16,
                f'original-Linux broker wire/cleanup evidence missing: {report!r}')
            require('C16_BROKER_OWNER_TAP_PASS' not in output,
                'unexpected duplicate output marker')
            print(f'C16_BROKER_OWNER_TAP_PASS {app_done.strip()} '
                f'owner_deadline=quarantined '
                f'original_linux_passive_open={native.get("passive_opens")} pool=0')
            return 0
        finally:
            if app is not None and app.poll() is None:
                app.kill()
                app.wait()
            if broker is not None and broker.poll() is None:
                broker.kill()
                broker.wait()
            capture.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--preload', type=Path, required=True)
    parser.add_argument('--broker', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--progress-client', type=Path, required=True)
    parser.add_argument('--pump-failure-only', action='store_true')
    parser.add_argument('--registration-negative-only', action='store_true')
    parser.add_argument('--malformed-owner-hello-only', action='store_true')
    parser.add_argument('--owner-death-only', action='store_true')
    parser.add_argument('--listener-close-only', action='store_true')
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if args.inside:
        return inside(args)
    command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
    for name in ('launcher', 'library', 'worker', 'dpdk_plugin_dir', 'preload',
                 'broker', 'client', 'progress_client'):
        command += ['--' + name.replace('_', '-'), str(getattr(args, name).resolve())]
    if args.pump_failure_only:
        command.append('--pump-failure-only')
    if args.registration_negative_only:
        command.append('--registration-negative-only')
    if args.malformed_owner_hello_only:
        command.append('--malformed-owner-hello-only')
    if args.owner_death_only:
        command.append('--owner-death-only')
    if args.listener_close_only:
        command.append('--listener-close-only')
    return subprocess.run(command).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'C16 broker admission wire fixture failed: {error}', file=sys.stderr)
        raise SystemExit(1)
