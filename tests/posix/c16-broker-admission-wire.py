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
    recent = getattr(process, '_ker_recent_lines', [])
    pending = getattr(process, '_ker_line_buffer', bytearray())
    eof = False
    while time.monotonic() < deadline:
        # A previous call can drain multiple records and return at the first
        # match. Consume complete retained records before waiting on the fd.
        while b'\n' in pending:
            raw, _, remainder = pending.partition(b'\n')
            pending = bytearray(remainder)
            line = raw.decode(errors='replace')
            recent.append(line)
            del recent[:-16]
            process._ker_recent_lines = recent
            if expected in line:
                process._ker_line_buffer = pending
                return line + '\n'
        ready, _, _ = select.select([process.stdout], [], [], 0.05)
        if ready:
            # Drain bytes before checking process.poll(): a short-lived child
            # can write its final complete marker and exit between iterations.
            # TextIOWrapper.readline() may prefetch later records, so use the
            # underlying fd and preserve partial lines across wait_line calls.
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                eof = True
            else:
                pending.extend(chunk)
                while b'\n' in pending:
                    raw, _, remainder = pending.partition(b'\n')
                    pending = bytearray(remainder)
                    line = raw.decode(errors='replace')
                    recent.append(line)
                    del recent[:-16]
                    process._ker_recent_lines = recent
                    if expected in line:
                        process._ker_line_buffer = pending
                        return line + '\n'
        process._ker_line_buffer = pending
        # poll() may report exit while more than one read chunk remains in the
        # pipe. EOF, not process exit alone, proves there is no later marker.
        if eof:
            if pending:
                line = pending.decode(errors='replace')
                recent.append(line)
                process._ker_recent_lines = recent[-16:]
                process._ker_line_buffer = bytearray()
            output, errors = process.communicate()
            raise RuntimeError(f'process exited before {expected}: rc={process.returncode}; '
                f'recent={recent!r}; stdout={output!r}; stderr={errors!r}')
    raise RuntimeError(f'timed out waiting for {expected}; recent={recent!r}')


def wait_process_stopped(process, timeout=5):
    status_path = Path(f'/proc/{process.pid}/status')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None or not status_path.exists():
            raise RuntimeError(f'owner exited before stop barrier: pid={process.pid}')
        for line in status_path.read_text().splitlines():
            if line.startswith('State:') and line.split()[1] in ('T', 't'):
                return
        time.sleep(.005)
    raise RuntimeError(f'owner did not stop at explicit-stop barrier: pid={process.pid}')


def collect_output(process, timeout=None):
    retained = bytes(getattr(process, '_ker_line_buffer', bytearray()))
    process._ker_line_buffer = bytearray()
    output, errors = process.communicate(timeout=timeout)
    return retained.decode(errors='replace') + output, errors


def wait_line_selftest():
    child = subprocess.Popen([sys.executable, '-c',
        "import os; os.write(1, b'FIRST_MARKER complete\\nSECOND_MARKER complete\\n'); os._exit(0)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    child.wait(timeout=2)
    require('FIRST_MARKER complete' in wait_line(child, 'FIRST_MARKER', 2),
        'wait_line lost the first complete marker written immediately before exit')
    require('SECOND_MARKER complete' in wait_line(child, 'SECOND_MARKER', 2),
        'wait_line lost a retained later marker written before immediate exit')

    buffered = subprocess.Popen([sys.executable, '-c',
        "import os; os.write(1, b'FIRST_BUFFERED_MARKER\\nSECOND_BUFFERED_MARKER\\n'); os._exit(0)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    buffered.wait(timeout=2)
    require('FIRST_BUFFERED_MARKER' in wait_line(buffered, 'FIRST_BUFFERED_MARKER', 2),
        'wait_line missed the marker preceding buffered output collection')
    collected, _ = collect_output(buffered, timeout=2)
    require(collected == 'SECOND_BUFFERED_MARKER\n' and
        buffered._ker_line_buffer == bytearray(),
        f'output collection lost or duplicated wait_line-buffered bytes: {collected!r}')

    large = subprocess.Popen([sys.executable, '-c',
        "import os; os.write(1, b'x' * 5000 + b'\\nLARGE_FINAL_MARKER complete\\n'); os._exit(0)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    large.wait(timeout=2)
    require('LARGE_FINAL_MARKER complete' in wait_line(large, 'LARGE_FINAL_MARKER', 2),
        'wait_line stopped at process exit before draining a later pipe chunk')

    missing = subprocess.Popen([sys.executable, '-c',
        "import os; os.write(1, b'OTHER_MARKER\\n'); os._exit(0)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    missing.wait(timeout=2)
    try:
        wait_line(missing, 'MISSING_MARKER', 2)
    except RuntimeError as error:
        require('OTHER_MARKER' in str(error),
            f'missing-marker exit omitted drained output: {error!r}')
    else:
        raise RuntimeError('wait_line accepted a marker that the child did not write')

    partial = subprocess.Popen([sys.executable, '-c',
        "import os; os.write(1, b'PARTIAL_MARK'); os._exit(0)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    partial.wait(timeout=2)
    started = time.monotonic()
    try:
        wait_line(partial, 'PARTIAL_MARKER', 2)
    except RuntimeError as error:
        require('PARTIAL_MARK' in str(error),
            f'partial-marker exit omitted its pending bytes: {error!r}')
        require(time.monotonic() - started < 1,
            'partial-marker exit was not diagnosed promptly')
    else:
        raise RuntimeError('wait_line accepted a partial marker without a newline')
    print('C16_WAIT_LINE_OBSERVER_PASS final-markers=drained large-output=drained '
        'missing-marker=rejected partial-marker=diagnosed')


def run_progress_client(path, rpc_path):
    progress = subprocess.run([str(path), str(rpc_path)],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=10, env=os.environ | {'TMPDIR': os.environ.get('TMPDIR', '/dev/shm')})
    require(progress.returncode == 0 and 'C16_RPC_PROGRESS_OK' in progress.stdout and
        'history=EBUSY' in progress.stdout,
        f'unrelated broker RPC did not complete: rc={progress.returncode}; '
        f'stdout={progress.stdout!r}; stderr={progress.stderr!r}')


def run_ordinary_tfo_client(path, rpc_path):
    result = subprocess.run([str(path), str(rpc_path), 'ordinary-tfo'],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=10, env=os.environ | {'TMPDIR': os.environ.get('TMPDIR', '/dev/shm')})
    require(result.returncode == 0 and 'C16_ORDINARY_TFO_OK enabled=1' in result.stdout,
        f'ordinary broker TCP_FASTOPEN behavior changed: rc={result.returncode}; '
        f'stdout={result.stdout!r}; stderr={result.stderr!r}')


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


def captured_syns(capture, source_ports):
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
        if (source_port in source_ports and destination_port == 8080 and
            flags & 0x12 == 0x02):
            matches.append(source_port)
    return matches


def captured_tcp_events(capture, source_ports, destination_ports):
    """Drain ingress frames without losing SYNACKs while looking for SYNs."""
    syns = []
    synacks = []
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
        if (source_port in source_ports and destination_port == 8080 and
            flags & 0x12 == 0x02):
            syns.append(source_port)
        if (source_port == 8080 and destination_port in destination_ports and
            flags & 0x12 == 0x12):
            synacks.append(destination_port)
    return syns, synacks


def drain_process_lines(process):
    recent = getattr(process, '_ker_recent_lines', [])
    pending = getattr(process, '_ker_line_buffer', bytearray())
    while select.select([process.stdout], [], [], 0)[0]:
        byte = os.read(process.stdout.fileno(), 1)
        if not byte:
            break
        pending.extend(byte)
        if byte == b'\n':
            recent.append(pending.decode(errors='replace').rstrip())
            del recent[:-16]
            pending = bytearray()
    process._ker_recent_lines = recent
    process._ker_line_buffer = pending
    return recent


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
            finalized_fifo = root / 'finalized.release'
            if args.finalized_timeout_only:
                os.mkfifo(finalized_fifo, 0o600)
                app_env['KER_C16_TEST_HOLD_FINALIZED_FIFO'] = str(finalized_fifo)
            cancel_fifo = root / 'cancel.release'
            if args.cancel_unsent_timeout_only:
                os.mkfifo(cancel_fifo, 0o600)
                app_env['KER_C16_TEST_HOLD_PREPARED_FIFO'] = str(cancel_fifo)
            if not args.pump_failure_only and not args.window_cycles_only and \
                    not args.window_cancel_only:
                app_env |= {'KER_C16_TEST_PUMP_DELAY_US': '80000',
                    'KER_C16_TEST_RECURSIVE_WAIT': '1'}
            if args.window_cancel_only:
                app_env['KER_C17_TEST_DELAY_PREPARED_MS'] = '350'
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
            if args.explicit_stop_live_listener_only:
                app_env['KER_C16_TEST_PAUSE_AFTER_PREPARE'] = '1'
            app_argument = ('pump-failure' if args.pump_failure_only else
                '1' if args.cancel_unsent_timeout_only else
                '1' if args.finalized_timeout_only else
                'window-cycles' if args.window_cycles_only else
                'window-cancel' if args.window_cancel_only else
                'owner-probe' if (args.registration_negative_only or
                    args.malformed_owner_hello_only or args.owner_death_only or
                    args.listener_close_only or args.explicit_stop_live_listener_only) else '16')
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
            if args.explicit_stop_live_listener_only:
                wait_line(app, 'C16_ATTACH_ENDPOINT path=', 20)
                app_ready = wait_line(app, 'C16_APP_READY', 10)
                require('C16_APP_READY' in app_ready,
                    'owner did not attach before explicit-stop listener check')
                os.kill(app.pid, signal.SIGSTOP)
                wait_process_stopped(app)
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                pre_finalize = wait_line(broker,
                    'C16_ADMISSION listener-ref-put-before-native-finalize', 10)
                require(pre_finalize.strip() ==
                    'C16_ADMISSION listener-ref-put-before-native-finalize',
                    f'listener reference was not released before native finalization: {pre_finalize!r}')
                bout, berr = collect_output(broker, timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed while stopping with live admission listener: '
                    f'rc={broker.returncode}; stdout={bout!r}; stderr={berr!r}')
                broker_lines = getattr(broker, '_ker_recent_lines', []) + bout.splitlines()
                require(broker_lines.count(
                    'C16_ADMISSION listener-ref-put-before-native-finalize') == 1 and
                    'C16_ADMISSION listener-ref-put-at-task-release' not in broker_lines,
                    f'listener reference was omitted, duplicated, or released after finalization: '
                    f'{broker_lines!r}')
                os.kill(app.pid, signal.SIGUSR2)
                os.kill(app.pid, signal.SIGCONT)
                app_output, app_errors = app.communicate(timeout=8)
                owner_stopped = ('C16_APP_DONE accepted=0 inserted=0' in app_output and
                    (app.returncode == 0 or (app.returncode == -signal.SIGABRT and
                        'ker owner pump callback status=-104' in app_errors)))
                require(owner_stopped,
                    f'stopped owner did not terminate after broker endpoint shutdown: '
                    f'rc={app.returncode}; stdout={app_output!r}; stderr={app_errors!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'explicit-stop listener lifecycle leaked broker I/O state: {report!r}')
                print('C16_EXPLICIT_STOP_LIVE_LISTENER_PASS '
                    'listener_ref=put-before-finalize task_release=no-op pool=0')
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
            if args.finalized_timeout_only or args.cancel_unsent_timeout_only:
                tfo_guard = wait_line(app, 'C16_TFO_GUARD_PASS', 20)
                require('prebind=EOPNOTSUPP' in tfo_guard and
                    'postlisten=EOPNOTSUPP' in tfo_guard,
                    f'admission-owned listener did not reject late TCP_FASTOPEN: {tfo_guard!r}')
            app_ready = wait_line(app, 'C16_APP_READY', 20)
            if args.window_cycles_only:
                require('C16_APP_READY' in app_ready,
                    f'owner did not attach for window-cycle test: {app_ready!r}')
                initial = wait_line(app, 'C17_WINDOW_INITIAL', 5)
                initial_match = re.search(r'epoch=(\d+) lease=(\d+) active=(\d+) inserted=(\d+)', initial)
                require(initial_match and int(initial_match.group(1)) == 1 and
                    int(initial_match.group(2)) > 0 and
                    int(initial_match.group(3)) == 1 and
                    int(initial_match.group(4)) == 0,
                    f'initial map window was not active: {initial!r}')
                initial_lease = int(initial_match.group(2))

                def complete_window_flow(source_port, payload):
                    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    peer.settimeout(8)
                    peer.bind(('198.18.0.1', source_port))
                    peer.connect(('198.18.0.2', 8080))
                    peer.sendall(payload)
                    received = bytearray()
                    while len(received) < len(payload):
                        chunk = peer.recv(len(payload) - len(received))
                        require(bool(chunk),
                            f'window flow {source_port} closed before echo')
                        received.extend(chunk)
                    require(bytes(received) == payload,
                        f'window flow {source_port} echo mismatch: {bytes(received)!r}')
                    peer.close()

                complete_window_flow(12021, b'c17-window-1')
                os.kill(app.pid, signal.SIGWINCH)
                retired1 = wait_line(app, 'C17_WINDOW_RETIRED', 10)
                retired1_match = re.search(
                    r'epoch=(\d+) lease=(\d+) active=(\d+) inserted=(\d+)', retired1)
                require(retired1_match and
                    tuple(map(int, retired1_match.groups())) ==
                    (1, initial_lease, 0, 1),
                    f'first retirement did not close the original map window: {retired1!r}')

                # Cross the broker's five-second initial-attach deadline while
                # this established owner remains deliberately retired. The
                # socket/listen RPCs below must be rejected without ending the
                # admission task or mutating the existing probe socket.
                retired_wait = time.monotonic()
                time.sleep(5.2)
                require(time.monotonic() - retired_wait >= 5.0,
                    'retired-window regression did not cross initial attach deadline')
                os.kill(app.pid, signal.SIGUSR1)
                rpc_probe = wait_line(app, 'C17_RETIRED_RPC_EAGAIN', 5)
                require('socket=1 listen=1 native_unchanged=1' in rpc_probe,
                    f'retired-window socket/listen operations mutated native state: '
                    f'{rpc_probe!r}')
                outside_snapshot = wait_line(app, 'C16_REQUESTS', 5)
                require('status=0' in outside_snapshot and 'count=0' in outside_snapshot,
                    f'established owner stopped responding during the retired window: '
                    f'{outside_snapshot!r}')

                # The same live listener must continue serving during the
                # interval when the original flow map is closed and its mark
                # gate is disabled. This flow must not mutate the closed map.
                complete_window_flow(12022, b'c17-outside-window')
                os.kill(app.pid, signal.SIGUSR1)
                outside = wait_line(app, 'C16_REQUESTS', 5)
                require('status=0' in outside and 'count=0' in outside and
                    'inserted=1' in outside,
                    f'outside-window listener flow touched the retired map: {outside!r}')

                os.kill(app.pid, signal.SIGHUP)
                ready2 = wait_line(app, 'C17_WINDOW_READY', 10)
                ready2_match = re.search(
                    r'epoch=(\d+) lease=(\d+) active=(\d+) inserted=(\d+)', ready2)
                require(ready2_match and int(ready2_match.group(1)) == 2 and
                    int(ready2_match.group(2)) > initial_lease and
                    int(ready2_match.group(3)) == 1 and
                    int(ready2_match.group(4)) == 1,
                    f'second window did not rearm with a fresh lease: {ready2!r}')
                lease2 = int(ready2_match.group(2))
                complete_window_flow(12023, b'c17-window-2')
                os.kill(app.pid, signal.SIGWINCH)
                retired2 = wait_line(app, 'C17_WINDOW_RETIRED', 10)
                retired2_match = re.search(
                    r'epoch=(\d+) lease=(\d+) active=(\d+) inserted=(\d+)', retired2)
                require(retired2_match and tuple(map(int, retired2_match.groups())) ==
                    (2, lease2, 0, 2),
                    f'second retirement did not settle the current epoch: {retired2!r}')
                os.kill(app.pid, signal.SIGHUP)
                ready3 = wait_line(app, 'C17_WINDOW_READY', 10)
                ready3_match = re.search(
                    r'epoch=(\d+) lease=(\d+) active=(\d+) inserted=(\d+)', ready3)
                require(ready3_match and int(ready3_match.group(1)) == 3 and
                    int(ready3_match.group(2)) > lease2 and
                    int(ready3_match.group(3)) == 1 and
                    int(ready3_match.group(4)) == 2,
                    f'third window did not rearm with a fresh lease: {ready3!r}')
                complete_window_flow(12024, b'c17-window-3')
                os.kill(app.pid, signal.SIGUSR2)
                done = wait_line(app, 'C16_APP_DONE', 10)
                require('accepted=4' in done and 'inserted=3' in done,
                    f'three active windows plus one outside-window flow were not accounted: {done!r}')
                output, errors = app.communicate(timeout=10)
                require(app.returncode == 0,
                    f'FF app failed after three window cycles: rc={app.returncode}; '
                    f'stdout={output!r}; stderr={errors!r}')
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after window cycles: rc={broker.returncode}; '
                    f'stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                native = report.get('native', {})
                require(report.get('outstanding') == 0 and report.get('tx', 0) >= 4 and
                    report.get('rx', 0) >= 4 and native.get('passive_opens', 0) >= 4,
                    f'original-Linux packet/lifecycle cleanup evidence missing: {report!r}')
                print(f'C17_ADMISSION_WINDOWS_PASS {done.strip()} leases={initial_lease},'
                    f'{lease2},{int(ready3_match.group(2))} outside_window=served pool=0')
                return 0
            if args.window_cancel_only:
                require('C16_APP_READY' in app_ready,
                    f'owner did not attach for delayed-cancel test: {app_ready!r}')
                peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                peer.setblocking(False)
                peer.bind(('198.18.0.1', 12031))
                pending = peer.connect_ex(('198.18.0.2', 8080))
                require(pending in (errno.EINPROGRESS, errno.EALREADY),
                    f'flow did not remain pending while PREPARED was delayed: {pending}')
                delayed = wait_line(app, 'C17_PREPARED_REPLY_DELAYED', 5)
                require('owner_prepared=1 response_pending=1' in delayed,
                    f'owner did not retain a nonblocking PREPARED response: {delayed!r}')
                os.kill(app.pid, signal.SIGWINCH)
                retire_begin = wait_line(app, 'C17_RETIRE_BEGIN_ACK', 5)
                require('state=retiring' in retire_begin,
                    f'broker did not acknowledge retirement during the packet transaction: '
                    f'{retire_begin!r}')
                prepared_timeout = wait_line(broker,
                    'C16_ADMISSION prepared-timeout remote_port=12031', 5)
                timeout_ns, packet_deadline_ns = trace_times(prepared_timeout,
                    'prepared-timeout', 12031)
                require(timeout_ns >= packet_deadline_ns,
                    f'PREPARED timeout did not occur after packet deadline: '
                    f'{prepared_timeout!r}')
                revoked = wait_line(broker,
                    'C16_ADMISSION request-revoked remote_port=12031', 5)
                cancel = wait_line(broker,
                    'C16_ADMISSION cancel-unsent-settled remote_port=12031', 5)
                revoke_ns, _ = trace_times(revoked, 'request-revoked', 12031)
                cancel_ns, _ = trace_times(cancel, 'cancel-unsent-settled', 12031)
                require(revoke_ns <= cancel_ns,
                    f'exact request revoke did not precede settled cancellation: '
                    f'{revoked!r}; {cancel!r}')
                window_task = wait_line(broker,
                    'C17_WINDOW_TASK retire-complete', 5)
                require('status=0' in window_task,
                    f'broker could not complete retirement after cancellation: '
                    f'{window_task!r}')
                try:
                    map_retired = wait_line(app, 'C17_RETIRE_AFTER_CANCEL', 10)
                except RuntimeError as error:
                    raise RuntimeError(f'{error}; broker_recent='
                        f'{getattr(broker, "_ker_recent_lines", [])!r}') from error
                retired_match = re.search(r'now_ns=(\d+)', map_retired)
                require('active=1 inserted=1 revoked=1 lookup=0' in map_retired and
                    retired_match and cancel_ns < int(retired_match.group(1)),
                    f'map closed before successful cancellation/revoke: '
                    f'{cancel!r}; {map_retired!r}')
                retired = wait_line(app, 'C17_WINDOW_RETIRED', 5)
                require('active=0' in retired,
                    f'owner did not report retirement after cancellation: {retired!r}')
                require(not captured_synacks(capture, {12031}),
                    'SYN-ACK escaped while retirement waited for PREPARED cancellation')
                peer.close()
                os.kill(app.pid, signal.SIGUSR2)
                wait_line(app, 'C16_APP_DONE', 5)
                output, errors = app.communicate(timeout=10)
                require(app.returncode == 0,
                    f'FF app failed after delayed cancellation: rc={app.returncode}; '
                    f'stdout={output!r}; stderr={errors!r}')
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after delayed cancellation: rc={broker.returncode}; '
                    f'stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0 and report.get('pool', 0) == 0,
                    f'delayed cancellation leaked broker I/O state: {report!r}')
                print('C17_RETIRE_PENDING_CANCEL_PASS retire_begin=acknowledged '
                    'cancelled=1 revoked=1 map_active_until_cancel=1 synack=0 pool=0')
                return 0
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
            if args.finalized_timeout_only:
                run_ordinary_tfo_client(args.progress_client, rpc_path)
                run_progress_client(args.progress_client, rpc_path)
                first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                first.settimeout(5)
                first.bind(('198.18.0.1', 12002))
                first.connect(('198.18.0.2', 8080))
                held = wait_line(app, 'C16_FINALIZED_REPLY_HELD', 5)
                require('allowed=1 created=1 map_retained=1' in held,
                    f'test did not hold a finalized fresh map entry: {held!r}')
                finalized_timeout = wait_line(broker,
                    'C16_ADMISSION finalized-timeout remote_port=12002', 5)
                timeout_ns, packet_deadline_ns = trace_times(
                    finalized_timeout, 'finalized-timeout', 12002)
                require(timeout_ns >= packet_deadline_ns,
                    f'FINALIZED wait did not expire after its packet deadline: '
                    f'{finalized_timeout!r}')
                quarantined = wait_line(broker,
                    'C16_ADMISSION accepted-quarantine-map-retained remote_port=12002', 5)
                require('accepted-quarantine-map-retained' in quarantined,
                    f'accepted transaction map was not retained during quarantine: {quarantined!r}')
                second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                second.setblocking(False)
                second.bind(('198.18.0.1', 12003))
                pending = second.connect_ex(('198.18.0.2', 8080))
                require(pending in (errno.EINPROGRESS, errno.EALREADY),
                    f'follow-up request did not remain behind the quarantined gate: {pending}')
                with open(finalized_fifo, 'wb', buffering=0) as gate:
                    gate.write(b'R')
                output, errors = app.communicate(timeout=8)
                require(app.returncode == -signal.SIGABRT and
                    'ker owner pump callback status=' in errors,
                    f'owner did not fail closed after the delayed FINALIZED reply: '
                    f'rc={app.returncode}; stdout={output!r}; stderr={errors!r}')
                synacks = captured_synacks(capture, {12003})
                require(not synacks,
                    f'quarantined task admitted a later SYNACK: {synacks!r}')
                first.close()
                second.close()
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after admission quarantine: rc={broker.returncode}; '
                    f'stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'finalization quarantine leaked broker I/O state: {report!r}')
                print('C16_FINALIZE_QUARANTINE_PASS accepted=1 map_retained=1 '
                    'followup_synack=0 owner=fail_closed pool=0')
                return 0
            if args.cancel_unsent_timeout_only:
                run_progress_client(args.progress_client, rpc_path)
                first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                first.setblocking(False)
                first.bind(('198.18.0.1', 12004))
                pending = first.connect_ex(('198.18.0.2', 8080))
                require(pending in (errno.EINPROGRESS, errno.EALREADY),
                    f'initial unaccepted connection did not remain pending: {pending}')
                held = wait_line(app, 'C16_PREPARED_REPLY_HELD', 5)
                require('owner_prepared=1 created=1 reservation=retained' in held,
                    f'owner did not hold a prepared map reservation: {held!r}')
                prepared_timeout = wait_line(broker,
                    'C16_ADMISSION prepared-timeout remote_port=12004', 5)
                timeout_ns, packet_deadline_ns = trace_times(
                    prepared_timeout, 'prepared-timeout', 12004)
                require(timeout_ns >= packet_deadline_ns,
                    f'PREPARED wait did not expire at the packet deadline: '
                    f'{prepared_timeout!r}')
                request_revoked = wait_line(broker,
                    'C16_ADMISSION request-revoked remote_port=12004', 5)
                require('request-revoked' in request_revoked,
                    f'pre-accept request was not revoked: {request_revoked!r}')
                unresolved = wait_line(broker,
                    'C16_ADMISSION cancel-unsent-unresolved remote_port=12004', 5)
                require('cancel-unsent-unresolved' in unresolved,
                    f'unacknowledged cancel did not quarantine the worker: {unresolved!r}')

                second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                second.setblocking(False)
                second.bind(('198.18.0.1', 12005))
                pending = second.connect_ex(('198.18.0.2', 8080))
                require(pending in (errno.EINPROGRESS, errno.EALREADY),
                    f'follow-up SYN did not remain pending: {pending}')
                captured = set()
                observed_synacks = []
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and 12005 not in captured:
                    syns, synacks = captured_tcp_events(capture,
                        {12004, 12005}, {12004, 12005})
                    captured.update(syns)
                    observed_synacks.extend(synacks)
                    if 12005 not in captured:
                        time.sleep(0.01)
                require(12005 in captured,
                    'follow-up SYN never reached the original-Linux TAP ingress')
                time.sleep(0.35)
                _, synacks = captured_tcp_events(capture, {12004, 12005},
                    {12004, 12005})
                observed_synacks.extend(synacks)
                lines = drain_process_lines(broker)
                reused = [line for line in lines if 'remote_port=12005' in line and
                    ('identity-ready' in line or 'request-revoked' in line)]
                require(not reused,
                    f'quarantined admission worker reused the stale channel: {reused!r}')
                require(not observed_synacks,
                    f'quarantined admission worker emitted a SYNACK during either '
                    f'the prepared or follow-up request: {observed_synacks!r}')

                with open(cancel_fifo, 'wb', buffering=0) as gate:
                    gate.write(b'R')
                output, errors = app.communicate(timeout=8)
                require(app.returncode == 3 and
                    'ker owner pump callback status=-32' in errors,
                    f'owner did not fail closed after channel quarantine: '
                    f'rc={app.returncode}; stdout={output!r}; stderr={errors!r}')
                first.close()
                second.close()
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as stop:
                    stop.sendto(b'STOP', str(stop_path))
                bout, berr = broker.communicate(timeout=35)
                require(broker.returncode == 0 and 'C16_BROKER_DONE' in bout,
                    f'broker failed after unresolved cancel quarantine: '
                    f'rc={broker.returncode}; stdout={bout!r}; stderr={berr!r}')
                report = json.loads(stats.read_text())
                require(report.get('outstanding') == 0,
                    f'unresolved cancel leaked broker I/O state: {report!r}')
                print('C16_CANCEL_UNSENT_QUARANTINE_PASS reservation=held '
                    'unrelated_request_revoked=0 followup_synack=0 pool=0')
                return 0
            require('pump_timeout=retained' in app_ready and
                'host_only=eopnotsupp' in app_ready and 'tfo_guard=ok' in app_ready,
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
    if '--wait-line-selftest' in sys.argv:
        wait_line_selftest()
        return 0
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
    parser.add_argument('--explicit-stop-live-listener-only', action='store_true')
    parser.add_argument('--finalized-timeout-only', action='store_true')
    parser.add_argument('--cancel-unsent-timeout-only', action='store_true')
    parser.add_argument('--window-cycles-only', action='store_true')
    parser.add_argument('--window-cancel-only', action='store_true')
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
    if args.explicit_stop_live_listener_only:
        command.append('--explicit-stop-live-listener-only')
    if args.finalized_timeout_only:
        command.append('--finalized-timeout-only')
    if args.cancel_unsent_timeout_only:
        command.append('--cancel-unsent-timeout-only')
    if args.window_cycles_only:
        command.append('--window-cycles-only')
    if args.window_cancel_only:
        command.append('--window-cancel-only')
    return subprocess.run(command).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'C16 broker admission wire fixture failed: {error}', file=sys.stderr)
        raise SystemExit(1)
