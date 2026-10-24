#!/usr/bin/env python3
"""Original Linux TCP/UDP peers over a real secondary directional ring PMD."""
import argparse
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import signal
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque

from hugepage_preflight import hugepage_capacity_error


def require(value, message):
    if not value: raise RuntimeError(message)


def tap_interfaces_for_process(pid):
    """Read the kernel-reported interface for every original TUN file description."""
    names = []
    for path in Path(f'/proc/{pid}/fdinfo').iterdir():
        try:
            information = path.read_text()
        except FileNotFoundError:
            continue
        names.extend(line.split(':', 1)[1].strip() for line in information.splitlines()
            if line.startswith('iff:'))
    return names


def line(process, timeout=25):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(timeout), 'packet-session output timed out')
    value = process.stdout.readline()
    if not value:
        raise RuntimeError('packet-session exited early: ' + process.stderr.read().decode())
    return value.decode().strip()


def resolve_dpdk_plugin_dir(plugin_dir, environ=None):
    environment = os.environ if environ is None else environ
    configured = plugin_dir if plugin_dir is not None else environment.get('KER_DPDK_PLUGIN_DIR')
    if not configured:
        raise RuntimeError('configured DPDK PMD directory is required (--dpdk-plugin-dir or KER_DPDK_PLUGIN_DIR)')
    try:
        root = Path(configured).expanduser().resolve(strict=True)
    except OSError as error:
        raise RuntimeError('configured DPDK PMD directory is unavailable: ' + str(configured)) from error
    if not root.is_dir():
        raise RuntimeError('configured DPDK PMD path is not a directory: ' + str(root))
    return root


def resolve_dpdk_plugin_paths(plugin_dir, modules, environ=None):
    root = resolve_dpdk_plugin_dir(plugin_dir, environ)
    resolved = []
    for module in modules:
        requested = root / ('librte_' + module + '.so')
        try:
            library = requested.resolve(strict=True)
        except OSError as error:
            raise RuntimeError('configured DPDK PMD is missing: ' + str(requested)) from error
        if not library.is_file() or not os.access(library, os.R_OK):
            raise RuntimeError('configured DPDK PMD is not a readable regular file: ' + str(library))
        resolved.append(str(library))
    return resolved


def dpdk_plugin_eal_options(paths):
    return ' '.join('-d ' + shlex.quote(path) for path in paths)


def namespace_reexec_command(args, plugin_dir, script=None):
    script_path = Path(__file__).resolve() if script is None else Path(script).resolve()
    command = ['unshare', '-Urn', sys.executable, str(script_path), '--inside',
        '--huge-dir', str(args.huge_dir), '--dpdk-plugin-dir', str(plugin_dir)]
    command.extend(value for name in ('worker', 'tool', 'library', 'app')
        for value in ('--' + name, str(getattr(args, name).resolve())))
    return command


def record(process, prefix):
    value = line(process)
    if not value.startswith(prefix + ' '):
        diagnostic = ''
        if process.poll() is None:
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: pass
        if process.poll() is not None and process.stderr is not None:
            diagnostic = process.stderr.read().decode(errors='replace')
        raise RuntimeError('unexpected output: ' + value + (('\nchild stderr:\n' + diagnostic) if diagnostic else ''))
    return json.loads(value[len(prefix) + 1:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('worker', 'tool', 'library', 'app'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--dpdk-plugin-dir', type=Path)
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    plugin_dir = resolve_dpdk_plugin_dir(args.dpdk_plugin_dir)
    plugin_paths = resolve_dpdk_plugin_paths(plugin_dir, ('mempool_ring',))
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed'); return 77
    if not args.inside:
        return subprocess.run(namespace_reexec_command(args, plugin_dir)).returncode
    require(Path('/dev/net/tun').exists(), 'original host TAP driver is required')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    interface = 'kersession0'
    try: socket.if_nametoindex(interface)
    except OSError: pass
    else: raise RuntimeError('refuse an existing TAP interface')
    fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH22x', interface.encode(), 0x1002))
    for command in (
        ['link', 'set', interface, 'address', '02:4b:45:52:00:01', 'mtu', '1500'],
        ['addr', 'add', '198.18.0.1/24', 'dev', interface],
        ['-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', interface, 'nodad'],
        ['link', 'set', interface, 'up']): subprocess.run(['ip', *command], check=True)
    spec = importlib.util.spec_from_file_location('ker_session_api', args.tool)
    api = importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    wire, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    wire.setblocking(False)
    stop = threading.Event(); errors = []; frames = []; counts = [0, 0]

    def bridge():
        to_tap, to_worker = deque(), deque()
        try:
            while not stop.is_set():
                readers = ([wire] if len(to_tap) < 64 else []) + ([tap] if len(to_worker) < 64 else [])
                writers = ([tap] if to_tap else []) + ([wire] if to_worker else [])
                readable, writable, _ = select.select(readers, writers, [], 0.02)
                if wire in readable:
                    data = wire.recv(65536)
                    require(14 <= len(data) <= 1518, 'malformed native wire frame')
                    to_tap.append(data); frames.append(('native', data))
                if tap in readable:
                    data = os.read(tap, 65536)
                    require(14 <= len(data) <= 1518, 'malformed host TAP frame')
                    to_worker.append(data); frames.append(('host', data))
                if tap in writable:
                    try: amount = os.write(tap, to_tap[0])
                    except BlockingIOError: pass
                    else:
                        require(amount == len(to_tap[0]), 'short TAP frame'); to_tap.popleft(); counts[0] += 1
                if wire in writable:
                    try: amount = wire.send(to_worker[0])
                    except BlockingIOError: pass
                    else:
                        require(amount == len(to_worker[0]), 'short Ethernet channel frame'); to_worker.popleft(); counts[1] += 1
        except ConnectionRefusedError:
            stop.set()  # The worker closes its transferred endpoint after kernel teardown.
        except BaseException as error: errors.append(str(error)); stop.set()

    thread = threading.Thread(target=bridge); thread.start()
    primary = app = standby = None
    handoff_read = -1
    handoff_write = -1
    exception_capture = None
    with tempfile.TemporaryDirectory(prefix='ker-session-packets-') as directory:
        root = Path(directory); path = root / 'control.sock'; stats_path = root / 'stats.json'
        plugin_options = dpdk_plugin_eal_options(plugin_paths)
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry --iova-mode=va '
            f'-m 64 {plugin_options} --huge-dir={shlex.quote(str(args.huge_dir))} '
            f'--file-prefix=packets-{os.getpid()}-{os.urandom(4).hex()}')
        common = ['--socket', str(path), '--worker', str(args.worker), '--eal', eal, '--paired-pmd']
        environment = os.environ | {'RUNTIME_DIRECTORY': str(root), 'PYTHONDONTWRITEBYTECODE': '1'}
        try:
            primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            created = record(primary, 'KER_SESSION_READY')
            require(created['rings'] == 128 and created['ports'] == 1 and created['epoch'] == 0 and created['slot'] == 0,
                'resident did not precreate the complete shared geometry and actual network port')
            handoff_read, handoff_write = os.pipe2(os.O_CLOEXEC)
            app = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--wire-fd', str(endpoint.fileno()),
                '--library', str(args.library), '--stats', str(stats_path), '--address', '198.18.0.2/24', '--address6', '2001:db8:1::2/64',
                '--test-live-handoff-fd', str(handoff_read), '--', str(args.app), '--fixed-mtu'],
                pass_fds=(endpoint.fileno(), handoff_read),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'KER_SESSION_TEST_HANDOFF_REPLAY_PREPARE': '1'}, bufsize=0)
            os.close(handoff_read)
            handoff_read = -1
            require(line(app) == 'READY', 'original Linux application did not start')
            initial = json.loads(stats_path.read_text())
            attached, grant, geometry = (initial[key] for key in ('attached', 'grant', 'geometry'))
            require(attached['pid'] == grant['pid'] and attached['validated_rings'] == 128 and geometry['rx_ring'] != geometry['tx_ring'],
                'worker is not the granted actual secondary with directional PMD queues')
            exception_name = created['exception_endpoint_name']
            exception_ifindex = created['exception_endpoint_ifindex']
            require(exception_name.startswith('kex') and exception_ifindex > 0 and
                geometry['exception_endpoint_ifindex'] == exception_ifindex,
                'resident and granted worker disagree on the persistent exception endpoint identity')
            subprocess.run(['ip', 'address', 'add', '198.18.0.77/32', 'dev', exception_name], check=True)
            exception_mac = bytes.fromhex(json.loads(subprocess.check_output(
                ['ip', '-json', 'link', 'show', 'dev', exception_name], text=True))[0]['address'].replace(':', ''))
            exception_capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            exception_capture.bind((exception_name, 0)); exception_capture.setblocking(False)
            require(attached['generation'] == 0 and grant['generation'] == 0 and
                grant['queue_owner_key'] == grant['exception_endpoint_owner_key'] != 0 and
                grant['exception_endpoint_fd'] is True and geometry['exception_endpoint_owner_key'] == grant['queue_owner_key'],
                'PMD queue and session exception endpoint do not share one grant identity')
            connection = api.Connection(path)
            try:
                census = connection.request(api.STATUS)
                require(census['generation'] == 508 and census['token'] == 3 and census['process'] == 1,
                    'packet TX/RX objects not journaled before native application startup')
            finally: connection.close()
            # Trace real process creation without replacing any successful
            # launch: a competing run must never invoke the application guard.
            trace = root / 'trace'; trace.mkdir()
            marker = root / 'forbidden-app-spawn'
            (trace / 'sitecustomize.py').write_text(
                'import os, subprocess\nfrom pathlib import Path\n_original = subprocess.Popen\n'
                'def record(*values, **options):\n'
                ' command = values[0] if values else options.get("args")\n'
                ' if isinstance(command, (list, tuple)) and command and Path(command[0]).name == "ker-app":\n'
                '  Path(os.environ["KER_TEST_APP_SPAWN_MARKER"]).write_text("spawned")\n'
                ' return _original(*values, **options)\nsubprocess.Popen = record\n')
            spare, rejected_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            rejected = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(rejected_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--', str(args.app)],
                pass_fds=(rejected_endpoint.fileno(),), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(marker)}, bufsize=0)
            rejected_endpoint.close()
            try:
                denied_output, denied_errors = rejected.communicate(timeout=20)
                require(rejected.returncode == 125 and b'PMD consumer grant rejected -16' in denied_errors and
                    b'KER_SESSION_ATTACHED' in denied_errors and not marker.exists(),
                    'busy secondary launched application or bypassed actual admission: ' + denied_errors.decode())
            finally:
                spare.close()
                if rejected.poll() is None: rejected.kill(); rejected.wait()
            standby_stats = root / 'standby.json'
            standby_marker = root / 'standby-app-spawn'
            standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--standby', '--generation', '1',
                '--wire-fd', str(endpoint.fileno()), '--library', str(args.library),
                '--stats', str(standby_stats), '--address6', '2001:db8:1::2/64',
                '--', str(args.app), '--fixed-mtu'], pass_fds=(endpoint.fileno(),),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(standby_marker),
                    'KER_SESSION_TEST_PENDING_HB_BEFORE_PMD': '1'}, bufsize=0)
            endpoint.close()
            deadline = time.monotonic() + 20
            while True:
                waiting = json.loads(standby_stats.read_text()) if standby_stats.exists() else {}
                if waiting.get('stage') == 'standby' and waiting.get('standby_samples', 0) >= 5: break
                require(standby.poll() is None and time.monotonic() < deadline, 'real paired standby did not stay attached')
                time.sleep(0.02)
            pending = waiting['attached']
            require(waiting['standby']['queue_owner_key'] == 0 and
                waiting['standby']['exception_endpoint_owner_key'] == 0 and
                waiting['standby']['exception_endpoint_fd'] is False,
                'denied standby received or claimed the persistent exception endpoint')
            # Inject one uniquely addressed real ARP exception through the session
            # endpoint while a second generation is attached but ungranted.
            exception_sender = bytes.fromhex('024b455200aa')
            arp = (b'\xff' * 6 + exception_sender + b'\x08\x06' +
                struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + exception_sender +
                socket.inet_aton('198.18.0.170') + b'\x00' * 6 + socket.inet_aton('198.18.0.77'))
            require(wire.send(arp) == len(arp), 'could not inject the selected ARP exception frame')
            arp_deadline = time.monotonic() + 5
            exception_frames = []
            arp_reply = []
            while time.monotonic() < arp_deadline:
                arp_reply = [frame for direction, frame in frames if direction == 'native' and
                    len(frame) >= 42 and frame[0:6] == exception_sender and frame[12:14] == b'\x08\x06' and
                    frame[20:22] == b'\x00\x02' and frame[22:28] == exception_mac and
                    frame[28:32] == socket.inet_aton('198.18.0.77') and frame[32:38] == exception_sender and
                    frame[38:42] == socket.inet_aton('198.18.0.170')]
                readable, _, _ = select.select([exception_capture], [], [], 0)
                if readable:
                    observed = exception_capture.recv(65536)
                    if observed == arp: exception_frames.append(observed)
                if arp_reply and exception_frames: break
                require(not errors and app.poll() is None and standby.poll() is None,
                    'exception path exited while waiting for the original Linux ARP reply')
                time.sleep(0.01)
            quiet_until = time.monotonic() + 0.15
            while time.monotonic() < quiet_until:
                readable, _, _ = select.select([exception_capture], [], [], 0.01)
                if readable and exception_capture.recv(65536) == arp: exception_frames.append(arp)
            require(len(exception_frames) == 1, 'the fixed exception endpoint did not receive the selected ARP frame exactly once')
            require(len(arp_reply) == 1, 'original Linux did not return exactly one ARP reply through the granted endpoint')
            # A large host UDP datagram forces real IPv4 fragments across the
            # native packet channel. The exception TAP is not a fragment sink;
            # the production counter advances only after packet_fd accepts it.
            fragment_probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                fragment_probe.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_MTU_DISCOVER', 10),
                    getattr(socket, 'IP_PMTUDISC_DONT', 0))
                fragment_probe.sendto(bytes((i * 13) & 255 for i in range(4096)), ('198.18.0.2', 44999))
            finally:
                fragment_probe.close()
            def selected_fragment(frame):
                return (len(frame) >= 34 and frame[12:14] == b'\x08\x00' and
                    socket.inet_ntoa(frame[26:30]) == '198.18.0.1' and
                    socket.inet_ntoa(frame[30:34]) == '198.18.0.2' and
                    (struct.unpack('!H', frame[20:22])[0] & 0x3fff) != 0)
            fragment_quiet_until = time.monotonic() + 0.3
            exception_fragments = []
            while time.monotonic() < fragment_quiet_until:
                readable, _, _ = select.select([exception_capture], [], [], 0.01)
                if readable:
                    captured = exception_capture.recv(65536)
                    if selected_fragment(captured): exception_fragments.append(captured)
            require(not exception_fragments, 'IPv4 fragment was copied to the exception TAP instead of native RX')
            require(not waiting['app_started'] and not standby_marker.exists() and
                attached['generation'] == 0 and pending['generation'] == 1 and
                pending['pid'] != attached['pid'] and pending['master'] != attached['master'] and
                pending['epoch'] != attached['epoch'] and pending['slot'] != attached['slot'] and
                pending['rings'] != attached['rings'], 'standby launched an app or reused the owner namespace')
            connection = api.Connection(path)
            try:
                owner = connection.request(api.PMD_STATUS)
                census = connection.request(api.STATUS)
                require(owner['epoch'] == attached['epoch'] and owner['slot'] == attached['slot'] and
                    owner['generation'] == 0 and owner['process'] == attached['process'] == 0 and
                    owner['token'] == grant['queue_owner_key'] and
                    census['generation'] == 507 and census['token'] == 4 and census['process'] == 2,
                    'standby acquired data leases or displaced a live owner')
            finally: connection.close()
            require(not select.select([standby.stdout], [], [], 0)[0], 'standby application produced output before admission')

            # Interrupt another real queued master. It must reap the actual
            # secondary without ever creating an application or data lease.
            spare, canceled_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            canceled_stats = root / 'canceled.json'
            canceled_marker = root / 'canceled-app-spawn'
            canceled = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--standby',
                '--wire-fd', str(canceled_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(canceled_stats), '--', str(args.app)], pass_fds=(canceled_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(canceled_marker)}, bufsize=0)
            canceled_endpoint.close()
            canceled_pidfd = -1
            try:
                deadline = time.monotonic() + 20
                while True:
                    queued = json.loads(canceled_stats.read_text()) if canceled_stats.exists() else {}
                    if queued.get('stage') == 'standby' and queued.get('standby_samples', 0) >= 3: break
                    require(canceled.poll() is None and time.monotonic() < deadline, 'cancel fixture never queued')
                    time.sleep(0.02)
                canceled_pidfd = os.pidfd_open(queued['attached']['pid'])
                canceled.send_signal(signal.SIGINT)
                canceled_output, canceled_errors = canceled.communicate(timeout=10)
                require(canceled.returncode == 130 and not canceled_output and not canceled_marker.exists() and
                    select.select([canceled_pidfd], [], [], 0)[0],
                    'queued cancellation launched an app or left its real worker alive: ' + canceled_errors.decode())
                deadline = time.monotonic() + 5
                while True:
                    connection = api.Connection(path)
                    try: census = connection.request(api.STATUS)
                    finally: connection.close()
                    if census['generation'] == 507 and census['token'] == 4 and census['process'] == 2: break
                    require(time.monotonic() < deadline, 'queued cancellation leaked its control lease')
                    time.sleep(0.02)
            finally:
                spare.close()
                if canceled_pidfd >= 0: os.close(canceled_pidfd)
                if canceled.poll() is None: canceled.kill(); canceled.wait()
            # SIGTERM while queued owns only its control lease: no packet
            # completion is expected until the PMD grant and packet loop exist.
            queued_trace = root / 'queued-signal-trace'; queued_trace.mkdir()
            (queued_trace / 'sitecustomize.py').write_text(
                'import os, subprocess\nfrom pathlib import Path\n_original = subprocess.Popen\n'
                'def record(*values, **options):\n'
                ' command = values[0] if values else options.get("args")\n'
                ' if isinstance(command, (list, tuple)) and command and Path(command[0]).name == "ker-app":\n'
                '  Path(os.environ["KER_TEST_APP_SPAWN_MARKER"]).write_text("spawned")\n'
                ' return _original(*values, **options)\nsubprocess.Popen = record\n')
            spare, queued_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            queued_stats = root / 'queued-sigterm.json'
            queued_marker = root / 'queued-sigterm-app-spawn'
            queued_term = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--standby',
                '--wire-fd', str(queued_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(queued_stats), '--', str(args.app)], pass_fds=(queued_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(queued_trace),
                    'KER_TEST_APP_SPAWN_MARKER': str(queued_marker)}, bufsize=0)
            queued_endpoint.close()
            queued_pidfd = -1
            try:
                deadline = time.monotonic() + 20
                while True:
                    queued = json.loads(queued_stats.read_text()) if queued_stats.exists() else {}
                    if queued.get('stage') == 'standby' and queued.get('standby_samples', 0) >= 3: break
                    require(queued_term.poll() is None and time.monotonic() < deadline,
                        'SIGTERM fixture never reached control-only standby')
                    time.sleep(0.02)
                queued_pidfd = os.pidfd_open(queued['attached']['pid'])
                queued_term.send_signal(signal.SIGTERM)
                queued_output, queued_errors = queued_term.communicate(timeout=10)
                queued = json.loads(queued_stats.read_text())
                require(queued_term.returncode == 143 and not queued_output and not queued_marker.exists() and
                    queued['stage'] == 'interrupted' and queued['signal'] == signal.SIGTERM and
                    not queued['app_started'] and queued['packet'] is None and queued['worker_code'] == 0 and
                    queued['app_code'] is None and select.select([queued_pidfd], [], [], 0)[0] and
                    b'KER_SESSION_PACKET_DONE' not in queued_errors,
                    'queued SIGTERM launched an app or reported packet activity: ' + repr(queued) + queued_errors.decode())
                connection = api.Connection(path)
                try:
                    owner = connection.request(api.PMD_STATUS)
                    census = connection.request(api.STATUS)
                    require(owner['epoch'] == attached['epoch'] and owner['slot'] == attached['slot'] and
                        census['generation'] == 507 and census['token'] == 4 and census['process'] == 2,
                        'queued SIGTERM changed original PMD ownership or leaked its control lease')
                finally: connection.close()
                print('PASS: queued SIGTERM returns143 with no app/packet activity and restores only the control lease')
            finally:
                spare.close()
                if queued_pidfd >= 0: os.close(queued_pidfd)
                if queued_term.poll() is None: queued_term.kill(); queued_term.wait()
            print('CHECK: live paired standby and canceled standby have no native application', flush=True)

            def exchange_native(process, *, finish=True):
                process.stdin.write(b'G'); process.stdin.flush()
                payload = bytes((i * 17 + (i >> 8)) & 255 for i in range(4097))
                for family, address in ((socket.AF_INET, '198.18.0.2'), (socket.AF_INET6, '2001:db8:1::2')):
                    with socket.socket(family, socket.SOCK_STREAM) as client:
                        client.settimeout(10); client.connect((address, 45000)); client.sendall(payload)
                        data = bytearray()
                        while True:
                            chunk = client.recv(8192)
                            if not chunk: break
                            data.extend(chunk)
                        require(bytes(data) == b'NATIVE:' + payload, 'native TCP bytes/EOF differ')
                    with socket.socket(family, socket.SOCK_DGRAM) as client:
                        client.settimeout(10); client.sendto(payload[:512], (address, 45000))
                        data, peer = client.recvfrom(8192)
                        require(data == b'NATIVE:' + payload[:512] and peer[0] == address, 'native UDP reply/peer differ')
                require(line(process) == 'NATIVE_DONE', 'native MTU rollback/service completion failed')
                if finish:
                    process.stdin.write(b'Q'); process.stdin.flush()

            def graceful_signal_release(process, stats_file, control_path):
                before = json.loads(stats_file.read_text())
                require(before.get('app_started') and before.get('stage') == 'application-started' and
                    before['grant']['queue_owner_key'] == before['grant']['exception_endpoint_owner_key'] != 0,
                    'replacement owner did not reach a fully granted application before cleanup')
                app_fd = os.pidfd_open(before['app_pid'])
                worker_fd = os.pidfd_open(before['attached']['pid'])
                try:
                    process.send_signal(signal.SIGTERM)
                    output, errors = process.communicate(timeout=20)
                    after = json.loads(stats_file.read_text())
                    require(process.returncode == 143 and after.get('stage') == 'interrupted' and
                        after.get('native_cleanup') == 'graceful' and after.get('app_code') == 143 and
                        after.get('worker_code') == 0 and after.get('packet', {}).get('status') == 0 and
                        after.get('native', {}).get('buffers_live') == 0 and
                        select.select([app_fd], [], [], 0)[0] and select.select([worker_fd], [], [], 0)[0],
                        'signal cleanup did not reap the replacement owner cleanly: ' + repr(after) + errors.decode())
                    connection = api.Connection(control_path)
                    try:
                        census = connection.request(api.STATUS)
                        require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0,
                            'replacement owner cleanup left a shared object leased')
                    finally: connection.close()
                    return output
                finally:
                    os.close(app_fd); os.close(worker_fd)

            exchange_native(app, finish=False)
            print('CHECK: first original Linux generation completed real TCP/UDP traffic', flush=True)
            before_handoff = json.loads(stats_path.read_text())
            require(before_handoff.get('stage') == 'application-started' and before_handoff['app_started'] and
                before_handoff['attached']['generation'] == 0 and before_handoff['grant']['generation'] == 0 and
                before_handoff['handoff_peer_attached']['generation'] == 1 and
                before_handoff['handoff_peer_early_denial']['queue_owner_key'] == 0 and
                before_handoff['handoff_peer_early_denial']['exception_endpoint_fd'] is False and
                before_handoff['handoff_peer_attached']['slot'] == before_handoff['attached']['slot'] and
                before_handoff['handoff_peer_attached']['epoch'] == before_handoff['attached']['epoch'],
                'handoff fixture did not attach opposite generations to the same live master slot')
            app_pidfd = os.pidfd_open(before_handoff['app_pid'])
            owner_pidfd = os.pidfd_open(before_handoff['attached']['pid'])
            try:
                require(not select.select([app_pidfd, owner_pidfd], [], [], 0)[0],
                    'application or original owner exited before the quiescent handoff barrier')
                require(os.write(handoff_write, b'H') == 1, 'could not signal the private handoff fixture trigger')
                os.close(handoff_write); handoff_write = -1
                deadline = time.monotonic() + 15
                while True:
                    handoff_snapshot = json.loads(stats_path.read_text())
                    if handoff_snapshot.get('stage') == 'handoff-complete': break
                    require(app.poll() is None and time.monotonic() < deadline,
                        'same-process handoff did not complete at the application quiescent barrier')
                    time.sleep(0.01)
                handoff = handoff_snapshot['handoff']
                protocol = handoff_snapshot['handoff_protocol']
                require(handoff['app_pid'] == before_handoff['app_pid'] and
                    handoff['old_worker_pid'] == before_handoff['attached']['pid'] and
                    handoff['peer_worker_pid'] == handoff_snapshot['handoff_peer_attached']['pid'] and
                    handoff['old_exception_fd_closed'] and handoff['old_owner_key'] != handoff['new_owner_key'] and
                    before_handoff['exception_endpoint_name'] in handoff['old_tun_interfaces_before'] and
                    before_handoff['exception_endpoint_name'] not in handoff['old_tun_interfaces_after'] and
                    before_handoff['exception_endpoint_name'] in handoff['successor_tun_interfaces'] and
                    handoff['resident']['token'] == handoff['new_owner_key'] and
                    handoff['successor']['generation'] == 1 and
                    protocol['negative_prepare']['status'] == -1 and protocol['negative_prepare']['same_replay'] and
                    protocol['replay_prepare']['same_response'] and
                    not select.select([app_pidfd, owner_pidfd], [], [], 0)[0],
                    'handoff changed the original app/owner process, failed exact grant transfer, or mishandled PREPARE validation/replay')
                print('PASS: same original Linux app and generation-zero worker remain live while the paired-ring grant and exception endpoint move to its same-slot generation-one peer', flush=True)
            finally:
                os.close(app_pidfd); os.close(owner_pidfd)
            app.stdin.write(b'Q'); app.stdin.flush()
            output, stderr = app.communicate(timeout=20)
            require(app.returncode == 0, 'packet-session application failed: ' + output.decode() + stderr.decode())
            require(b'PASS: original native IPv4/IPv6 TCP/UDP services' in output, 'native application proof absent')
            finished = json.loads(stats_path.read_text())
            require(finished['stage'] == 'finished' and finished['app_started'], 'supervisor completion snapshot absent')
            stats, native = finished['packet'], finished['native']
            require(stats['tx'] > 0 and stats['rx'] > 0 and stats['to_wire'] > 0 and stats['from_wire'] > 0 and stats['status'] == 0 and
                stats['exception_from_wire'] >= 1 and stats['exception_to_wire'] >= 1 and stats['exception_to_native'] >= 1 and
                stats['exception_endpoint_owner_key'] == grant['queue_owner_key'] and stats['fragment_to_native'] >= 1,
                'actual single-owner ARP exception, fragment-to-native route, or endpoint identity accounting differs')
            require(native['passive_opens'] >= 2 and native['udp_in_datagrams'] >= 1 and native['udp_out_datagrams'] >= 1 and
                native['udp6_in_datagrams'] >= 1 and native['udp6_out_datagrams'] >= 1 and native['buffers_live'] == 0,
                'traffic bypassed original Linux or retained native buffers')
            require(line(standby) == 'READY', 'retained standby did not start a real original Linux application')
            admitted = json.loads(standby_stats.read_text())
            require(admitted['attached'] == pending and admitted['grant']['pid'] == pending['pid'] and
                admitted['grant']['epoch'] == pending['epoch'] and admitted['grant']['generation'] == 1 and
                admitted['grant']['exception_endpoint_ifindex'] == exception_ifindex and
                admitted['grant']['exception_endpoint_fd'] is True and standby_marker.exists(),
                'takeover restarted the standby PID/EAL/epoch or skipped the real application launch')
            connection = api.Connection(path)
            try:
                owner = connection.request(api.PMD_STATUS)
                census = connection.request(api.STATUS)
                require(owner['epoch'] == pending['epoch'] and owner['slot'] == pending['slot'] and
                    owner['generation'] == 1 and owner['process'] == 0 and
                    owner['token'] == admitted['grant']['queue_owner_key'] == admitted['grant']['exception_endpoint_owner_key'] and
                    owner['token'] != 0 and census['generation'] == 508 and census['token'] == 3 and census['process'] == 1,
                    'takeover did not transfer exactly the two journaled device objects')
            finally: connection.close()
            exchange_native(standby)
            print('CHECK: same-PID retained standby completed real TCP/UDP traffic', flush=True)
            standby_output, standby_errors = standby.communicate(timeout=20)
            require(standby.returncode == 0 and b'PASS: original native IPv4/IPv6 TCP/UDP services' in standby_output,
                'native traffic after same-PID takeover failed: ' + standby_errors.decode())
            require(b'KER_SESSION_TEST_PENDING_HB_QUEUED' in standby_errors and
                b'KER_SESSION_TEST_PENDING_HB_DRAINED' in standby_errors,
                'paired standby PMD acquisition did not exercise the queued-heartbeat boundary')
            taken = json.loads(standby_stats.read_text())
            require(taken['stage'] == 'finished' and taken['packet']['tx'] > 0 and taken['packet']['rx'] > 0 and
                taken['native']['passive_opens'] >= 2 and taken['native']['udp_in_datagrams'] >= 1 and
                taken['native']['udp6_in_datagrams'] >= 1 and taken['native']['buffers_live'] == 0,
                'takeover traffic bypassed original PMD/Linux or left native buffers')
            stop.set(); thread.join(timeout=3)
            require(not thread.is_alive(), 'external Ethernet bridge did not stop')
            connection = api.Connection(path)
            try:
                census = connection.request(api.STATUS)
                require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0,
                    'original control/TX/RX objects not returned after both exact secondary deaths')
            finally: connection.close()
            protocols = set()
            for direction, frame in frames:
                if frame[12:14] == b'\x08\x00' and len(frame) >= 34: protocols.add((direction, 4, frame[23]))
                if frame[12:14] == b'\x86\xdd' and len(frame) >= 54: protocols.add((direction, 6, frame[20]))
            require(all((direction, version, protocol) in protocols for direction in ('native', 'host')
                for version in (4, 6) for protocol in (6, 17)), 'independent Ethernet capture missed TCP/UDP directions')
            require(not errors and all(counts), 'external wire bridge failed: ' + repr(errors))
            # Kill the real granted worker at the published worker-ready
            # boundary. Both instrumentation wrappers forward real operations;
            # neither creates a successful fake child or fake EAL reply.
            with (trace / 'sitecustomize.py').open('a') as out:
                out.write('import json, select, signal\n_replace = os.replace\n'
                    'def replace(source, target):\n'
                    ' result = _replace(source, target)\n'
                    ' if os.fspath(target) == os.environ.get("KER_TEST_KILL_AT_WORKER_READY"):\n'
                    '  data = json.loads(Path(target).read_text())\n'
                    '  if data.get("stage") == "worker-ready":\n'
                    '   fd = os.pidfd_open(data["attached"]["pid"])\n'
                    '   try:\n'
                    '    signal.pidfd_send_signal(fd, signal.SIGKILL)\n'
                    '    if not select.select([fd], [], [], 5)[0]:raise RuntimeError("test worker death timeout")\n'
                    '   finally:os.close(fd)\n'
                    ' return result\nos.replace = replace\n')
            spare, prestart_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            prestart_stats = root / 'prestart.json'
            prestart = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(prestart_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(prestart_stats), '--', str(args.app)], pass_fds=(prestart_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace), 'KER_TEST_APP_SPAWN_MARKER': str(marker),
                    'KER_TEST_KILL_AT_WORKER_READY': str(prestart_stats)}, bufsize=0)
            prestart_endpoint.close()
            try:
                prestart_output, prestart_errors = prestart.communicate(timeout=20)
                snapshot = json.loads(prestart_stats.read_text())
                require(prestart.returncode == 125 and b'exited before application launch' in prestart_errors and
                    not marker.exists() and snapshot['stage'] == 'failed' and not snapshot['app_started'],
                    'known dead ready worker still launched an app: ' + prestart_errors.decode())
            finally:
                spare.close()
                if prestart.poll() is None: prestart.kill(); prestart.wait()
            # Deliver SIGTERM to the real launcher just after it starts its
            # actual worker. It must wait for EAL startup, quiesce that worker,
            # and return the signal status without ever spawning ker-app.
            with (trace / 'sitecustomize.py').open('a') as out:
                out.write('import signal\n_start_worker = subprocess.Popen\n'
                    'def signal_after_worker(*values, **options):\n'
                    ' command = values[0] if values else options.get("args")\n'
                    ' result = _start_worker(*values, **options)\n'
                    ' if isinstance(command, (list, tuple)) and command and Path(command[0]).name == "ker-io-session":\n'
                    '  os.kill(os.getpid(), signal.SIGTERM)\n'
                    ' return result\nsubprocess.Popen = signal_after_worker\n')
            signal_stats = root / 'signal-before-app.json'
            spare, signal_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            signalled = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(signal_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(signal_stats), '--', str(args.app)], pass_fds=(signal_endpoint.fileno(),),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment | {'PYTHONPATH': str(trace)}, bufsize=0)
            signal_endpoint.close()
            try:
                _, signal_errors = signalled.communicate(timeout=20)
                snapshot = json.loads(signal_stats.read_text())
                require(signalled.returncode == 143 and not snapshot['app_started'] and
                    snapshot['stage'] == 'interrupted' and b'KER_SESSION_PACKET_DONE' in signal_errors and
                    not marker.exists(), 'pre-app SIGTERM did not clean the actual worker: ' + signal_errors.decode())
                print('PASS: pre-app SIGTERM drains the actual worker, returns143, and never launches ker-app')
            finally:
                spare.close()
                if signalled.poll() is None: signalled.kill(); signalled.wait()
            # Fail an actual granted worker while the real native application
            # is waiting at its setup barrier. The supervisor must report125,
            # stop the app and recover all three original journaled objects.
            sink, failed_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            failed = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(failed_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(root / 'failed.json'), '--', str(args.app)],
                pass_fds=(failed_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            failed_endpoint.close()
            worker_pidfd = -1
            try:
                require(line(failed) == 'READY', 'failure fixture did not reach original Linux')
                failed_worker = json.loads((root / 'failed.json').read_text())['attached']
                worker_pidfd = os.pidfd_open(failed_worker['pid'])
                signal.pidfd_send_signal(worker_pidfd, signal.SIGKILL)
                failed.wait(timeout=15)  # Keep stdin open so EOF cannot mask backend loss.
                failed_output, failed_errors = failed.communicate(timeout=2)
                require(failed.returncode == 125 and b'exited while application was running' in failed_errors and
                    b'PASS:' not in failed_output and select.select([worker_pidfd], [], [], 0)[0],
                    'worker loss was reported as successful application teardown: ' + failed_errors.decode())
                deadline = time.monotonic() + 5
                while True:
                    connection = api.Connection(path)
                    try: census = connection.request(api.STATUS)
                    finally: connection.close()
                    if census['generation'] == 511 and census['token'] == 0 and census['process'] == 0: break
                    require(time.monotonic() < deadline, 'worker death leaked original packet/control objects')
                    time.sleep(0.02)
            finally:
                sink.close()
                if worker_pidfd >= 0: os.close(worker_pidfd)
                if failed.poll() is None: failed.kill(); failed.wait()
            # SIGTERM the real launcher while its original Linux application
            # is held at READY with stdin still open. The launcher must reap
            # both native children and preserve the conventional signal status.
            sink, interrupted_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            interrupted_stats = root / 'interrupted.json'
            interrupted = subprocess.Popen([sys.executable, str(args.tool), 'run', *common,
                '--wire-fd', str(interrupted_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(interrupted_stats), '--address6', '2001:db8:1::2/64', '--', str(args.app), '--signal-ready'],
                pass_fds=(interrupted_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            interrupted_endpoint.close()
            app_pidfd = worker_pidfd = -1
            try:
                require(line(interrupted) == 'READY', 'SIGTERM fixture did not reach original Linux')
                snapshot = json.loads(interrupted_stats.read_text())
                app_pidfd = os.pidfd_open(snapshot['app_pid'])
                worker_pidfd = os.pidfd_open(snapshot['attached']['pid'])
                interrupted.send_signal(signal.SIGTERM)
                interrupted_output, interrupted_errors = interrupted.communicate(timeout=15)
                snapshot = json.loads(interrupted_stats.read_text())
                require(interrupted.returncode == 143 and snapshot['stage'] == 'interrupted' and
                    snapshot['native_cleanup'] == 'graceful' and snapshot['native']['buffers_live'] == 0 and
                    snapshot['worker_code'] == 0 and snapshot['packet']['status'] == 0 and
                    select.select([app_pidfd], [], [], 0)[0] and select.select([worker_pidfd], [], [], 0)[0],
                    'SIGTERM did not report exact child cleanup: ' + repr(snapshot) + interrupted_errors.decode())
                connection = api.Connection(path)
                try:
                    census = connection.request(api.STATUS)
                    require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0,
                        'SIGTERM left original session pool objects leased')
                finally: connection.close()
            finally:
                sink.close()
                for pidfd in (app_pidfd, worker_pidfd):
                    if pidfd >= 0: os.close(pidfd)
                if interrupted.poll() is None: interrupted.kill(); interrupted.wait()
            primary.stdin.close(); primary.stdin = None
            try:
                primary_output, primary_errors = primary.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                primary.kill()
                primary_output, primary_errors = primary.communicate(timeout=5)
                raise RuntimeError('resident packet cleanup timed out: stdout=' + primary_output.decode(errors='replace') +
                    ' stderr=' + primary_errors.decode(errors='replace'))
            require(primary.returncode == 0, 'resident packet-device cleanup failed: ' + primary_errors.decode(errors='replace'))
            require(b'KER_SESSION_DRAINED' in primary_output, 'resident pool cleanup proof absent')
            # Stop the resident while a second real native application remains
            # at READY. Its registration socket must quiesce the worker inside
            # the resident's five second cleanup window.
            stop_path = root / 'resident-stop.sock'
            stop_common = ['--socket', str(stop_path), '--worker', str(args.worker), '--eal', eal,
                '--paired-pmd']
            stopping_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *stop_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            record(stopping_primary, 'KER_SESSION_READY')
            sink, resident_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            resident_stats = root / 'resident-stop.json'
            resident_app = subprocess.Popen([sys.executable, str(args.tool), 'run', *stop_common,
                '--wire-fd', str(resident_endpoint.fileno()), '--library', str(args.library),
                '--stats', str(resident_stats), '--address6', '2001:db8:1::2/64', '--', str(args.app)],
                pass_fds=(resident_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            resident_endpoint.close()
            app_pidfd = worker_pidfd = -1
            try:
                require(line(resident_app) == 'READY', 'resident-shutdown fixture did not reach original Linux')
                snapshot = json.loads(resident_stats.read_text())
                app_pidfd = os.pidfd_open(snapshot['app_pid'])
                worker_pidfd = os.pidfd_open(snapshot['attached']['pid'])
                stopping_primary.send_signal(signal.SIGTERM)
                resident_output, resident_errors = stopping_primary.communicate(timeout=8)
                launcher_output, launcher_errors = resident_app.communicate(timeout=12)
                require(stopping_primary.returncode == 0 and b'KER_SESSION_DRAINED' in resident_output,
                    'resident did not complete normal DRAINED cleanup: ' + resident_errors.decode())
                require(resident_app.returncode == 125 and b'worker exited while application was running' in launcher_errors and
                    select.select([app_pidfd], [], [], 0)[0] and select.select([worker_pidfd], [], [], 0)[0],
                    'resident shutdown did not reap launcher children or report backend loss: ' + launcher_errors.decode())
            finally:
                sink.close()
                for pidfd in (app_pidfd, worker_pidfd):
                    if pidfd >= 0: os.close(pidfd)
                for process in (resident_app, stopping_primary):
                    if process.poll() is None: process.kill(); process.wait()
            # Deterministically stop after phase 2 is published but before the
            # destructive TAP write. The resident must fail closed, not regrant.
            boundary_path = root / 'exception-write-boundary.sock'
            boundary_eal = eal.replace('packets-', 'exception-write-boundary-')
            boundary_common = ['--socket', str(boundary_path), '--worker', str(args.worker),
                '--eal', boundary_eal, '--paired-pmd']
            boundary_marker = root / 'hold-exception-write'
            boundary_environment = environment | {'KER_SESSION_TEST_HOLD_EXCEPTION_WRITE': str(boundary_marker)}
            boundary_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *boundary_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=boundary_environment, bufsize=0)
            boundary_ready = record(boundary_primary, 'KER_SESSION_READY')
            boundary_wire, boundary_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            boundary_stats = root / 'exception-write-owner.json'
            boundary_owner = subprocess.Popen([sys.executable, str(args.tool), 'run', *boundary_common,
                '--wire-fd', str(boundary_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(boundary_stats), '--', str(args.app)],
                pass_fds=(boundary_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=boundary_environment, bufsize=0)
            boundary_endpoint.close()
            try:
                require(line(boundary_owner) == 'READY', 'write-boundary owner did not reach original Linux')
                boundary_state = json.loads(boundary_stats.read_text())
                boundary_grant = boundary_state['grant']
                require(boundary_state['attached']['pid'] == boundary_grant['pid'] and
                    boundary_grant['queue_owner_key'] == boundary_grant['exception_endpoint_owner_key'] != 0 and
                    boundary_grant['exception_endpoint_ifindex'] == boundary_ready['exception_endpoint_ifindex'] and
                    boundary_grant['exception_endpoint_fd'] is True,
                    'write-boundary owner did not hold the paired PMD/TAP grant before standby startup')
            except BaseException:
                boundary_wire.close()
                for process in (boundary_owner, boundary_primary):
                    if process.poll() is None: process.kill(); process.wait()
                raise
            boundary_standby_stats = root / 'exception-write-standby.json'
            boundary_standby_wire = boundary_standby_endpoint = boundary_standby = None
            try:
                boundary_standby_wire, boundary_standby_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                boundary_standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *boundary_common,
                    '--standby', '--wire-fd', str(boundary_standby_endpoint.fileno()), '--library', str(args.library),
                    '--address6', '2001:db8:1::2/64', '--stats', str(boundary_standby_stats), '--', str(args.app)],
                    pass_fds=(boundary_standby_endpoint.fileno(),), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                boundary_standby_endpoint.close(); boundary_standby_endpoint = None
            except BaseException:
                if boundary_standby_endpoint is not None: boundary_standby_endpoint.close()
                if boundary_standby_wire is not None: boundary_standby_wire.close()
                boundary_wire.close()
                for process in (boundary_standby, boundary_owner, boundary_primary):
                    if process is not None and process.poll() is None: process.kill(); process.wait()
                raise
            boundary_pidfd = -1
            try:
                deadline = time.monotonic() + 15
                while True:
                    state = json.loads(boundary_standby_stats.read_text()) if boundary_standby_stats.exists() else {}
                    if state.get('stage') == 'standby' and state.get('standby_samples', 0) >= 2: break
                    require(boundary_standby.poll() is None and time.monotonic() < deadline,
                        'write-boundary standby did not remain attached')
                    time.sleep(0.02)
                boundary_pending = state['attached']
                require(boundary_pending['generation'] == 0 and
                    state['standby']['queue_owner_key'] == 0 and
                    state['standby']['exception_endpoint_owner_key'] == 0 and
                    state['standby']['exception_endpoint_fd'] is False,
                    'phase-2 standby unexpectedly held an endpoint grant before owner death')
                boundary_marker.touch()
                frame = (b'\xff' * 6 + bytes.fromhex('024b455200aa') + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('024b455200aa') +
                    socket.inet_aton('198.18.0.170') + b'\x00' * 6 + socket.inet_aton('198.18.0.77'))
                require(boundary_wire.send(frame) == len(frame), 'write-boundary frame injection failed')
                owner_state = json.loads(boundary_stats.read_text())
                worker_pid = owner_state['attached']['pid']; boundary_pidfd = os.pidfd_open(worker_pid)
                deadline = time.monotonic() + 10
                stopped = False
                while time.monotonic() < deadline:
                    try: status_text = Path(f'/proc/{worker_pid}/status').read_text()
                    except FileNotFoundError: break
                    stopped = any(line.startswith('State:') and line.split()[1] == 'T' for line in status_text.splitlines())
                    if stopped: break
                    time.sleep(0.01)
                require(stopped, 'worker did not stop after publishing phase 2 before TAP write')
                signal.pidfd_send_signal(boundary_pidfd, signal.SIGKILL)
                require(select.select([boundary_pidfd], [], [], 5)[0], 'phase-2 owner death was not observed')
                os.close(boundary_pidfd); boundary_pidfd = -1
                boundary_owner.communicate(timeout=15)
                primary_output, primary_errors = boundary_primary.communicate(timeout=10)
                standby_output, standby_errors = boundary_standby.communicate(timeout=10)
                standby_state = json.loads(boundary_standby_stats.read_text())
                require(boundary_primary.returncode == 125 and b'KER_SESSION_DRAINED' not in primary_output and
                    boundary_standby.returncode == 125 and standby_state.get('stage') == 'failed' and
                    not standby_state.get('app_started', False) and 'grant' not in standby_state and
                    standby_state.get('attached') == boundary_pending and not standby_output,
                    'ambiguous TAP write was reassigned instead of failing the session closed: ' +
                    primary_errors.decode(errors='replace') + standby_errors.decode(errors='replace'))
            finally:
                if boundary_pidfd >= 0: os.close(boundary_pidfd)
                boundary_wire.close(); boundary_standby_wire.close()
                for process in (boundary_owner, boundary_primary, boundary_standby):
                    if process.poll() is None: process.kill(); process.wait()
            # Stop the actual granted worker after a TAP output has entered the
            # exact RX lease/PMD TX path but before external-wire send. Reaping
            # must account this known one-frame discard exactly once.
            discard_path = root / 'exception-discard.sock'
            discard_eal = eal.replace('packets-', 'exception-discard-')
            discard_common = ['--socket', str(discard_path), '--worker', str(args.worker),
                '--eal', discard_eal, '--paired-pmd']
            discard_marker = root / 'hold-exception-output'
            discard_environment = environment | {'KER_SESSION_TEST_HOLD_EXCEPTION_OUTPUT': str(discard_marker)}
            discard_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *discard_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=discard_environment, bufsize=0)
            discard_ready = record(discard_primary, 'KER_SESSION_READY')
            discard_wire, discard_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            discard_stats = root / 'exception-discard-owner.json'
            discard_owner = subprocess.Popen([sys.executable, str(args.tool), 'run', *discard_common,
                '--wire-fd', str(discard_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(discard_stats), '--', str(args.app)],
                pass_fds=(discard_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=discard_environment, bufsize=0)
            discard_endpoint.close()
            try:
                require(line(discard_owner) == 'READY', 'exception-discard owner did not reach original Linux')
                discard_state = json.loads(discard_stats.read_text())
                discard_grant = discard_state['grant']
                require(discard_state['attached']['pid'] == discard_grant['pid'] and
                    discard_grant['queue_owner_key'] == discard_grant['exception_endpoint_owner_key'] != 0 and
                    discard_grant['exception_endpoint_ifindex'] == discard_ready['exception_endpoint_ifindex'] and
                    discard_grant['exception_endpoint_fd'] is True,
                    'exception-discard owner did not hold the paired PMD/TAP grant before standby startup')
            except BaseException:
                discard_wire.close()
                for process in (discard_owner, discard_primary):
                    if process.poll() is None: process.kill(); process.wait()
                raise
            discard_standby_stats = root / 'exception-discard-standby.json'
            standby_wire = standby_endpoint = discard_standby = None
            try:
                standby_wire, standby_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                discard_standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *discard_common,
                    '--standby', '--wire-fd', str(standby_endpoint.fileno()), '--library', str(args.library),
                    '--address6', '2001:db8:1::2/64', '--stats', str(discard_standby_stats), '--', str(args.app), '--signal-ready'],
                    pass_fds=(standby_endpoint.fileno(),), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                standby_endpoint.close(); standby_endpoint = None
            except BaseException:
                if standby_endpoint is not None: standby_endpoint.close()
                if standby_wire is not None: standby_wire.close()
                discard_wire.close()
                for process in (discard_standby, discard_owner, discard_primary):
                    if process is not None and process.poll() is None: process.kill(); process.wait()
                raise
            discard_pidfd = -1
            try:
                deadline = time.monotonic() + 15
                while True:
                    state = json.loads(discard_standby_stats.read_text()) if discard_standby_stats.exists() else {}
                    if state.get('stage') == 'standby' and state.get('standby_samples', 0) >= 2: break
                    require(discard_standby.poll() is None and time.monotonic() < deadline,
                        'exception-discard standby did not remain attached')
                    time.sleep(0.02)
                subprocess.run(['ip', 'address', 'add', '198.18.0.99/32',
                    'dev', discard_ready['exception_endpoint_name']], check=True)
                raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                raw.bind((discard_ready['exception_endpoint_name'], 0))
                frame = (b'\xff' * 6 + bytes.fromhex('024b45520099') + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('024b45520099') +
                    socket.inet_aton('198.18.0.170') + b'\x00' * 6 + socket.inet_aton('198.18.0.99'))
                discard_marker.touch()
                require(raw.send(frame) == len(frame), 'could not inject test Ethernet frame into the resident TAP')
                raw.close()
                owner_state = json.loads(discard_stats.read_text())
                worker_pid = owner_state['attached']['pid']; discard_pidfd = os.pidfd_open(worker_pid)
                deadline = time.monotonic() + 10
                stopped = False
                while time.monotonic() < deadline:
                    try: status_text = Path(f'/proc/{worker_pid}/status').read_text()
                    except FileNotFoundError: break
                    stopped = any(line.startswith('State:') and 'T' in line for line in status_text.splitlines())
                    if stopped: break
                    time.sleep(0.01)
                require(stopped, 'worker did not stop at the published phase-5 output boundary')
                signal.pidfd_send_signal(discard_pidfd, signal.SIGKILL)
                require(select.select([discard_pidfd], [], [], 5)[0], 'phase-5 worker death was not observed')
                os.close(discard_pidfd); discard_pidfd = -1
                discard_owner.communicate(timeout=15)
                require(discard_owner.returncode == 125, 'killed packet owner did not report backend failure')
                require(line(discard_standby) == 'READY', 'standby did not inherit the exact persistent endpoint after phase-5 reclaim')
                admitted = json.loads(discard_standby_stats.read_text())
                require(admitted['grant']['queue_owner_key'] == admitted['grant']['exception_endpoint_owner_key'] != 0 and
                    admitted['grant']['exception_endpoint_ifindex'] == discard_ready['exception_endpoint_ifindex'] and
                    admitted['grant']['exception_endpoint_fd'] is True,
                    'phase-5 regrant did not retain the same endpoint identity/fd authorization')
                discard_standby_output = graceful_signal_release(discard_standby, discard_standby_stats, discard_path)
                discard_primary.stdin.close(); discard_primary.stdin = None
                discard_primary_output, discard_primary_errors = discard_primary.communicate(timeout=20)
                require(discard_primary.returncode == 0, 'exception-discard resident cleanup failed: ' + discard_primary_errors.decode())
                reclaim_records = [json.loads(line.removeprefix('KER_SESSION_EXCEPTION_RECLAIM '))
                    for line in discard_primary_output.decode().splitlines()
                    if line.startswith('KER_SESSION_EXCEPTION_RECLAIM ')]
                drained_records = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                    for line in discard_primary_output.decode().splitlines() if line.startswith('KER_SESSION_DRAINED ')]
                require(reclaim_records == [{'phase': 5, 'discarded': 1, 'total': 1}] and
                    drained_records and drained_records[-1]['exception_lease_discarded'] == 1,
                    'resident did not account the single known phase-5 output discard exactly once')
            finally:
                if discard_pidfd >= 0: os.close(discard_pidfd)
                discard_wire.close(); standby_wire.close()
                for process in (discard_owner, discard_primary, discard_standby):
                    if process.poll() is None: process.kill(); process.wait()
            # Phase 7 means the selected exception frame has been copied to
            # the persistent TAP, but the same journaled mbuf is still pending
            # native RX. Kill the exact owner at that boundary and prove one
            # discard is accounted before the same endpoint is regranted.
            native_path = root / 'exception-native.sock'
            native_eal = eal.replace('packets-', 'exception-native-')
            native_common = ['--socket', str(native_path), '--worker', str(args.worker),
                '--eal', native_eal, '--paired-pmd']
            native_marker = root / 'hold-exception-native'
            native_environment = environment | {'KER_SESSION_TEST_HOLD_EXCEPTION_NATIVE': str(native_marker)}
            native_primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *native_common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=native_environment, bufsize=0)
            native_ready = record(native_primary, 'KER_SESSION_READY')
            native_wire, native_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            native_owner_stats = root / 'exception-native-owner.json'
            native_owner = subprocess.Popen([sys.executable, str(args.tool), 'run', *native_common,
                '--wire-fd', str(native_endpoint.fileno()), '--library', str(args.library),
                '--address6', '2001:db8:1::2/64', '--stats', str(native_owner_stats), '--', str(args.app)],
                pass_fds=(native_endpoint.fileno(),), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=native_environment, bufsize=0)
            native_endpoint.close()
            native_standby_wire = native_standby_endpoint = native_standby = None
            native_pidfd = -1
            try:
                require(line(native_owner) == 'READY', 'phase-7 owner did not reach original Linux')
                native_owner_state = json.loads(native_owner_stats.read_text())
                native_grant = native_owner_state['grant']
                require(native_owner_state['attached']['pid'] == native_grant['pid'] and
                    native_grant['queue_owner_key'] == native_grant['exception_endpoint_owner_key'] != 0 and
                    native_grant['exception_endpoint_ifindex'] == native_ready['exception_endpoint_ifindex'] and
                    native_grant['exception_endpoint_fd'] is True,
                    'phase-7 owner did not hold the endpoint grant')
                subprocess.run(['ip', 'address', 'add', '198.18.0.100/32',
                    'dev', native_ready['exception_endpoint_name']], check=True)
                native_standby_stats = root / 'exception-native-standby.json'
                native_standby_wire, native_standby_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
                native_standby = subprocess.Popen([sys.executable, str(args.tool), 'run', *native_common,
                    '--standby', '--generation', '1', '--wire-fd', str(native_standby_endpoint.fileno()),
                    '--library', str(args.library), '--address6', '2001:db8:1::2/64',
                    '--stats', str(native_standby_stats), '--', str(args.app), '--signal-ready'],
                    pass_fds=(native_standby_endpoint.fileno(),), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
                native_standby_endpoint.close(); native_standby_endpoint = None
                deadline = time.monotonic() + 15
                while True:
                    state = json.loads(native_standby_stats.read_text()) if native_standby_stats.exists() else {}
                    if state.get('stage') == 'standby' and state.get('standby_samples', 0) >= 2: break
                    require(native_standby.poll() is None and time.monotonic() < deadline,
                        'phase-7 standby did not remain attached')
                    time.sleep(0.02)
                require(state['attached']['generation'] == 1 and
                    state['standby']['exception_endpoint_fd'] is False and
                    state['standby']['exception_endpoint_owner_key'] == 0,
                    'phase-7 standby received the endpoint before admission')
                native_marker.touch()
                native_frame = (b'\xff' * 6 + bytes.fromhex('024b455200bb') + b'\x08\x06' +
                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + bytes.fromhex('024b455200bb') +
                    socket.inet_aton('198.18.0.171') + b'\x00' * 6 + socket.inet_aton('198.18.0.100'))
                require(native_wire.send(native_frame) == len(native_frame), 'phase-7 ARP injection failed')
                native_pid = native_owner_state['attached']['pid']; native_pidfd = os.pidfd_open(native_pid)
                deadline = time.monotonic() + 10
                stopped = False
                while time.monotonic() < deadline:
                    try: status_text = Path(f'/proc/{native_pid}/status').read_text()
                    except FileNotFoundError: break
                    stopped = any(line.startswith('State:') and line.split()[1] == 'T' for line in status_text.splitlines())
                    if stopped: break
                    time.sleep(0.01)
                require(stopped, 'worker did not stop after TAP copy at phase 7 before native RX enqueue')
                signal.pidfd_send_signal(native_pidfd, signal.SIGKILL)
                require(select.select([native_pidfd], [], [], 5)[0], 'phase-7 owner death was not observed')
                os.close(native_pidfd); native_pidfd = -1
                native_owner.communicate(timeout=15)
                require(native_owner.returncode == 125, 'phase-7 owner loss did not fail its launcher')
                require(line(native_standby) == 'READY', 'phase-7 exact-death recovery did not regrant the endpoint')
                native_admitted = json.loads(native_standby_stats.read_text())
                require(native_admitted['grant']['generation'] == 1 and
                    native_admitted['grant']['exception_endpoint_ifindex'] == native_ready['exception_endpoint_ifindex'] and
                    native_admitted['grant']['exception_endpoint_fd'] is True and
                    native_admitted['grant']['queue_owner_key'] == native_admitted['grant']['exception_endpoint_owner_key'] != 0,
                    'phase-7 regrant changed endpoint identity or owner authorization')
                native_standby_output = graceful_signal_release(native_standby, native_standby_stats, native_path)
                native_primary.stdin.close(); native_primary.stdin = None
                native_primary_output, native_primary_errors = native_primary.communicate(timeout=20)
                require(native_primary.returncode == 0, 'phase-7 resident cleanup failed: ' + native_primary_errors.decode())
                reclaim_records = [json.loads(line.removeprefix('KER_SESSION_EXCEPTION_RECLAIM '))
                    for line in native_primary_output.decode().splitlines()
                    if line.startswith('KER_SESSION_EXCEPTION_RECLAIM ')]
                drained_records = [json.loads(line.removeprefix('KER_SESSION_DRAINED '))
                    for line in native_primary_output.decode().splitlines() if line.startswith('KER_SESSION_DRAINED ')]
                require(reclaim_records == [{'phase': 7, 'discarded': 1, 'total': 1}] and
                    drained_records and drained_records[-1]['exception_lease_discarded'] == 1,
                    'resident did not account exactly one known phase-7 native-handoff discard')
            finally:
                if native_pidfd >= 0: os.close(native_pidfd)
                native_wire.close()
                if native_standby_endpoint is not None: native_standby_endpoint.close()
                if native_standby_wire is not None: native_standby_wire.close()
                for process in (native_owner, native_primary, native_standby):
                    if process is not None and process.poll() is None: process.kill(); process.wait()
            print('PASS: exact phase-7 TAP-copy/native-handoff lease is reclaimed once before endpoint regrant')
            print('PASS: exact phase-5 TAP output lease is reclaimed and counted once before endpoint regrant')
            print('PASS: original guest Linux peers exchange exact IPv4/IPv6 TCP4097/UDP512 with original imported Linux')
            print('PASS: actual granted EAL secondary consumes independent original PMD RX/TX queues; resident stays off packet path')
            print('PASS: fixed1500 MTU rejects live mutation coherently; original Linux/PMD counters and bidirectional Ethernet capture')
            print('PASS: original control/TX/RX journal restores all511 objects after process death and native kernel teardown')
            print('PASS: real competing secondary never launches an application; actual worker loss returns125 and restores all original objects')
            print('PASS: app-owned SIGTERM reaches native DONE; launcher reports143, reaps exact children, worker packet status0 and native buffers0')
            print('PASS: resident SIGTERM closes registration, worker exits before five second deadline, resident drains, launcher reports125')
            print('PASS: retained paired standby keeps the same actual PID/EAL/epoch and carries real native TCP/UDP after admission')
            print('PASS: source A4 primary precreates all128 coordinate rings and one original network port before actual secondary lookup')
        finally:
            if handoff_read >= 0:
                os.close(handoff_read)
                handoff_read = -1
            if handoff_write >= 0:
                os.close(handoff_write)
                handoff_write = -1
            if app is not None and app.poll() is None:
                app.terminate()
                try: app.wait(timeout=10)
                except subprocess.TimeoutExpired: app.kill(); app.wait()
            if standby is not None and standby.poll() is None:
                standby.terminate()
                try: standby.wait(timeout=10)
                except subprocess.TimeoutExpired: standby.kill(); standby.wait()
            if primary is not None and primary.poll() is None:
                primary.terminate()
                try: primary.wait(timeout=10)
                except subprocess.TimeoutExpired: primary.kill(); primary.wait()
            stop.set(); thread.join(timeout=3); wire.close(); endpoint.close(); os.close(tap)
            if exception_capture is not None: exception_capture.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
