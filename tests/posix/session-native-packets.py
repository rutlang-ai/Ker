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


def line(process, timeout=25):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(timeout), 'packet-session output timed out')
    value = process.stdout.readline()
    if not value:
        raise RuntimeError('packet-session exited early: ' + process.stderr.read().decode())
    return value.decode().strip()


def record(process, prefix):
    value = line(process)
    require(value.startswith(prefix + ' '), 'unexpected output: ' + value)
    return json.loads(value[len(prefix) + 1:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('worker', 'tool', 'library', 'app'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--huge-dir', type=Path, default=Path('/dev/hugepages'))
    args = parser.parse_args()
    reason = hugepage_capacity_error(args.huge_dir, 64 * 1024 * 1024)
    if reason:
        print('SKIP: ' + reason + '; no host settings changed'); return 77
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside',
            '--huge-dir', str(args.huge_dir),
            *[value for name in ('worker', 'tool', 'library', 'app') for value in ('--' + name, str(getattr(args, name).resolve()))]]).returncode
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
    primary = app = None
    with tempfile.TemporaryDirectory(prefix='ker-session-packets-') as directory:
        root = Path(directory); path = root / 'control.sock'; stats_path = root / 'stats.json'
        eal = (f'--lcores=0@{min(os.sched_getaffinity(0))} --no-pci --no-telemetry --iova-mode=va '
            f'-m 64 --huge-dir={args.huge_dir} --file-prefix=packets-{os.getpid()}-{os.urandom(4).hex()}')
        common = ['--socket', str(path), '--worker', str(args.worker), '--eal', eal, '--paired-pmd']
        environment = os.environ | {'RUNTIME_DIRECTORY': str(root), 'PYTHONDONTWRITEBYTECODE': '1'}
        try:
            primary = subprocess.Popen([sys.executable, str(args.tool), 'serve', *common],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            created = record(primary, 'KER_SESSION_READY')
            require(created['rings'] == 128 and created['ports'] == 1 and created['epoch'] == 0 and created['slot'] == 0,
                'resident did not precreate the complete shared geometry and actual network port')
            app = subprocess.Popen([sys.executable, str(args.tool), 'run', *common, '--wire-fd', str(endpoint.fileno()),
                '--library', str(args.library), '--stats', str(stats_path), '--address', '198.18.0.2/24', '--address6', '2001:db8:1::2/64',
                '--', str(args.app), '--fixed-mtu'], pass_fds=(endpoint.fileno(),),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            endpoint.close()
            require(line(app) == 'READY', 'original Linux application did not start')
            initial = json.loads(stats_path.read_text())
            attached, grant, geometry = (initial[key] for key in ('attached', 'grant', 'geometry'))
            require(attached['pid'] == grant['pid'] and attached['validated_rings'] == 128 and geometry['rx_ring'] != geometry['tx_ring'],
                'worker is not the granted actual secondary with directional PMD queues')
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
            app.stdin.write(b'G'); app.stdin.flush()
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
            require(line(app) == 'NATIVE_DONE', 'native MTU rollback/service completion failed')
            app.stdin.write(b'Q'); app.stdin.flush()
            output, stderr = app.communicate(timeout=20)
            stop.set(); thread.join(timeout=3)
            require(not thread.is_alive(), 'external Ethernet bridge did not stop')
            require(app.returncode == 0, 'packet-session application failed: ' + output.decode() + stderr.decode())
            require(b'PASS: original native IPv4/IPv6 TCP/UDP services' in output, 'native application proof absent')
            finished = json.loads(stats_path.read_text())
            require(finished['stage'] == 'finished' and finished['app_started'], 'supervisor completion snapshot absent')
            stats, native = finished['packet'], finished['native']
            require(stats['tx'] > 0 and stats['rx'] > 0 and stats['to_wire'] > 0 and stats['from_wire'] > 0 and stats['status'] == 0,
                'actual original PMD/host wire traffic absent')
            require(native['passive_opens'] >= 2 and native['udp_in_datagrams'] >= 1 and native['udp_out_datagrams'] >= 1 and
                native['udp6_in_datagrams'] >= 1 and native['udp6_out_datagrams'] >= 1 and native['buffers_live'] == 0,
                'traffic bypassed original Linux or retained native buffers')
            connection = api.Connection(path)
            try:
                census = connection.request(api.STATUS)
                require(census['generation'] == 511 and census['token'] == 0 and census['process'] == 0,
                    'original control/TX/RX objects not returned after exact secondary death')
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
            print('PASS: original guest Linux peers exchange exact IPv4/IPv6 TCP4097/UDP512 with original imported Linux')
            print('PASS: actual granted EAL secondary consumes independent original PMD RX/TX queues; resident stays off packet path')
            print('PASS: fixed1500 MTU rejects live mutation coherently; original Linux/PMD counters and bidirectional Ethernet capture')
            print('PASS: original control/TX/RX journal restores all511 objects after process death and native kernel teardown')
            print('PASS: real competing secondary never launches an application; actual worker loss returns125 and restores all original objects')
            print('PASS: app-owned SIGTERM reaches native DONE; launcher reports143, reaps exact children, worker packet status0 and native buffers0')
            print('PASS: resident SIGTERM closes registration, worker exits before five second deadline, resident drains, launcher reports125')
            print('PASS: source A4 primary precreates all128 coordinate rings and one original network port before actual secondary lookup')
        finally:
            if app is not None and app.poll() is None:
                app.terminate()
                try: app.wait(timeout=10)
                except subprocess.TimeoutExpired: app.kill(); app.wait()
            if primary is not None and primary.poll() is None:
                primary.terminate()
                try: primary.wait(timeout=10)
                except subprocess.TimeoutExpired: primary.kill(); primary.wait()
            stop.set(); thread.join(timeout=3); wire.close(); endpoint.close(); os.close(tap)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
