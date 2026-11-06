"""Verify real native shutdown while administrative RPC clients remain open.

This is a fixture lifecycle control, not an upstream protocol test case.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import time


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load('socket_fixture', 'linux-mptcp-socket-selftest.py')
cleanup = load('socket_fixture_cleanup', 'linux-mptcp-diag-selftest.py')
require = fixture.require


def main():
    parser = argparse.ArgumentParser()
    for name in ('server', 'launcher', 'library', 'worker', 'pmd_dir', 'manifest', 'evidence'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    parser.add_argument('--channels', type=int, default=8)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    require(1 <= args.channels <= 32, 'invalid fixture control channel count')
    if not args.inside:
        return subprocess.run(['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                               *sys.argv[1:], '--inside']).returncode
    manifest = json.loads(args.manifest.read_text())
    report = dict(status='FAIL', scope='native fixture shutdown control; not upstream TAP coverage',
        fingerprint=manifest['fingerprint'], revision=manifest['linux']['revision'],
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest(), channels=args.channels)
    environment = {k: v for k, v in os.environ.items() if k != 'LD_PRELOAD' and not k.startswith('KER_')}
    try:
        for command in (['ip', 'link', 'set', 'lo', 'up'],
                        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
                        *[['ip', 'link', 'set', name, 'up'] for name in ('kerhost', 'kerlink', 'kerpeer')]):
            subprocess.run(command, check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 '
               f'-d {shlex.quote(str(args.pmd_dir / "librte_net_tap.so"))} --vdev=net_tap0,iface=kerpeer,remote=kerlink')
        with tempfile.TemporaryDirectory(prefix='ker-mptcp-stop-', dir='/dev/shm') as temporary:
            root = Path(temporary)
            channel, counts, stats = root / 'socket', root / 'counts.json', root / 'stats.json'
            with (root / 'stdout').open('w+') as out, (root / 'stderr').open('w+') as err:
                process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
                    '--stats', str(stats), '--', str(args.server), str(channel), str(counts)],
                    env=environment, stdout=out, stderr=err, start_new_session=True)
                held = []
                try:
                    deadline = time.monotonic() + 20
                    while not channel.exists():
                        require(process.poll() is None and time.monotonic() < deadline, 'resident kernel startup failed')
                        time.sleep(0.01)
                    # These requests enter Linux before becoming idle, so each
                    # worker also has a real LKL task to retire at shutdown.
                    data = b'\0/proc/sys/net/mptcp/enabled\0'
                    for _ in range(args.channels):
                        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                        held.append(client); client.settimeout(5); client.connect(str(channel))
                        client.sendall(fixture.HEADER.pack(fixture.MAGIC, 23, len(data), 0, 0, 0, 0) + data)
                        packet, _, flags, _ = client.recvmsg(fixture.HEADER.size + 131072)
                        require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
                                len(packet) >= fixture.HEADER.size, 'invalid native control response')
                        magic, operation, size, _, _, _, result = fixture.HEADER.unpack_from(packet)
                        require((magic, operation, size, result) == (fixture.MAGIC, 23, 2, 0) and
                                packet[fixture.HEADER.size:] == b'1\n', 'control did not read real native MPTCP state')
                    started = time.monotonic()
                    fixture.stop(channel)
                    require(process.wait(timeout=10) == 0, 'native shutdown failed with idle control clients')
                    report['shutdown_seconds'] = time.monotonic() - started
                    report['eof_after_stop'] = [client.recv(1) == b'' for client in held]
                    require(all(report['eof_after_stop']), 'idle administrative channels were not closed')
                    report['native_fixture'] = json.loads(counts.read_text())
                    native = report['native_fixture']
                    require(native['channel_slots'] == native['channels_opened'] == args.channels + 1,
                            'control did not retain all native workers through STOP')
                    require(native['sockets'] == native['accepts'] == native['live'] == 0,
                            'fixture control unexpectedly created or retained protocol sockets')
                    report['stats'] = json.loads(stats.read_text())
                    observed = report['stats']
                    require(observed.get('outstanding') == 0 and observed.get('worker_exit_code') == 0 and
                            observed.get('control_eof') is True and observed.get('shutdown_timed_out') is False,
                            'native kernel/worker did not stop normally')
                    require(observed.get('native', {}).get('active_opens') == 0 and
                            observed.get('native', {}).get('passive_opens') == 0,
                            'fixture lifecycle control was mixed with TCP protocol activity')
                    report['status'] = 'PASS_NATIVE_FIXTURE_SHUTDOWN_CONTROL'
                    print('NATIVE_MPTCP_FIXTURE_SHUTDOWN_PASS', args.channels)
                    return 0
                finally:
                    for client in held: client.close()
                    if process.poll() is None:
                        cleanup.kill_tree(process.pid); process.wait(timeout=10)
                    for stream, key in ((out, 'server_stdout'), (err, 'server_stderr')):
                        stream.flush(); stream.seek(0); report[key] = stream.read()
    except BaseException as error:
        report['error'] = str(error)
        raise
    finally:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        sys.exit('Native fixture shutdown failed: ' + str(error))
