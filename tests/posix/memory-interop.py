#!/usr/bin/env python3
"""Exercise application memory buffers with original-Linux TCP and a host peer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def exchange(listener):
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(20)
        size = os.sysconf('SC_PAGESIZE') * 2
        data = bytearray()
        while len(data) < size:
            part = connection.recv(size - len(data))
            require(part, 'native peer closed before the application payload arrived')
            data.extend(part)
        require(data == bytes((i * 37 + 11) & 255 for i in range(size)),
                'application payload differs at the independent host peer')
        require(connection.recv(1) == b'', 'native peer did not finish its request')
        connection.sendall(bytes(value ^ 0x5a for value in data))
        connection.shutdown(socket.SHUT_WR)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'probe'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mode', choices=('shared', 'file', 'calloc', 'realloc'), required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
                   '--inside', '--mode', args.mode]
        for name in ('launcher', 'library', 'worker', 'app', 'probe'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    for scope in ('all', 'default'):
        Path('/proc/sys/net/ipv6/conf/' + scope + '/disable_ipv6').write_text('1\n')
    for command in (['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
                    ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
                    ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    launcher = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--port', 'net_tap0', '--eal', eal]
    env = os.environ.copy()
    env.pop('KER_TEST_STARTUP_FAILURE', None)
    env['LD_PRELOAD'] = str(args.probe) + ' ' + env.get('LD_PRELOAD', '')
    with tempfile.TemporaryDirectory(prefix='ker-memory-') as directory, socket.socket() as listener:
        root = Path(directory)
        cleanup, stats = root / 'cleanup', root / 'stats.json'
        env['KER_TEST_STARTUP_CLEANUP'] = str(cleanup)
        listener.settimeout(20)
        listener.bind(('198.18.0.1', 0)); listener.listen(1)
        with ThreadPoolExecutor(max_workers=1) as pool:
            peer = pool.submit(exchange, listener)
            result = subprocess.run([*launcher, '--stats', str(stats), '--', str(args.app),
                args.mode, str(listener.getsockname()[1]), str(root / 'mapping-XXXXXX')],
                env=env, capture_output=True, text=True, timeout=40)
            require(result.returncode == 0, f'{result.stdout}\n{result.stderr}')
            peer.result(timeout=5)
        require('PASS: POSIX application buffer' in result.stdout, 'missing application checks')
        record = json.loads(stats.read_text())
        require(record['native']['active_opens'] > 0, 'original Linux did not open TCP')
        require(record['tx'] > 0 and record['rx'] > 0,
                f'no actual DPDK traffic: {record}')
        require(record['outstanding'] == 0, f'packet buffers leaked: {record}')
        require(cleanup.is_file() and cleanup.read_text().strip() == '0', 'real EAL cleanup failed')
        require(not list(root.glob('mapping-*')), 'temporary backing file was not removed')
        print(f'PASS: {args.mode} buffer, independent host TCP/DPDK payload and actual cleanup')
    return 0


if __name__ == '__main__':
    sys.exit(main())
