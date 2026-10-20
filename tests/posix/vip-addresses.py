#!/usr/bin/env python3
"""Validate actual native IPv4 VIP configuration against independent host TCP."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile


def require(value, message):
    if not value:
        raise RuntimeError(message)


def receive(peer):
    result = b''
    while len(result) < 8:
        part = peer.recv(8 - len(result))
        require(part, 'unexpected TCP EOF')
        result += part
    require(result == b'vip-test', 'TCP payload changed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    commands = [
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up'],
    ]
    for command in commands:
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-vip-') as directory:
        root = Path(directory)
        for index, mode in enumerate(('ini', 'cli')):
            config, stats = root / (mode + '.ini'), root / (mode + '.json')
            aliases = '198.18.0.3/24, 198.18.0.4/24' if mode == 'ini' else '198.18.0.99/24'
            config.write_text('[network]\naddress=198.18.0.2/24\nvip_addresses=' + aliases +
                              '\n[dpdk]\nport=net_tap0\neal=' + eal + '\n')
            command = [sys.executable, str(args.launcher), '--config', str(config),
                       '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats)]
            if mode == 'cli':
                command += ['--vip-address', '198.18.0.3/24', '--vip-address', '198.18.0.4/24']
            port = 28300 + index * 2
            env = dict(os.environ, KER_NATIVE_VIP_ADDRESSES='198.18.0.99/24')
            with socket.socket() as listener, (root / (mode + '.log')).open('w+') as log:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('198.18.0.1', port + 1)); listener.listen(2); listener.settimeout(10)
                process = subprocess.Popen([*command, '--', str(args.app), str(port),
                    '198.18.0.2', '198.18.0.3', '198.18.0.4'], env=env,
                    stdout=subprocess.PIPE, stderr=log, text=True)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'native VIP startup timeout')
                    line = process.stdout.readline()
                    require(line.strip() == 'READY', 'native VIP startup failed: ' + line)
                    for address in ('198.18.0.2', '198.18.0.3', '198.18.0.4'):
                        with socket.create_connection((address, port), timeout=10) as peer:
                            peer.sendall(b'vip-test'); receive(peer)
                    for expected in ('198.18.0.3', '198.18.0.4'):
                        peer, address = listener.accept()
                        with peer:
                            peer.settimeout(10)
                            require(address[0] == expected, 'native VIP source binding changed: ' + str(address))
                            receive(peer); peer.sendall(b'vip-test')
                    output, _ = process.communicate(timeout=20)
                    log.flush(); log.seek(0)
                    require(process.returncode == 0 and 'PASS:' in output,
                            f'{mode}: native VIP test failed: {output} {log.read()}')
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'], 'VIP worker traffic/cleanup missing')
                    require(record['native']['active_opens'] >= 2 and record['native']['passive_opens'] >= 3,
                            'VIP TCP bypassed original Linux')
                    print('PASS: ' + mode + ' VIP addresses, independent host TCP, native counters and cleanup', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait()
    return 0


if __name__ == '__main__':
    sys.exit(main())
