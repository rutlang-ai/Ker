#!/usr/bin/env python3
"""Validate configured native IPv6 against independent host TCP/UDP and NDP."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile

PAYLOAD = b'native-ipv6\0'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def receive(peer):
    result = b''
    while len(result) < len(PAYLOAD):
        part = peer.recv(len(PAYLOAD) - len(result))
        require(part, 'unexpected TCP EOF')
        result += part
    require(result == PAYLOAD, 'payload changed')


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
        ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad'],
        ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up'],
    ]
    for command in commands:
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-ipv6-') as directory:
        root = Path(directory)
        for index, mode in enumerate(('ini', 'cli')):
            subprocess.run(['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            config, stats = root / (mode + '.ini'), root / (mode + '.json')
            address6 = '2001:db8:1::2/64' if mode == 'ini' else '2001:db8:1::99/64'
            config.write_text('[network]\naddress=198.18.0.2/24\naddress6=' + address6 +
                              '\n[dpdk]\nport=net_tap0\neal=' + eal + '\n')
            command = [sys.executable, str(args.launcher), '--config', str(config),
                       '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats)]
            if mode == 'cli':
                command += ['--address6', '2001:db8:1::2/64', '--no-all-multicast']
            port = 28400 + index * 2
            env = dict(os.environ, KER_NATIVE_ADDRESS6='2001:db8:1::99/64')
            with socket.socket(socket.AF_INET6) as listener, \
                    socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as datagram, \
                    (root / (mode + '.log')).open('w+') as log:
                for peer in (listener, datagram):
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    peer.bind(('2001:db8:1::1', port + 1)); peer.settimeout(10)
                listener.listen(1)
                process = subprocess.Popen([*command, '--', str(args.app), str(port)], env=env,
                    stdout=subprocess.PIPE, stderr=log, text=True)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'native IPv6 startup timeout')
                    line = process.stdout.readline()
                    require(line.strip() == 'READY', 'native IPv6 startup failed: ' + line)
                    with socket.socket(socket.AF_INET6) as peer:
                        peer.settimeout(10); peer.connect(('2001:db8:1::2', port))
                        peer.sendall(PAYLOAD); receive(peer)
                    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
                        peer.settimeout(10); peer.connect(('2001:db8:1::2', port))
                        peer.send(PAYLOAD)
                        require(peer.recv(256) == PAYLOAD, 'native UDP echo changed')
                    peer, address = listener.accept()
                    with peer:
                        peer.settimeout(10)
                        require(address[0] == '2001:db8:1::2', 'native TCP source changed')
                        receive(peer); peer.sendall(PAYLOAD)
                    packet, address = datagram.recvfrom(256)
                    require(address[0] == '2001:db8:1::2' and packet == PAYLOAD,
                            'native UDP source or payload changed')
                    datagram.sendto(packet, address)
                    with socket.create_connection(('198.18.0.2', port), timeout=10) as peer:
                        peer.sendall(PAYLOAD); receive(peer)
                    output, _ = process.communicate(timeout=20)
                    log.flush(); log.seek(0)
                    require(process.returncode == 0 and 'PASS:' in output,
                            f'{mode}: native IPv6 test failed: {output} {log.read()}')
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'],
                            'IPv6 worker traffic/cleanup missing')
                    require(record['native']['active_opens'] >= 1 and record['native']['passive_opens'] >= 2,
                            'TCP bypassed original Linux')
                    neighbors = json.loads(subprocess.check_output(
                        ['ip', '-j', '-6', 'neigh', 'show', 'dev', 'kerhost'], text=True))
                    require(any(peer.get('dst') == '2001:db8:1::2' and
                        peer.get('lladdr', '').lower() == record['io']['mac'].lower() for peer in neighbors),
                        'host neighbor discovery did not resolve the native device')
                    print('PASS: ' + mode + ' IPv6 TCP/UDP both directions, IPv4, NDP and cleanup', flush=True)
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
        # The independent host owns ::1. Original Linux must detect the
        # duplicate and fail startup before the application's READY/main.
        conflict_stats = root / 'duplicate.json'
        failed = subprocess.run([*command, '--address6', '2001:db8:1::1/64',
            '--stats', str(conflict_stats), '--', str(args.app), str(port)],
            env=env, capture_output=True, text=True, timeout=25)
        require(failed.returncode == 125 and 'IPv6 interface configuration/DAD' in failed.stderr,
                f'duplicate IPv6 address was accepted: {failed.returncode} {failed.stderr}')
        require('READY' not in failed.stdout and
            'application did not initialize the native Linux backend' in failed.stderr,
            'duplicate IPv6 address reached application readiness')
        record = json.loads(conflict_stats.read_text())
        require(record['outstanding'] == 0 and 'native' not in record,
                'duplicate IPv6 startup did not clean up the worker')
        print('PASS: original Linux duplicate-address detection rejects the host address before main', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
