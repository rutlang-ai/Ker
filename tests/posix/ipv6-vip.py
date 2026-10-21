#!/usr/bin/env python3
"""Validate native IPv6 VIPs against independent host TCP/UDP and NDP."""
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
    with tempfile.TemporaryDirectory(prefix='ker-ipv6-vip-') as directory:
        root = Path(directory)
        for index, mode in enumerate(('ini', 'cli', 'omitted', 'max')):
            subprocess.run(['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            config, stats = root / (mode + '.ini'), root / (mode + '.json')
            aliases = '2001:db8:1::3/128,2001:db8:1::4/128' if mode == 'ini' else '2001:db8:1::99/64'
            if mode == 'omitted':
                aliases = ''
            if mode == 'max':
                aliases = ','.join(f'2001:db8:1::{i:x}/128' for i in range(3, 35))
            config.write_text('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\nvip_addresses6=' + aliases +
                              '\n[dpdk]\nport=net_tap0\neal=' + eal + '\n')
            command = [sys.executable, str(args.launcher), '--config', str(config),
                       '--library', str(args.library), '--io-worker', str(args.worker), '--stats', str(stats)]
            if mode == 'cli':
                command += ['--vip-address6', '2001:db8:1::3/128', '--vip-address6', '2001:db8:1::4/128', '--no-all-multicast']
            port = 28400 + index * 2
            env = dict(os.environ, KER_NATIVE_VIP_ADDRESSES6='2001:db8:1::99/64')
            with socket.socket(socket.AF_INET6) as listener, \
                    socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as datagram, \
                    (root / (mode + '.log')).open('w+') as log:
                for peer in (listener, datagram):
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    peer.bind(('2001:db8:1::1', port + 1)); peer.settimeout(10)
                listener.listen(1)
                process = subprocess.Popen([*command, '--', str(args.app), str(port), *(['primary-only'] if mode == 'omitted' else ['max'] if mode == 'max' else [])], env=env,
                    stdout=subprocess.PIPE, stderr=log, text=True)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'native IPv6 startup timeout')
                    line = process.stdout.readline()
                    require(line.strip() == 'READY', 'native IPv6 startup failed: ' + line)
                    for expected in (('2001:db8:1::2',) if mode == 'omitted' else
                                     ('2001:db8:1::2', '2001:db8:1::3', '2001:db8:1::4')):
                        with socket.socket(socket.AF_INET6) as peer:
                            peer.settimeout(10); peer.connect((expected, port))
                            peer.sendall(PAYLOAD); receive(peer)
                        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
                            peer.settimeout(10); peer.connect((expected, port))
                            peer.send(PAYLOAD)
                            require(peer.recv(256) == PAYLOAD, 'native UDP echo changed')
                        peer, address = listener.accept()
                        with peer:
                            peer.settimeout(10)
                            require(address[0] == expected, 'native TCP source changed')
                            receive(peer); peer.sendall(PAYLOAD)
                        packet, address = datagram.recvfrom(256)
                        require(address[0] == expected and packet == PAYLOAD,
                                'native UDP source or payload changed')
                        datagram.sendto(packet, address)
                    output, _ = process.communicate(timeout=20)
                    log.flush(); log.seek(0)
                    require(process.returncode == 0 and 'PASS:' in output,
                            f'{mode}: native IPv6 test failed: {output} {log.read()}')
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'],
                            'IPv6 worker traffic/cleanup missing')
                    count = 1 if mode == 'omitted' else 3
                    require(record['native']['active_opens'] >= count and record['native']['passive_opens'] >= count,
                            'TCP bypassed original Linux')
                    require(record['native']['udp6_in_datagrams'] >= 2 * count and
                        record['native']['udp6_out_datagrams'] >= 2 * count and
                        record['native']['udp6_in_errors'] == 0, 'IPv6 UDP kernel counters missing or erroneous')
                    neighbors = json.loads(subprocess.check_output(
                        ['ip', '-j', '-6', 'neigh', 'show', 'dev', 'kerhost'], text=True))
                    for expected in (('2001:db8:1::2',) if mode == 'omitted' else
                                     ('2001:db8:1::2', '2001:db8:1::3', '2001:db8:1::4')):
                        require(any(peer.get('dst') == expected and
                            peer.get('lladdr', '').lower() == record['io']['mac'].lower() for peer in neighbors),
                            'host NDP did not resolve ' + expected)
                    print('PASS: ' + mode + ' IPv6 VIP TCP/UDP in both directions, NDP and cleanup', flush=True)
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
        failed = subprocess.run([*command, '--vip-address6', '2001:db8:1::1/64',
            '--stats', str(conflict_stats), '--', str(args.app), str(port)],
            env=env, capture_output=True, text=True, timeout=25)
        require(failed.returncode == 125 and 'IPv6 interface configuration/DAD' in failed.stderr,
                f'duplicate IPv6 address was accepted: {failed.returncode} {failed.stderr}')
        require('READY' not in failed.stdout and
            'application did not initialize the native Linux backend' in failed.stderr,
            'duplicate IPv6 VIP reached application readiness')
        record = json.loads(conflict_stats.read_text())
        require(record['outstanding'] == 0 and 'native' not in record,
                'duplicate IPv6 startup did not clean up the worker')
        print('PASS: original Linux duplicate-address detection rejects a VIP owned by the host before main', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
