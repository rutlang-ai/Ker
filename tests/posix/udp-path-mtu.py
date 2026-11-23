#!/usr/bin/env python3
"""Validate actual IPv4/IPv6 router-generated UDP path MTU errors."""
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


def ip(*args):
    subprocess.run(['ip', *args], check=True)


def ready(process, expected):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(20), 'startup timeout')
    require(process.stdout.readline().strip() == expected, 'unexpected startup response')


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def peer(family, port):
    print('NAMESPACE_READY', flush=True)
    require(sys.stdin.readline().strip() == 'CONFIGURE', 'peer barrier failed')
    ip('link', 'set', 'lo', 'up')
    ip('addr', 'add', '198.19.0.2/24', 'dev', 'peer0')
    ip('-6', 'addr', 'add', '2001:db8:2::2/64', 'dev', 'peer0', 'nodad')
    ip('link', 'set', 'peer0', 'mtu', '1280', 'up')
    ip('route', 'add', 'default', 'via', '198.19.0.1')
    ip('-6', 'route', 'add', 'default', 'via', '2001:db8:2::1', 'dev', 'peer0')
    with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as fd:
        fd.bind(('198.19.0.2' if family == 4 else '2001:db8:2::2', port + 1)); fd.settimeout(15)
        print('PEER_READY', flush=True)
        packet, source = fd.recvfrom(65535)
        require(source[0] == ('198.18.0.2' if family == 4 else '2001:db8:1::2'), 'native source changed')
        require(packet == bytes((i * 71) & 255 for i in range(1232)), 'remote received wrong PMTU recovery')
        fd.sendto(packet, source)
    print('PASS: independent PMTU recovery peer', flush=True)
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--peer', type=int)
    p.add_argument('--port', type=int)
    p.add_argument('--inside', action='store_true')
    for name in ('app', 'launcher', 'library', 'worker'):
        p.add_argument('--' + name, type=Path)
    args = p.parse_args()
    if args.peer:
        return peer(args.peer, args.port)
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('app', 'launcher', 'library', 'worker'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    ip('-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad')
    ip('link', 'set', 'kerhost', 'up'); ip('link', 'set', 'kerlink', 'up')
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-udp-path-mtu-') as directory:
        root = Path(directory)
        for family in (4, 6):
            port = 28700 + family
            with (root / f'peer{family}.log').open('w+') as log:
                process = None
                try:
                    process = subprocess.Popen(['unshare', '-n', sys.executable, str(Path(__file__).resolve()),
                        '--peer', str(family), '--port', str(port)], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=log, text=True)
                    ready(process, 'NAMESPACE_READY')
                    ip('link', 'add', 'router0', 'type', 'veth', 'peer', 'name', 'peer0')
                    ip('link', 'set', 'peer0', 'netns', str(process.pid))
                    ip('addr', 'add', '198.19.0.1/24', 'dev', 'router0')
                    ip('-6', 'addr', 'add', '2001:db8:2::1/64', 'dev', 'router0', 'nodad')
                    ip('link', 'set', 'router0', 'mtu', '1280', 'up')
                    Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
                    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1\n')
                    process.stdin.write('CONFIGURE\n'); process.stdin.flush(); ready(process, 'PEER_READY')
                    stats = root / f'stats{family}.json'
                    result = subprocess.run([sys.executable, str(args.launcher), '--library', str(args.library),
                        '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--gateway', '198.18.0.1',
                        '--address6', '2001:db8:1::2/64', '--gateway6', '2001:db8:1::1', '--port', 'net_tap0',
                        '--eal', eal, '--stats', str(stats), '--', str(args.app), str(family), str(port)],
                        capture_output=True, text=True, timeout=30)
                    require(result.returncode == 0 and 'PASS:' in result.stdout,
                            f'IPv{family} PMTU: {result.returncode} {result.stdout} {result.stderr}')
                    output, _ = process.communicate(timeout=10)
                    require(process.returncode == 0 and 'PASS:' in output, 'PMTU peer failed')
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'] and 'native' in record,
                            'PMTU packet/cleanup evidence missing')
                    print(result.stdout.strip(), flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    stop(process)
                    subprocess.run(['ip', 'link', 'del', 'router0'], capture_output=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
