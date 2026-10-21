#!/usr/bin/env python3
"""Native Linux -> independent Linux router -> remote Linux peer over IPv6."""
import argparse
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile

PAYLOAD = b'routed-ipv6\0'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ip(*args):
    subprocess.run(['ip', *args], check=True)


def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(20), 'startup line timeout')
    result = process.stdout.readline().strip()
    require(result, 'process exited before startup line')
    return result


def receive_stream(peer):
    data = b''
    while len(data) < len(PAYLOAD):
        part = peer.recv(len(PAYLOAD) - len(data))
        require(part, 'unexpected TCP EOF')
        data += part
    require(data == PAYLOAD, 'TCP payload changed')


def receive_datagram(peer):
    data, ancillary, flags, address = peer.recvmsg(256, socket.CMSG_SPACE(4))
    hops = [struct.unpack('i', value)[0] for level, kind, value in ancillary
            if level == socket.IPPROTO_IPV6 and kind == socket.IPV6_HOPLIMIT]
    require(data == PAYLOAD and not flags and hops == [63], f'UDP payload/hop limit changed: {hops}')
    require(address[0] == '2001:db8:1::2', 'native IPv6 source changed')
    return address


def peer_main(port):
    # Parent moves the veth endpoint only after this child entered its netns.
    print('NAMESPACE_READY', flush=True)
    require(sys.stdin.readline().strip() == 'CONFIGURE', 'missing peer configuration barrier')
    ip('link', 'set', 'lo', 'up')
    ip('-6', 'addr', 'add', '2001:db8:2::2/64', 'dev', 'peer0', 'nodad')
    ip('link', 'set', 'peer0', 'up')
    ip('-6', 'route', 'add', 'default', 'via', '2001:db8:2::1', 'dev', 'peer0')
    with socket.socket(socket.AF_INET6) as listener, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        for fd in (listener, udp):
            fd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            fd.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 64)
            fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            fd.bind(('2001:db8:2::2', port + 1)); fd.settimeout(10)
        udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
        listener.listen(1)
        print('PEER_READY', flush=True)
        accepted, address = listener.accept()
        with accepted:
            accepted.settimeout(10)
            require(address[0] == '2001:db8:1::2', 'native TCP source changed')
            receive_stream(accepted); accepted.sendall(PAYLOAD)
        address = receive_datagram(udp)
        udp.sendto(PAYLOAD, address)
        with socket.socket(socket.AF_INET6) as outgoing:
            outgoing.settimeout(10); outgoing.connect(('2001:db8:1::2', port))
            outgoing.sendall(PAYLOAD); receive_stream(outgoing)
        udp.connect(('2001:db8:1::2', port)); udp.send(PAYLOAD)
        receive_datagram(udp)
    print('PASS: independent remote IPv6 TCP/UDP peer, hop limit 63', flush=True)
    return 0


def forwarded():
    fields = Path('/proc/net/snmp6').read_text().splitlines()
    return next(int(value) for name, value in (line.split() for line in fields) if name == 'Ip6OutForwDatagrams')


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--peer', type=int)
    args = parser.parse_args()
    if args.peer is not None:
        return peer_main(args.peer)
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    ip('-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad')
    ip('-6', 'addr', 'add', 'fe80::1/64', 'dev', 'kerhost', 'nodad')
    ip('link', 'set', 'kerhost', 'up'); ip('link', 'set', 'kerlink', 'up')
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-ipv6-route-') as directory:
        root = Path(directory)
        common = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--address6', '2001:db8:1::2/64', '--port', 'net_tap0', '--eal', eal]
        env = dict(os.environ, KER_NATIVE_GATEWAY6='2001:db8:1::1')
        for name, options, expected, diagnostic in (
            ('omitted', [], 0, 'PASS: no implicit IPv6 default route'),
            ('offlink', ['--gateway6', '2001:db8:3::1'], 125, 'IPv6 default route')):
            stats = root / (name + '.json')
            result = subprocess.run([*common, *options, '--stats', str(stats), '--',
                str(args.app), '28500', 'unrouted'], env=env, capture_output=True, text=True, timeout=25)
            require(result.returncode == expected and diagnostic in result.stdout + result.stderr,
                    f'{name}: {result.returncode} {result.stdout} {result.stderr}')
            record = json.loads(stats.read_text())
            require(record['outstanding'] == 0 and ('native' in record) == (expected == 0),
                    f'{name}: cleanup or native startup state invalid')
            if expected:
                require('application did not initialize the native Linux backend' in result.stderr,
                        'invalid gateway reached native READY')
            print('PASS: ' + name + ' IPv6 route boundary and cleanup', flush=True)
        for index, mode in enumerate(('ini-global', 'cli-link-local')):
            port = 28510 + index * 2
            config, stats = root / (mode + '.ini'), root / (mode + '.json')
            config.write_text('[network]\ngateway6=' + ('2001:db8:1::1' if index == 0 else '2001:db8:3::1') + '\n')
            options = ['--config', str(config)]
            if index:
                options += ['--gateway6', 'fe80::1']
            peer = app = None
            with (root / (mode + '.peer.log')).open('w+') as peer_log, (root / (mode + '.app.log')).open('w+') as app_log:
                try:
                    peer = subprocess.Popen(['unshare', '-n', sys.executable, str(Path(__file__).resolve()),
                        '--peer', str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=peer_log, text=True)
                    require(line(peer) == 'NAMESPACE_READY', 'remote netns startup failed')
                    ip('link', 'add', 'router0', 'type', 'veth', 'peer', 'name', 'peer0')
                    ip('link', 'set', 'peer0', 'netns', str(peer.pid))
                    ip('-6', 'addr', 'add', '2001:db8:2::1/64', 'dev', 'router0', 'nodad')
                    ip('link', 'set', 'router0', 'up')
                    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1\n')
                    peer.stdin.write('CONFIGURE\n'); peer.stdin.flush()
                    require(line(peer) == 'PEER_READY', 'remote listeners not ready')
                    before = forwarded()
                    app = subprocess.Popen([*common, *options, '--stats', str(stats), '--',
                        str(args.app), str(port), 'routed'], env=env, stdout=subprocess.PIPE,
                        stderr=app_log, text=True)
                    require(line(app) == 'READY', 'native routed startup failed')
                    output, _ = app.communicate(timeout=30)
                    peer_output, _ = peer.communicate(timeout=10)
                    require(app.returncode == 0 and peer.returncode == 0 and
                            'PASS:' in output and 'PASS:' in peer_output, 'routed apps failed')
                    require(forwarded() > before, 'independent router forwarded no IPv6 packets')
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'] and
                            record['native']['active_opens'] >= 1 and record['native']['passive_opens'] >= 1,
                            'native routed traffic/cleanup evidence missing')
                    print('PASS: ' + mode + ' routed IPv6 TCP/UDP both directions and forwarding counters', flush=True)
                except Exception:
                    for log in (peer_log, app_log):
                        log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    stop(app); stop(peer)
                    # Peer netns teardown removes its veth pair too.
                    subprocess.run(['ip', 'link', 'del', 'router0'], capture_output=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
