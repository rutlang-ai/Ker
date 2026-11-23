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


def check_vlan_capture(directory, router_mac):
    # Require actual tagged remote UDP in both directions, and NDP for the
    # router next hop on that VLAN. A successful local-only echo is insufficient.
    gateway_seen = False
    for direction in ('tx', 'rx'):
        routed = False
        for path in directory.glob('ker-' + direction + '-*.pcap'):
            data = path.read_bytes()
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            offset = 24
            while offset < len(data):
                _, _, count, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + count]; offset += count
                require(len(frame) == count == original, 'truncated routed VLAN evidence')
                if frame[12:14] != b'\x81\x00' or frame[16:18] != b'\x86\xdd':
                    continue
                require(struct.unpack('!H', frame[14:16])[0] & 4095 == 100, 'wrong routed VLAN tag')
                if frame[24] == 17 and PAYLOAD in frame[58:]:
                    remote = frame[42:58] if direction == 'tx' else frame[26:42]
                    require(remote == socket.inet_pton(socket.AF_INET6, '2001:db8:2::2'), 'not a routed remote datagram')
                    require(frame[:6] == router_mac if direction == 'tx' else frame[6:12] == router_mac,
                            'routed Ethernet peer is not the independent router')
                    routed = True
                if direction == 'tx' and frame[24] == 58 and len(frame) >= 82 and frame[58] == 135:
                    target = frame[66:82]
                    require(target != socket.inet_pton(socket.AF_INET6, '2001:db8:2::2'), 'NDP used remote endpoint instead of gateway')
                    gateway_seen |= target in [socket.inet_pton(socket.AF_INET6, address)
                                              for address in ('fe80::1', '2001:db8:1::1')]
        require(routed, direction + ': no tagged routed remote UDP')
    require(gateway_seen, 'missing tagged gateway neighbor solicitation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--vlan6', action='store_true')
    parser.add_argument('--peer', type=int)
    args = parser.parse_args()
    if args.peer is not None:
        return peer_main(args.peer)
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        if args.vlan6:
            command += ['--vlan6']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    ip('link', 'set', 'kerhost', 'up'); ip('link', 'set', 'kerlink', 'up')
    router_interface = 'kerhost'
    if args.vlan6:
        router_interface = 'kerhost.100'
        ip('link', 'add', 'link', 'kerhost', 'name', router_interface, 'type', 'vlan', 'id', '100')
        ip('link', 'set', router_interface, 'up')
    ip('-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', router_interface, 'nodad')
    ip('-6', 'addr', 'add', 'fe80::1/64', 'dev', router_interface, 'nodad')
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-ipv6-route-') as directory:
        root = Path(directory)
        common = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal, '--no-promiscuous']
        common += ['--vlan', '100=2001:db8:1::2/64'] if args.vlan6 else ['--address6', '2001:db8:1::2/64']
        gateway_option = '--vlan-gateway6' if args.vlan6 else '--gateway6'
        gateway_value = lambda address: '100=' + address if args.vlan6 else address
        env = dict(os.environ, KER_NATIVE_GATEWAY6='2001:db8:1::1', KER_NATIVE_VLAN_GATEWAY6='100=fe80::1')
        for name, options, expected, diagnostic in (
            ('omitted', [], 0, 'PASS: no implicit IPv6 default route'),
            ('offlink', [gateway_option, gateway_value('2001:db8:3::1')], 125, 'IPv6 default route')):
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
            config.write_text(('[vlan.100]\naddresses=2001:db8:1::2/64\ngateway6=' if args.vlan6 else '[network]\ngateway6=') +
                ('2001:db8:1::1' if index == 0 else '2001:db8:3::1') + '\n')
            options = ['--config', str(config)]
            if index:
                options += [gateway_option, gateway_value('fe80::1')]
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
                    capture = root / (mode + '-capture')
                    capture.mkdir()
                    app = subprocess.Popen([*common, *options, '--pcap-dir', str(capture), '--stats', str(stats), '--',
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
                            record['native']['active_opens'] >= 1 and record['native']['passive_opens'] >= 1 and
                            record['native']['udp6_in_datagrams'] == 2 and record['native']['udp6_out_datagrams'] == 2,
                            'native routed traffic/cleanup evidence missing')
                    if args.vlan6:
                        check_vlan_capture(capture, bytes.fromhex(json.loads(subprocess.check_output(
                            ['ip', '-j', 'link', 'show', 'kerhost']))[0]['address'].replace(':', '')))
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
