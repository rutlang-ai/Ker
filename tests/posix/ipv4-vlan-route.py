#!/usr/bin/env python3
"""Native Linux -> independent Linux router -> remote Linux peer over IPv4."""
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

PAYLOAD = b'routed-ipv4\0'


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
            if level == socket.IPPROTO_IP and kind == socket.IP_TTL]
    require(data == PAYLOAD and not flags and hops == [63], f'UDP payload/TTL changed: {hops}')
    require(address[0] == '198.19.100.2', 'native IPv4 source changed')
    return address


def peer_main(port):
    # Parent moves the veth endpoint only after this child entered its netns.
    print('NAMESPACE_READY', flush=True)
    require(sys.stdin.readline().strip() == 'CONFIGURE', 'missing peer configuration barrier')
    ip('link', 'set', 'lo', 'up')
    ip('addr', 'add', '198.19.200.2/24', 'dev', 'peer0')
    ip('link', 'set', 'peer0', 'up')
    ip('route', 'add', 'default', 'via', '198.19.200.1', 'dev', 'peer0')
    with socket.socket(socket.AF_INET) as listener, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        for fd in (listener, udp):
            fd.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
            fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            fd.bind(('198.19.200.2', port + 1)); fd.settimeout(10)
        udp.setsockopt(socket.IPPROTO_IP, getattr(socket, 'IP_RECVTTL', 12), 1)
        listener.listen(1)
        print('PEER_READY', flush=True)
        accepted, address = listener.accept()
        with accepted:
            accepted.settimeout(10)
            require(address[0] == '198.19.100.2', 'native TCP source changed')
            receive_stream(accepted); accepted.sendall(PAYLOAD)
        address = receive_datagram(udp)
        udp.sendto(PAYLOAD, address)
        with socket.socket(socket.AF_INET) as outgoing:
            outgoing.settimeout(10); outgoing.connect(('198.19.100.2', port))
            outgoing.sendall(PAYLOAD); receive_stream(outgoing)
        udp.connect(('198.19.100.2', port)); udp.send(PAYLOAD)
        receive_datagram(udp)
    print('PASS: independent remote IPv4 TCP/UDP peer, TTL 63', flush=True)
    return 0


def forwarded():
    lines = Path('/proc/net/snmp').read_text().splitlines()
    header = next(i for i, value in enumerate(lines) if value.startswith('Ip:'))
    return int(dict(zip(lines[header].split(), lines[header + 1].split()))['ForwDatagrams'])


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def check_vlan_capture(directory, router_mac, gateway):
    gateway_seen = False
    remote_ip = socket.inet_aton('198.19.200.2')
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
                if frame[12:14] != b'\x81\x00':
                    continue
                require(struct.unpack('!H', frame[14:16])[0] & 4095 == 100, 'wrong routed VLAN tag')
                if frame[16:18] == b'\x08\x06' and direction == 'tx' and frame[24:26] == b'\x00\x01':
                    require(frame[42:46] != remote_ip, 'ARP used remote endpoint instead of gateway')
                    gateway_seen |= frame[42:46] == socket.inet_aton(gateway)
                if frame[16:18] != b'\x08\x00' or len(frame) < 38:
                    continue
                packet = frame[18:]
                ihl = (packet[0] & 15) * 4
                if packet[9] == 17 and packet[ihl + 8:] == PAYLOAD:
                    remote = packet[16:20] if direction == 'tx' else packet[12:16]
                    require(remote == remote_ip, 'not a routed remote datagram')
                    require(frame[:6] == router_mac if direction == 'tx' else frame[6:12] == router_mac,
                            'routed Ethernet peer is not the independent router')
                    require(packet[8] == (64 if direction == 'tx' else 63), 'IPv4 wire TTL mismatch')
                    routed = True
        require(routed, direction + ': no tagged routed remote UDP')
    require(gateway_seen, 'missing ARP for the configured VLAN gateway')


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
    ip('link', 'set', 'kerhost', 'up'); ip('link', 'set', 'kerlink', 'up')
    ip('link', 'add', 'link', 'kerhost', 'name', 'kerhost.100', 'type', 'vlan', 'id', '100')
    ip('link', 'set', 'kerhost.100', 'up')
    for address in ('198.19.100.1/24', '198.19.100.3/24'):
        ip('addr', 'add', address, 'dev', 'kerhost.100')
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-ipv4-route-') as directory:
        root = Path(directory)
        common = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal]
        common += ['--vlan', '100=198.19.100.2/24']
        env = dict(os.environ, KER_NATIVE_VLAN_GATEWAY='100=198.19.100.1',
                   LKL_HIJACK_NET_GATEWAY='198.18.0.1')
        for name, options, expected, diagnostic in (
            ('omitted', [], 0, 'PASS: no implicit IPv4 default route'),
            ('offlink', ['--vlan-gateway', '100=198.19.101.1'], 125, 'IPv4 default route')):
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
            print('PASS: ' + name + ' IPv4 route boundary and cleanup', flush=True)
        for index, mode in enumerate(('ini-gateway', 'cli-override')):
            port = 28510 + index * 2
            config, stats = root / (mode + '.ini'), root / (mode + '.json')
            config.write_text('[vlan.100]\naddresses=198.19.100.2/24\ngateway=' +
                ('198.19.100.1' if index == 0 else '198.19.101.1') + '\n')
            options = ['--config', str(config)]
            gateway = '198.19.100.1' if index == 0 else '198.19.100.3'
            if index:
                options += ['--vlan-gateway', '100=' + gateway]
            peer = app = None
            with (root / (mode + '.peer.log')).open('w+') as peer_log, (root / (mode + '.app.log')).open('w+') as app_log:
                try:
                    peer = subprocess.Popen(['unshare', '-n', sys.executable, str(Path(__file__).resolve()),
                        '--peer', str(port)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=peer_log, text=True)
                    require(line(peer) == 'NAMESPACE_READY', 'remote netns startup failed')
                    ip('link', 'add', 'router0', 'type', 'veth', 'peer', 'name', 'peer0')
                    ip('link', 'set', 'peer0', 'netns', str(peer.pid))
                    ip('addr', 'add', '198.19.200.1/24', 'dev', 'router0')
                    ip('link', 'set', 'router0', 'up')
                    Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
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
                    require(forwarded() > before, 'independent router forwarded no IPv4 packets')
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'] and
                            record['native']['active_opens'] >= 1 and record['native']['passive_opens'] >= 1 and
                            record['native']['udp_in_datagrams'] == 2 and record['native']['udp_out_datagrams'] == 2,
                            'native routed traffic/cleanup evidence missing')
                    check_vlan_capture(capture, bytes.fromhex(json.loads(subprocess.check_output(
                        ['ip', '-j', 'link', 'show', 'kerhost']))[0]['address'].replace(':', '')), gateway)
                    print('PASS: ' + mode + ' routed IPv4 TCP/UDP both directions and forwarding counters', flush=True)
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
