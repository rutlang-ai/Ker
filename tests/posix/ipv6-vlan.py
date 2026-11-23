#!/usr/bin/env python3
"""Validate original Linux IPv6 VLANs with independent host VLAN peers."""
import argparse
import atexit
from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile

from dpdk_runtime import private_runtime_environment

PAYLOAD = b'native-ipv6\0'
IPV4_FINAL_ACK = b'native-vlan-final-ack\0'
DATAGRAM = bytes((i * 17 + 3) % 256 for i in range(1452))
ADDRESSES = ((100, '2001:db8:100::2'), (100, '2001:db8:100::3'), (200, '2001:db8:200::2'))
VLANS = ('100=198.19.100.2/24,2001:db8:100::2/64,2001:db8:100::3/128', '200=2001:db8:200::2/64')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ip(*args):
    subprocess.run(['ip', *args], check=True)


def receive(peer):
    result = b''
    while len(result) < len(PAYLOAD):
        part = peer.recv(len(PAYLOAD) - len(result))
        require(part, 'unexpected TCP EOF')
        result += part
    require(result == PAYLOAD, 'TCP payload changed')


def checksum(data):
    data += bytes(len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def wrong_frame(destination, source, tag, port):
    payload = b'wrong-vlan-must-not-be-delivered'
    src = socket.inet_pton(socket.AF_INET6, '2001:db8:100::1')
    dst = socket.inet_pton(socket.AF_INET6, '2001:db8:100::2')
    udp = struct.pack('!HHHH', 29099, port, len(payload) + 8, 0) + payload
    pseudo = src + dst + struct.pack('!I3xB', len(udp), 17)
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
    ethernet = destination + source
    ethernet += struct.pack('!HHH', 0x8100, tag, 0x86dd) if tag is not None else b'\x86\xdd'
    return ethernet + struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 64, src, dst) + udp


def capture_check(directory):
    for direction in ('tx', 'rx'):
        full, wrong, full_positions, wrong_positions = set(), set(), [], []
        position = 0
        for path in sorted(directory.glob('ker-' + direction + '-*.pcap')):
            data = path.read_bytes()
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            offset = 24
            while offset < len(data):
                _, _, count, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + count]; offset += count
                position += 1
                require(len(frame) == count == original, 'truncated IPv6 VLAN wire evidence')
                if b'wrong-vlan-must-not-be-delivered' in frame:
                    wrong_positions.append(position)
                    wrong.add(struct.unpack('!H', frame[14:16])[0] & 4095 if frame[12:14] == b'\x81\x00' else None)
                if (len(frame) == 1518 and frame[12:14] == b'\x81\x00' and
                        frame[16:18] == b'\x86\xdd' and frame[24] == 17):
                    tag = struct.unpack('!H', frame[14:16])[0] & 4095
                    udp = frame[58:]
                    pseudo = frame[26:58] + struct.pack('!I3xB', len(udp), 17)
                    require(frame[64:66] != b'\0\0' and checksum(pseudo + udp) == 0, 'invalid IPv6 UDP checksum')
                    require(udp[8:] == DATAGRAM, 'tagged IPv6 UDP payload changed')
                    full_positions.append(position); full.add(tag)
        require(full == {100, 200}, f'{direction}: missing full-sized IPv6 VLAN packets {full}')
        if direction == 'rx':
            require({200, 300, None} <= wrong, 'negative frames did not reach DPDK RX')
            require(max(wrong_positions) < min(full_positions), 'negative probes arrived after valid UDP')


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
    runtime = tempfile.TemporaryDirectory(prefix='ker-ipv6-vlan-runtime-')
    atexit.register(runtime.cleanup)
    env = private_runtime_environment(Path(runtime.name) / 'dpdk')
    env['KER_NATIVE_VLANS'] = '300=2001:db8:300::2/64'
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    for name in ('kerhost', 'kerlink'):
        ip('link', 'set', name, 'up')
    for tag in (100, 200):
        name = f'kerhost.{tag}'
        ip('link', 'add', 'link', 'kerhost', 'name', name, 'type', 'vlan', 'id', str(tag))
        ip('-6', 'addr', 'add', f'2001:db8:{tag}::1/64', 'dev', name, 'nodad')
        ip('link', 'set', name, 'up')
    ip('addr', 'add', '198.19.100.1/24', 'dev', 'kerhost.100')
    host_mac = bytes.fromhex(json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'kerhost']))[0]['address'].replace(':', ''))
    cpu = min(os.sched_getaffinity(0))
    eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    base = [sys.executable, str(args.launcher), '--library', str(args.library), '--io-worker', str(args.worker),
            '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal, '--no-all-multicast']
    with tempfile.TemporaryDirectory(prefix='ker-ipv6-vlan-') as directory:
        root = Path(directory)
        config = root / 'vlans.ini'
        config.write_text(''.join(f'[vlan.{value.split("=", 1)[0]}]\naddresses={value.split("=", 1)[1]}\n' for value in VLANS))
        for n, mode in enumerate(('ini-large', 'cli-scatter')):
            stats, capture = root / (mode + '.json'), root / mode
            capture.mkdir()
            # Each profile starts a fresh TAP endpoint but reuses this host
            # VLAN. Discard the previous endpoint's dynamic ARP entry so the
            # host resolves the current endpoint through normal ARP.
            ip('-4', 'neigh', 'flush', 'dev', 'kerhost.100')
            options = ['--config', str(config)]
            if mode == 'cli-scatter':
                override = root / 'override.ini'; override.write_text('[vlan.300]\naddresses=2001:db8:300::2/64\n')
                options = ['--config', str(override), '--mbuf-mode', 'scatter', '--vlan', VLANS[0], '--vlan', VLANS[1]]
            port = 28500 + n * 2
            command = [*base, *options, '--stats', str(stats), '--pcap-dir', str(capture)]
            with ExitStack() as stack:
                listeners, datagrams = {}, {}
                for tag in (100, 200):
                    listener = stack.enter_context(socket.socket(socket.AF_INET6))
                    datagram = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
                    for peer in (listener, datagram):
                        peer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        peer.bind((f'2001:db8:{tag}::1', port + 1)); peer.settimeout(8)
                    listener.listen(2); listeners[tag] = listener; datagrams[tag] = datagram
                log = stack.enter_context((root / (mode + '.log')).open('w+'))
                process = subprocess.Popen([*command, '--', str(args.app), str(port)], env=env,
                                           stdout=subprocess.PIPE, stderr=log, text=True)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        require(selector.select(25), 'IPv6 VLAN startup timeout')
                    response = process.stdout.readline().strip()
                    require(response.startswith('READY '), 'IPv6 VLAN setup failed: ' + response)
                    worker_mac = bytes.fromhex(response.split()[1].replace(':', ''))
                    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
                        raw.bind(('kerhost', 0))
                        for tag in (200, 300, None):
                            frame = wrong_frame(worker_mac, host_mac, tag, port)
                            require(raw.send(frame) == len(frame), 'negative frame send failed')
                    for tag, address in ADDRESSES:
                        with socket.socket(socket.AF_INET6) as peer:
                            peer.settimeout(8); peer.connect((address, port)); peer.sendall(PAYLOAD); receive(peer)
                        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as peer:
                            peer.settimeout(8); peer.connect((address, port)); peer.send(DATAGRAM)
                            require(peer.recv(1600) == DATAGRAM, 'IPv6 VLAN UDP echo changed')
                        peer, source = listeners[tag].accept()
                        with peer:
                            peer.settimeout(8); require(source[0] == address, 'native TCP source changed')
                            receive(peer); peer.sendall(PAYLOAD)
                        packet, source = datagrams[tag].recvfrom(1600)
                        require(source[0] == address and packet == DATAGRAM, 'native UDP source/payload changed')
                        datagrams[tag].sendto(packet, source)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
                        peer.settimeout(8); peer.connect(('198.19.100.2', port)); peer.send(PAYLOAD)
                        require(peer.recv(256) == PAYLOAD, 'mixed IPv4 VLAN traffic failed')
                        peer.send(IPV4_FINAL_ACK)
                    output = process.communicate(timeout=20)[0]
                    require(process.returncode == 0 and 'PASS:' in output, 'native app failed: ' + output)
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'], 'worker traffic/reclamation missing')
                    require(record['native']['active_opens'] == 3 and record['native']['passive_opens'] == 3 and
                            record['native']['udp6_in_datagrams'] == 6 and record['native']['udp6_out_datagrams'] == 6 and
                            record['native']['udp_in_datagrams'] == 2, 'traffic bypassed original Linux: ' + str(record))
                    neighbors = json.loads(subprocess.check_output(
                        ['ip', '-j', '-4', 'neigh', 'show', 'to', '198.19.100.2', 'dev', 'kerhost.100']))
                    require(any(entry.get('lladdr', '').lower() == record['io']['mac'].lower()
                                for entry in neighbors),
                            'host IPv4 ARP did not resolve the current native endpoint: ' + str(neighbors))
                    for tag, address in ADDRESSES:
                        neighbors = json.loads(subprocess.check_output(['ip', '-j', '-6', 'neigh', 'show', 'dev', f'kerhost.{tag}']))
                        require(any(p.get('dst') == address and p.get('lladdr', '').lower() == record['io']['mac'].lower()
                                    for p in neighbors), 'host VLAN NDP failed: ' + address)
                    capture_check(capture)
                    print('PASS: ' + mode + ' IPv6 VLAN/VIP TCP/UDP, metadata, NDP, wire tags/checksums and mixed IPv4', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    print(f'native process return code: {process.poll()}', file=sys.stderr)
                    print('native stats: ' + (stats.read_text() if stats.exists() else '<not written>'), file=sys.stderr)
                    try:
                        neighbors = subprocess.check_output(
                            ['ip', '-j', '-4', 'neigh', 'show', 'dev', 'kerhost.100'], text=True).strip()
                        link_stats = subprocess.check_output(
                            ['ip', '-s', 'link', 'show', 'dev', 'kerhost.100'], text=True).strip()
                        print('IPv4 VLAN neighbor state: ' + neighbors, file=sys.stderr)
                        print('IPv4 VLAN link counters:\n' + link_stats, file=sys.stderr)
                    except subprocess.SubprocessError as diagnostic_error:
                        print('IPv4 VLAN diagnostics failed: ' + str(diagnostic_error), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait()
        maximum = root / 'max.ini'
        maximum_values = [f'{tag}=' + ','.join(
            f'2001:db8:1234:5678:9abc:def0:{tag:x}:{i:x}/128' for i in range(2, 10)) for tag in range(100, 116)]
        maximum.write_text(''.join(f'[vlan.{value.split("=", 1)[0]}]\naddresses={value.split("=", 1)[1]}\n'
                                   for value in maximum_values))
        require(len(';'.join(maximum_values)) > 4096, 'maximum profile did not exercise expanded serialized bound')
        for name, options, app_args in (
                ('max', ['--config', str(maximum)], ['max']),
                ('duplicate', ['--vlan', '100=198.19.100.2/24,2001:db8:100::2/64,2001:db8:100::1/128'], ['28510'])):
            stats = root / (name + '.json')
            result = subprocess.run([*base, *options, '--stats', str(stats), '--', str(args.app), *app_args],
                                    env=env, capture_output=True, text=True, timeout=30)
            if name == 'max':
                require(result.returncode == 0 and 'PASS:' in result.stdout, 'maximum IPv6 VLANs failed: ' + result.stderr)
            else:
                require(result.returncode == 125 and 'VLAN configuration' in result.stderr and 'READY' not in result.stdout,
                        'duplicate IPv6 VLAN reached main: ' + result.stderr)
            require(json.loads(stats.read_text())['outstanding'] == 0, name + ': worker leaked buffers')
            print('PASS: ' + name + ' IPv6 VLAN startup and cleanup', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
