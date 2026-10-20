#!/usr/bin/env python3
"""Feed independent malformed/reordered UDP vectors to original Linux over DPDK."""
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


def require(value, message):
    if not value:
        raise RuntimeError(message)


def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(20), 'native wire-vector startup timeout')
    return process.stdout.readline().strip()


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def payload(tag, size=24):
    return bytes([ord(tag)]) + bytes((i * 71) & 255 for i in range(1, size))


def udp(family, data, port, bad=False, zero=False):
    source = socket.inet_pton(socket.AF_INET if family == 4 else socket.AF_INET6,
                             '198.18.0.1' if family == 4 else '2001:db8:1::1')
    destination = socket.inet_pton(socket.AF_INET if family == 4 else socket.AF_INET6,
                                  '198.18.0.2' if family == 4 else '2001:db8:1::2')
    header = struct.pack('!HHHH', 50600, port, 8 + len(data), 0)
    pseudo = source + destination + (struct.pack('!BBH', 0, 17, 8 + len(data)) if family == 4
                                    else struct.pack('!I3xB', 8 + len(data), 17))
    value = checksum(pseudo + header + data) or 65535
    if bad:
        value = (value ^ 1) or 2
    if zero:
        value = 0
    return source, destination, header[:6] + struct.pack('!H', value) + data


def frames(family, source_mac, destination_mac, source, destination, data, identity, fragmented=False):
    ethernet = destination_mac + source_mac + struct.pack('!H', 0x0800 if family == 4 else 0x86dd)
    chunk = (1480 if family == 4 else 1448) if fragmented else len(data)
    result = []
    for start in range(0, len(data), chunk):
        part = data[start:start + chunk]
        more = start + len(part) < len(data)
        if family == 4:
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(part), identity,
                                 (start // 8) | (0x2000 if more else 0), 64, 17, 0, source, destination)
            header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        else:
            header = struct.pack('!IHBB16s16s', 6 << 28, len(part) + (8 if fragmented else 0),
                                 44 if fragmented else 17, 64, source, destination)
            if fragmented:
                header += struct.pack('!BBHI', 17, 0, start | int(more), identity)
        result.append(ethernet + header + part)
    return result


def timeout_on_wire(capture, family):
    for path in capture.glob('ker-tx-*.pcap'):
        data = path.read_bytes(); offset = 24
        endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
        while offset < len(data):
            _, _, length, _ = struct.unpack(endian + 'IIII', data[offset:offset + 16]); offset += 16
            packet = data[offset:offset + length]; offset += length
            if family == 4 and len(packet) >= 36 and packet[12:14] == b'\x08\x00' and packet[23] == 1:
                header = 14 + (packet[14] & 15) * 4
                if packet[header:header + 2] == b'\x0b\x01':
                    return True
            if family == 6 and len(packet) >= 56 and packet[12:14] == b'\x86\xdd' and packet[20] == 58:
                if packet[54:56] == b'\x03\x01':
                    return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('app', 'launcher', 'library', 'worker'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('app', 'launcher', 'library', 'worker'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        return subprocess.run(command).returncode
    for command in (
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad'],
        ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    source_mac = bytes.fromhex(json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'kerhost'], text=True))[0]['address'].replace(':', ''))
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-udp-wire-') as directory:
        root = Path(directory)
        for family in (4, 6):
            stats, capture = root / f'stats{family}.json', root / f'pcap{family}'
            capture.mkdir(); port = 28800 + family
            with (root / f'app{family}.log').open('w+') as log:
                process = subprocess.Popen([sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--address6', '2001:db8:1::2/64',
                    '--port', 'net_tap0', '--eal', eal, '--sysctl', 'net.ipv4.ipfrag_time=1',
                    '--sysctl', 'net.ipv6.ip6frag_time=1', '--stats', str(stats), '--pcap-dir', str(capture),
                    '--pcap-snaplen', '2048', '--', str(args.app), str(family), str(port)],
                    stdout=subprocess.PIPE, stderr=log, text=True)
                try:
                    response = line(process)
                    require(response.startswith('READY '), 'wire receiver did not start')
                    destination_mac = bytes.fromhex(response.split()[1].replace(':', ''))
                    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
                        raw.bind(('kerhost', 0))
                        def send(data, identity, fragmented=False, reverse=False, first_only=False):
                            source, destination, packet = data
                            packets = frames(family, source_mac, destination_mac, source, destination, packet, identity, fragmented)
                            if first_only:
                                packets = packets[:1]
                            if reverse:
                                packets.reverse()
                            for packet in packets:
                                require(raw.send(packet) == len(packet), 'short raw packet send')
                        send(udp(family, payload('B'), port, bad=True), 1)
                        send(udp(family, payload('Z'), port, zero=True), 2)
                        send(udp(family, payload('G'), port), 3)
                        send(udp(family, payload('X', 4096), port), 4, fragmented=True, first_only=True)
                        send(udp(family, payload('F', 4096), port), 5, fragmented=True, reverse=True)
                        for identity, tag in ((6, '2'), (7, '1'), (8, '1')):
                            send(udp(family, payload(tag), port), identity)
                        require(line(process) == 'REASSEMBLED', 'reverse fragments or datagram sequence failed')
                        require(line(process) == 'TIMEOUT_CHECKED', 'incomplete fragment was delivered')
                        send(udp(family, payload('R'), port), 9)
                    output, _ = process.communicate(timeout=15)
                    require(process.returncode == 0 and 'PASS:' in output, 'wire receiver failed: ' + output)
                    record = json.loads(stats.read_text()); native = record['native']
                    require(record['outstanding'] == 0 and record['rx'] >= 10, 'wire packet/cleanup evidence missing')
                    require(native['ip_reasm_ok' if family == 4 else 'ip6_reasm_ok'] >= 1 and
                            native['ip_reasm_fails' if family == 4 else 'ip6_reasm_fails'] >= 1,
                            'original Linux reassembly success/timeout counters missing')
                    require(native['udp_in_errors' if family == 4 else 'udp6_in_errors'] >= (1 if family == 4 else 2),
                            'original Linux checksum drop counters missing')
                    require(timeout_on_wire(capture, family), 'no real ICMP reassembly-timeout response')
                    print(output.strip(), flush=True)
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
