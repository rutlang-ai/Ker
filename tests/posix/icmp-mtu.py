#!/usr/bin/env python3
"""Execute the static ICMP scenarios from F-Stack's manual MTU checklist."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import importlib.util
spec = importlib.util.spec_from_file_location('network6', Path(__file__).with_name('udp-network6.py'))
network6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network6)
require, ready, checksum, stop = network6.require, network6.ready, network6.checksum, network6.stop


def validate_ipv4_flags(flags, echo_request=False):
    require(not flags & 0x3fff, 'fragmented IPv4 echo')
    if echo_request:
        require(flags & 0x4000, 'IPv4 echo request missing DF')


def wire(directory, mtu):
    df_requests = {}
    for direction in ('tx', 'rx'):
        seen = set()
        request_count = 0
        for path in directory.glob('ker-' + direction + '-*.pcap'):
            data = path.read_bytes()
            require(len(data) >= 24, 'short PCAP header')
            endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
            require(struct.unpack_from(endian + 'I', data, 20)[0] == 1, 'not Ethernet')
            offset = 24
            while offset < len(data):
                require(offset + 16 <= len(data), 'short PCAP record')
                _, _, size, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + size]; offset += size
                require(len(frame) == size == original, 'truncated capture')
                if len(frame) < 34:
                    continue
                packet = frame[14:]
                if frame[12:14] == b'\x08\x00' and packet[9] == 1:
                    header = (packet[0] & 15) * 4
                    total = int.from_bytes(packet[2:4], 'big')
                    flags = int.from_bytes(packet[6:8], 'big')
                    validate_ipv4_flags(flags)
                    require(total <= mtu and checksum(packet[:header]) == 65535, 'bad IPv4 header')
                    icmp = packet[header:total]
                    family, pseudo = 4, b''
                elif frame[12:14] == b'\x86\xdd' and packet[6] == 58:
                    total = 40 + int.from_bytes(packet[4:6], 'big')
                    icmp = packet[40:total]
                    family = 6
                    pseudo = packet[8:40] + struct.pack('!I3xB', len(icmp), 58)
                else:
                    continue
                if len(icmp) < 8 or icmp[0] not in (0, 8, 128, 129) or icmp[4:6] != b'KE':
                    continue
                if family == 4 and icmp[0] == 8:
                    validate_ipv4_flags(flags, echo_request=True)
                    request_count += 1
                require(icmp[1] == 0 and checksum(pseudo + icmp) == 65535, 'bad ICMP checksum')
                sequence = int.from_bytes(icmp[6:8], 'big')
                require(sequence in (0, 1, 2), 'bad sequence')
                payload_size = (0, 1, mtu - (28 if family == 4 else 48))[sequence]
                require(len(icmp) == payload_size + 8, 'bad ICMP size')
                require(icmp[8:] == bytes((i * 17 + sequence) & 255 for i in range(8, len(icmp))),
                        'wire payload corrupted')
                if sequence == 2:
                    require(total == mtu and size == mtu + 14, 'missing full MTU Ethernet frame')
                seen.add((family, icmp[0], sequence))
        expected = {(family, kind, seq) for family, kinds in ((4, (0, 8)), (6, (128, 129)))
                    for kind in kinds for seq in range(3)}
        require(seen == expected, direction + ': missing requests/replies: ' + str(expected - seen))
        require(request_count == 3, direction + ': expected three captured IPv4 echo requests')
        df_requests[direction] = request_count
    return df_requests


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
    for command in (
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad'],
        ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up']):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    with tempfile.TemporaryDirectory(prefix='ker-icmp-mtu-') as directory:
        root = Path(directory)
        for mtu, mode in ((1500, 'large'), (9000, 'large'), (9000, 'scatter')):
            name = str(mtu) + '-' + mode
            for interface in ('kerhost', 'kerlink'):
                subprocess.run(['ip', 'link', 'set', interface, 'mtu', str(mtu)], check=True)
            subprocess.run(['ip', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            subprocess.run(['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            stats, capture = root / (name + '.json'), root / (name + '-pcap')
            capture.mkdir()
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--address6', '2001:db8:1::2/64', '--port', 'net_tap0', '--eal', eal,
                '--mtu', str(mtu), '--max-mtu', '9000', '--mbuf-mode', mode,
                '--stats', str(stats), '--pcap-dir', str(capture), '--pcap-snaplen', '65535',
                '--', str(args.app), 'native', str(mtu), '198.18.0.1', '2001:db8:1::1']
            with (root / (name + '.log')).open('w+') as log:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=log, text=True)
                try:
                    ready(process)
                    peer = subprocess.run([str(args.app), 'peer', str(mtu), '198.18.0.2',
                        '2001:db8:1::2'], capture_output=True, text=True, timeout=20)
                    require(peer.returncode == 0 and peer.stdout.count('PASS:') == 2,
                            'host-to-native echo failed: ' + peer.stdout + peer.stderr)
                    output, _ = process.communicate('G', timeout=25)
                    require(process.returncode == 0 and output.count('PASS:') == 2,
                            'native-to-host echo failed: ' + output)
                    record = json.loads(stats.read_text())
                    require(record['tx'] > 0 and record['rx'] > 0 and record['outstanding'] == 0,
                            'missing DPDK traffic or leaked buffers')
                    require(record['io']['mtu'] == mtu and record['io']['mbuf_mode'] == mode,
                            'worker ignored MTU/buffer mode')
                    if mtu == 9000 and mode == 'scatter':
                        require(record['tx_multiseg'] > 0 and record['rx_multiseg'] > 0,
                                'jumbo did not use TX/RX mbuf chains')
                    elif mode == 'large':
                        require(record['tx_multiseg'] == record['rx_multiseg'] == 0,
                                'large mode unexpectedly used chains')
                    df_requests = wire(capture, mtu)
                    print('PASS: ' + name + ' bidirectional IPv4/IPv6 ICMP, DF on captured IPv4 echo requests '
                          + str(df_requests) + ', full frames/checksums, zero leaks', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    stop(process)
    return 0


if __name__ == '__main__':
    sys.exit(main())
