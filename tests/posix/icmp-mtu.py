#!/usr/bin/env python3
"""Execute the static ICMP scenarios from F-Stack's manual MTU checklist."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


spec = importlib.util.spec_from_file_location('network6', Path(__file__).with_name('udp-network6.py'))
network6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(network6)
require, ready, checksum, stop = network6.require, network6.ready, network6.checksum, network6.stop


def captured_frames(directory, direction):
    magic = {bytes.fromhex('d4c3b2a1'): '<', bytes.fromhex('4d3cb2a1'): '<',
             bytes.fromhex('a1b2c3d4'): '>', bytes.fromhex('a1b23c4d'): '>'}
    for path in directory.glob(f'ker-{direction}-*.pcap'):
        data = path.read_bytes()
        require(len(data) >= 24 and data[:4] in magic, f'invalid PCAP header in {path}')
        endian = magic[data[:4]]
        require(struct.unpack_from(endian + 'I', data, 20)[0] == 1, 'capture is not Ethernet')
        offset = 24
        while offset < len(data):
            require(offset + 16 <= len(data), 'short PCAP record header')
            _, _, size, original = struct.unpack_from(endian + 'IIII', data, offset)
            offset += 16
            require(size == original and offset + size <= len(data), 'truncated capture')
            yield data[offset:offset + size]
            offset += size


def verify_wire(directory, mtu):
    expected = {(family, kind, seq) for family, kinds in ((4, (0, 8)), (6, (128, 129)))
                for kind in kinds for seq in range(3)}
    for direction in ('tx', 'rx'):
        seen = set()
        for frame in captured_frames(directory, direction):
            packet = frame[14:]
            if frame[12:14] == b'\x08\x00' and len(packet) >= 20 and packet[9] == 1:
                family, header = 4, (packet[0] & 15) * 4
                total = int.from_bytes(packet[2:4], 'big')
                pseudo = b''
            elif frame[12:14] == b'\x86\xdd' and len(packet) >= 40 and packet[6] == 58:
                family, header = 6, 40
                total = header + int.from_bytes(packet[4:6], 'big')
                pseudo = packet[8:40] + struct.pack('!I3xB', total - header, 58)
            else:
                continue
            icmp = packet[header:total]
            if len(icmp) < 8 or icmp[4:6] != b'KE':
                continue
            sequence = int.from_bytes(icmp[6:8], 'big')
            key = (family, icmp[0], sequence)
            require(key in expected and key not in seen, f'{direction}: unexpected ICMP probe {key}')
            require(header + 8 <= total <= min(mtu, len(packet)), 'bad IP length')
            if family == 4:
                flags = int.from_bytes(packet[6:8], 'big')
                require(header >= 20 and checksum(packet[:header]) == 65535, 'bad IPv4 header')
                require(not flags & 0x3fff, 'fragmented IPv4 echo')
                if icmp[0] == 8:
                    require(flags & 0x4000, 'ICMPv4 request missing DF')
            require(icmp[1] == 0 and checksum(pseudo + icmp) == 65535, 'bad ICMP checksum')
            payload_size = (0, 1, mtu - (28 if family == 4 else 48))[sequence]
            require(len(icmp) == payload_size + 8, 'bad ICMP size')
            require(icmp[8:] == bytes((i * 17 + sequence) & 255 for i in range(8, len(icmp))),
                    'wire payload corrupted')
            if sequence == 2:
                require(total == mtu and len(frame) == mtu + 14, 'missing full MTU Ethernet frame')
            seen.add(key)
        require(seen == expected, f'{direction}: missing ICMP probes {expected - seen}')


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
            name = f'{mtu}-{mode}'
            for interface in ('kerhost', 'kerlink'):
                subprocess.run(['ip', 'link', 'set', interface, 'mtu', str(mtu)], check=True)
            subprocess.run(['ip', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            subprocess.run(['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            stats, capture = root / (name + '.json'), root / (name + '-pcap')
            capture.mkdir()
            mtu_options = [] if mtu == 1500 else ['--mtu', str(mtu), '--mbuf-mode', mode]
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--address6', '2001:db8:1::2/64', '--port', 'net_tap0', '--eal', eal,
                *mtu_options,
                '--stats', str(stats), '--pcap-dir', str(capture), '--pcap-snaplen', '65535',
                '--', str(args.app), 'native', str(mtu), '198.18.0.1', '2001:db8:1::1']
            with (root / (name + '.log')).open('w+') as log:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=log, text=True)
                try:
                    ready(process)
                    peer = subprocess.run([str(args.app), 'peer', str(mtu), '198.18.0.2',
                        '2001:db8:1::2'], capture_output=True, text=True, timeout=20)
                    require(peer.returncode == 0 and peer.stdout.count('PASS IPv') == 2,
                            'host-to-native echo failed: ' + peer.stdout + peer.stderr)
                    output, _ = process.communicate('G', timeout=25)
                    require(process.returncode == 0 and output.count('PASS IPv') == 2,
                            'native-to-host echo failed: ' + output)
                    record = json.loads(stats.read_text())
                    require(record['tx'] > 0 and record['rx'] > 0 and record['outstanding'] == 0,
                            'missing DPDK traffic or leaked buffers')
                    require(record['io']['mtu'] == mtu and record['io']['mbuf_mode'] == mode,
                            'worker ignored MTU/buffer mode')
                    if mode == 'scatter':
                        require(record['tx_multiseg'] > 0 and record['rx_multiseg'] > 0,
                                'jumbo did not use TX/RX mbuf chains')
                    else:
                        require(record['tx_multiseg'] == record['rx_multiseg'] == 0,
                                'large mode unexpectedly used chains')
                    verify_wire(capture, mtu)
                    print(f'PASS {name} bidirectional IPv4/IPv6 ICMP, full frames and buffer reclamation',
                          flush=True)
                except Exception:
                    log.flush()
                    log.seek(0)
                    print(log.read(), file=sys.stderr)
                    raise
                finally:
                    stop(process)
    return 0


if __name__ == '__main__':
    sys.exit(main())
