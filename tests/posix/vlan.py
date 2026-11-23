#!/usr/bin/env python3
"""Original Linux 802.1Q over real DPDK, with an independent host VLAN peer."""
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


def ip(*args):
    subprocess.run(['ip', *args], check=True)


def checksum(data):
    data += bytes(len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def wrong_frame(destination, source, tag):
    payload = b'wrong-vlan-must-not-be-delivered'
    src, dst = socket.inet_aton('198.19.100.1'), socket.inet_aton('198.19.100.2')
    udp = struct.pack('!HHHH', 29099, 29100, len(payload) + 8, 0) + payload
    pseudo = src + dst + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    ethernet = destination + source
    ethernet += struct.pack('!HHH', 0x8100, tag, 0x0800) if tag is not None else b'\x08\x00'
    return ethernet + header + udp


def capture_check(directory):
    for direction in ('tx', 'rx'):
        full, wrong, full_positions, wrong_positions = set(), set(), [], []
        position = 0
        for path in directory.glob('ker-' + direction + '-*.pcap'):
            data = path.read_bytes()
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            offset = 24
            while offset < len(data):
                _, _, count, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + count]; offset += count
                position += 1
                require(len(frame) == count == original, 'truncated VLAN wire evidence')
                if b'wrong-vlan-must-not-be-delivered' in frame:
                    wrong_positions.append(position)
                    wrong.add(struct.unpack('!H', frame[14:16])[0] & 4095 if frame[12:14] == b'\x81\x00' else None)
                if frame[12:14] == b'\x81\x00' and frame[16:18] == b'\x08\x00':
                    tag = struct.unpack('!H', frame[14:16])[0] & 4095
                    if len(frame) == 1518 and frame[27] == 17:
                        require(checksum(frame[18:38]) == 0, 'invalid tagged IPv4 checksum')
                        udp = frame[38:]
                        pseudo = frame[30:38] + struct.pack('!BBH', 0, 17, len(udp))
                        require(checksum(pseudo + udp) == 0, 'invalid tagged UDP checksum')
                        require(struct.unpack_from('!H', frame, 24)[0] & 0x3fff == 0, 'unexpected VLAN fragmentation')
                        full_positions.append(position)
                        full.add(tag)
        require(full == {100, 200}, f'{direction}: missing full-size tagged packets {full}')
        if direction == 'rx':
            require(wrong_positions and max(wrong_positions) < min(full_positions), 'negative VLAN probes were not received before the valid UDP traffic')
            require({200, 300, None} <= wrong, 'negative VLAN probes did not cross the DPDK receive path')


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
    ip('link', 'set', 'lo', 'up')
    ip('link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink')
    for name in ('kerhost', 'kerlink'):
        ip('link', 'set', name, 'up')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    for tag in (100, 200):
        ip('link', 'add', 'link', 'kerhost', 'name', f'kerhost.{tag}', 'type', 'vlan', 'id', str(tag))
        ip('addr', 'add', f'198.19.{tag}.1/24', 'dev', f'kerhost.{tag}')
        ip('link', 'set', f'kerhost.{tag}', 'up')
    host_mac = bytes.fromhex(json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'kerhost']))[0]['address'].replace(':', ''))
    cpu = min(os.sched_getaffinity(0))
    eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    with tempfile.TemporaryDirectory(prefix='ker-vlan-') as directory:
        root = Path(directory)
        config = root / 'vlans.ini'
        config.write_text('[vlan.100]\naddresses=198.19.100.2/24,198.19.100.3/24,198.19.100.4/24,198.19.100.5/24\n[vlan.200]\naddresses=198.19.200.2/24\n')
        omitted = subprocess.run([sys.executable, str(args.launcher), '--library', str(args.library),
                                  '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                                  '--port', 'net_tap0', '--eal', eal, '--', str(args.app), 'ker', 'absent'],
                                 capture_output=True, text=True, timeout=25,
                                 env=dict(os.environ, KER_NATIVE_VLANS='300=192.0.2.30/24'))
        require(omitted.returncode == 0 and 'PASS:' in omitted.stdout,
                'ambient VLAN configuration was accepted: ' + omitted.stdout + omitted.stderr)
        for mode in ('ini-large', 'cli-scatter'):
            stats, capture = root / (mode + '.json'), root / mode
            capture.mkdir()
            options = ['--config', str(config)]
            if mode == 'cli-scatter':
                # An unrelated INI VLAN must be replaced, not appended.
                override = root / 'override.ini'; override.write_text('[vlan.100]\naddresses=192.0.2.2/24\n')
                options = ['--config', str(override), '--vlan', '100=198.19.100.2/24,198.19.100.3/24,198.19.100.4/24,198.19.100.5/24',
                           '--vlan', '200=198.19.200.2/24', '--mbuf-mode', 'scatter']
            command = [sys.executable, str(args.launcher), '--library', str(args.library), '--io-worker', str(args.worker),
                       '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal, *options,
                       '--stats', str(stats), '--pcap-dir', str(capture), '--pcap-snaplen', '10000', '--', str(args.app), 'ker']
            with (root / (mode + '.log')).open('w+') as log:
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True,
                                           env=dict(os.environ, KER_NATIVE_VLANS='300=192.0.2.30/24'))
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        require(selector.select(25), 'VLAN native startup timeout')
                    response = process.stdout.readline().strip()
                    require(response.startswith('READY '), 'native VLAN setup failed: ' + response)
                    worker_mac = bytes.fromhex(response.split()[1].replace(':', ''))
                    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
                        raw.bind(('kerhost', 0))
                        for tag in (200, 300, None):
                            packet = wrong_frame(worker_mac, host_mac, tag)
                            require(raw.send(packet) == len(packet), 'negative VLAN send failed')
                    for slot, (tag, host) in enumerate(((100, 2), (100, 3), (100, 4), (100, 5), (200, 2))):
                        address = f'198.19.{tag}.{host}'
                        message = f'vlan-{tag}-slot-{slot}'.encode()
                        with socket.create_connection((address, 29100 + slot), timeout=5) as tcp:
                            tcp.sendall(message)
                            received = b''
                            while len(received) < len(message):
                                part = tcp.recv(len(message) - len(received))
                                require(part, 'tagged TCP premature EOF')
                                received += part
                            require(received == message, 'tagged TCP payload mismatch')
                        payload = bytes((i * 17 + slot) % 256 for i in range(1472))
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                            udp.settimeout(5); udp.connect((address, 29100 + slot)); udp.send(payload)
                            require(udp.recv(1600) == payload, 'tagged UDP payload mismatch')
                    output = process.communicate(timeout=20)[0]
                    require(process.returncode == 0 and 'PASS:' in output, 'native VLAN app failed: ' + output)
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['tx'] and record['rx'] and
                            record['native']['udp_in_datagrams'] == 5 and record['native']['udp_out_datagrams'] == 5 and
                            record['native']['passive_opens'] == 5, 'VLAN traffic bypassed original kernel or leaked buffers: ' + str(record))
                    capture_check(capture)
                    print('PASS: ' + mode + ', dual VLAN/VIP TCP+UDP, full tags/checksums, device isolation and cleanup', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=10)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
    return 0


if __name__ == '__main__':
    sys.exit(main())
