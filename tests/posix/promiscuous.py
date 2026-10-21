#!/usr/bin/env python3
"""Real PMD receive-mode selection and original Linux foreign-MAC rejection."""
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

PAYLOAD = b'native-mac-only\0'
FOREIGN = b'foreign-mac-must-not-reach-socket'


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


def packet_frame(destination, source, port, sequence, payload):
    src, dst = socket.inet_aton('198.18.0.1'), socket.inet_aton('198.18.0.2')
    udp = struct.pack('!HHHH', 29899, port, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), sequence, 0, 64, 17, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return destination + source + b'\x08\x00' + header + udp


def check_capture(directory, enabled):
    foreign, valid, positions = [], [], 0
    for path in sorted(directory.glob('ker-rx-*.pcap')):
        data = path.read_bytes()
        endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
        offset = 24
        while offset < len(data):
            _, _, count, original = struct.unpack_from(endian + 'IIII', data, offset)
            offset += 16
            frame = data[offset:offset + count]; offset += count
            positions += 1
            require(len(frame) == count == original, 'truncated PMD receive evidence')
            if FOREIGN in frame:
                ip_packet = frame[14:]
                ihl = (ip_packet[0] & 15) * 4
                udp = ip_packet[ihl:]
                pseudo = ip_packet[12:20] + struct.pack('!BBH', 0, 17, len(udp))
                require(checksum(ip_packet[:ihl]) == 0 and checksum(pseudo + udp) == 0,
                        'foreign probe checksum invalid')
                foreign.append(positions)
            if PAYLOAD in frame:
                valid.append(positions)
    require(valid, 'no valid traffic crossed PMD RX')
    require(len(foreign) == (3 if enabled else 0), f'foreign MAC PMD admission mismatch: {foreign}')
    if enabled:
        require(max(foreign) < min(valid), 'foreign probes did not precede valid socket traffic')


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
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'kerhost')
    for name in ('kerhost', 'kerlink'):
        ip('link', 'set', name, 'up')
    host_mac = bytes.fromhex(json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'kerhost']))[0]['address'].replace(':', ''))
    cpu = min(os.sched_getaffinity(0))
    eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink'
    with tempfile.TemporaryDirectory(prefix='ker-promiscuous-') as directory:
        root = Path(directory)
        for index, (name, ini, cli, expected) in enumerate((
                ('omitted', None, [], False), ('ini-on', True, [], True),
                ('cli-off', True, ['--no-promiscuous'], False), ('ini-off', False, [], False),
                ('cli-on', False, ['--promiscuous'], True))):
            config, stats, capture = root / (name + '.ini'), root / (name + '.json'), root / name
            capture.mkdir()
            config.write_text('' if ini is None else '[dpdk]\npromiscuous=' + str(int(ini)) + '\n')
            port = 29800 + index
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0',
                '--eal', eal, '--config', str(config), *cli, '--stats', str(stats), '--pcap-dir', str(capture),
                '--', str(args.app), str(port)]
            with (root / (name + '.log')).open('w+') as log:
                app = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(app.stdout, selectors.EVENT_READ)
                        require(selector.select(20), 'promiscuous startup timeout')
                    response = app.stdout.readline().strip()
                    require(response.startswith('READY '), 'application did not become ready: ' + response)
                    worker_mac = bytes.fromhex(response.split()[1].replace(':', ''))
                    other_mac = bytes([worker_mac[0] ^ 2]) + worker_mac[1:-1] + bytes([worker_mac[-1] ^ 1])
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, \
                            socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as raw:
                        udp.settimeout(8); udp.bind(('198.18.0.1', 29899)); udp.connect(('198.18.0.2', port))
                        raw.bind(('kerhost', 0))
                        for sequence in range(3):
                            frame = packet_frame(other_mac, host_mac, port, sequence, FOREIGN + bytes([sequence]))
                            require(raw.send(frame) == len(frame), 'foreign probe send failed')
                        # The same packet builder with the native destination MAC
                        # must reach UDP: malformed raw frames cannot explain a drop.
                        frame = packet_frame(worker_mac, host_mac, port, 3, PAYLOAD)
                        require(raw.send(frame) == len(frame), 'native-MAC control send failed')
                        require(udp.recv(256) == PAYLOAD, 'UDP admission/payload changed')
                    with socket.socket(socket.AF_INET) as tcp:
                        tcp.settimeout(8); tcp.connect(('198.18.0.2', port)); tcp.sendall(PAYLOAD)
                        packet = b''
                        while len(packet) < len(PAYLOAD):
                            part = tcp.recv(len(PAYLOAD) - len(packet))
                            require(part, 'unexpected TCP EOF'); packet += part
                        require(packet == PAYLOAD, 'TCP payload changed')
                    output = app.communicate(timeout=20)[0]
                    require(app.returncode == 0 and 'PASS:' in output, 'native MAC admission failed: ' + output)
                    record = json.loads(stats.read_text())
                    require(record['io']['promiscuous'] is expected, 'PMD state readback mismatch')
                    require(record['outstanding'] == 0 and record['native']['passive_opens'] == 1 and
                            record['native']['udp_in_datagrams'] == 1 and record['native']['udp_out_datagrams'] == 1,
                            'missing original-kernel traffic or leaked packets')
                    check_capture(capture, expected)
                    print('PASS: ' + name + ' PMD state, foreign MAC boundary, TCP/UDP and cleanup', flush=True)
                except Exception:
                    log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    if app.poll() is None:
                        app.terminate()
                        try:
                            app.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            app.kill(); app.wait()
    return 0


if __name__ == '__main__':
    sys.exit(main())
