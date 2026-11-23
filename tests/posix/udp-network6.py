#!/usr/bin/env python3
"""IPv6 UDP peers over real DPDK Ethernet, including wire fragment checksums."""
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


def ready(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(20), 'server startup timeout')
    response = process.stdout.readline().strip()
    require(response == 'READY' or response.startswith('READY '), 'server failed before READY: ' + response)


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total


def validate_fragments(directory):
    for direction in ('tx', 'rx'):
        fragments, datagrams, count = {}, [], 0
        for path in directory.glob('ker-' + direction + '-*.pcap'):
            data = path.read_bytes()
            require(len(data) >= 24, 'missing PCAP header')
            endian = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
            require(struct.unpack(endian + 'I', data[20:24])[0] == 1, 'capture is not Ethernet')
            offset = 24
            while offset < len(data):
                require(offset + 16 <= len(data), 'short PCAP record')
                _, _, captured, original = struct.unpack(endian + 'IIII', data[offset:offset + 16])
                offset += 16
                frame = data[offset:offset + captured]; offset += captured
                require(len(frame) == captured == original, 'truncated wire capture')
                if len(frame) < 54 or frame[12:14] != b'\x86\xdd':
                    continue
                packet = frame[14:]
                payload_len = struct.unpack('!H', packet[4:6])[0]
                packet = packet[:40 + payload_len]
                source, destination, kind = packet[8:24], packet[24:40], packet[6]
                if kind == 17:
                    datagrams.append((source, destination, packet[40:]))
                elif kind == 44 and packet[40] == 17:
                    count += 1
                    flags, identity = struct.unpack('!HI', packet[42:48])
                    start = flags & 0xfff8
                    parts = fragments.setdefault((source, destination, identity), {'segments': {}, 'end': None})
                    require(start not in parts['segments'], 'duplicate fragment offset')
                    parts['segments'][start] = packet[48:]
                    if not flags & 1:
                        parts['end'] = start + len(packet) - 48
        require(count > 0 and len(fragments) >= 3, f'{direction}: no actual IPv6 fragmentation')
        for (source, destination, _), parts in fragments.items():
            result = b''
            for start, segment in sorted(parts['segments'].items()):
                require(start == len(result), 'wire fragments have a gap/overlap')
                result += segment
            require(parts['end'] == len(result), 'missing final IPv6 fragment')
            datagrams.append((source, destination, result))
        require(len(datagrams) >= 5, f'{direction}: incomplete UDP wire evidence')
        for source, destination, udp in datagrams:
            require(len(udp) >= 8 and udp[6:8] != b'\0\0', 'zero mandatory IPv6 UDP checksum')
            require(struct.unpack('!H', udp[4:6])[0] == len(udp), 'UDP length changed in fragmentation')
            pseudo = source + destination + struct.pack('!I3xB', len(udp), 17)
            require(checksum(pseudo + udp) == 65535, 'invalid IPv6 UDP wire checksum')
    print('PASS: IPv6 fragments reassemble and complete UDP checksums validate in both directions', flush=True)


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
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--ssm4', action='store_true')
    parser.add_argument('--broadcast4', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        if args.ssm4:
            command += ['--ssm4']
        if args.broadcast4:
            command += ['--broadcast4']
        return subprocess.run(command).returncode
    commands = [
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', 'addr', 'add', '198.18.0.3/24', 'dev', 'kerhost'],
        ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'kerhost', 'nodad'],
        ['ip', '-6', 'addr', 'add', '2001:db8:1::3/64', 'dev', 'kerhost', 'nodad'],
        ['ip', 'link', 'set', 'kerhost', 'up'], ['ip', 'link', 'set', 'kerlink', 'up'],
    ]
    for command in commands:
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
           '--iova-mode=va -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink')
    base = [sys.executable, str(args.launcher), '--library', str(args.library), '--io-worker', str(args.worker),
        '--address', '198.18.0.2/24', '--address6', '2001:db8:1::2/64', '--port', 'net_tap0', '--eal', eal]
    scenarios = ('limited',) if args.broadcast4 else ('ssm',) if args.ssm4 else ('ancillary', 'errors', 'fragments', 'segmentation', 'multicast', 'ssm')
    with tempfile.TemporaryDirectory(prefix='ker-udp-network6-') as directory:
        root = Path(directory)
        for scenario in scenarios:
            for native_server in (False, True):
                name = scenario + ('-server' if native_server else '-client')
                subprocess.run(['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
                port, server = 28600, None
                stats, capture = root / (name + '.json'), root / (name + '-pcap')
                capture.mkdir()
                native_options = [*base, '--stats', str(stats), '--pcap-dir', str(capture), '--pcap-snaplen', '2048', '--']
                host_local, native_local = ('198.18.0.1', '198.18.0.2') if args.ssm4 or args.broadcast4 else ('2001:db8:1::1', '2001:db8:1::2')
                def command(native, role):
                    local, remote, ipv4 = (native_local, host_local, '198.18.0.2') if native else (host_local, native_local, '198.18.0.1')
                    app = [str(args.app), role, local, remote, str(port), scenario] if args.ssm4 or args.broadcast4 else [str(args.app), role, local, remote, str(port), scenario, ipv4]
                    return [*native_options, *app] if native else app
                with (root / (name + '.log')).open('w+') as log:
                    try:
                        server = subprocess.Popen(command(native_server, 'server'), stdout=subprocess.PIPE, stderr=log, text=True)
                        ready(server)
                        if scenario == 'ssm':
                            # A real third source must be rejected before the allowed sender.
                            bad_source = ('198.18.0.3' if args.ssm4 else '2001:db8:1::3') if native_server else host_local
                            with socket.socket(socket.AF_INET if args.ssm4 else socket.AF_INET6, socket.SOCK_DGRAM) as bad:
                                index = socket.if_nametoindex('kerhost')
                                if args.ssm4:
                                    bad.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('198.18.0.1'))
                                    destination = ('239.255.42.17', port)
                                else:
                                    bad.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
                                    destination = ('ff3e::114', port, 0, index)
                                bad.bind((bad_source, 0)); bad.sendto(b'\x5a' * 33, destination)
                        client = subprocess.run(command(not native_server, 'client'), capture_output=True, text=True, timeout=35)
                        require(client.returncode == 0 and 'PASS:' in client.stdout,
                                name + ': client failed: ' + client.stdout + client.stderr)
                        output, _ = server.communicate(timeout=15)
                        require(server.returncode == 0 and 'PASS:' in output, name + ': server failed: ' + output)
                        record = json.loads(stats.read_text())
                        require(record['outstanding'] == 0 and record['tx'] and record['rx'], name + ': missing packet/cleanup evidence')
                        prefix = 'udp_' if args.ssm4 or args.broadcast4 else 'udp6_'
                        require(record['native'][prefix + 'in_datagrams'] > 0 and record['native'][prefix + 'out_datagrams'] > 0,
                                name + ': original IPv6 UDP counters missing')
                        if scenario == 'fragments':
                            validate_fragments(capture)
                        print('PASS: UDP network ' + name, flush=True)
                    except Exception:
                        log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                        raise
                    finally:
                        stop(server)
    return 0


if __name__ == '__main__':
    sys.exit(main())
