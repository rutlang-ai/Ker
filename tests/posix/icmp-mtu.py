#!/usr/bin/env python3
"""Verify F-Stack MTU scenarios with native and host ICMP peers."""
import argparse
import importlib.util
import json
import os
import selectors
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


def verify_wire(directory, mtus):
    expected = {(family, kind, phase * 4 + probe)
                for family, kinds in ((4, (0, 8)), (6, (128, 129)))
                for kind in kinds for phase in range(len(mtus)) for probe in range(3)}
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
            phase, probe = divmod(sequence, 4)
            mtu = mtus[phase]
            require(header + 8 <= total <= min(mtu, len(packet)), 'bad IP length')
            if family == 4:
                flags = int.from_bytes(packet[6:8], 'big')
                require(header >= 20 and checksum(packet[:header]) == 65535, 'bad IPv4 header')
                require(not flags & 0x3fff, 'fragmented IPv4 echo')
                if icmp[0] == 8:
                    require(flags & 0x4000, 'ICMPv4 request missing DF')
            require(icmp[1] == 0 and checksum(pseudo + icmp) == 65535, 'bad ICMP checksum')
            payload_size = (0, 1, mtu - (28 if family == 4 else 48))[probe]
            require(len(icmp) == payload_size + 8, 'bad ICMP size')
            require(icmp[8:] == bytes((i * 17 + probe) & 255 for i in range(8, len(icmp))),
                    'wire payload corrupted')
            if probe == 2:
                require(total == mtu and len(frame) == mtu + 14, 'missing full MTU Ethernet frame')
            seen.add(key)
        require(seen == expected, f'{direction}: missing ICMP probes {expected - seen}')


def host_link_mtu(mtu):
    for interface in ('kerhost', 'kerlink'):
        subprocess.run(['ip', 'link', 'set', interface, 'mtu', str(mtu)], check=True)


def flush_host_neighbors():
    for family in ('-4', '-6'):
        subprocess.run(['ip', family, 'neigh', 'flush', 'dev', 'kerhost'], check=True)


def verify_tap_mtu(expected):
    result = subprocess.run(['ip', '-j', 'link', 'show', 'dev', 'kerpeer'],
                            check=True, capture_output=True, text=True, timeout=5)
    observed = json.loads(result.stdout)[0]['mtu']
    require(observed == expected, f'TAP MTU {observed}, expected {expected}')


def send_gate(process, command):
    process.stdin.write(command)
    process.stdin.flush()


def expect_line(process, expected):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(15), f'timed out waiting for {expected}')
    received = process.stdout.readline().strip()
    require(received == expected, f'expected {expected!r}, received {received!r}')


def host_echo(app, mtu, phase):
    peer = subprocess.run([str(app), 'peer', str(mtu), '198.18.0.2',
                           '2001:db8:1::2', str(phase)], capture_output=True, text=True, timeout=20)
    require(peer.returncode == 0 and 'PASS IPv4 and IPv6' in peer.stdout,
            'host-to-native echo failed: ' + peer.stdout + peer.stderr)


def verify_stats(record, startup_mtu, mode, mtus):
    require(record['tx'] > 0 and record['rx'] > 0 and record['outstanding'] == 0,
            'missing DPDK traffic or unreclaimed buffers')
    require(record['io']['mtu'] == startup_mtu and record['io']['mbuf_mode'] == mode,
            'worker ignored startup MTU or buffer mode')
    require(record['mtu_final'] == mtus[-1] and record['mtu_changes'] ==
            sum(previous != current for previous, current in zip(mtus, mtus[1:])),
            'worker did not report the expected MTU transitions')
    if mode == 'scatter':
        require(record['tx_multiseg'] > 0 and record['rx_multiseg'] > 0,
                'jumbo did not use TX/RX mbuf chains')
    else:
        require(record['tx_multiseg'] == record['rx_multiseg'] == 0,
                'large mode unexpectedly used chains')


def run_profile(args, root, eal, mtu, mode, scenario):
    name = f'{mtu}-{mode}-{scenario}'
    host_link_mtu(mtu)
    flush_host_neighbors()
    stats, capture = root / (name + '.json'), root / (name + '-pcap')
    capture.mkdir()
    live = scenario != 'static'
    role = 'native' if not live else f'live-{scenario}'
    options = []
    if live:
        options = ['--max-mtu', '1500' if scenario == 'ceiling' else '9000', '--mbuf-mode', mode]
        if mode == 'scatter':
            config = root / 'live-mtu.ini'
            config.write_text('[network]\nlive_mtu = true\n')
            options += ['--config', str(config)]
        else:
            options += ['--live-mtu']
    elif mtu != 1500:
        options = ['--mtu', str(mtu), '--mbuf-mode', mode]
    command = [sys.executable, str(args.launcher), '--library', str(args.library),
               '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
               '--address6', '2001:db8:1::2/64', '--port', 'net_tap0', '--eal', eal,
               *options, '--stats', str(stats), '--pcap-dir', str(capture), '--pcap-snaplen', '65535',
               '--', str(args.app), role, str(mtu), '198.18.0.1', '2001:db8:1::1']
    env = os.environ.copy()
    if scenario in ('rollback', 'fatal'):
        env['LD_PRELOAD'] = ':'.join(filter(None, (env.get('LD_PRELOAD'), str(args.failure_library))))
        env['KER_TEST_MTU_FAILURE'] = scenario

    with (root / (name + '.log')).open('w+') as log:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=log, text=True, env=env)
        try:
            ready(process)
            if scenario == 'fatal':
                process.communicate('G', timeout=20)
                log.seek(0)
                messages = log.read()
                require(process.returncode == 125 and 'INJECT: PMD rejected the rollback' in messages
                        and 'ker: MTU device transaction failed' in messages,
                        'unrecoverable PMD transaction did not stop the backend')
                record = json.loads(stats.read_text())
                require(record['outstanding'] == 0 and record['mtu_changes'] == 0,
                        'fatal MTU transaction reported a commit or retained buffers')
                print('PASS fatal rollback stops the worker and reclaims mbufs', flush=True)
                return
            if live:
                mtus = (1500, 1500 if scenario == 'ceiling' else 9000, 1500)
                send_gate(process, 'G')
                if scenario == 'rollback':
                    expect_line(process, 'ROLLBACK')
                    verify_tap_mtu(1500)
                    send_gate(process, 'N')
                for phase, phase_mtu in enumerate(mtus):
                    expect_line(process, f'PHASE {phase} {phase_mtu}')
                    verify_tap_mtu(phase_mtu)
                    host_link_mtu(phase_mtu)
                    flush_host_neighbors()
                    host_echo(args.app, phase_mtu, phase)
                    send_gate(process, 'G')
                    expect_line(process, f'DONE {phase}')
                    send_gate(process, 'N')
                output, _ = process.communicate(timeout=20)
                require(process.returncode == 0, 'native live echo process failed: ' + output)
            else:
                mtus = (mtu,)
                host_echo(args.app, mtu, 0)
                output, _ = process.communicate('G', timeout=25)
                require(process.returncode == 0 and 'PASS IPv4 and IPv6' in output,
                        'native-to-host echo failed: ' + output)
            verify_stats(json.loads(stats.read_text()), mtu, mode, mtus)
            verify_wire(capture, mtus)
            if scenario == 'rollback':
                log.seek(0)
                require(log.read().count('INJECT: PMD changed MTU before returning EIO') == 1,
                        'expected exactly one recoverable PMD failure')
            print(f'PASS {name} MTUs {mtus}, verified two-way IPv4/IPv6 traffic and buffer reclamation',
                  flush=True)
        except Exception:
            log.flush()
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            stop(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--failure-library', type=Path)
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'failure-library'):
            path = getattr(args, name.replace('-', '_'))
            if path:
                command += ['--' + name, str(path.resolve())]
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
    if args.failure_library:
        profiles = [(1500, 'large', 'change'), (1500, 'scatter', 'change'),
                    (1500, 'large', 'ceiling'), (1500, 'large', 'rollback'), (1500, 'large', 'fatal')]
    else:
        profiles = [(1500, 'large', 'static'), (9000, 'large', 'static'), (9000, 'scatter', 'static')]
    with tempfile.TemporaryDirectory(prefix='ker-icmp-mtu-') as directory:
        for mtu, mode, scenario in profiles:
            run_profile(args, Path(directory), eal, mtu, mode, scenario)
    return 0


if __name__ == '__main__':
    sys.exit(main())
