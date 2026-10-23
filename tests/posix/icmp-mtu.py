#!/usr/bin/env python3
"""Execute the static ICMP scenarios from F-Stack's manual MTU checklist."""
import argparse
import json
import os
import re
import resource
import signal
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


def wire(directory, mtu, dynamic=False, ceiling=False):
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
                    require(checksum(packet[:header]) == 65535, 'bad IPv4 header')
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
                require(sequence in range(9 if dynamic else 3), 'bad sequence')
                phase, probe = divmod(sequence, 3)
                frame_mtu = (1500 if ceiling else (1500, 9000, 1500)[phase]) if dynamic else mtu
                payload_size = (0, 1, frame_mtu - (28 if family == 4 else 48))[probe]
                require(total <= frame_mtu and len(icmp) == payload_size + 8, 'bad ICMP size')
                require(icmp[8:] == bytes((i * 17 + probe) & 255 for i in range(8, len(icmp))),
                        'wire payload corrupted')
                if probe == 2:
                    require(total == frame_mtu and size == frame_mtu + 14, 'missing full MTU Ethernet frame')
                seen.add((family, icmp[0], sequence))
        expected = {(family, kind, seq) for family, kinds in ((4, (0, 8)), (6, (128, 129)))
                    for kind in kinds for seq in range(9 if dynamic else 3)}
        require(seen == expected, direction + ': missing requests/replies: ' + str(expected - seen))
        require(request_count == (9 if dynamic else 3),
                direction + ': expected three IPv4 echo requests per MTU phase')
        df_requests[direction] = request_count
    return df_requests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--dynamic', action='store_true')
    parser.add_argument('--failure-library', type=Path)
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app'):
            command += ['--' + name, str(getattr(args, name).resolve())]
        if args.dynamic:
            require(args.failure_library and args.failure_library.is_file(), 'missing PMD failure fixture')
            command += ['--dynamic', '--failure-library', str(args.failure_library.resolve())]
        return subprocess.run(command).returncode
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
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
        profiles = ((1500, 'large', ''), (1500, 'scatter', ''), (1500, 'large', 'before'), (1500, 'large', 'after'), (1500, 'large', 'rollback'), (1500, 'large', 'read-error'), (1500, 'large', 'read-mismatch'), (1500, 'large', 'rollback-read-error'), (1500, 'large', 'rollback-read-mismatch'), (1500, 'large', 'ceiling')) if args.dynamic else ((1500, 'large', ''), (9000, 'large', ''), (9000, 'scatter', ''))
        for mtu, mode, failure in profiles:
            name = str(mtu) + '-' + mode + ('-' + failure if failure else '')
            injected = failure in ('before', 'after', 'rollback', 'read-error', 'read-mismatch',
                                   'rollback-read-error', 'rollback-read-mismatch')
            readback_fault = failure in ('read-error', 'read-mismatch', 'rollback-read-error', 'rollback-read-mismatch')
            ceiling = failure == 'ceiling'
            for interface in ('kerhost', 'kerlink'):
                subprocess.run(['ip', 'link', 'set', interface, 'mtu', str(mtu)], check=True)
            subprocess.run(['ip', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            subprocess.run(['ip', '-6', 'neigh', 'flush', 'dev', 'kerhost'], check=True)
            stats, capture = root / (name + '.json'), root / (name + '-pcap')
            capture.mkdir()
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--address6', '2001:db8:1::2/64', '--port', 'net_tap0', '--eal', eal,
                '--mtu', str(mtu), '--max-mtu', '1500' if ceiling else '9000', '--mbuf-mode', mode,
                '--stats', str(stats), '--pcap-dir', str(capture), '--pcap-snaplen', '65535',
                '--', str(args.app), ('dynamic-fault' if readback_fault else ('dynamic-reject' if injected else ('dynamic-ceiling' if ceiling else 'dynamic'))) if args.dynamic else 'native', str(mtu), '198.18.0.1', '2001:db8:1::1']
            with (root / (name + '.log')).open('w+') as log:
                environment = dict(os.environ)
                environment.pop('KER_TEST_MTU_FAILURE', None)
                if injected:
                    environment['KER_TEST_MTU_FAILURE'] = failure
                    environment['LD_PRELOAD'] = str(args.failure_library) + ':' + environment.get('LD_PRELOAD', '')
                process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=log, text=True)
                try:
                    ready(process)
                    if readback_fault:
                        output, _ = process.communicate(timeout=20)
                        log.flush(); log.seek(0); errors = log.read()
                        injection = ('INJECT: MTU readback error after PMD start generation=' if failure in ('read-error', 'rollback-read-error')
                                     else 'INJECT: MTU readback mismatch after PMD start generation=')
                        injected_at = errors.find(injection)
                        match = re.search(r'generation=(\d+)', errors[injected_at:]) if injected_at >= 0 else None
                        require(process.returncode != 0 and match,
                                'readback ambiguity did not fail the native transaction: ' + output + errors)
                        generation = match.group(1)
                        stopped = errors.find('INJECT: actual PMD stop succeeded generation=' + generation, injected_at)
                        close_record = 'INJECT: PMD close after stop=1 generation=' + generation + ' stopped_generation=' + generation
                        closed = errors.find(close_record)
                        require(stopped > injected_at and closed > stopped,
                                'actual PMD was not stopped successfully before close: ' + errors)
                        record = json.loads(stats.read_text())
                        require(record['outstanding'] == 0,
                                'readback ambiguity leaked actual PMD packet buffers')
                        print('PASS: ' + failure + ' stopped actual PMD before close and freed all buffers', flush=True)
                        continue
                    if failure == 'rollback':
                        process.communicate(timeout=20)
                        log.flush(); log.seek(0); errors = log.read()
                        require(process.returncode in (125, 128 + signal.SIGABRT) and
                                'INJECT: PMD rollback failure' in errors and
                                'MTU device transaction failed' in errors,
                                'ambiguous rollback was not fatal: ' + errors)
                        record = json.loads(stats.read_text())
                        require(record['outstanding'] == 0, 'fatal MTU path leaked mbufs')
                        print('PASS: failed PMD rollback terminates the backend and frees mbufs', flush=True)
                        continue
                    if args.dynamic:
                        if injected:
                            require(process.stdout.readline().strip() == 'ROLLBACK', 'missing rejected MTU transaction')
                            actual = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'kerpeer']))[0]['mtu']
                            require(actual == 1500, 'PMD did not restore actual TAP MTU')
                            process.stdin.write('R'); process.stdin.flush()
                        for phase, phase_mtu in enumerate((1500, 1500, 1500) if ceiling else (1500, 9000, 1500)):
                            require(process.stdout.readline().strip() == f'PHASE {phase} {phase_mtu}',
                                    'native MTU transaction/readback failed')
                            actual = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'kerpeer']))[0]['mtu']
                            require(actual == phase_mtu, 'real TAP PMD interface MTU differs')
                            for interface in ('kerhost', 'kerlink'):
                                subprocess.run(['ip', 'link', 'set', interface, 'mtu', str(phase_mtu)], check=True)
                            peer = subprocess.run([str(args.app), 'peer', str(phase_mtu), '198.18.0.2',
                                '2001:db8:1::2', str(phase)], capture_output=True, text=True, timeout=20)
                            require(peer.returncode == 0 and peer.stdout.count('PASS:') == 2,
                                    'dynamic host-to-native echo failed: ' + peer.stdout + peer.stderr)
                            process.stdin.write('G'); process.stdin.flush()
                            for _ in range(2):
                                require(process.stdout.readline().startswith('PASS:'), 'native dynamic ICMP failed')
                            require(process.stdout.readline().strip() == f'DONE {phase}', 'missing native phase completion')
                            process.stdin.write('N'); process.stdin.flush()
                        output, _ = process.communicate(timeout=20)
                        require(process.returncode == 0, 'dynamic native app failed: ' + output)
                    else:
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
                    if args.dynamic:
                        require(record['mtu_final'] == 1500 and record['mtu_changes'] == (0 if ceiling else 2),
                                'missing live PMD MTU transition evidence')
                    if (mtu == 9000 or args.dynamic) and mode == 'scatter':
                        require(record['tx_multiseg'] > 0 and record['rx_multiseg'] > 0,
                                'jumbo did not use TX/RX mbuf chains')
                    elif mode == 'large':
                        require(record['tx_multiseg'] == record['rx_multiseg'] == 0,
                                'large mode unexpectedly used chains')
                    if injected:
                        log.flush(); log.seek(0)
                        require(log.read().count('INJECT: MTU ' + failure + ' PMD set') == 1,
                                'missing actual PMD failure injection')
                    df_requests = wire(capture, mtu, args.dynamic, ceiling)
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
