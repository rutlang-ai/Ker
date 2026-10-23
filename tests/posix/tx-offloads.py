#!/usr/bin/env python3
"""Native virtio TX metadata -> real original TAP PMD -> independent wire capture."""
import argparse
import concurrent.futures
import json
import os
import signal
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading


def require(value, message):
    if not value:
        raise RuntimeError(message)


def launch(command, **options):
    process = subprocess.Popen(command, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, **options)
    try:
        output, errors = process.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, output, errors), process.pid


def folded(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total


def capture(sock, stop, port):
    counts = {'tcp4': 0, 'tcp6': 0, 'udp4': 0, 'udp6': 0}
    coverage = {4: bytearray(512 * 1024), 6: bytearray(512 * 1024)}
    initial = {}
    sock.settimeout(.1)
    while True:
        try:
            frame = sock.recv(65536)
        except socket.timeout:
            if stop.is_set():
                break
            continue
        if frame[12:14] == b'\x08\x00' and frame[26:30] == socket.inet_pton(socket.AF_INET, '198.18.0.2'):
            version, offset = 4, 14 + (frame[14] & 15) * 4
            length, proto = struct.unpack_from('!H', frame, 16)[0], frame[23]
            packet = frame[14:14 + length]
            require(folded(packet[:offset - 14]) == 65535, 'wire IPv4 header checksum')
            payload = frame[offset:14 + length]
            pseudo = frame[26:34] + bytes([0, proto]) + struct.pack('!H', len(payload))
        elif frame[12:14] == b'\x86\xdd' and frame[22:38] == socket.inet_pton(socket.AF_INET6, '2001:db8:1::2'):
            version, offset = 6, 54
            length, proto = struct.unpack_from('!H', frame, 18)[0], frame[20]
            payload = frame[offset:54 + length]
            pseudo = frame[22:54] + struct.pack('!I', len(payload)) + bytes([0, 0, 0, proto])
            length += 40
        else:
            continue
        if proto not in (6, 17) or len(payload) < 8 or struct.unpack_from('!H', payload, 2)[0] != port:
            continue
        require(length <= 1500, 'wire segment exceeds native MTU')
        require(folded(pseudo + payload) == 65535, 'wire TCP/UDP checksum IPv' + str(version))
        if proto == 17:
            require(payload[6:8] != b'\0\0', 'UDP checksum omitted')
        if proto == 6:
            data = payload[(payload[12] >> 4) * 4:]
            if data:
                sequence = struct.unpack_from('!I', payload, 4)[0]
                initial.setdefault(version, sequence)
                relative = (sequence - initial[version]) & 0xffffffff
                require(relative + len(data) <= len(coverage[version]), 'wire TCP sequence range')
                require(data == bytes(((relative + i) * 17 ^ ((relative + i) >> 8) ^ ((relative + i) >> 16) ^ (version == 6)) & 255 for i in range(len(data))),
                        'wire TCP payload differs')
                coverage[version][relative:relative + len(data)] = b'\1' * len(data)
        counts[('tcp' if proto == 6 else 'udp') + str(version)] += 1
    require(all(value.count(1) == 512 * 1024 for value in coverage.values()), 'wire capture missed TCP payload bytes')
    _, drops = struct.unpack('II', sock.getsockopt(263, 6, 8))
    require(drops == 0, 'independent packet socket dropped ' + str(drops) + ' packets')
    return counts


def peer(sock, tcp, family):
    sock.settimeout(20)
    if tcp:
        connection, _ = sock.accept()
        with connection:
            connection.settimeout(20)
            offset = 0
            while True:
                data = connection.recv(65536)
                if not data:
                    break
                require(data == bytes(((offset + i) * 17 ^ ((offset + i) >> 8) ^ ((offset + i) >> 16) ^ family) & 255 for i in range(len(data))), 'TCP bulk byte stream')
                offset += len(data)
            require(offset == 512 * 1024, 'missing original TCP bulk bytes')
            connection.sendall(b'ACK-DONE')
    else:
        for length in (0, 1, 511, 1400):
            data, address = sock.recvfrom(65536)
            require(data == bytes((i * 17 + family) & 255 for i in range(length)), 'UDP payload')
            sock.sendto(data, address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'pmd-root', 'failure-library'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'pmd-root', 'failure-library'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command).returncode
    for command in (
            ['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'link', 'add', 'offhost', 'type', 'veth', 'peer', 'name', 'offlink'],
            ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'offhost'],
            ['ip', '-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'offhost', 'nodad'],
            ['ip', 'link', 'set', 'offhost', 'up'], ['ip', 'link', 'set', 'offlink', 'up']):
        subprocess.run(command, check=True)
    for name in ('offhost', 'offlink'):
        subprocess.run(['ethtool', '-K', name, 'gro', 'off', 'gso', 'off', 'tso', 'off'], check=True, capture_output=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 '
           '--vdev=net_tap0,iface=offpeer,remote=offlink')
    with tempfile.TemporaryDirectory(prefix='ker-tx-offloads-') as directory:
        root = Path(directory)
        modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_null.so'))
        if not modules:
            print('SKIP: install original net_null PMD for capability rejection control')
            return 77
        for requested in ('checksum', 'tso'):
            marker = root / (requested + '-must-not-start')
            rejected = root / (requested + '-rejected.json')
            bad_eal = eal.rsplit(' --vdev=', 1)[0] + ' --vdev=net_null0,no-rx=1'
            environment = dict(os.environ)
            environment['LD_PRELOAD'] = str(modules[0])
            result = subprocess.run([sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_null0',
                '--eal', bad_eal, '--tx-offloads', requested, '--stats', str(rejected),
                '--', '/usr/bin/touch', str(marker)], env=environment, capture_output=True, text=True, timeout=20)
            require(result.returncode == 125 and not marker.exists() and
                    'requested TX checksum/TSO offloads exceed' in result.stderr and
                    json.loads(rejected.read_text())['outstanding'] == 0,
                    'unsupported original PMD accepted offloads: ' + result.stdout + result.stderr)
        print('PASS: unsupported original PMD rejects checksum/TSO before application entry, zero mbufs', flush=True)
        for mode, storage in (('off', 'large'), ('checksum', 'large'), ('tso', 'large'), ('tso', 'scatter')):
            sockets = []
            wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            wire.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            wire.bind(('offhost', 0))
            stop = threading.Event()
            port = 42000
            stats = root / (mode + '-' + storage + '.json')
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    try:
                        recording = executor.submit(capture, wire, stop, port)
                        peers = []
                        for family in (0, 1):
                            for tcp in (False, True):
                                sock = socket.socket(socket.AF_INET6 if family else socket.AF_INET,
                                                     socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
                                sockets.append(sock)
                                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                sock.bind(('2001:db8:1::1' if family else '198.18.0.1', port))
                                if tcp:
                                    sock.listen()
                                peers.append(executor.submit(peer, sock, tcp, family))
                        result, _ = launch([sys.executable, str(args.launcher), '--library', str(args.library),
                            '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--address6', '2001:db8:1::2/64',
                            '--port', 'net_tap0', '--eal', eal, '--mbuf-mode', storage, '--tx-offloads', mode,
                            '--stats', str(stats), '--', str(args.app), str(port)])
                        require(result.returncode == 0 and result.stdout.count('PASS:') == 2,
                                mode + ': native offload failed: ' + result.stdout + result.stderr)
                        for future in peers:
                            future.result(timeout=2)
                        stop.set()
                        counts = recording.result(timeout=2)
                        require(counts['tcp4'] > 100 and counts['tcp6'] > 100 and counts['udp4'] == counts['udp6'] == 4,
                                'missing complete independent wire evidence: ' + str(counts))
                        record = json.loads(stats.read_text())
                        require(record['mtu_changes'] == 2 and record['mtu_final'] == 1500, 'missing actual offload queue restart')
                        require(record['outstanding'] == 0 and record['dropped'] == 0, 'offload ownership/drop failure')
                        require(record['io']['tx_offload_mode'] == {'off': 0, 'checksum': 1, 'tso': 2}[mode], 'wrong actual mode')
                        if mode == 'off':
                            require(record['tx_tcp_checksum'] == record['tx_udp_checksum'] == record['tx_tso4'] == 0, 'default changed')
                        else:
                            require(record['tx_tcp_checksum'] > 100 and record['tx_udp_checksum'] == 8 and record['tx_ip_checksum'] > 0,
                                    'no actual original Linux metadata requests: ' + str(record))
                            require(record['tx_tso6'] == 0 and not record['io']['tx_offload_features'] & (1 << 12),
                                    'TAP advertised unsupported original DPDK IPv6 GSO')
                            require((record['tx_tso4'] > 0) == (mode == 'tso'), 'missing original IPv4 GSO requests: ' + str(record))
                        print('PASS: ' + mode + '/' + storage + ' original Linux metadata -> original TAP PMD software offload; '
                              'wire=' + str(counts) + '; requests=' + str({k: record[k] for k in ('tx_tcp_checksum', 'tx_udp_checksum', 'tx_ip_checksum', 'tx_tso4', 'tx_tso6')}), flush=True)
                    finally:
                        stop.set()
            finally:
                stop.set()
                wire.close()
                for sock in sockets:
                    sock.close()
        environment = dict(os.environ)
        environment['LD_PRELOAD'] = str(args.failure_library) + ':' + environment.get('LD_PRELOAD', '')
        failed_stats = root / 'tap-rejection.json'
        result, group = launch([sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
            '--tx-offloads', 'checksum', '--stats', str(failed_stats), '--', str(args.app), '42000', 'failure'], env=environment)
        failed = json.loads(failed_stats.read_text())
        require(result.returncode == 125 and 'INJECT: original TAP checksum writev EAGAIN' in result.stderr and
                'TAP rejected an offload buffer; retry is unsupported' in result.stderr and failed['outstanding'] > 0,
                'pinned TAP rejection was hidden or retried: ' + result.stdout + result.stderr + str(failed))
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            pass
        else:
            raise RuntimeError('failed offload backend left live processes')
        print('PASS: original TAP rejected-buffer ownership defect is diagnosed; backend fails125 without retry, all processes reaped; outstanding=' + str(failed['outstanding']), flush=True)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
