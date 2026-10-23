#!/usr/bin/env python3
"""Real host TAP exception ownership and native/original-PMD coexistence."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import struct
import sys
import tempfile
import threading


def require(value, message):
    if not value:
        raise RuntimeError(message)


def ready_line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(15), 'application setup barrier timed out')
    return process.stdout.readline().strip()


def frame(identifier, ether_type=0x88b5):
    return b'\xff' * 6 + bytes.fromhex('02123456789a') + ether_type.to_bytes(2, 'big') + bytes(
        (identifier + i * 17) & 255 for i in range(50))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'ownership', 'pmd-root'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_tap.so'))
    if not modules or not Path('/dev/net/tun').exists():
        print('SKIP: original TAP PMD and /dev/net/tun are required')
        return 77
    environment = dict(os.environ, LD_PRELOAD=str(modules[0]))
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'ownership', 'pmd-root'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command, env=environment).returncode
    # Only this private test namespace: suppress unrelated automatic host IPv6
    # packets so exact queue counters can be asserted. Native Linux is separate.
    Path('/proc/sys/net/ipv6/conf/default/disable_ipv6').write_text('1')
    result = subprocess.run([str(args.ownership)], env=environment, text=True, capture_output=True, timeout=20)
    require(result.returncode == 0, 'real ownership test failed: ' + result.stdout + result.stderr)
    cases = ('test_kni_alloc_primary_happy_path', 'test_kni_process_tx_basic', 'test_kni_process_tx_partial_drop', 'test_kni_process_rx_forward',
             'test_kni_process_rx_partial_drop', 'test_kni_process_tx_kernel_ratelimit',
             'test_kni_process_tx_kernel_ratelimit_exceeded', 'test_kni_enqueue_full_ring_drops')
    require(all(result.stdout.count('PASS: ' + case + '\n') == 1 for case in cases),
            'missing exact source ownership markers: ' + result.stdout)
    print(result.stdout, end='', flush=True)
    for command in (['ip', 'link', 'set', 'lo', 'up'],
                    ['ip', 'link', 'add', 'wirehost', 'type', 'veth', 'peer', 'name', 'wirelink'],
                    ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'wirehost'],
                    ['ip', 'link', 'set', 'wirehost', 'up'], ['ip', 'link', 'set', 'wirelink', 'up']):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-exception-') as directory:
        root = Path(directory)
        capture = root / 'pcap'; capture.mkdir(mode=0o700)
        config, stats = root / 'bridge.ini', root / 'stats.json'
        config.write_text('[network]\naddress=198.18.0.2/24\nmax_mtu=1500\n'
            '[dpdk]\nport=net_tap0\nexception_iface=hostexcept\nexception_type=34997\nexception_queue=256\n'
            f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 '
            '--vdev=net_tap0,iface=wirepeer,remote=wirelink\n'
            f'[capture]\ndirectory={capture}\n')
        command = [sys.executable, str(args.launcher), '--config', str(config), '--library', str(args.library),
                   '--io-worker', str(args.worker), '--stats', str(stats), '--', str(args.app)]
        host = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host.bind(('198.18.0.1', 42000)); host.settimeout(10)
        wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88b5))
        wire.bind(('wirehost', 0)); wire.settimeout(3)
        process = None
        with (root / 'worker.log').open('w+') as log:
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    def echo():
                        for _ in range(32):
                            payload, peer = host.recvfrom(4096)
                            require(payload == b'native-UDP-remains-on-original-Linux\0', 'native UDP bytes changed')
                            host.sendto(payload, peer)
                    echoed = executor.submit(echo)
                    process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=log, text=True, start_new_session=True)
                    require(ready_line(process) == 'READY', 'native app failed before main')
                    exception = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                    exception.bind(('hostexcept', 0)); exception.settimeout(3)
                    # Exact raw bytes traverse a genuine wire PMD -> selected
                    # worker queue -> host Linux TAP -> independent AF_PACKET.
                    for identifier in range(4):
                        data = frame(identifier)
                        require(wire.send(data) == len(data), 'wire injection incomplete')
                        require(exception.recv(4096) == data, 'exception host bytes differ')
                    wire_mac = json.loads(subprocess.check_output(
                        ['ip', '-j', 'link', 'show', 'wirepeer'], text=True))[0]['address']
                    host_mac = json.loads(subprocess.check_output(
                        ['ip', '-j', 'link', 'show', 'hostexcept'], text=True))[0]['address']
                    require(wire_mac == host_mac, 'exception TAP does not share the actual wire PMD MAC')
                    unicast = bytes.fromhex(wire_mac.replace(':', '')) + frame(20)[6:]
                    require(wire.send(unicast) == len(unicast), 'unicast injection incomplete')
                    received, origin = exception.recvfrom(4096)
                    require(received == unicast and origin[2] == socket.PACKET_HOST,
                            'unicast was not classified as host traffic by original Linux')
                    # Non-selected EtherType stays on the native path.
                    other = frame(10, 0x88b6)
                    require(wire.send(other) == len(other), 'non-selected injection incomplete')
                    exception.settimeout(0.1)
                    try:
                        observed = exception.recv(4096)
                        raise RuntimeError('non-selected frame leaked to exception TAP: ' + observed.hex())
                    except socket.timeout:
                        pass
                    exception.settimeout(3)
                    for identifier in range(4, 8):
                        data = frame(identifier)
                        require(exception.send(data) == len(data), 'host injection incomplete')
                        require(wire.recv(4096) == data, 'exception wire bytes differ')
                    flood_stop = threading.Event()
                    burst_ready = threading.Event()
                    flood_counts = {'sent': 0, 'wire': 0, 'errors': []}
                    def produce_exception_tx():
                        try:
                            for identifier in range(32, 160):
                                if exception.send(frame(identifier)) != 64:
                                    raise RuntimeError('short exception TAP write')
                                flood_counts['sent'] += 1
                            burst_ready.set()
                            flood_stop.wait(5)
                        except BaseException as error:
                            flood_counts['errors'].append(str(error)); burst_ready.set()
                    def drain_exception_wire():
                        try:
                            while not flood_stop.is_set():
                                try:
                                    wire.recv(4096)
                                    flood_counts['wire'] += 1
                                except socket.timeout:
                                    continue
                        except BaseException as error:
                            flood_counts['errors'].append(str(error))
                    producer = threading.Thread(target=produce_exception_tx)
                    producer.start()
                    require(burst_ready.wait(3) and flood_counts['sent'] == 128,
                            'could not queue bounded exception TX burst: ' + str(flood_counts))
                    process.stdin.write('G'); process.stdin.flush()
                    # Let the real DPDK ring fill before draining it. Both native
                    # UDP and exception packets must resume after partial acceptance.
                    import time
                    time.sleep(0.05)
                    drain = threading.Thread(target=drain_exception_wire)
                    drain.start()
                    require(ready_line(process) == 'NATIVE_DONE', 'normal native UDP or MTU guard failed')
                    echoed.result(timeout=3)
                    flood_stop.set(); producer.join(timeout=2); drain.join(timeout=4)
                    require(not producer.is_alive() and not drain.is_alive() and not flood_counts['errors'] and
                            flood_counts['sent'] == 128 and flood_counts['wire'] > 0,
                            'native and bounded exception TX did not both progress: ' + str(flood_counts))
                    output, _ = process.communicate('Q', timeout=15)
                    require(process.returncode == 0 and 'PASS: native UDP and exception bridge coexist' in output,
                            'native runtime/worker failed: ' + output)
                    exception.close()
                record = json.loads(stats.read_text())
                require(record['outstanding'] == 0, 'exception path leaked owned mbufs')
                require(record['exception_to_host'] == 5 and record['exception_from_host'] >= 128,
                        'missing actual worker direction or queued burst progress: ' + str(record))
                require(record['exception_selected'] == 5 and record['exception_enqueued'] == 5 and
                        record['exception_to_host_dropped'] == record['exception_wire_dropped'] == 0,
                        'unexpected exception loss or double routing')
                require(record['rx'] > 0 and record['tx'] > 0 and record['native']['udp_out_datagrams'] == record['native']['udp_in_datagrams'] == 32,
                        'non-selected native traffic did not run original Linux')
                require(subprocess.run(['ip', 'link', 'show', 'hostexcept'], capture_output=True).returncode != 0,
                        'ephemeral exception TAP leaked after worker close')
                def captured(direction):
                    frames = []
                    for path in capture.glob('ker-' + direction + '*.pcap'):
                        data = path.read_bytes()
                        require(data[:4] == b'\xd4\xc3\xb2\xa1', 'unexpected capture format')
                        offset = 24
                        while offset < len(data):
                            require(offset + 16 <= len(data), 'truncated pcap record')
                            _, _, length, original = struct.unpack_from('<IIII', data, offset)
                            offset += 16
                            require(length == original and offset + length <= len(data), 'incomplete exception capture')
                            frames.append(data[offset:offset + length]); offset += length
                    return frames
                for direction, identifiers in (('rx', range(4)), ('tx', range(4, 8))):
                    frames = captured(direction)
                    require(all(frames.count(frame(identifier)) == 1 for identifier in identifiers),
                            'exception data missing/duplicated in actual ' + direction + ' pcap')
                    if direction == 'rx':
                        require(frames.count(unicast) == 1, 'unicast missing/duplicated in RX pcap')
                print('PASS: actual wire PMD <-> exclusive host TAP; exact frames and native UDP; zero mbufs', flush=True)
            except BaseException:
                log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                raise
            finally:
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                wire.close(); host.close()
        # Existing TAP is neither attached nor changed. Startup must reject
        # before app entry and reclaim the already-configured wire PMD/pool.
        subprocess.run(['ip', 'tuntap', 'add', 'dev', 'takenexcept', 'mode', 'tap'], check=True)
        subprocess.run(['ip', 'link', 'set', 'takenexcept', 'mtu', '1400', 'up'], check=True)
        before = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'takenexcept'], text=True))[0]
        marker = root / 'app-entered'
        result = subprocess.run(command[:-2] + ['--exception-iface', 'takenexcept', '--', '/usr/bin/touch', str(marker)],
            env=environment, text=True, capture_output=True, timeout=20)
        if result.returncode != 125:
            raise RuntimeError('existing TAP startup rejection failed: ' + result.stdout + result.stderr)
        require('host exception TAP startup failed' in result.stderr, 'startup failed outside the exception adapter: ' + result.stderr)
        after = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show', 'takenexcept'], text=True))[0]
        require(not marker.exists() and before['flags'] == after['flags'] and before['mtu'] == after['mtu'] and
                before['address'] == after['address'], 'existing TAP mutated or app entered')
        require(json.loads(stats.read_text())['outstanding'] == 0, 'failed startup leaked PMD mbufs')
        print('PASS: existing TAP rejected before app; flags/MTU/MAC preserved, zero mbufs')
    return 0


if __name__ == '__main__':
    sys.exit(main())
