#!/usr/bin/env python3
"""Actual destination-port steering between host and imported Linux stacks."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import selectors
import time
import signal
import socket
import subprocess
import struct
import sys
import tempfile


SOURCE_CASES = {
    'test_ff_kni_init_tcp_udp_port_bitmaps',
    'test_ff_kni_proto_filter_ipv4_short',
    'test_ff_kni_proto_filter_non_ip_frame',
    'test_ff_kni_proto_filter_ipv4_tcp_kni_disabled',
    'test_ff_kni_proto_filter_ipv4_udp_kni_disabled',
    'test_ff_kni_proto_filter_ipv4_oversized_ihl',
    'test_ff_kni_proto_filter_ipv4_ipip_recurse',
    'test_ff_kni_proto_filter_ipv4_ospf_returns_ospf',
    'test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_short',
    'test_ff_kni_proto_filter_ipv4_udp_kni_enabled_short',
    'test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_match_returns_kni',
    'test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_miss_returns_unknown',
    'test_ff_kni_proto_filter_ipv4_udp_kni_enabled_match_returns_kni',
    'test_p3_ndp_classification',
    'test_ff_kni_init_null_port_lists',
}

def require(value, message):
    if not value:
        raise RuntimeError(message)


def ip(*arguments):
    subprocess.run(['ip', *arguments], check=True)


def line(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        require(selector.select(20), 'service barrier timeout')
    return process.stdout.readline().strip()


def payload(size):
    return bytes((i * 17 + (i >> 8)) & 255 for i in range(size))


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def icmp_mtu_frames():
    source4, destination4 = socket.inet_aton('198.18.0.1'), socket.inet_aton('198.18.0.2')
    quoted4 = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 901, 0, 64, 17, 0,
                                     destination4, source4))
    struct.pack_into('!H', quoted4, 10, checksum(quoted4))
    quoted4 += struct.pack('!HHHH', 45001, 45002, 8, 0)
    error4 = bytearray(struct.pack('!BBHI', 3, 4, 0, 1400) + quoted4)
    struct.pack_into('!H', error4, 2, checksum(error4))
    outer4 = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(error4), 902, 0, 64, 1, 0,
                                   source4, destination4))
    struct.pack_into('!H', outer4, 10, checksum(outer4))
    source6 = socket.inet_pton(socket.AF_INET6, '2001:db8:1::1')
    destination6 = socket.inet_pton(socket.AF_INET6, '2001:db8:1::2')
    quoted6 = struct.pack('!IHBB16s16s', 6 << 28, 8, 17, 64, destination6, source6)
    quoted6 += struct.pack('!HHHH', 45001, 45002, 8, 0)
    error6 = bytearray(struct.pack('!BBHI', 2, 0, 0, 1400) + quoted6)
    pseudo = source6 + destination6 + struct.pack('!I3xB', len(error6), 58)
    struct.pack_into('!H', error6, 2, checksum(pseudo + error6))
    outer6 = struct.pack('!IHBB16s16s', 6 << 28, len(error6), 58, 64, source6, destination6)
    return [(0x0800, outer4 + error4), (0x86dd, outer6 + error6)]


def receive(fd, count):
    result = b''
    while len(result) < count:
        data = fd.recv(count - len(result)); require(data, 'early TCP EOF'); result += data
    return result


def remote():
    print('NAMESPACE_READY', flush=True)
    require(sys.stdin.readline().strip() == 'CONFIGURE', 'remote setup barrier')
    ip('link', 'set', 'lo', 'up')
    ip('addr', 'add', '198.18.0.1/24', 'dev', 'client0')
    ip('-6', 'addr', 'add', '2001:db8:1::1/64', 'dev', 'client0', 'nodad')
    ip('link', 'set', 'client0', 'up')
    print('REMOTE_READY', flush=True)
    require(sys.stdin.readline().strip() == 'GO', 'remote data barrier')
    for family, target in ((socket.AF_INET, '198.18.0.2'), (socket.AF_INET6, '2001:db8:1::2')):
        for native, port in ((False, 45001), (True, 45000)):
            identity = b'NATIVE:' if native else b'HOST:'
            with socket.socket(family, socket.SOCK_STREAM) as tcp:
                tcp.settimeout(10); tcp.connect((target, port)); tcp.sendall(payload(4097))
                require(receive(tcp, len(identity) + 4097) == identity + payload(4097), 'TCP reached wrong stack or changed data')
            with socket.socket(family, socket.SOCK_DGRAM) as udp:
                udp.settimeout(10); udp.connect((target, port)); udp.send(payload(512))
                require(udp.recv(4096) == identity + payload(512), 'UDP reached wrong stack or changed data')
    print('REMOTE_DONE', flush=True)
    require(sys.stdin.readline().strip() == 'QUIT', 'remote teardown barrier')
    print('PASS: remote original Linux IPv4/IPv6 TCP/UDP selected both stacks', flush=True)
    return 0


def host_service(listener, tcp):
    if tcp:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(10)
            require(receive(connection, 4097) == payload(4097), 'host TCP request differs')
            connection.sendall(b'HOST:' + payload(4097))
    else:
        data, peer = listener.recvfrom(4096)
        require(data == payload(512), 'host UDP request differs')
        listener.sendto(b'HOST:' + data, peer)


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def main():
    if '--remote' in sys.argv:
        return remote()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'app', 'classifier', 'pmd-root', 'backpressure'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    modules = list(args.pmd_root.glob('dpdk/pmds-*/librte_net_tap.so'))
    if not modules or not Path('/dev/net/tun').exists():
        print('SKIP: actual original TAP PMD and /dev/net/tun required'); return 77
    environment = dict(os.environ, LD_PRELOAD=str(args.backpressure.resolve()) + ':' + str(modules[0]))
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'app', 'classifier', 'pmd-root', 'backpressure'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command, env=environment).returncode
    classified = subprocess.run([str(args.classifier)], env=environment, text=True, capture_output=True, timeout=15)
    markers = [value.removeprefix('FILTER_SOURCE_CASE ') for value in classified.stdout.splitlines()
               if value.startswith('FILTER_SOURCE_CASE ')]
    require(classified.returncode == 0 and len(markers) == len(SOURCE_CASES) and set(markers) == SOURCE_CASES,
            'original DPDK classifier acceptance failed: ' + classified.stdout + classified.stderr)
    print(classified.stdout, end='', flush=True)
    ip('link', 'set', 'lo', 'up')
    cpu = min(os.sched_getaffinity(0))
    with tempfile.TemporaryDirectory(prefix='ker-service-steer-') as directory:
        root = Path(directory)
        for policy in ('accept', 'reject'):
            peer = app = host_capture = None
            sockets = []
            with (root / (policy + '.peer.log')).open('w+') as peer_log, (root / (policy + '.app.log')).open('w+') as app_log:
                try:
                    peer = subprocess.Popen(['unshare', '-n', sys.executable, str(Path(__file__).resolve()), '--remote'],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=peer_log, text=True)
                    require(line(peer) == 'NAMESPACE_READY', 'remote namespace failed')
                    ip('link', 'add', 'wirelink', 'type', 'veth', 'peer', 'name', 'client0')
                    ip('link', 'set', 'client0', 'netns', str(peer.pid)); ip('link', 'set', 'wirelink', 'up')
                    peer.stdin.write('CONFIGURE\n'); peer.stdin.flush()
                    require(line(peer) == 'REMOTE_READY', 'remote interface failed')
                    selected = 45001 if policy == 'accept' else 45000
                    capture = root / (policy + '-capture'); capture.mkdir(mode=0o700)
                    config, stats = root / (policy + '.ini'), root / (policy + '.json')
                    config.write_text('[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\nmax_mtu=1500\n'
                        '[dpdk]\nport=net_tap0\nexception_iface=hostservices\nexception_mode=ports\n'
                        f'exception_policy={policy}\nexception_tcp_ports={selected}\nexception_udp_ports={selected}\n'
                        f'eal=--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry --iova-mode=va -m 96 '
                        '--vdev=net_tap0,iface=wirepeer,remote=wirelink\n'
                        f'[capture]\ndirectory={capture}\n')
                    command = [sys.executable, str(args.launcher), '--config', str(config), '--library', str(args.library),
                        '--io-worker', str(args.worker), '--stats', str(stats), '--', str(args.app)]
                    app = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=app_log, text=True, start_new_session=True)
                    require(line(app) == 'READY', 'native services failed to start')
                    # Actual wire RX must reject ambiguous fragment ownership
                    # explicitly, without a Ker reassembly/flow-state substitute.
                    mac = bytes.fromhex(json.loads(subprocess.check_output(
                        ['ip', '-j', 'link', 'show', 'wirepeer'], text=True))[0]['address'].replace(':', ''))
                    udp = struct.pack('!HHHH', 12345, 45001, 16, 0)
                    ip4 = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 28, 123, 0x2000, 64, 17, 0,
                        socket.inet_aton('198.18.0.1'), socket.inet_aton('198.18.0.2')))
                    checksum = sum(struct.unpack('!10H', ip4)); checksum = (checksum & 65535) + (checksum >> 16)
                    struct.pack_into('!H', ip4, 10, (~checksum) & 65535)
                    ip6 = struct.pack('!IHBB16s16s', 6 << 28, 16, 44, 64,
                        socket.inet_pton(socket.AF_INET6, '2001:db8:1::1'), socket.inet_pton(socket.AF_INET6, '2001:db8:1::2'))
                    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as injection:
                        injection.bind(('wirepeer', 0))
                        for ether_type, fragment in ((0x0800, bytes(ip4) + udp),
                                (0x86dd, ip6 + struct.pack('!BBHI', 17, 0, 1, 123) + udp)):
                            frame = mac + bytes.fromhex('021122334466') + ether_type.to_bytes(2, 'big') + fragment
                            require(injection.send(frame) == len(frame), 'fragment boundary injection incomplete')
                    ip('addr', 'add', '198.18.0.2/24', 'dev', 'hostservices')
                    ip('-6', 'addr', 'add', '2001:db8:1::2/64', 'dev', 'hostservices', 'nodad')
                    ip('link', 'set', 'hostservices', 'promisc', 'on')
                    host_capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW | socket.SOCK_NONBLOCK, socket.htons(3))
                    host_capture.bind(('hostservices', 0))
                    # Bounded, checksummed error frames enter the genuine worker;
                    # Linux retains quote validation and PMTU/error processing.
                    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as injection:
                        injection.bind(('wirepeer', 0))
                        for ether_type, packet in icmp_mtu_frames():
                            frame = mac + bytes.fromhex('021122334466') + ether_type.to_bytes(2, 'big') + packet
                            require(injection.send(frame) == len(frame), 'ICMP MTU error injection incomplete')
                    for family, address in ((socket.AF_INET, '198.18.0.2'), (socket.AF_INET6, '2001:db8:1::2')):
                        for tcp in (True, False):
                            fd = socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM); sockets.append(fd)
                            fd.settimeout(15); fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            fd.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'hostservices\0')
                            fd.bind((address, 45001))
                            if tcp: fd.listen(2)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                        services = [executor.submit(host_service, fd, index % 2 == 0) for index, fd in enumerate(sockets)]
                        app.stdin.write('G'); app.stdin.flush(); peer.stdin.write('GO\n'); peer.stdin.flush()
                        require(line(app) == 'NATIVE_DONE', 'native data path failed')
                        require(line(peer) == 'REMOTE_DONE', 'remote data phase failed')
                        for future in services: future.result(timeout=2)
                        # Continue briefly after seeing both types so a duplicate
                        # host copy cannot hide behind the first matching pair.
                        host_errors = {}
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            with selectors.DefaultSelector() as selector:
                                selector.register(host_capture, selectors.EVENT_READ)
                                timeout = min(0.25, deadline - time.monotonic()) if len(host_errors) == 2 else deadline - time.monotonic()
                                if not selector.select(max(0, timeout)): break
                            frame = host_capture.recv(2048)
                            if frame[12:14] == b'\x08\x00' and len(frame) >= 42 and frame[23] == 1 and frame[34:36] == b'\x03\x04':
                                key = 'ipv4-frag-needed'
                            elif frame[12:14] == b'\x86\xdd' and len(frame) >= 62 and frame[20] == 58 and frame[54] == 2:
                                key = 'ipv6-packet-too-big'
                            else: continue
                            host_errors[key] = host_errors.get(key, 0) + 1
                        require(host_errors == {'ipv4-frag-needed': 1, 'ipv6-packet-too-big': 1},
                                'host TAP did not receive exactly one copy of each ICMP error: ' + str(host_errors))
                        output, _ = app.communicate('Q', timeout=15)
                        require(app.returncode == 0 and 'PASS: original native' in output, 'native shutdown failed: ' + output)
                        peer_out, _ = peer.communicate('QUIT\n', timeout=10)
                        require(peer.returncode == 0 and 'PASS: remote original Linux' in peer_out, 'remote data failed: ' + peer_out)
                    record = json.loads(stats.read_text())
                    require(record['outstanding'] == 0 and record['exception_to_host'] > 0 and record['exception_from_host'] > 0
                            and record['exception_shared_selected'] > 0 and record['exception_shared_failed'] == 0
                            and record['exception_shared_icmp_error'] == 2 and record['exception_fragment_dropped'] == 2,
                            'missing real steering/control ownership: ' + str(record))
                    require(record['native']['active_opens'] == 0 and record['native']['passive_opens'] == 2
                            and record['native']['udp_in_datagrams'] == record['native']['udp6_in_datagrams'] == 1,
                            'wrong original-native socket traffic counters: ' + str(record['native']))
                    require(sum(record['rx_by_queue']) == record['rx'] + record['rx_dropped'] + record['exception_selected']
                            - record['exception_shared_selected'] + record['rx_shutdown_discarded'] - record['rx_startup_discarded'],
                            'shared control frames were double counted')
                    app_log.flush(); app_log.seek(0); trace = app_log.read()
                    require(trace.count('INJECT: exception ARP native-channel EAGAIN') == 3
                            and trace.count('INJECT: IPv4 frag-needed native-channel EAGAIN') == 1
                            and trace.count('INJECT: IPv6 Packet-Too-Big native-channel EAGAIN') == 1
                            and record['rx_retries'] >= 5, 'actual native-channel backpressure was not exercised')
                    arp_frames = 0
                    mtu_errors = {}
                    for path in capture.glob('ker-rx-*.pcap'):
                        data = path.read_bytes(); endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
                        offset = 24
                        while offset < len(data):
                            _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset); offset += 16
                            require(length == original and offset + length <= len(data), 'truncated RX frame')
                            frame = data[offset:offset + length]; offset += length
                            if frame[12:14] == b'\x08\x06': arp_frames += 1
                            if frame[12:14] == b'\x08\x00' and len(frame) >= 42 and frame[23] == 1 and frame[34:36] == b'\x03\x04':
                                mtu_errors['ipv4-frag-needed'] = mtu_errors.get('ipv4-frag-needed', 0) + 1
                            if frame[12:14] == b'\x86\xdd' and len(frame) >= 62 and frame[20] == 58 and frame[54] == 2:
                                mtu_errors['ipv6-packet-too-big'] = mtu_errors.get('ipv6-packet-too-big', 0) + 1
                    require(mtu_errors == {'ipv4-frag-needed': 1, 'ipv6-packet-too-big': 1},
                            'native RX did not receive exactly one copy of each ICMP error: ' + str(mtu_errors))
                    require(arp_frames > 0 and arp_frames == record['exception_shared_arp'],
                            'retained RX control frame cloned more than once: ' + str(record))
                    print('PASS: ' + policy + ' policy; host/native ICMP error copies survive EAGAIN; actual TCP/UDP; zero mbufs', flush=True)
                except BaseException:
                    for log in (peer_log, app_log):log.flush(); log.seek(0); print(log.read(), file=sys.stderr)
                    raise
                finally:
                    for fd in sockets:fd.close()
                    if host_capture is not None: host_capture.close()
                    stop(app); stop(peer)
        # Invalid policy/ports must fail parsing before worker or app entry.
        invalid = root / 'invalid.ini'; invalid.write_text(config.read_text().replace('exception_policy=reject','exception_policy=invalid'))
        marker = root / 'entered'
        result = subprocess.run([sys.executable, str(args.launcher), '--config', str(invalid), '--library', str(args.library),
            '--io-worker', str(args.worker), '--', '/usr/bin/touch', str(marker)], env=environment, text=True, capture_output=True, timeout=10)
        require(result.returncode == 2 and not marker.exists() and 'invalid exception mode or accept/reject policy' in result.stderr,
                'invalid policy reached worker/app')
    return 0


if __name__ == '__main__':sys.exit(main())
