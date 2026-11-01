#!/usr/bin/env python3
"""Exercise owner-scoped request_sock census on the original LKL TCP stack."""
import argparse
import os
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=15)
    require(result.returncode == 0, f'{command!r}: {result.stderr.strip()}')
    return result.stdout


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    words = struct.unpack('!%dH' % (len(data) // 2), data)
    total = sum(words)
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(frame):
    if len(frame) < 54:
        return None
    ether_type = frame[12:14]
    if ether_type == b'\x86\xdd':
        ip = frame[14:]
        if len(ip) < 60 or ip[0] >> 4 != 6 or ip[6] != socket.IPPROTO_TCP:
            return None
        payload_len = struct.unpack_from('!H', ip, 4)[0]
        if payload_len < 20 or payload_len + 40 > len(ip):
            return None
        tcp = ip[40:40 + payload_len]
        offset = (tcp[12] >> 4) * 4
        if offset < 20 or len(tcp) < offset:
            return None
        return {'src': socket.inet_ntop(socket.AF_INET6, ip[8:24]),
            'dst': socket.inet_ntop(socket.AF_INET6, ip[24:40]),
            'sport': struct.unpack_from('!H', tcp, 0)[0],
            'dport': struct.unpack_from('!H', tcp, 2)[0],
            'seq': struct.unpack_from('!I', tcp, 4)[0],
            'ack': struct.unpack_from('!I', tcp, 8)[0], 'flags': tcp[13],
            'window': struct.unpack_from('!H', tcp, 14)[0],
            'options': tcp[20:offset], 'payload': tcp[offset:], 'src_mac': frame[6:12],
            'dst_mac': frame[0:6], 'family': socket.AF_INET6}
    if ether_type != b'\x08\x00':
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0xf) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or ip[9] != socket.IPPROTO_TCP:
        return None
    total = struct.unpack_from('!H', ip, 2)[0]
    if total < ihl + 20 or total > len(ip):
        return None
    tcp = ip[ihl:total]
    offset = (tcp[12] >> 4) * 4
    if offset < 20 or len(tcp) < offset:
        return None
    return {'src': socket.inet_ntoa(ip[12:16]), 'dst': socket.inet_ntoa(ip[16:20]),
        'sport': struct.unpack_from('!H', tcp, 0)[0],
        'dport': struct.unpack_from('!H', tcp, 2)[0],
        'seq': struct.unpack_from('!I', tcp, 4)[0],
        'ack': struct.unpack_from('!I', tcp, 8)[0], 'flags': tcp[13],
        'window': struct.unpack_from('!H', tcp, 14)[0],
        'options': tcp[20:offset], 'payload': tcp[offset:], 'src_mac': frame[6:12],
        'dst_mac': frame[0:6], 'family': socket.AF_INET}


def timestamp(options):
    offset = 0
    while offset < len(options):
        kind = options[offset]
        if kind == 0:
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 2 > len(options):
            break
        length = options[offset + 1]
        if length < 2 or offset + length > len(options):
            break
        if kind == 8 and length == 10:
            return struct.unpack_from('!II', options, offset + 2)
        offset += length
    return None


def inject_ack(raw, host_mac, syn, synack):
    options = b''
    ts = timestamp(syn['options'])
    peer_ts = timestamp(synack['options'])
    if ts and peer_ts:
        options = b'\x01\x01\x08\x0a' + struct.pack('!II',
            (ts[0] + 1) & 0xffffffff, peer_ts[0])
    tcp = bytearray(struct.pack('!HHIIBBHHH', syn['sport'], syn['dport'],
        (syn['seq'] + 1 + len(syn['payload'])) & 0xffffffff,
        (synack['seq'] + 1) & 0xffffffff,
        ((20 + len(options)) // 4) << 4, 0x10, 65535, 0, 0) + options)
    if syn['family'] == socket.AF_INET6:
        src = socket.inet_pton(socket.AF_INET6, syn['src'])
        dst = socket.inet_pton(socket.AF_INET6, syn['dst'])
        pseudo = src + dst + struct.pack('!I', len(tcp)) + b'\0\0\0' + bytes([socket.IPPROTO_TCP])
        struct.pack_into('!H', tcp, 16, checksum(pseudo + tcp))
        ip = struct.pack('!IHBB16s16s', 6 << 28, len(tcp), socket.IPPROTO_TCP,
            64, src, dst)
        raw.send(synack['src_mac'] + host_mac + b'\x86\xdd' + ip + tcp)
    else:
        src, dst = socket.inet_aton(syn['src']), socket.inet_aton(syn['dst'])
        pseudo = src + dst + b'\0\x06' + struct.pack('!H', len(tcp))
        struct.pack_into('!H', tcp, 16, checksum(pseudo + tcp))
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp),
            0, 0x4000, 64, socket.IPPROTO_TCP, 0, src, dst))
        struct.pack_into('!H', ip, 10, checksum(ip))
        raw.send(synack['src_mac'] + host_mac + b'\x08\x00' + ip + tcp)


def read_state(prefix, expected, process, timeout=10):
    path = Path(str(prefix) + '.state')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            value = path.read_text().strip()
            if value.startswith(expected):
                return value
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise RuntimeError(f'fixture exited before {expected}: {process.returncode}; '
                f'{stdout!r} {stderr!r}')
        time.sleep(0.01)
    raise RuntimeError(f'timed out waiting for {expected}; process_alive={process.poll() is None}; '
        f'state={path.read_text().strip() if path.exists() else "<missing>"}')


def has_fastopen_cookie(options, cookie_required):
    offset = 0
    while offset < len(options):
        kind = options[offset]
        if kind == 0:
            break
        if kind == 1:
            offset += 1
            continue
        if offset + 2 > len(options):
            break
        length = options[offset + 1]
        if length < 2 or offset + length > len(options):
            break
        if kind == 34:
            return length > 2 if cookie_required else True
        offset += length
    return False


def connect_and_capture(capture, port, fastopen_data=None, family=socket.AF_INET,
        server_address='198.18.0.2', host_address='198.18.0.1'):
    client = socket.socket(family, socket.SOCK_STREAM)
    client.settimeout(10)
    failures = []
    pending = []
    def connect():
        try:
            if fastopen_data is None:
                client.connect((server_address, port))
            else:
                client.sendto(fastopen_data, socket.MSG_FASTOPEN, (server_address, port))
        except BlockingIOError as error:
            if fastopen_data is not None and error.errno == 115:
                pending.append(error)
            else:
                failures.append(error)
        except BaseException as error:
            failures.append(error)
    thread = threading.Thread(target=connect, daemon=True)
    thread.start()
    syn = synack = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and synack is None:
        try:
            frame, _ = capture.recvfrom(65535)
        except TimeoutError:
            continue
        item = packet(frame)
        if not item:
            continue
        if item['src'] == host_address and item['dst'] == server_address and \
                item['dport'] == port and item['flags'] & 0x02:
            syn = item
        if item['src'] == server_address and item['dst'] == host_address and \
                item['sport'] == port and item['flags'] & 0x12 == 0x12:
            synack = item
    require(syn is not None and synack is not None,
        f'missing wire SYN/SYN-ACK for port {port}: syn={syn!r} synack={synack!r}; '
        f'connect_failures={failures!r}; pending={pending!r}')
    require(syn['sport'] == synack['dport'] and
        (syn['seq'] + 1 + len(syn['payload'])) & 0xffffffff == synack['ack'],
        f'SYN-ACK does not match captured SYN: {syn!r} {synack!r}')
    return client, syn, synack, thread, failures, pending


def inside(args):
    for command in (
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', '-6', 'addr', 'add', '2001:db8::1/64', 'dev', 'kerhost', 'nodad'],
        ['ip', 'link', 'set', 'kerhost', 'up'],
        ['ip', 'link', 'set', 'kerlink', 'up'],
        ['ip', 'link', 'set', 'kerpeer', 'up'],
    ):
        run(command)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
        f'--iova-mode=va -m 64 -d {args.dpdk_plugin_dir / "librte_net_tap.so"} '
        '--vdev=net_tap0,iface=kerpeer,remote=kerlink')
    port = 43971
    mark = 0xC1301
    table = f'ker_owner_req_{os.getpid()}'
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind(('kerhost', 0)); capture.settimeout(0.2)
    link = run(['ip', '-o', 'link', 'show', 'kerhost'])
    host_mac = bytes.fromhex(re.search(r'link/ether ([0-9a-f:]+)', link).group(1).replace(':', ''))
    table_created = False
    process = None
    try:
        run(['nft', 'add', 'table', 'inet', table]); table_created = True
        run(['nft', 'add', 'chain', 'inet', table, 'output', '{', 'type', 'filter',
            'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}'])
        run(['nft', 'add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
            'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
            'tcp', 'dport', str(port), 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop'])
        run(['nft', 'add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
            'ip6', 'saddr', '2001:db8::1', 'ip6', 'daddr', '2001:db8::2',
            'tcp', 'dport', str(port + 1), 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop'])
        with tempfile.TemporaryDirectory(prefix='ker-ff-owner-requests-') as tmp:
            root = Path(tmp); prefix = root / 'control'
            stats = root / 'stats.json'
            command = [sys.executable, str(args.launcher), '--library', str(args.library),
                '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                '--address6', '2001:db8::2/64',
                '--port', 'net_tap0', '--eal', eal, '--stats', str(stats), '--',
                str(args.runtime_test)]
            env = os.environ | {'KER_C13_CONTROL': str(prefix),
                'KER_C13_MARK': str(mark), 'KER_C13_PORT': str(port),
                'RUNTIME_DIRECTORY': str(root)}
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            read_state(prefix, 'READY', process)

            first, syn1, synack1, first_thread, first_failures, first_pending = connect_and_capture(
                capture, port, b'owner-request-cookie-prime')
            require(has_fastopen_cookie(syn1['options'], False),
                f'first SYN did not request a Fast Open cookie: {syn1["options"]!r}')
            require(has_fastopen_cookie(synack1['options'], True),
                f'listener did not return a Fast Open cookie: {synack1["options"]!r}')
            Path(str(prefix) + '.command').write_text('QUERY1\n')
            first_state = read_state(prefix, 'SYN_REQUEST', process)
            require(first_state == 'SYN_REQUEST count=1',
                f'ACK-suppressed ordinary SYN did not yield one marked request_sock: {first_state!r}')
            counters = run(['nft', 'list', 'chain', 'inet', table, 'output'])
            counts = re.findall(r'counter packets (\d+) bytes (\d+)', counters)
            require(counts and sum(int(item[0]) for item in counts) > 0,
                f'host ACK suppression did not drop an actual wire ACK: {counters!r}')
            raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            raw.bind(('kerhost', 0))
            inject_ack(raw, host_mac, syn1, synack1)
            Path(str(prefix) + '.command').write_text('ACCEPT1\n')
            first_done = read_state(prefix, 'FIRST_ACCEPTED', process)
            require(first_done == 'FIRST_ACCEPTED count=0',
                f'ACK completion left a request_sock counted: {first_done!r}')
            first.close()
            first_thread.join(5)
            require(not first_thread.is_alive() and not first_failures,
                f'Fast Open cookie-prime client failed: {first_failures!r}; pending={first_pending!r}')
            Path(str(prefix) + '.command').write_text('NEXT1\n')

            tfo_ready = read_state(prefix, 'TFO_READY', process)
            require(tfo_ready == 'TFO_READY count=0', tfo_ready)
            second, syn2, synack2, second_thread, second_failures, second_pending = connect_and_capture(
                capture, port, b'valid-tfo-cookie-payload')
            require(has_fastopen_cookie(syn2['options'], True) and syn2['payload'],
                f'second SYN did not carry cached TFO cookie and data: {syn2!r}')
            Path(str(prefix) + '.command').write_text('QUERY2\n')
            cookie_state = read_state(prefix, 'TFO_SYN', process)
            require(cookie_state == 'TFO_SYN count=0',
                f'valid-cookie TFO full SYN_RECV socket was incorrectly counted: {cookie_state!r}')
            counters = run(['nft', 'list', 'chain', 'inet', table, 'output'])
            counts = re.findall(r'counter packets (\d+) bytes (\d+)', counters)
            require(sum(int(item[0]) for item in counts) >= 2,
                f'ACK suppression did not reach both Fast Open handshakes: {counters!r}')
            inject_ack(raw, host_mac, syn2, synack2)
            Path(str(prefix) + '.command').write_text('ACCEPT2\n')
            tfo_done = read_state(prefix, 'TFO_ACCEPTED', process)
            require(tfo_done == 'TFO_ACCEPTED count=0', tfo_done)
            second_thread.join(5)
            require(not second_thread.is_alive() and not second_failures,
                f'valid-cookie TFO client failed: {second_failures!r}; pending={second_pending!r}')
            second.close(); raw.close()
            Path(str(prefix) + '.command').write_text('NEXT2\n')

            cookie_ready = read_state(prefix, 'COOKIE_READY', process)
            require(cookie_ready == 'COOKIE_READY count=0', cookie_ready)
            third, syn3, synack3, third_thread, third_failures, third_pending = \
                connect_and_capture(capture, port)
            Path(str(prefix) + '.command').write_text('QUERY3\n')
            cookie_state = read_state(prefix, 'COOKIE_SYN', process)
            require(cookie_state == 'COOKIE_SYN count=0',
                f'forced TCP syncookie SYN unexpectedly created a request_sock: {cookie_state!r}')
            counters = run(['nft', 'list', 'chain', 'inet', table, 'output'])
            counts = re.findall(r'counter packets (\d+) bytes (\d+)', counters)
            require(sum(int(item[0]) for item in counts) >= 3,
                f'forced-cookie ACK suppression did not observe the third handshake: {counters!r}')
            raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            raw.bind(('kerhost', 0))
            inject_ack(raw, host_mac, syn3, synack3)
            Path(str(prefix) + '.command').write_text('ACCEPT3\n')
            cookie_done = read_state(prefix, 'COOKIE_ACCEPTED', process)
            require(cookie_done == 'COOKIE_ACCEPTED count=0', cookie_done)
            third_thread.join(5)
            require(not third_thread.is_alive() and not third_failures,
                f'forced-cookie client failed: {third_failures!r}; pending={third_pending!r}')
            third.close(); raw.close()
            Path(str(prefix) + '.command').write_text('NEXT3\n')
            require(read_state(prefix, 'IPV6_READY', process) == 'IPV6_READY count=0',
                'fixture did not create its IPv6 owner listener')
            fourth, syn4, synack4, fourth_thread, fourth_failures, fourth_pending = \
                connect_and_capture(capture, port + 1, family=socket.AF_INET6,
                    server_address='2001:db8::2', host_address='2001:db8::1')
            Path(str(prefix) + '.command').write_text('QUERY4\n')
            v6_state = read_state(prefix, 'IPV6_SYN_REQUEST', process)
            require(v6_state == 'IPV6_SYN_REQUEST count=1',
                f'ACK-suppressed IPv6 SYN did not yield one owner request_sock: {v6_state!r}')
            counters = run(['nft', 'list', 'chain', 'inet', table, 'output'])
            counts = re.findall(r'counter packets (\d+) bytes (\d+)', counters)
            require(counts and sum(int(item[0]) for item in counts) >= 4,
                f'host ACK suppression did not observe IPv6 handshake: {counters!r}')
            raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            raw.bind(('kerhost', 0))
            inject_ack(raw, host_mac, syn4, synack4)
            # Stop filtering after the independently injected handshake ACK so
            # final ACK/FIN teardown can complete on the real host stack.
            run(['nft', 'flush', 'chain', 'inet', table, 'output'])
            fourth_thread.join(2)
            require(not fourth_thread.is_alive() and not fourth_failures,
                f'IPv6 connect did not finish after injected ACK: {fourth_failures!r}; '
                f'pending={fourth_pending!r}; syn={syn4!r}; synack={synack4!r}')
            Path(str(prefix) + '.command').write_text('ACCEPT4\n')
            v6_done = read_state(prefix, 'IPV6_ACCEPTED', process)
            require(v6_done == 'IPV6_ACCEPTED count=0',
                f'IPv6 ACK completion left request_sock counted: {v6_done!r}')
            Path(str(prefix) + '.command').write_text('NEXT4\n')
            fourth.close(); raw.close()
            require(read_state(prefix, 'DONE', process) == 'DONE count=0',
                'fixture did not close the listener cleanly')
            output, errors = process.communicate(timeout=20)
            require(process.returncode == 0,
                f'fixture failed: rc={process.returncode}; stdout={output!r}; stderr={errors!r}')
            require(json_outstanding(stats) == 0, 'LKL/DPDK worker did not cleanly stop')
        print('PASS: original-Linux IPv4/IPv6 owner request_sock queries, ACK completion, valid-cookie full TFO SYN_RECV exclusion, forced syncookie exclusion')
        return 0
    finally:
        capture.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
        if table_created:
            subprocess.run(['nft', 'delete', 'table', 'inet', table],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)


def json_outstanding(path):
    import json
    return json.loads(path.read_text()).get('outstanding')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'dpdk-plugin-dir', 'runtime-test'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'dpdk-plugin-dir', 'runtime-test'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command).returncode
    try:
        return inside(args)
    except BaseException as error:
        print(f'owner request runtime failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
