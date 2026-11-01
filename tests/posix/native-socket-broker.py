#!/usr/bin/env python3
"""Original-Linux socket and epoll capabilities survive frontend fork+exec."""
import argparse
import array
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def read_line(stream, timeout, process=None):
    selector = select.poll()
    selector.register(stream, select.POLLIN | select.POLLHUP | select.POLLERR)
    if not selector.poll(int(timeout * 1000)):
        raise RuntimeError('timed out waiting for frontend/broker output')
    line = stream.readline()
    if line:
        return line.rstrip(b'\n').decode(errors='replace')
    diagnostic = ''
    if process and process.stderr:
        diagnostic = process.stderr.read(8192).decode(errors='replace')
    raise RuntimeError('process exited before expected output: ' + diagnostic)


def recv_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        data = connection.recv(length - len(result))
        require(data, f'peer closed after {len(result)} of {length} expected bytes')
        result.extend(data)
    return bytes(result)


def reap_frontend_child(pid, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError as error:
            raise RuntimeError(f'frontend child {pid} was not reparented to the test supervisor') from error
        if waited == pid:
            require(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                f'frontend exec child exited abnormally: status={status}')
            return
        time.sleep(0.01)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    raise RuntimeError(f'frontend exec child {pid} did not exit')


def stop_frontend_children(pids):
    owned = sorted({pid for pid in pids if pid is not None})
    for pid in owned:
        try:
            os.kill(pid, signal.SIGQUIT)
        except ProcessLookupError:
            pass
    for pid in owned:
        try:
            reap_frontend_child(pid, 8)
        except BaseException:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    waited, _ = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if waited == pid:
                    break
                time.sleep(0.02)


def receive_bootstrap(connection):
    data, ancillary, flags, _ = connection.recvmsg(16, socket.CMSG_SPACE(3 * array.array('i').itemsize),
        socket.MSG_CMSG_CLOEXEC)
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'bootstrap capability frame was truncated')
    require(len(data) == 8, f'bootstrap record length differs: {data!r}')
    magic, version, count = struct.unpack('=IHH', data)
    require(magic == 0x4b534243 and version == 1 and count in (2, 3),
        f'bootstrap record differs: {data!r}')
    fds = []
    for level, kind, payload in ancillary:
        require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
            'bootstrap carried an unexpected ancillary record')
        values = array.array('i'); values.frombytes(payload[:len(payload) - len(payload) % values.itemsize])
        fds.extend(values.tolist())
    if len(fds) != count:
        for fd in fds:
            os.close(fd)
        raise RuntimeError(f'bootstrap delivered {len(fds)} capabilities, expected {count}')
    return fds


def receive_group_bootstrap(connection):
    data, ancillary, flags, _ = connection.recvmsg(16, socket.CMSG_SPACE(array.array('i').itemsize),
        socket.MSG_CMSG_CLOEXEC)
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'group bootstrap frame was truncated')
    require(data == struct.pack('=IHH', 0x4b534243, 1, 1),
        f'group bootstrap record differs: {data!r}')
    fds = []
    for level, kind, payload in ancillary:
        require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
            'group bootstrap carried unexpected ancillary data')
        values = array.array('i'); values.frombytes(payload[:len(payload) - len(payload) % values.itemsize])
        fds.extend(values.tolist())
    if len(fds) != 1:
        for fd in fds: os.close(fd)
        raise RuntimeError(f'group bootstrap delivered {len(fds)} capabilities, expected one')
    return fds


def census_command(process, command, timeout=10):
    try:
        process.stdin.write((command + '\n').encode())
        process.stdin.flush()
    except BrokenPipeError as error:
        output, errors = process.communicate(timeout=2)
        raise RuntimeError(f'member census client exited before command {command!r}: '
            f'rc={process.returncode}; stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
    return read_line(process.stdout, timeout, process)


def receive_metadata_fds(connection, expected_tag, expected_index=None, count=2):
    data, ancillary, flags, _ = connection.recvmsg(8,
        socket.CMSG_SPACE(array.array('i').itemsize * count), socket.MSG_CMSG_CLOEXEC)
    fds = []
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array('i')
            values.frombytes(payload[:len(payload) - len(payload) % values.itemsize])
            fds.extend(values.tolist())
    valid = not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    if expected_index is None:
        valid = valid and data == expected_tag and len(fds) == count
    else:
        valid = valid and data == bytes((ord(expected_tag), expected_index)) and len(fds) == 1
    if not valid:
        for fd in fds:
            os.close(fd)
        raise RuntimeError(f'invalid metadata capability transfer: data={data!r} flags={flags} fds={fds!r}')
    return fds


def census_observation(args, rpc_path, census_fds):
    result = subprocess.run([str(args.member_census_client), '--observe', str(rpc_path),
        str(census_fds[0]), str(census_fds[1])], pass_fds=tuple(census_fds),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    require(result.returncode == 0,
        f'metadata census query failed: stdout={result.stdout!r}; stderr={result.stderr!r}')
    lines = result.stdout.decode().splitlines()
    require(len(lines) == 2, f'metadata census emitted malformed results: {lines!r}')
    return [parse_census_line(line) for line in lines]


def tcp_observation(args, rpc_path, observer_fd):
    result = subprocess.run([str(args.member_census_client), '--tcp-observe', str(rpc_path),
        str(observer_fd)], pass_fds=(observer_fd,), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=10)
    require(result.returncode == 0,
        f'TCP send-queue observer failed: stdout={result.stdout!r}; stderr={result.stderr!r}')
    line = result.stdout.decode().strip()
    require(line.startswith('TCP_OBSERVER '), f'malformed TCP observer result: {line!r}')
    return {key: int(value, 0) for key, value in
        (item.split('=', 1) for item in line.split()[1:])}


def census_nft(*arguments):
    result = subprocess.run(['nft', *arguments], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=10)
    require(result.returncode == 0,
        f'nft {arguments!r} failed: {result.stderr.strip()}')
    return result.stdout


def checksum16(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ipv4_tcp_frame(frame):
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0f) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or ip[9] != socket.IPPROTO_TCP or len(ip) < ihl + 20:
        return None
    total = struct.unpack_from('!H', ip, 2)[0]
    if total < ihl + 20 or total > len(ip):
        return None
    tcp = ip[ihl:total]
    data_offset = (tcp[12] >> 4) * 4
    if data_offset < 20 or len(tcp) < data_offset:
        return None
    return {
        'eth_src': frame[6:12], 'eth_dst': frame[0:6],
        'src': socket.inet_ntoa(ip[12:16]), 'dst': socket.inet_ntoa(ip[16:20]),
        'sport': struct.unpack_from('!H', tcp, 0)[0],
        'dport': struct.unpack_from('!H', tcp, 2)[0],
        'seq': struct.unpack_from('!I', tcp, 4)[0],
        'ack': struct.unpack_from('!I', tcp, 8)[0],
        'flags': tcp[13], 'options': tcp[20:data_offset],
        'payload': tcp[data_offset:],
    }


def tcp_timestamp(options):
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 2 > len(options):
            break
        length = options[index + 1]
        if length < 2 or index + length > len(options):
            break
        if kind == 8 and length == 10:
            return struct.unpack_from('!II', options, index + 2)
        index += length
    return None


def inject_tcp_ack(packet, template, ack_number, sack=None):
    options = b''
    timestamp = tcp_timestamp(template['options'])
    if timestamp:
        echo = tcp_timestamp(packet['options'])
        options = b'\x01\x01\x08\x0a' + struct.pack('!II',
            (timestamp[0] + 1) & 0xffffffff, echo[0] if echo else 0)
    if sack:
        if not options:
            options = b'\x01\x01'
        options += b'\x05\x0a' + struct.pack('!II', sack[0], sack[1])
        options += b'\x01' * (-len(options) % 4)
    tcp = bytearray(struct.pack('!HHIIBBHHH', template['sport'], template['dport'],
        (template['seq'] + 1) & 0xffffffff, ack_number, ((20 + len(options)) // 4) << 4,
        0x10, 65535, 0, 0) + options)
    source = socket.inet_aton(template['src'])
    destination = socket.inet_aton(template['dst'])
    pseudo = source + destination + b'\0\x06' + struct.pack('!H', len(tcp))
    struct.pack_into('!H', tcp, 16, checksum16(pseudo + tcp))
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp),
        0, 0x4000, 64, socket.IPPROTO_TCP, 0, source, destination))
    struct.pack_into('!H', ip, 10, checksum16(ip))
    return packet['eth_src'] + packet['eth_dst'] + b'\x08\x00' + ip + tcp


def wait_payload_state(prefix, expected, process, timeout=12):
    path = Path(str(prefix) + '.state')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            value = path.read_text().strip()
            if value.startswith(expected):
                return value
        if process.poll() is not None:
            output, errors = process.communicate()
            raise RuntimeError(f'payload runtime exited before {expected}: {process.returncode}; '
                f'stdout={output!r}; stderr={errors!r}')
        time.sleep(0.01)
    raise RuntimeError(f'timed out waiting for payload runtime state {expected}')


def tcp_sack_permitted(options):
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 2 > len(options):
            break
        length = options[index + 1]
        if length < 2 or index + length > len(options):
            break
        if kind == 4 and length == 2:
            return True
        index += length
    return False


def run_payload_snapshot_wire_probe(args, eal, root):
    port = 43891
    table = f'ker_payload_{os.getpid()}'
    prefix = root / 'payload-control'
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sack_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    process = None
    peer = None
    sack_peer = None
    table_created = False
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('198.18.0.1', port)); listener.listen(1); listener.settimeout(20)
        sack_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sack_listener.bind(('198.18.0.1', port + 1)); sack_listener.listen(1)
        sack_listener.settimeout(20)
        capture.bind(('kerhost', 0)); capture.settimeout(0.25)
        census_nft('add', 'table', 'inet', table); table_created = True
        census_nft('add', 'chain', 'inet', table, 'output', '{', 'type', 'filter',
            'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}')
        census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
            'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
            'tcp', 'sport', str(port), 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
        census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
            'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
            'tcp', 'sport', str(port + 1), 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
        command = [sys.executable, str(args.launcher), '--library',
            str(args.member_census_test_library), '--io-worker', str(args.worker),
            '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
            '--stats', str(root / 'stats.json'), '--', str(args.member_census_runtime_test)]
        environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
            'RUNTIME_DIRECTORY': str(root), 'KER_C9_PAYLOAD_CONTROL': str(prefix),
            'KER_C9_PAYLOAD_PORT': str(port), 'KER_C9_PAYLOAD_SACK_PORT': str(port + 1)}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
        peer, _ = listener.accept()
        peer.settimeout(2)
        synack = None
        data = None
        fin = None
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and (synack is None or data is None or fin is None):
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = ipv4_tcp_frame(frame)
            if not packet:
                continue
            if packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
                    packet['sport'] == port and packet['flags'] & 0x12 == 0x12:
                synack = packet
            if packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['dport'] == port and len(packet['payload']) == 1200:
                data = packet
                if packet['flags'] & 0x01:
                    fin = packet
            if packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['dport'] == port and packet['flags'] & 0x01:
                fin = packet
        require(synack is not None and data is not None and fin is not None,
            f'could not capture real TCP SYN-ACK/data/FIN: synack={synack} data={data} fin={fin}')
        expected_payload = bytes((index * 17 + 3) & 0xff for index in range(1200))
        require(data['payload'] == expected_payload,
            'captured original-Linux TCP payload differs from the generated test bytes')
        require(fin['seq'] == (data['seq'] + len(data['payload'])) & 0xffffffff,
            f'captured FIN did not immediately follow the payload: data={data} fin={fin}')
        require(wait_payload_state(prefix, 'READY', process).startswith('READY'),
            'payload process did not close its last application descriptor')
        rule = census_nft('list', 'chain', 'inet', table, 'output')
        counter = re.search(r'counter packets (\d+) bytes (\d+)', rule)
        require(counter is not None and int(counter.group(1)) > 0,
            f'nft did not drop a real ACK-only packet: {rule!r}')
        ack_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        ack_socket.bind(('kerhost', 0))
        try:
            partial = 137
            ack_socket.send(inject_tcp_ack(data, synack,
                (data['seq'] + partial) & 0xffffffff))
            Path(str(prefix) + '.command').write_text('PARTIAL\n')
            partial_state = wait_payload_state(prefix, 'PARTIAL', process)
            partial_values = dict(item.split('=') for item in partial_state.split()[1:])
            require(int(partial_values['bytes']) == 1200 - partial and
                int(partial_values['sockets']) == 1,
                f'partial ACK did not leave the exact queued suffix: {partial_state!r}')
            ack_socket.send(inject_tcp_ack(data, synack, (data['seq'] + 1200) & 0xffffffff))
            Path(str(prefix) + '.command').write_text('FULL\n')
            full_state = wait_payload_state(prefix, 'FULL', process)
            full_values = dict(item.split('=') for item in full_state.split()[1:])
            require(int(full_values['bytes']) == 0 and int(full_values['sockets']) == 1,
                f'full payload ACK did not leave only the queued FIN control byte: {full_state!r}')
            ack_socket.send(inject_tcp_ack(data, synack, (data['seq'] + 1201) & 0xffffffff))
            Path(str(prefix) + '.command').write_text('FINACK\n')
        finally:
            ack_socket.close()
        sack_peer, _ = sack_listener.accept()
        sack_peer.settimeout(2)
        sack_synack = None
        sack_segments = {}
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and (sack_synack is None or
                sum(len(item['payload']) for item in sack_segments.values()) < 1200 or
                len(sack_segments) < 3):
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = ipv4_tcp_frame(frame)
            if not packet:
                continue
            if packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
                    packet['sport'] == port + 1 and packet['flags'] & 0x12 == 0x12:
                sack_synack = packet
            if packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['dport'] == port + 1 and packet['payload']:
                sack_segments[packet['seq']] = packet
        sack_base = sack_synack['ack'] if sack_synack else 0
        segments = sorted(sack_segments.values(),
            key=lambda item: (item['seq'] - sack_base) & 0xffffffff)
        require(sack_synack is not None and len(segments) >= 3 and
            sum(len(item['payload']) for item in segments) == 1200,
            f'could not capture three MSS-bounded payload segments: synack={sack_synack} '
            f'segments={[(p["seq"], len(p["payload"])) for p in segments]}')
        require(tcp_sack_permitted(sack_synack['options']),
            f'peer did not negotiate SACK: {sack_synack["options"]!r}')
        require(segments[0]['seq'] == sack_base and all(
            segments[index]['seq'] == (segments[index - 1]['seq'] +
                len(segments[index - 1]['payload'])) & 0xffffffff
            for index in range(1, len(segments))),
            f'captured data sequence ranges are not contiguous: '
            f'{[(p["seq"], len(p["payload"])) for p in segments]}')
        expected_sack_payload = bytes((index * 29 + 11) & 0xff for index in range(1200))
        observed_sack_payload = b''.join(packet['payload'] for packet in segments)
        require(observed_sack_payload == expected_sack_payload,
            'captured SACK-flow payload does not match the generated bytes')
        sack_rule = census_nft('list', 'chain', 'inet', table, 'output')
        sack_counters = re.findall(r'counter packets (\d+) bytes (\d+)', sack_rule)
        require(len(sack_counters) == 2 and int(sack_counters[1][0]) > 0,
            f'ACK suppression counter missing for SACK flow: {sack_rule!r}')
        sack_ack = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sack_ack.bind(('kerhost', 0))
        try:
            middle = segments[1]
            sack_ack.send(inject_tcp_ack(middle, sack_synack, sack_base,
                (middle['seq'], (middle['seq'] + len(middle['payload'])) & 0xffffffff)))
            Path(str(prefix) + '.command').write_text('SACK\n')
            sack_state = wait_payload_state(prefix, 'SACK bytes=', process)
            sack_values = dict(item.split('=') for item in sack_state.split()[1:])
            require(int(sack_values['bytes']) == 1200 and int(sack_values['sockets']) == 1 and
                int(sack_values['sacked']) > 0,
                f'SACK-only ACK was not processed without advancing queued payload: {sack_state!r}')
            sack_ack.send(inject_tcp_ack(segments[-1], sack_synack,
                (sack_base + 1200) & 0xffffffff))
            Path(str(prefix) + '.command').write_text('SACK_FULL\n')
            full_sack_state = wait_payload_state(prefix, 'SACK_FULL', process)
            full_sack_values = dict(item.split('=') for item in full_sack_state.split()[1:])
            require(int(full_sack_values['bytes']) == 0,
                f'cumulative ACK after SACK left payload: {full_sack_state!r}')
            sack_fin = None
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and sack_fin is None:
                try:
                    frame, _ = capture.recvfrom(65535)
                except TimeoutError:
                    continue
                packet = ipv4_tcp_frame(frame)
                if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                        packet['dport'] == port + 1 and packet['flags'] & 0x01:
                    sack_fin = packet
            require(sack_fin is not None and sack_fin['seq'] == (sack_base + 1200) & 0xffffffff,
                f'SACK flow close did not emit its expected FIN: {sack_fin}')
            sack_ack.send(inject_tcp_ack(segments[-1], sack_synack,
                (sack_base + 1201) & 0xffffffff))
            Path(str(prefix) + '.command').write_text('FINACK2\n')
        finally:
            sack_ack.close()
        output, errors = process.communicate(timeout=20)
        require(process.returncode == 0 and 'C9_PAYLOAD_PARTIAL_ACK_ORPHAN_OK' in output,
            f'payload runtime failed: stdout={output!r}; stderr={errors!r}')
        print(f'C9_PAYLOAD_WIRE_OK captured=1200 partial_ack=137 remaining=1063 '
            f'full_ack=0 fin_seq={fin["seq"]} dropped_ack_packets={counter.group(1)} '
            f'sack_segments={len(segments)} sack_drop_packets={sack_counters[1][0]} '
            f'sack_only_bytes={sack_values["bytes"]} '
            f'tcpi_sacked={sack_values["sacked"]} descriptorless=true')
    finally:
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        if peer is not None:
            peer.close()
        if sack_peer is not None:
            sack_peer.close()
        if table_created:
            try: census_nft('delete', 'table', 'inet', table)
            except (OSError, subprocess.SubprocessError, RuntimeError): pass
        capture.close(); listener.close(); sack_listener.close()


def run_ff_owner_payload_probe(args, rpc_path, capabilities):
    ports = (43901, 43902, 43903, 43904)
    lengths = (1200, 700, 900, 1100)
    seeds = (3, 19, 31, 47)
    table = f'ker_ff_owner_{os.getpid()}'
    listeners = []
    peers = []
    processes = []
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    inbound_capture = None
    table_created = False
    try:
        for port in ports:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('198.18.0.1', port)); listener.listen(1); listener.settimeout(20)
            listeners.append(listener)
        capture.bind(('kerhost', 0)); capture.settimeout(0.25)
        census_nft('add', 'table', 'inet', table); table_created = True
        census_nft('add', 'chain', 'inet', table, 'output', '{', 'type', 'filter',
            'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}')
        for port in ports:
            census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
                'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
                'tcp', 'sport', str(port), 'tcp', 'flags', '&',
                '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')

        environment = os.environ | {
            'LD_PRELOAD': f'{args.fstack_runtime.resolve()}:{args.preload_library.resolve()}',
            'KER_SOCKET_BROKER_PATH': str(rpc_path),
            'PYTHONDONTWRITEBYTECODE': '1',
        }
        legacy = subprocess.run([str(args.ff_owner_payload_client), '--legacy-history'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=20)
        require(legacy.returncode == 0 and
            b'OWNER_BEGIN_REFUSED_AFTER_LEGACY_HISTORY\n' in legacy.stdout,
            f'owner begin accepted closed legacy socket history: rc={legacy.returncode}; '
            f'stdout={legacy.stdout!r}; stderr={legacy.stderr!r}')
        missing_owner = subprocess.run([str(args.ff_owner_payload_client),
            '--syncache-without-owner'], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=environment, timeout=10)
        require(missing_owner.returncode == -signal.SIGABRT and
            b'ker fstack request-sock snapshot failed:' in missing_owner.stderr,
            f'syncache count succeeded without an authenticated owner: '
            f'rc={missing_owner.returncode}; stderr={missing_owner.stderr!r}')
        foreign = subprocess.run([str(args.ff_owner_payload_client), '--foreign-history'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=20)
        require(foreign.returncode == -signal.SIGABRT and
            b'ker fstack request-sock snapshot failed:' in foreign.stderr,
            f'owner request gate accepted closed generic socket history: '
            f'rc={foreign.returncode}; stdout={foreign.stdout!r}; stderr={foreign.stderr!r}')
        exec_history = subprocess.run([str(args.ff_owner_payload_client),
            '--foreign-history-exec'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=20)
        require(exec_history.returncode == 0 and
            b'OWNER_REBEGIN_REFUSED_AFTER_EXEC_HISTORY\n' in exec_history.stdout,
            f'owner re-begin forgot broker-side history across exec/reconnect: '
            f'rc={exec_history.returncode}; stdout={exec_history.stdout!r}; '
            f'stderr={exec_history.stderr!r}')
        for port, size, seed in zip(ports[:2], lengths[:2], seeds[:2]):
            process = subprocess.Popen([str(args.ff_owner_payload_client),
                '--owner-payload', str(port), str(size), str(seed)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
            processes.append(process)
        exec_process = subprocess.Popen([str(args.ff_owner_payload_client),
            '--owner-reexec', str(ports[2]), str(lengths[2]), str(seeds[2])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, bufsize=0)
        processes.append(exec_process)
        legacy_process = subprocess.Popen([str(args.ff_owner_payload_client),
            '--legacy-payload-reexec', str(ports[3]), str(lengths[3]), str(seeds[3])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, bufsize=0)
        processes.append(legacy_process)
        owner_listener_ports = []
        for port in ports:
            listeners[ports.index(port)].settimeout(1)
            deadline = time.monotonic() + 20
            while True:
                try:
                    peer, _ = listeners[ports.index(port)].accept()
                    break
                except TimeoutError:
                    dead = [process for process in processes if process.poll() is not None]
                    if dead:
                        details = []
                        for process in dead:
                            output, errors = process.communicate()
                            details.append((process.returncode, output, errors))
                        raise RuntimeError(f'FF owner process exited before connect: {details!r}')
                    if time.monotonic() >= deadline:
                        raise RuntimeError('FF owner process did not connect within 20 seconds')
            peer.settimeout(10); peers.append(peer)
        for process in processes[:2]:
            listener_line = read_line(process.stdout, 30, process)
            require(listener_line.startswith('OWNER_LISTENER '),
                f'FF owner did not publish its marked listener: {listener_line!r}')
            owner_listener_ports.append(int(listener_line.split()[1]))
            require(read_line(process.stdout, 30, process) == 'OWNER_READY',
                'FF owner client did not close its last application descriptor')
        require(read_line(exec_process.stdout, 30, exec_process) == 'OWNER_EXEC_READY',
            'FF owner exec client did not close its application descriptor before exec')
        require(read_line(legacy_process.stdout, 30, legacy_process) ==
            'OWNER_LEGACY_EXEC_READY',
            'legacy generic client did not close its application descriptor before exec')
        require(read_line(legacy_process.stdout, 20, legacy_process) ==
            'OWNER_REBEGIN_REFUSED_AFTER_EXEC_HISTORY',
            'owner re-begin did not reject legacy payload history after exec')
        for process in processes[:3]:
            process.stdin.write(b'Q'); process.stdin.flush()
        request_counts = []
        for process in processes[:3]:
            line = read_line(process.stdout, 15, process)
            require(line.startswith('OWNER_REQUESTS '),
                f'unexpected FF owner request-count response: {line!r}')
            request_counts.append(int(line.split()[1]))
        require(request_counts == [0, 0, 0],
            f'authenticated FF owner request counts were not empty before inbound SYNs: {request_counts!r}')
        owner_listener_port = owner_listener_ports[0]
        census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
            'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
            'tcp', 'dport', str(owner_listener_port), 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
        link = subprocess.run(['ip', '-o', 'link', 'show', 'kerhost'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        require(link.returncode == 0, f'could not read host veth identity: {link.stderr}')
        host_mac = bytes.fromhex(re.search(r'link/ether ([0-9a-f:]+)', link.stdout)
            .group(1).replace(':', ''))
        host_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_client.settimeout(10)
        inbound_capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        inbound_capture.bind(('kerhost', 0)); inbound_capture.settimeout(0.25)
        connect_errors = []
        def connect_owner_listener():
            try: host_client.connect(('198.18.0.2', owner_listener_port))
            except BaseException as error: connect_errors.append(error)
        connect_thread = threading.Thread(target=connect_owner_listener, daemon=True)
        connect_thread.start()
        inbound_syn = inbound_synack = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and inbound_synack is None:
            try: frame, _ = inbound_capture.recvfrom(65535)
            except TimeoutError: continue
            item = ipv4_tcp_frame(frame)
            if not item: continue
            if item['src'] == '198.18.0.1' and item['dst'] == '198.18.0.2' and \
                    item['dport'] == owner_listener_port and item['flags'] & 0x02:
                inbound_syn = item
            if item['src'] == '198.18.0.2' and item['dst'] == '198.18.0.1' and \
                    item['sport'] == owner_listener_port and item['flags'] & 0x12 == 0x12:
                inbound_synack = item
        require(inbound_syn is not None and inbound_synack is not None,
            f'owner listener did not exchange wire SYN/SYN-ACK: syn={inbound_syn!r} '
            f'synack={inbound_synack!r}; errors={connect_errors!r}')
        rule_text = census_nft('-a', 'list', 'chain', 'inet', table, 'output')
        rule_line = next((line for line in rule_text.splitlines()
            if f'tcp dport {owner_listener_port}' in line), None)
        require(rule_line is not None and
            (counter := re.search(r'counter packets (\d+)', rule_line)) is not None and
            int(counter.group(1)) > 0,
            f'host ACK suppression did not drop the owner handshake ACK: {rule_text!r}')
        query = processes[0]
        query.stdin.write(b'Q'); query.stdin.flush()
        request_line = read_line(query.stdout, 15, query)
        require(request_line == 'OWNER_REQUESTS 1',
            f'authenticated owner did not report its real marked request_sock: {request_line!r}')
        isolated_counts = []
        for process in processes[1:3]:
            process.stdin.write(b'Q'); process.stdin.flush()
            line = read_line(process.stdout, 15, process)
            require(line.startswith('OWNER_REQUESTS '),
                f'unexpected other-owner request response: {line!r}')
            isolated_counts.append(int(line.split()[1]))
        require(isolated_counts == [0, 0],
            f'one owner request leaked into other process counts: {isolated_counts!r}')
        ack_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        ack_socket.bind(('kerhost', 0))
        ack_socket.send(inject_tcp_ack(inbound_syn, inbound_synack,
            (inbound_synack['seq'] + 1) & 0xffffffff))
        handle = re.search(r'# handle (\d+)$', rule_line)
        require(handle is not None, f'could not identify temporary ACK rule: {rule_line!r}')
        census_nft('delete', 'rule', 'inet', table, 'output', 'handle', handle.group(1))
        inbound_capture.close()
        connect_thread.join(5)
        require(not connect_thread.is_alive() and not connect_errors,
            f'host connect did not complete after raw ACK: {connect_errors!r}')
        request_line = None
        for _ in range(100):
            query.stdin.write(b'Q'); query.stdin.flush()
            request_line = read_line(query.stdout, 15, query)
            if request_line == 'OWNER_REQUESTS 0': break
            require(request_line == 'OWNER_REQUESTS 1',
                f'authenticated owner returned an invalid post-ACK count: {request_line!r}')
            time.sleep(0.01)
        require(request_line == 'OWNER_REQUESTS 0',
            f'authenticated owner request count did not clear after ACK: {request_line!r}')
        query.stdin.write(b'A'); query.stdin.flush()
        require(read_line(query.stdout, 15, query) == 'OWNER_ACCEPTED',
            'FF owner did not accept the completed handshake')
        ack_socket.close(); host_client.close()
        for fd in capabilities:
            os.close(fd)
        capabilities.clear()

        synacks = {}
        data_segments = {port: {} for port in ports}
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and any(
                not synacks.get(port) or sum(len(packet['payload'])
                    for packet in data_segments[port].values()) < lengths[index]
                for index, port in enumerate(ports)):
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = ipv4_tcp_frame(frame)
            if not packet:
                continue
            for port in ports:
                if packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
                        packet['sport'] == port and packet['flags'] & 0x12 == 0x12:
                    synacks[port] = packet
                if packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                        packet['dport'] == port and packet['payload']:
                    data_segments[port][packet['seq']] = packet
        for index, port in enumerate(ports):
            segments = sorted(data_segments[port].values(),
                key=lambda item: (item['seq'] - synacks[port]['ack']) & 0xffffffff)
            require(port in synacks and sum(len(packet['payload']) for packet in segments) == lengths[index],
                f'owner {index} did not emit its complete TCP payload: {segments!r}')
            observed = b''.join(packet['payload'] for packet in segments)
            expected = bytes((offset * 17 + seeds[index] * 29 + 3) & 0xff
                for offset in range(lengths[index]))
            require(observed == expected, f'owner {index} wire payload differs from source bytes')
            require(recv_exact(peers[index], lengths[index]) == expected,
                f'host peer did not receive owner {index} original-Linux stream')

        legacy_output, legacy_errors = legacy_process.communicate(timeout=10)
        require(legacy_process.returncode == 0,
            f'legacy payload re-begin failed: rc={legacy_process.returncode}; '
            f'stdout={legacy_output!r}; stderr={legacy_errors!r}')

        rule_text = census_nft('list', 'chain', 'inet', table, 'output')
        counters = re.findall(r'counter packets (\d+) bytes (\d+)', rule_text)
        require(len(counters) == len(ports) and all(int(item[0]) > 0 for item in counters),
            f'ACK suppression did not count real packets for every owner: {rule_text!r}')

        ack_sockets = []
        owner_processes = processes[:3]
        try:
            for _ in ports:
                ack = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                ack.bind(('kerhost', 0)); ack_sockets.append(ack)
            first = min(data_segments[ports[0]].values(), key=lambda p: (p['seq'] - synacks[ports[0]]['ack']) & 0xffffffff)
            second = min(data_segments[ports[1]].values(), key=lambda p: (p['seq'] - synacks[ports[1]]['ack']) & 0xffffffff)
            ack_sockets[0].send(inject_tcp_ack(first, synacks[ports[0]],
                (first['seq'] + 137) & 0xffffffff))
            for process in owner_processes:
                process.stdin.write(b'S'); process.stdin.flush()
            values = []
            for process in owner_processes:
                line = read_line(process.stdout, 15, process)
                require(line.startswith('OWNER_SNAPSHOT '), f'unexpected owner snapshot response: {line!r}')
                values.append(int(line.split()[1]))
            require(values == [lengths[0] - 137, lengths[1], lengths[2]],
                f'FF owner mark snapshots were not process-isolated after partial ACK: {values!r}')

            ack_sockets[0].send(inject_tcp_ack(first, synacks[ports[0]],
                (first['seq'] + lengths[0]) & 0xffffffff))
            for process in owner_processes:
                process.stdin.write(b'S'); process.stdin.flush()
            values = [int(read_line(process.stdout, 15, process).split()[1])
                for process in owner_processes]
            require(values == [0, lengths[1], lengths[2]],
                f'first process full ACK changed another process owner snapshot: {values!r}')

            ack_sockets[1].send(inject_tcp_ack(second, synacks[ports[1]],
                (second['seq'] + lengths[1]) & 0xffffffff))
            for process in owner_processes:
                process.stdin.write(b'S'); process.stdin.flush()
            values = [int(read_line(process.stdout, 15, process).split()[1])
                for process in owner_processes]
            require(values == [0, 0, lengths[2]],
                f'second process full ACK changed exec-owner payload: {values!r}')

            third = min(data_segments[ports[2]].values(),
                key=lambda p: (p['seq'] - synacks[ports[2]]['ack']) & 0xffffffff)
            ack_sockets[2].send(inject_tcp_ack(third, synacks[ports[2]],
                (third['seq'] + 100) & 0xffffffff))
            for process in owner_processes:
                process.stdin.write(b'S'); process.stdin.flush()
            values = [int(read_line(process.stdout, 15, process).split()[1])
                for process in owner_processes]
            require(values == [0, 0, lengths[2] - 100],
                f'owner payload was lost or cross-counted across exec reinitialization: {values!r}')
            ack_sockets[2].send(inject_tcp_ack(third, synacks[ports[2]],
                (third['seq'] + lengths[2]) & 0xffffffff))
            for process in owner_processes:
                process.stdin.write(b'S'); process.stdin.flush()
            values = [int(read_line(process.stdout, 15, process).split()[1])
                for process in owner_processes]
            require(values == [0, 0, 0],
                f'full ACK did not clear exec-owner payload after re-begin: {values!r}')
            legacy_packet = min(data_segments[ports[3]].values(),
                key=lambda p: (p['seq'] - synacks[ports[3]]['ack']) & 0xffffffff)
            ack_sockets[3].send(inject_tcp_ack(legacy_packet, synacks[ports[3]],
                (legacy_packet['seq'] + lengths[3]) & 0xffffffff))
        finally:
            for ack in ack_sockets:
                ack.close()

        for process in owner_processes:
            process.stdin.write(b'E'); process.stdin.flush()
        for process in owner_processes:
            output, errors = process.communicate(timeout=20)
            require(process.returncode == 0 and b'OWNER_DONE\n' in output,
                f'FF owner process failed: rc={process.returncode}; stdout={output!r}; stderr={errors!r}')
        print(f'C13_FF_SYNCACHE_COUNT_OK owner_listener={owner_listener_port} '
            f'wire_count=1->0 isolated={isolated_counts!r} '
            f'C12_FF_OWNER_PAYLOAD_OK owner_pids={[p.pid for p in processes]} '
            f'partial_ack=137 exec_rebegin=true snapshots={values!r} descriptorless=true '
            f'ack_drop_packets={[item[0] for item in counters]}')
    finally:
        if inbound_capture is not None:
            inbound_capture.close()
        for process in processes:
            if process.poll() is None:
                process.kill(); process.wait()
        for peer in peers:
            peer.close()
        if table_created:
            try: census_nft('delete', 'table', 'inet', table)
            except (OSError, subprocess.SubprocessError, RuntimeError): pass
        capture.close()
        for listener in listeners:
            listener.close()


def parse_census_line(line):
    fields = {}
    for item in line.split()[2:]:
        if '=' in item:
            name, value = item.split('=', 1)
            fields[name] = int(value, 0)
    return fields


def receive_pressure_pattern(connection, size):
    payload = recv_exact(connection, size)
    expected = bytes((index * 17 + 3) & 0xff for index in range(size))
    require(payload == expected,
        'host did not receive the exact queued original-Linux send prefix after descriptor close')
    require(connection.recv(1) == b'', 'original Linux send queue did not end in orderly FIN')


def census_accept(process, member, slot):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = census_command(process, f'ACCEPT {member} {slot}', 5)
        parts = response.split()
        require(len(parts) == 5 and parts[:3] == ['ACCEPT', str(member), str(slot)],
            f'bad original Linux accept result: {response!r}')
        if int(parts[3]) >= 0:
            return
        require(int(parts[4]) in (errno.EAGAIN, errno.EWOULDBLOCK),
            f'original Linux accept failed: {response!r}')
        time.sleep(0.01)
    raise RuntimeError(f'listener {member} did not accept its completed TCP handshake')


def run_member_census_client(args, rpc_path, broker, capability):
    supervisor, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    supervisor.settimeout(20)
    client = subprocess.Popen([str(args.member_census_client), str(rpc_path), str(capability),
        str(child_control.fileno())], pass_fds=(capability, child_control.fileno()),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    os.close(capability)
    child_control.close()
    census_fds = []
    observer_fds = []
    table = f'ker_census_{os.getpid()}'
    table_created = False
    rule_installed = False
    peers = []
    try:
        census_fds = receive_metadata_fds(supervisor, b'C', count=2)
        require(read_line(client.stdout, 20, client) == 'CENSUS_CLIENT_READY',
            'member census client did not create member/listener metadata handles')
        first = census_command(client, 'SNAP')
        second = read_line(client.stdout, 10, client)
        first_values = parse_census_line(first)
        second_values = parse_census_line(second)
        require(first_values.get('listen') == 1 and second_values.get('listen') == 1 and
            first_values.get('cookie') and second_values.get('cookie') and
            first_values['cookie'] != second_values['cookie'],
            f'census did not isolate both original Linux listeners: {first!r} {second!r}')

        census_nft('add', 'table', 'inet', table)
        table_created = True
        census_nft('add', 'chain', 'inet', table, 'output',
            '{', 'type', 'filter', 'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}')
        census_nft('add', 'rule', 'inet', table, 'output',
            'oifname', 'kerhost',
            'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
            'tcp', 'dport', '4097',
            'tcp', 'sport', '43123', 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
        rule_installed = True
        pending = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pending.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        pending.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        pending.bind(('198.18.0.1', 43123))
        pending.setblocking(False)
        result = pending.connect_ex(('198.18.0.2', 4097))
        require(result in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK),
            f'normal TCP connect failed before SYN_RECV observation: {result}')
        peers.append(pending)
        wait_syn = census_command(client, 'WAIT 3 1 7000', 10)
        require(wait_syn == 'WAIT 3 FOUND',
            f'original Linux did not report the ACK-blocked normal TCP SYN_RECV: {wait_syn!r}')
        before_select = census_observation(args, rpc_path, census_fds)
        require(before_select[0].get('synrecv') == 1 and before_select[1].get('synrecv') == 0,
            f'ACK-blocked SYN_RECV was not isolated to member0: {before_select!r}')
        rule_text = census_nft('list', 'chain', 'inet', table, 'output')
        rule_counter = re.search(r'counter packets (\d+) bytes (\d+)', rule_text)
        require(rule_counter is not None and int(rule_counter.group(1)) > 0,
            f'ACK-drop rule did not count a real matching packet: {rule_text!r}')
        selected = census_command(client, 'SELECT 1')
        require(selected == 'SELECT 1 0 0', f'could not flip listener selection during SYN_RECV: {selected!r}')
        after_select = census_observation(args, rpc_path, census_fds)
        require(after_select[0].get('synrecv') == 1 and after_select[1].get('synrecv') == 0,
            f'SYN_RECV did not remain on old member after selector flip: {after_select!r}')
        census_nft('delete', 'table', 'inet', table)
        table_created = False
        rule_installed = False
        _, writable, exceptional = select.select([], [pending], [pending], 8)
        require(writable and not exceptional and pending.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
            'ordinary TCP handshake did not complete after allowing its real ACK')
        census_accept(client, 0, 0)
        pending.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        fill0 = census_command(client, 'FILL 0', 30).split()
        require(len(fill0) == 8 and fill0[0] == 'FILL' and fill0[1] == '0' and
            int(fill0[2]) > 0 and int(fill0[3]) > 0 and int(fill0[4]) == 0 and
            int(fill0[5]) == 0 and int(fill0[6]) > 0 and int(fill0[7]) > 0,
            f'original Linux member0 sender did not reach EAGAIN: {fill0!r}')
        sent0 = int(fill0[2])
        observer_fds.append(receive_metadata_fds(supervisor, 'O', 0, count=1)[0])
        require(census_command(client, 'CLOSE 0') == 'CLOSE 0 0 0',
            'could not close old accepted TCP descriptor after native send pressure')

        fresh = socket.create_connection(('198.18.0.2', 4097), timeout=8)
        fresh.settimeout(8); fresh.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096); peers.append(fresh)
        census_accept(client, 1, 1)
        fill1 = census_command(client, 'FILL 1', 30).split()
        require(len(fill1) == 8 and fill1[0] == 'FILL' and fill1[1] == '1' and
            int(fill1[2]) > 0 and int(fill1[3]) > 0 and int(fill1[4]) == 0 and
            int(fill1[5]) == 0 and int(fill1[6]) > 0 and int(fill1[7]) > 0,
            f'original Linux member1 sender did not reach EAGAIN: {fill1!r}')
        sent1 = int(fill1[2])
        observer_fds.append(receive_metadata_fds(supervisor, 'O', 1, count=1)[0])
        require(census_command(client, 'CLOSE 1') == 'CLOSE 1 0 0',
            'could not close new accepted TCP descriptor after native send pressure')

        require(census_command(client, 'CLOSE_GROUP') == 'GROUP_CLOSED',
            'could not release group/member descriptors while metadata handles persist')
        require(census_command(client, 'QUIT') == 'CENSUS_CLIENT_DONE',
            'native TCP worker did not exit after closing every accepted/group/member descriptor')
        output, errors = client.communicate(timeout=20)
        require(client.returncode == 0,
            f'member census client failed: stdout={output!r}; stderr={errors.decode(errors="replace")}')

        # The worker has exited and all its native socket descriptors are
        # closed. Supervisor-held metadata capabilities are the only remaining
        # references while the host delays reads from both streams.
        before_drain = census_observation(args, rpc_path, census_fds)
        for index, values in enumerate(before_drain):
            require(values.get('listen') == 0 and
                (values.get('finwait1', 0) + values.get('closing', 0) + values.get('lastack', 0)) > 0,
                f'metadata did not observe descriptorless closing TCP on member {index}: {values!r}')
        for index, observer_fd in enumerate(observer_fds):
            state = tcp_observation(args, rpc_path, observer_fd)
            require(state.get('present') == 1 and state.get('send_queue', 0) > 0,
                f'original-Linux accepted send queue was not observable before drain, member {index}: {state!r}')

        pending.settimeout(10); fresh.settimeout(10)
        receive_pressure_pattern(pending, sent0)
        receive_pressure_pattern(fresh, sent1)
        pending.close(); peers.remove(pending)
        fresh.close(); peers.remove(fresh)

        deadline = time.monotonic() + 8
        timewait_started = time.monotonic()
        after_drain = before_drain
        while time.monotonic() < deadline:
            after_drain = census_observation(args, rpc_path, census_fds)
            if all(values.get('timewait', 0) >= 1 for values in after_drain): break
            time.sleep(0.05)
        require(all(values.get('timewait', 0) >= 1 and values.get('listen') == 0
                for values in after_drain),
            f'original Linux did not retain the closed-member TIME_WAIT rows: {after_drain!r}')
        require(all(values.get('cookie') == initial.get('cookie')
                for values, initial in zip(after_drain, [first_values, second_values])),
            f'metadata listener identity changed after all listener handles closed: {after_drain!r}')
        for fd in observer_fds + census_fds:
            os.close(fd)
        observer_fds.clear(); census_fds.clear()
        supervisor.close()
        print(f'MEMBER_CENSUS_SYN_RECV_FLIP_OK old-member=0 new-flow=member1 '
            f'worker-exit-before-host-drain=true native_send_pressure={sent0},{sent1} '
            f'observed_send_queue={fill0[3]},{fill1[3]} '
            f'payload_snapshot={fill0[6]}:{fill0[7]},{fill1[6]}:{fill1[7]} '
            f'time_wait_after_drain_ms={int((time.monotonic() - timewait_started) * 1000)} '
            'closing/TIME_WAIT/listen-close verified')
    finally:
        if table_created:
            try:
                census_nft('delete', 'table', 'inet', table)
            except (OSError, subprocess.SubprocessError, RuntimeError):
                pass
        for peer in peers:
            peer.close()
        if client.poll() is None:
            client.kill(); client.wait()
        for fd in observer_fds + census_fds:
            try: os.close(fd)
            except OSError: pass
        supervisor.close()


def run_reuseport_group_client(args, rpc_path, broker, capability):
    client = subprocess.Popen([str(args.reuseport_group_client), str(rpc_path), str(capability),
        str(args.inherited_group_probe), str(args.preload_library)],
        pass_fds=(capability,), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    os.close(capability)
    owner_table = f'ker_c18_{os.getpid()}'
    owner_table_created = False
    try:
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_READY_0',
            'owner group did not select its first claimed listener')
        first_owner = socket.create_connection(('198.18.0.2', 4100), timeout=10)
        first_owner.settimeout(10); first_owner.sendall(b'OWNER-00')
        require(recv_exact(first_owner, 8) == b'WORKER-0',
            'first claimed owner did not accept and answer real TCP traffic')
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_ACCEPTED_0',
            'first owner actor did not finish its accepted stream')
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_READY_1',
            'owner group did not select its second claimed listener')
        second_owner = socket.create_connection(('198.18.0.2', 4100), timeout=10)
        second_owner.settimeout(10); second_owner.sendall(b'OWNER-01')
        require(recv_exact(second_owner, 8) == b'WORKER-1',
            'second claimed owner did not accept and answer real TCP traffic')
        second_owner.close()
        first_owner.sendall(b'OLD-0001')
        require(recv_exact(first_owner, 8) == b'OLD-ACK1',
            'accepted member-0 stream stopped working after member-1 served a fresh connection')
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_ACCEPTED_1',
            'second owner actor or retained member-0 stream did not finish')
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_WAIT_PAYLOAD',
            'owner actors did not reach the descriptorless payload checkpoint')

        census_nft('add', 'table', 'inet', owner_table); owner_table_created = True
        census_nft('add', 'chain', 'inet', owner_table, 'output',
            '{', 'type', 'filter', 'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}')
        peer_port = first_owner.getsockname()[1]
        census_nft('add', 'rule', 'inet', owner_table, 'output',
            'oifname', 'kerhost', 'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
            'tcp', 'sport', str(peer_port), 'tcp', 'dport', '4100', 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
        client.stdin.write(b'SEND\n'); client.stdin.flush()
        pending_line = read_line(client.stdout, 20, client)
        require(pending_line == 'OWNER_GROUP_DESCRIPTORLESS_PENDING bytes=1200 owner_sockets=1 member_sockets=1',
            f'owner and member READ authorities disagreed on descriptorless queued payload: {pending_line!r}')
        rule = census_nft('list', 'chain', 'inet', owner_table, 'output')
        counter = re.search(r'counter packets (\d+)', rule)
        require(counter is not None,
            f'owner-group ACK-drop rule did not report its counter: {rule!r}')
        data = recv_exact(first_owner, 1200)
        expected = bytes((index * 17 + 3) & 0xff for index in range(1200))
        require(data == expected,
            'descriptorless member-0 stream delivered different TCP payload bytes')
        rule = census_nft('list', 'chain', 'inet', owner_table, 'output')
        counter = re.search(r'counter packets (\d+)', rule)
        require(counter is not None and int(counter.group(1)) > 0,
            f'owner-group test did not drop a real ACK-only packet: {rule!r}')
        census_nft('delete', 'table', 'inet', owner_table); owner_table_created = False
        client.stdin.write(b'DRAIN\n'); client.stdin.flush()
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_DESCRIPTORLESS_DRAINED bytes=0',
            'owner and member payload snapshots did not drain after real ACK delivery')
        first_owner.close()
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_TWO_ACTOR_TCP_OK',
            'owner group did not prove two-actor original-Linux TCP selection and census')
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_HISTORY_FAIL_CLOSED_OK',
            'owner group did not reject post-claim unowned network history')
        poisoned_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        poisoned_probe.settimeout(2)
        try:
            poisoned_probe.connect(('198.18.0.2', 4101))
        except OSError as error:
            require(error.errno == errno.ECONNREFUSED,
                f'failed owner-group publish left a reachable listener: {error!r}')
        else:
            raise RuntimeError('failed owner-group publish created a reachable listener')
        finally:
            poisoned_probe.close()
        require(read_line(client.stdout, 20, client) == 'OWNER_GROUP_DEAD_OWNER_FAIL_CLOSED_OK',
            'owner-group publish did not reject a claimed actor that exited before materialization')
        dead_owner_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dead_owner_probe.settimeout(2)
        try:
            dead_owner_probe.connect(('198.18.0.2', 4102))
        except OSError as error:
            require(error.errno == errno.ECONNREFUSED,
                f'dead-owner publish created a reachable listener: {error!r}')
        else:
            raise RuntimeError('dead-owner publish created a reachable listener')
        finally:
            dead_owner_probe.close()
        require(read_line(client.stdout, 20, client) == 'CENSUS_LIFETIME_OK',
            'member census did not verify live and post-close metadata snapshots')
        census_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        census_probe.settimeout(2)
        try:
            census_probe.connect(('198.18.0.2', 4099))
        except OSError as error:
            require(error.errno == errno.ECONNREFUSED,
                f'metadata-only capabilities retained a closed census listener: {error!r}')
        else:
            raise RuntimeError('metadata-only capabilities kept the census listener reachable')
        finally:
            census_probe.close()
        require(read_line(client.stdout, 20, client) == 'GROUP_READY_0',
            'client did not publish selector-zero group')
        first = socket.create_connection(('198.18.0.2', 4097), timeout=10)
        first.settimeout(10); first.sendall(b'FIRST-00')
        require(recv_exact(first, 8) == b'REPLY-00', 'selector zero did not deliver to listener zero')
        require(read_line(client.stdout, 20, client) == 'ACCEPTED_0',
            'initial selector did not accept on listener zero')

        require(read_line(client.stdout, 20, client) == 'GROUP_READY_1',
            'client did not switch the original group selector to one')
        second = socket.create_connection(('198.18.0.2', 4097), timeout=10)
        second.settimeout(10); second.sendall(b'SECOND-1')
        first.sendall(b'FLIP-000')
        require(recv_exact(second, 8) == b'REPLY-01', 'selector one did not deliver to listener one')
        require(recv_exact(first, 8) == b'FLIP-ACK', 'accepted stream changed across selector flip')
        require(read_line(client.stdout, 20, client) == 'ACCEPTED_1_AND_PRIOR_STREAM_OK',
            'selector-one accept or prior stream check failed')

        require(read_line(client.stdout, 20, client) == 'GROUP_READY_0_AGAIN',
            'client did not switch the original group selector back to zero')
        third = socket.create_connection(('198.18.0.2', 4097), timeout=10)
        third.settimeout(10); third.sendall(b'THIRD-00')
        require(recv_exact(third, 8) == b'REPLY-02', 'selector-zero restoration did not reach listener zero')
        require(read_line(client.stdout, 20, client) == 'ALL_GROUP_HANDLES_CLOSED',
            'client did not close group and managed-member capabilities')
        require(recv_exact(first, 11) == b'AFTER-CLOSE',
            'accepted stream did not survive final group/member capability close')
        require(read_line(client.stdout, 20, client) == 'ACCEPTED_STREAM_AFTER_LISTENER_CLOSE',
            'client did not complete accepted-stream write after listener close')

        # The broker observes capability HUP asynchronously. Retry only the
        # connection attempt; any successful connection is a real failure.
        deadline = time.monotonic() + 5
        refused = False
        attempts = 0
        while time.monotonic() < deadline:
            attempts += 1
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(0.25)
            try:
                probe.connect(('198.18.0.2', 4097))
            except OSError as error:
                refused = error.errno == errno.ECONNREFUSED
            else:
                probe.close()
                raise RuntimeError('fresh connection succeeded after final group/member capability close')
            finally:
                probe.close()
            if refused: break
            time.sleep(0.02)
        require(refused, 'listener group remained reachable after all group handles closed')
        first.sendall(b'CLOSE-REPLY!')
        require(read_line(client.stdout, 20, client) == 'GROUP_CLIENT_DONE',
            'client failed to finish the accepted stream after listener teardown')
        first.shutdown(socket.SHUT_WR); second.close(); third.close()
        require(first.recv(1) == b'', 'accepted stream had unexpected data after close reply')
        first.close()
        output, errors = client.communicate(timeout=20)
        require(client.returncode == 0,
            f'reuseport group client failed: stdout={output!r}; stderr={errors.decode(errors="replace")}')
        print(f'REUSEPORT_GROUP selector0/1/0 delivered exact streams; accepted TCP survived final listener close; '
            f'fresh-connect attempts={attempts}')
    except BaseException as error:
        if owner_table_created:
            try: census_nft('delete', 'table', 'inet', owner_table)
            except (OSError, subprocess.SubprocessError, RuntimeError): pass
        if client.poll() is None:
            client.kill(); client.wait()
        if not hasattr(client, 'communicate'):
            raise
        output, errors = client.communicate(timeout=5)
        raise RuntimeError(f'{error}; owner-group client rc={client.returncode}; '
            f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error


GENERATION_MESSAGE = struct.Struct('=IIIIQ')
GENERATION_REQUEST_MAGIC = 0x4b455257
GENERATION_RESPONSE_MAGIC = 0x4b455252


class TcpObserverSnapshot(ctypes.Structure):
    _fields_ = [('cookie', ctypes.c_uint64), ('receive_queue', ctypes.c_uint32),
        ('send_queue', ctypes.c_uint32), ('state', ctypes.c_uint8), ('present', ctypes.c_uint8)]


def load_generation_controller(path, rpc_path):
    # The supervisor owns this single SDK context; rpc_lock serializes every
    # call even while the external traffic thread probes the listener.
    library = ctypes.CDLL(str(path), use_errno=True)
    library.ker_test_generation_controller_open.argtypes = [ctypes.c_char_p]
    library.ker_test_generation_controller_open.restype = ctypes.c_void_p
    library.ker_test_generation_controller_close.argtypes = [ctypes.c_void_p]
    library.ker_test_generation_controller_close.restype = None
    library.ker_test_generation_member.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint]
    library.ker_test_generation_member.restype = ctypes.c_int
    library.ker_test_generation_select.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint]
    library.ker_test_generation_select.restype = ctypes.c_int
    library.ker_test_generation_describe.argtypes = [ctypes.c_void_p, ctypes.c_int,
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
    library.ker_test_generation_describe.restype = ctypes.c_int
    library.ker_test_generation_observe.argtypes = [ctypes.c_void_p, ctypes.c_int,
        ctypes.POINTER(TcpObserverSnapshot)]
    library.ker_test_generation_observe.restype = ctypes.c_int
    context = library.ker_test_generation_controller_open(os.fsencode(rpc_path))
    require(context, f'generation supervisor could not open authenticated SDK context: {ctypes.get_errno()}')
    return library, context, threading.Lock()


def controller_call(result, operation):
    if result < 0:
        code = ctypes.get_errno()
        raise RuntimeError(f'{operation} failed with errno {code}: {os.strerror(code)}')
    return result


def generation_pack(kind, generation=0, worker=0, process_id=0, nonce=0):
    return GENERATION_MESSAGE.pack(kind, generation, worker, process_id, nonce)


def generation_receive(control, timeout=3):
    poller = select.poll()
    poller.register(control, select.POLLIN | select.POLLHUP | select.POLLERR)
    if not poller.poll(int(timeout * 1000)):
        raise RuntimeError('timed out waiting for generation worker control message')
    data, ancillary, flags, _ = control.recvmsg(GENERATION_MESSAGE.size,
        socket.CMSG_SPACE(16 * array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
    rights = []
    malformed_ancillary = False
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array('i')
            if len(payload) % values.itemsize:
                malformed_ancillary = True
            values.frombytes(payload[:len(payload) - len(payload) % values.itemsize])
            rights.extend(values.tolist())
        else:
            malformed_ancillary = True
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(data) != GENERATION_MESSAGE.size or malformed_ancillary:
        for fd in rights: os.close(fd)
        raise RuntimeError('generation worker control message was malformed or truncated')
    message = GENERATION_MESSAGE.unpack(data)
    if message[0] == 2:
        if len(rights) != 1:
            for fd in rights: os.close(fd)
            raise RuntimeError(f'accepted stream must transfer exactly one metadata observer: {rights!r}')
    else:
        if rights:
            for fd in rights: os.close(fd)
            raise RuntimeError(f'non-accept worker message carried descriptors: {rights!r}')
    return message, rights


def spawn_generation_worker(args, rpc_path, generation, worker_index, member_fd, paused):
    parent_control, child_control = socket.socketpair(socket.AF_UNIX,
        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    process = None
    try:
        process = subprocess.Popen([str(args.generation_worker), str(rpc_path), str(member_fd),
            str(child_control.fileno()), str(generation), str(worker_index), str(int(paused))],
            pass_fds=(member_fd, child_control.fileno()), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    except BaseException:
        parent_control.close()
        raise
    finally:
        os.close(member_fd)
        child_control.close()
    try:
        message, rights = generation_receive(parent_control, 15)
        if (message[0] != 1 or message[1] != generation or message[2] != worker_index or
                message[3] != process.pid or rights):
            for fd in rights: os.close(fd)
            raise RuntimeError(f'generation worker readiness identity differs: {message!r}')
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        parent_control.close()
        raise
    return {'generation': generation, 'worker': worker_index, 'process': process,
        'control': parent_control, 'pid': process.pid, 'pending': {},
        'seen_nonces': set(), 'command_nonce': 0, 'control_lock': threading.Lock()}


def generation_command(worker, kind):
    with worker['control_lock']:
        worker['command_nonce'] += 1
        nonce = worker['command_nonce']
        worker['control'].sendall(generation_pack(kind, worker['generation'], worker['worker'],
            worker['pid'], nonce))
        while True:
            message, rights = generation_receive(worker['control'], 3)
            if message[0] == 2:
                if (message[1] != worker['generation'] or message[2] != worker['worker'] or
                        message[3] != worker['pid'] or message[4] in worker['seen_nonces']):
                    for fd in rights: os.close(fd)
                    raise RuntimeError(f'worker accept event identity/nonce invalid: {message!r}')
                worker['seen_nonces'].add(message[4])
                worker['pending'][message[4]] = rights[0]
                continue
            require(message == (4, worker['generation'], worker['worker'], worker['pid'], nonce),
                f'worker did not acknowledge applied control command: {message!r}')
            return


def generation_observer_for(worker, nonce):
    with worker['control_lock']:
        pending = worker['pending']
        while nonce not in pending:
            message, rights = generation_receive(worker['control'], 3)
            if (message[0] != 2 or message[1] != worker['generation'] or
                    message[2] != worker['worker'] or message[3] != worker['pid'] or
                    message[4] in worker['seen_nonces']):
                for fd in rights: os.close(fd)
                raise RuntimeError(f'accepted stream worker identity/nonce invalid: {message!r}')
            worker['seen_nonces'].add(message[4])
            pending[message[4]] = rights[0]
        return pending.pop(nonce)


def generation_tcp_request(controls, nonce, commit_state=None, commit_lock=None, keep_observer=True):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    connection.setblocking(False)
    started_at = time.monotonic()
    counted_pre_commit = False
    observer = -1
    success = False
    try:
        if commit_state is None:
            initiated_after_commit = None
            connect_result = connection.connect_ex(('198.18.0.2', 4097))
        else:
            with commit_lock:
                initiated_after_commit = commit_state['selected']
                if not initiated_after_commit:
                    commit_state['pre_inflight'] += 1
                    counted_pre_commit = True
                connect_result = connection.connect_ex(('198.18.0.2', 4097))
        if connect_result not in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
            raise OSError(connect_result, os.strerror(connect_result))
        poller = select.poll()
        poller.register(connection, select.POLLOUT | select.POLLERR | select.POLLHUP)
        remaining = 2 - (time.monotonic() - started_at)
        if remaining <= 0 or not poller.poll(max(1, int(remaining * 1000))):
            raise TimeoutError('connect exceeded the two-second response deadline')
        connect_error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if connect_error:
            raise OSError(connect_error, os.strerror(connect_error))
        remaining = 2 - (time.monotonic() - started_at)
        if remaining <= 0: raise TimeoutError('connect exceeded the two-second response deadline')
        connection.settimeout(remaining)
        connection.sendall(struct.pack('!IQ', GENERATION_REQUEST_MAGIC, nonce))
        response = struct.unpack('!IIIIQ', recv_exact(connection, 24))
        require(time.monotonic() - started_at <= 2,
            f'nonce {nonce} response exceeded its two-second deadline')
        require(response[0] == GENERATION_RESPONSE_MAGIC and response[4] == nonce,
            f'generation worker response identity differs: {response!r}')
        generation, worker_index, process_id = response[1:4]
        key = (generation, worker_index)
        require(key in controls, f'connection reached unknown worker generation/identity: {response!r}')
        if initiated_after_commit and generation != 1:
            raise RuntimeError(f'post-selector connection reached old generation: {response!r}')
        worker = controls[key]
        require(process_id == worker['pid'], f'response PID differs from authenticated worker: {response!r}')
        observer = generation_observer_for(worker, nonce)
        snapshot = TcpObserverSnapshot()
        with controls['rpc_lock']:
            result = controls['controller'].ker_test_generation_observe(
                controls['context'], observer, ctypes.byref(snapshot))
        controller_call(result, 'observer snapshot')
        require(snapshot.present and snapshot.cookie != 0,
            f'worker transferred a non-live metadata observer: {response!r} '
            f'snapshot={snapshot.cookie, snapshot.present}')
        if keep_observer:
            controls['observers'].append((observer, snapshot.cookie, nonce))
            observer = -1
        success = True
        return connection, response, initiated_after_commit
    except BaseException as error:
        raise RuntimeError(f'nonce {nonce} connect/response failed: {error}') from error
    finally:
        if observer >= 0: os.close(observer)
        if not success: connection.close()
        if counted_pre_commit:
            with commit_lock:
                commit_state['pre_inflight'] -= 1


def generation_stream_payload(nonce, phase, sequence):
    return bytes(((index * 37 + nonce * 11 + phase * 53 + sequence * 97) & 0xff)
        for index in range(257))


def pump_generation_stream(connection, nonce, commit_state, transition_lock, stop,
    counts, errors, first_frame):
    sequence = 0
    try:
        while not stop.is_set():
            with transition_lock:
                phase = int(commit_state['selected'])
                payload = generation_stream_payload(nonce, phase, sequence)
            connection.sendall(payload)
            require(recv_exact(connection, len(payload)) == payload,
                f'generation {phase} stream payload mismatch for nonce {nonce} sequence {sequence}')
            counts[phase] += 1
            first_frame.set()
            sequence += 1
            time.sleep(0.005)
    except BaseException as error:
        errors.append(error)


def reap_generation_worker(worker, timeout=5):
    message, rights = generation_receive(worker['control'], timeout)
    if message != (3, worker['generation'], worker['worker'], worker['pid'], 0) or rights:
        for fd in rights: os.close(fd)
        raise RuntimeError(f'worker did not report clean retirement: {message!r}')
    result = worker['process'].wait(timeout=timeout)
    output = worker['process'].stderr.read()
    require(result == 0, f'worker failed during clean retirement: {output!r}')
    worker['control'].close()


def run_generation_handoff(args, rpc_path, broker, group_fd, root):
    library = None
    context = None
    rpc_lock = threading.Lock()
    controls = {'controller': None, 'context': None, 'rpc_lock': rpc_lock, 'observers': []}
    workers = {}
    streams = []
    traffic_results = []
    traffic_errors = []
    traffic = None
    traffic_stop = threading.Event()
    stream_pumps = []
    stream_pump_errors = []
    transition_lock = threading.Lock()
    commit_state = {'selected': False, 'pre_inflight': 0}
    controller_closed = False
    stage = 'initialize generation controller'
    try:
        for artifact in (args.generation_worker, args.generation_controller):
            dependencies = subprocess.run(['ldd', str(artifact.resolve())],
                text=True, capture_output=True, check=True).stdout
            require('ker-posix' not in dependencies and 'liblkl' not in dependencies.lower(),
                f'generation SDK process unexpectedly links the in-process kernel: {artifact}: {dependencies}')
        library, context, rpc_lock = load_generation_controller(args.generation_controller, rpc_path)
        controls.update(controller=library, context=context, rpc_lock=rpc_lock)
        stage = 'describe group control capability'
        group_kind = ctypes.c_int(-1); group_flags = ctypes.c_int(-1)
        with rpc_lock:
            described = library.ker_test_generation_describe(context, group_fd,
                ctypes.byref(group_kind), ctypes.byref(group_flags))
        controller_call(described, 'describe supervisor group')
        require(group_kind.value == 3 and group_flags.value == 0,
            f'supervisor did not receive CONTROL group identity: {group_kind.value, group_flags.value}')

        def start_worker(generation, index, paused, member_index=None):
            if member_index is None: member_index = index
            with rpc_lock:
                member_fd = controller_call(library.ker_test_generation_member(
                    context, group_fd, member_index), f'create worker member {member_index}')
            worker = spawn_generation_worker(args, rpc_path, generation, index, member_fd, paused)
            workers[(generation, index)] = worker
            return worker

        stage = 'start old workers'
        old0 = start_worker(0, 0, False)
        old1 = start_worker(0, 1, True, member_index=0)
        nonce = 1
        stage = 'accept deterministic old worker zero stream'
        first, first_response, _ = generation_tcp_request(controls | workers, nonce, keep_observer=True)
        require(first_response[1:4] == (0, 0, old0['pid']),
            f'old member did not deterministically reach worker zero: {first_response!r}')
        streams.append((first, nonce, old0))
        stage = 'switch accept barrier to old worker one'
        generation_command(old0, 10)
        generation_command(old1, 11)
        nonce += 1
        second, second_response, _ = generation_tcp_request(controls | workers, nonce, keep_observer=True)
        require(second_response[1:4] == (0, 1, old1['pid']),
            f'old member did not deterministically reach worker one: {second_response!r}')
        streams.append((second, nonce, old1))
        generation_command(old0, 11)

        stage = 'fill twelve retained old streams'
        for _ in range(10):
            nonce += 1
            connection, response, _ = generation_tcp_request(controls | workers, nonce,
                keep_observer=True)
            require(response[1] == 0, f'pre-transition connection reached a non-old generation: {response!r}')
            streams.append((connection, nonce, workers[(response[1], response[2])]))
        require(len(streams) == 12, f'expected twelve retained old streams, got {len(streams)}')

        stage = 'start replacement workers'
        new0 = start_worker(1, 0, True, member_index=1)
        new1 = start_worker(1, 1, True, member_index=1)
        generation_command(new0, 11)
        generation_command(new1, 11)

        # Each old accepted stream continuously transfers nonce-specific data
        # through the selector publication while worker accept loops retire.
        stage = 'start active old-stream pumps'
        for connection, stream_nonce, _ in streams:
            counts = [0, 0]
            first_frame = threading.Event()
            pump = threading.Thread(target=pump_generation_stream,
                args=(connection, stream_nonce, commit_state, transition_lock, traffic_stop,
                    counts, stream_pump_errors, first_frame),
                name=f'old-stream-{stream_nonce}')
            pump.start()
            stream_pumps.append((pump, counts, first_frame, stream_nonce))
        for _, _, first_frame, stream_nonce in stream_pumps:
            require(first_frame.wait(2), f'old stream {stream_nonce} sent no pre-selector payload')

        # A no-retry external probe loop overlaps selector publication. The
        # initiation lock defines which connect calls began after SELECT
        # returned; only those are required to reach member one.
        def fresh_probe_loop():
            nonlocal nonce
            try:
                for _ in range(24):
                    if traffic_stop.is_set(): break
                    nonce += 1
                    connection, response, initiated_after = generation_tcp_request(
                        controls | workers, nonce, commit_state, transition_lock, keep_observer=False)
                    require(initiated_after is None or not initiated_after or response[1] == 1,
                        f'post-selector probe reached old generation: {response!r}')
                    connection.close()
                    traffic_results.append((nonce, response, initiated_after))
                    time.sleep(0.025)
            except BaseException as error:
                traffic_errors.append(error)

        stage = 'launch overlapping fresh probes'
        traffic = threading.Thread(target=fresh_probe_loop, name='generation-fresh-probes')
        traffic.start()
        deadline = time.monotonic() + 3
        while len(traffic_results) < 3 and time.monotonic() < deadline and not traffic_errors:
            time.sleep(0.005)
        require(not traffic_errors and len(traffic_results) >= 3,
            f'fresh probes did not establish pre-transition traffic: {traffic_errors!r}')
        stage = 'publish selector one'
        with transition_lock:
            with rpc_lock:
                controller_call(library.ker_test_generation_select(context, group_fd, 1),
                    'publish new reuseport member')
            commit_state['selected'] = True
        stage = 'drain pre-selector in-flight probes'
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with transition_lock:
                remaining_pre = commit_state['pre_inflight']
            if remaining_pre == 0: break
            time.sleep(0.002)
        require(remaining_pre == 0,
            f'{remaining_pre} pre-selector connect(s) remained in flight before old accept retirement')
        stage = 'retire old worker accept loops while streams stay active'
        for worker in (old0, old1): generation_command(worker, 12)
        require(old0['process'].poll() is None and old1['process'].poll() is None,
            'old workers exited before their twelve accepted streams completed')
        traffic.join(timeout=5)
        require(not traffic.is_alive() and not traffic_errors,
            f'continuous fresh probe thread failed: {traffic_errors!r}')
        post_select = [item for item in traffic_results if item[2]]
        pre_select = [item for item in traffic_results if not item[2]]
        require(len(pre_select) >= 3 and len(post_select) >= 8,
            f'probe coverage around selector was too small: pre={len(pre_select)} post={len(post_select)}')
        require(all(result[1][1] == 1 for result in post_select),
            'a fresh connection initiated after successful SELECT reached the old generation')

        # Accept-only barriers prove both replacement workers actually serve
        # connections while existing old-generation streams remain open.
        stage = 'pause replacement worker one'
        generation_command(new1, 10)
        nonce += 1
        stage = 'accept replacement worker zero stream'
        new_worker0_stream, response0, _ = generation_tcp_request(controls | workers, nonce,
            keep_observer=False)
        require(response0[1:4] == (1, 0, new0['pid']),
            f'new member did not reach worker zero while worker one was paused: {response0!r}')
        new_worker0_stream.close()
        stage = 'switch replacement accept barrier to worker one'
        generation_command(new0, 10)
        generation_command(new1, 11)
        nonce += 1
        stage = 'accept replacement worker one stream'
        new_worker1_stream, response1, _ = generation_tcp_request(controls | workers, nonce,
            keep_observer=False)
        require(response1[1:4] == (1, 1, new1['pid']),
            f'new member did not reach worker one while worker zero was paused: {response1!r}')
        new_worker1_stream.close()
        generation_command(new0, 11)

        stage = 'verify old payload during selector handoff'
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            require(not stream_pump_errors, f'old stream pump failed: {stream_pump_errors!r}')
            if all(counts[1] >= 2 for _, counts, _, _ in stream_pumps): break
            time.sleep(0.005)
        require(all(counts[1] >= 2 for _, counts, _, _ in stream_pumps),
            f'not every old stream transferred payload after selector: '
            f'{[(stream_nonce, counts) for _, counts, _, stream_nonce in stream_pumps]}')

        stage = 'finish old streams after active payload transfer'
        traffic_stop.set()
        for pump, _, _, _ in stream_pumps: pump.join(timeout=3)
        require(not any(pump.is_alive() for pump, _, _, _ in stream_pumps),
            'old stream pump did not stop within its bounded I/O deadline')
        require(not stream_pump_errors,
            f'old stream payload echo failed: {stream_pump_errors!r}')
        require(all(counts[0] > 0 and counts[1] > 0 for _, counts, _, _ in stream_pumps),
            f'old streams lack confirmed payload on both sides of SELECT: '
            f'{[(stream_nonce, counts) for _, counts, _, stream_nonce in stream_pumps]}')
        for connection, stream_nonce, _ in streams:
            connection.shutdown(socket.SHUT_WR)
            require(connection.recv(1) == b'',
                f'old stream {stream_nonce} did not reach normal peer EOF after echoed payload')
            connection.close()
        streams.clear()

        stage = 'reap old workers after accepted stream completion'
        reap_generation_worker(old0)
        reap_generation_worker(old1)

        stage = 'prove replacement generation after old worker exit'
        nonce += 1
        after_old_exit, after_old_exit_response, _ = generation_tcp_request(
            controls | workers, nonce, keep_observer=False)
        require(after_old_exit_response[1] == 1,
            f'new generation stopped serving after old worker exit: {after_old_exit_response!r}')
        after_old_exit.close()

        # Metadata-only observer capabilities remain usable after the old
        # worker descriptors close, without retaining any TCP descriptor.
        stage = 'verify old metadata after worker teardown'
        for observer, cookie, stream_nonce in controls['observers']:
            deadline = time.monotonic() + 5
            final = TcpObserverSnapshot()
            while time.monotonic() < deadline:
                with rpc_lock:
                    result = library.ker_test_generation_observe(context, observer,
                        ctypes.byref(final))
                controller_call(result, f'final observer snapshot for nonce {stream_nonce}')
                require(final.cookie == cookie,
                    f'observer identity changed for nonce {stream_nonce}: {final.cookie} != {cookie}')
                if not final.present or final.state == 6: break
                time.sleep(0.01)
            require(not final.present or final.state == 6,
                f'original TCP state did not reach TIME_WAIT/absence for nonce {stream_nonce}: '
                f'{final.present, final.state}')

        stage = 'retire replacement workers last'
        for worker in (new0, new1): generation_command(worker, 12)
        reap_generation_worker(new0)
        reap_generation_worker(new1)

        stage = 'release observer and group capabilities'
        for observer, _, _ in controls['observers']:
            os.close(observer)
        controls['observers'].clear()
        os.close(group_fd)
        group_fd = -1
        library.ker_test_generation_controller_close(context)
        controller_closed = True
        try:
            output, errors = broker.communicate(timeout=30)
        except subprocess.TimeoutExpired as error:
            broker.kill(); output, errors = broker.communicate(timeout=10)
            raise RuntimeError(f'generation broker did not release group after worker exit: '
                f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
        require(b'BROKER_DONE' in output and broker.returncode == 0,
            f'generation broker did not finalize cleanly: {output!r} {errors.decode(errors="replace")}')
        stats = json.loads((root / 'stats.json').read_text())
        native = stats.get('native', {})
        require(stats.get('outstanding') == 0 and stats.get('tx', 0) > 0 and
            stats.get('rx', 0) > 0 and native.get('passive_opens', 0) >= 36,
            f'original-Linux listener traffic or pool cleanup missing: {stats!r}')
        minimum_pre = min(counts[0] for _, counts, _, _ in stream_pumps)
        minimum_post = min(counts[1] for _, counts, _, _ in stream_pumps)
        print(f'GENERATION_HANDOFF_OK old_streams=12 old_workers=2 new_workers=2 '
            f'pre_select_probes={len(pre_select)} post_select_probes={len(post_select)} '
            f'min_old_payload_echoes_pre={minimum_pre} min_old_payload_echoes_post={minimum_post} '
            f'worker_pids={[worker["pid"] for worker in workers.values()]} '
            f'original_passive_opens={native.get("passive_opens")} outstanding={stats.get("outstanding")}')
    except BaseException as error:
        raise RuntimeError(f'{error}; generation stage={stage}') from error
    finally:
        traffic_stop.set()
        for connection, _, _ in streams:
            try: connection.close()
            except OSError: pass
        for worker in workers.values():
            if worker['process'].poll() is None:
                try: worker['process'].kill()
                except OSError: pass
                worker['process'].wait()
            try: worker['control'].close()
            except OSError: pass
        if traffic is not None and traffic.is_alive(): traffic.join(timeout=6)
        for pump, _, _, _ in stream_pumps:
            if pump.is_alive(): pump.join(timeout=3)
        if ((traffic is not None and traffic.is_alive()) or
                any(pump.is_alive() for pump, _, _, _ in stream_pumps)):
            raise RuntimeError('generation traffic/pump threads did not stop before controller cleanup')
        for observer, _, _ in controls['observers']:
            try: os.close(observer)
            except OSError: pass
        controls['observers'].clear()
        for worker in workers.values():
            for pending_fd in worker['pending'].values():
                try: os.close(pending_fd)
                except OSError: pass
            worker['pending'].clear()
            if worker['process'].stderr:
                worker['process'].stderr.close()
        if group_fd >= 0:
            try: os.close(group_fd)
            except OSError: pass
        if context is not None and not controller_closed:
            library.ker_test_generation_controller_close(context)


def send_host_socket_probe(connection):
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        record = struct.pack('=IHH', 0x4b534248, 1, 1)
        descriptors = array.array('i', [host_socket.fileno()])
        sent = connection.sendmsg([record], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)])
        require(sent == len(record), 'host socket probe transfer was short')
        require(connection.recv(4) == b'OKAY', 'broker did not reject the host TCP descriptor')
    finally:
        host_socket.close()


def run_preloaded_frontend(args, rpc_path, broker, capabilities):
    environment = os.environ | {
        'LD_PRELOAD': str(args.preload_library.resolve()),
        'KER_SOCKET_BROKER_PATH': str(rpc_path),
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    frontend = subprocess.Popen([str(args.preload_client), str(capabilities[0]),
        str(capabilities[1])], pass_fds=tuple(capabilities), stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
    for fd in capabilities:
        os.close(fd)
    capabilities.clear()
    broker_stopped = False
    try:
        require(read_line(frontend.stdout, 20, frontend) == 'BROKER_STOP_HOST_FIFO',
            'preloaded caller did not reach the host-FIFO signal-safety check')
        os.killpg(broker.pid, signal.SIGSTOP)
        broker_stopped = True
        frontend.stdin.write(b'H'); frontend.stdin.flush()
        require(read_line(frontend.stdout, 5, frontend) == 'HOST_FIFO_WRITE_OK',
            'ordinary host FIFO write waited on broker classification while broker was stopped')
        require(read_line(frontend.stdout, 5, frontend) == 'BROKER_STOP_SIGNAL_RPC',
            'preloaded caller did not reach the delayed-RPC signal test')
        frontend.stdin.write(b'R'); frontend.stdin.flush()
        time.sleep(0.1)
        frontend.send_signal(signal.SIGUSR2)
        time.sleep(0.1)
        try:
            os.killpg(broker.pid, signal.SIGCONT)
        except ProcessLookupError:
            pass
        broker_stopped = False
        require(read_line(frontend.stdout, 20, frontend) == 'PARENT_READY',
            'preloaded caller did not finish host/mixed-epoll checks')
        peer = socket.create_connection(('198.18.0.2', 4097), timeout=10)
        peer.settimeout(10)
        require(read_line(frontend.stdout, 20, frontend) == 'ACCEPTED_FIRST',
            'preloaded caller did not accept the first original-Linux connection')
        before = bytes((index * 31 + 17) & 0xff for index in range(24))
        peer.sendall(before)
        require(recv_exact(peer, len(before)) == before,
            'active stream did not round-trip before fork/exec')
        require(read_line(frontend.stdout, 20, frontend) == 'PREFORK_STREAM_OK',
            'preloaded caller did not finish the active pre-fork stream')
        require(read_line(frontend.stdout, 20, frontend) == 'CHILD_READY',
            'exec replacement did not reconnect and recover inherited socket capabilities')
        after = bytes((index * 31 + 93) & 0xff for index in range(4097))
        peer.sendall(after)
        require(recv_exact(peer, len(after)) == after,
            'active 4097-byte stream did not continue across fork/exec')
        require(read_line(frontend.stdout, 20, frontend) == 'STREAM_OK',
            'exec replacement did not validate/echo the continued stream')
        peer.shutdown(socket.SHUT_WR)
        second = socket.create_connection(('198.18.0.2', 4097), timeout=10)
        second.settimeout(10)
        require(read_line(frontend.stdout, 20, frontend) == 'SECOND_ACCEPTED',
            'exec replacement did not accept a new connection on inherited listener')
        second.sendall(b'FRESH-ACCEPT')
        require(recv_exact(second, 9) == b'REPLY-TWO', 'fresh accepted stream reply differs')
        second.shutdown(socket.SHUT_WR)
        require(second.recv(1) == b'', 'fresh accepted stream had unexpected trailing bytes')
        peer.close(); second.close()
        require(read_line(frontend.stdout, 20, frontend) == 'CHILD_DONE',
            'exec replacement did not close the socket/epoll capabilities')
        output, errors = frontend.communicate(timeout=15)
        require(frontend.returncode == 0,
            f'preloaded frontend failed: stdout={output!r}; stderr={errors.decode(errors="replace")}')
        return frontend
    except BaseException:
        if broker_stopped:
            try:
                os.killpg(broker.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        if frontend.poll() is None:
            frontend.kill(); frontend.wait()
        raise


def run_fstack_bridge_frontend(args, rpc_path, capabilities):
    preload = str(args.preload_library.resolve())
    if args.fstack_runtime:
        preload = str(args.fstack_runtime.resolve()) + ':' + preload
    environment = os.environ | {
        'LD_PRELOAD': preload,
        'KER_SOCKET_BROKER_PATH': str(rpc_path),
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    host_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    host_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host_listener.bind(('198.18.0.1', 4097)); host_listener.listen(1); host_listener.settimeout(15)
    frontend = subprocess.Popen([str(args.fstack_client), str(capabilities[1])],
        pass_fds=tuple(capabilities),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, bufsize=0)
    for fd in capabilities:
        os.close(fd)
    capabilities.clear()
    peer = None
    try:
        require(read_line(frontend.stdout, 20, frontend) == 'FF_CONNECTING',
            'FF leaf caller did not enter the original-Linux connect path')
        peer, _ = host_listener.accept()
        peer.settimeout(10)
        require(read_line(frontend.stdout, 20, frontend) == 'FF_CONNECTED',
            'FF leaf caller did not finish the original-Linux connection')
        payload = bytes((index * 31 + 17) & 0xff for index in range(4097))
        peer.sendall(payload)
        require(recv_exact(peer, len(payload)) == payload,
            'FF leaf caller did not echo the exact original-Linux stream')
        require(peer.recv(1) == b'', 'FF leaf stream had unexpected trailing bytes')
        output, errors = frontend.communicate(timeout=20)
        require(frontend.returncode == 0,
            f'FF leaf caller failed: stdout={output!r}; stderr={errors.decode(errors="replace")}')
        require(output == b'FF_STREAM_OK\n',
            f'FF leaf caller did not confirm final descriptor/pool checks: {output!r}')
    except BaseException:
        if frontend.poll() is None:
            frontend.kill(); frontend.wait()
        raise
    finally:
        if peer is not None:
            peer.close()
        host_listener.close()


def run_fstack_drain_failure_frontend(args, rpc_path, broker, capabilities):
    environment = os.environ | {
        'LD_PRELOAD': str(args.preload_library.resolve()),
        'KER_SOCKET_BROKER_PATH': str(rpc_path),
        'PYTHONDONTWRITEBYTECODE': '1',
    }

    def disable_core_dumps():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    frontend = subprocess.Popen([str(args.fstack_drain_failure_client),
        '--broker-death-census'],
        pass_fds=tuple(capabilities), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=environment, bufsize=0,
        preexec_fn=disable_core_dumps)
    for fd in capabilities:
        os.close(fd)
    capabilities.clear()
    try:
        require(read_line(frontend.stdout, 15, frontend) == 'DRAIN_FAILURE_READY',
            'FF census client did not query a live broker before failure injection')
        os.killpg(broker.pid, signal.SIGKILL)
        broker_output, broker_errors = broker.communicate(timeout=10)
        require(broker.returncode == -signal.SIGKILL,
            f'isolated broker group did not die by SIGKILL: {broker.returncode}; '
            f'stdout={broker_output!r}; stderr={broker_errors.decode(errors="replace")}')
        frontend.stdin.write(b'F'); frontend.stdin.flush()
        output, errors = frontend.communicate(timeout=10)
        diagnostic = errors.decode(errors='replace')
        require(frontend.returncode == 0 and output == b'DRAIN_FAILURE_OK\n',
            f'FF census did not fail closed after broker death: returncode={frontend.returncode}; '
            f'stdout={output!r}; stderr={diagnostic!r}')
        require('ker fstack socket census failed: errno=' in diagnostic,
            f'broker-death abort diagnostic missing: {diagnostic!r}')
        print('PASS: a live registered socket census aborts on broker death')
    except BaseException:
        if frontend.poll() is None:
            frontend.kill(); frontend.wait()
        raise


def wait_for_path(path, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise RuntimeError(f'timed out waiting for {description}: {path}')


def read_http_response(connection, expected_body=None, pause_before_body=0, on_body_start=None,
    io_timeout=30):
    connection.settimeout(io_timeout)
    header = bytearray()
    while not header.endswith(b'\r\n\r\n'):
        byte = connection.recv(1)
        require(byte, 'nginx closed before HTTP headers completed')
        header.extend(byte)
        require(len(header) <= 65536, 'nginx HTTP headers exceeded the bound')
    lines = header.decode('latin-1').split('\r\n')
    require(lines[0].startswith('HTTP/1.1 200 '), f'unexpected HTTP status: {lines[0]!r}')
    content_length = None
    for line in lines[1:]:
        if line.lower().startswith('content-length:'):
            content_length = int(line.split(':', 1)[1].strip())
    require(content_length is not None, 'static response omitted Content-Length')
    body = bytearray()
    if pause_before_body:
        first = connection.recv(min(4096, content_length))
        require(first, 'nginx closed before static body started')
        body.extend(first)
        if on_body_start:
            on_body_start()
        time.sleep(pause_before_body)
    digest = hashlib.sha256()
    if body:
        digest.update(body)
    while len(body) < content_length:
        chunk = connection.recv(min(65536, content_length - len(body)))
        require(chunk, f'nginx body ended at {len(body)} of {content_length} bytes')
        body.extend(chunk); digest.update(chunk)
    require(connection.recv(1) == b'', 'HTTP response contained bytes after Content-Length')
    if expected_body is not None:
        require(bytes(body) == expected_body, 'small HTTP response body differed')
    return content_length, digest.hexdigest()


def request_static(address, port, path, pause_before_body=0, timeout=20):
    connection = socket.create_connection((address, port), timeout=timeout)
    connection.sendall(f'GET {path} HTTP/1.1\r\nHost: ker.test\r\nConnection: close\r\n\r\n'.encode())
    try:
        return read_http_response(connection, pause_before_body=pause_before_body,
            io_timeout=timeout)
    finally:
        connection.close()


def nginx_worker_for_request(access_log, address, port, path):
    token = f'c11-{os.getpid()}-{time.monotonic_ns()}'
    response = request_static(address, port, f'{path}?{token}', timeout=3)
    require(response[0] == len(b'preload-http-ok\n'),
        f'worker identity request returned an unexpected body: {response!r}')
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if access_log.exists():
            for line in reversed(access_log.read_text().splitlines()):
                fields = line.split()
                if len(fields) == 2 and fields[1] == f'/small.txt?{token}':
                    return int(fields[0])
        time.sleep(0.01)
    raise RuntimeError(f'no Nginx access-log record for worker proof token {token}')


def prove_nginx_workers_serve(access_log, expected_pids, stage):
    require(len(expected_pids) == 2,
        f'{stage}: expected exactly two worker identities, got {sorted(expected_pids)!r}')
    observed = set()
    for _ in range(80):
        observed.add(nginx_worker_for_request(access_log, '198.18.0.2', 4098, '/small.txt'))
        if expected_pids <= observed:
            return
    raise RuntimeError(f'{stage}: workers failed to serve independently: '
        f'expected={sorted(expected_pids)!r}; observed={sorted(observed)!r}')


def wait_for_static(address, port, timeout=30):
    deadline = time.monotonic() + timeout
    last_error = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            result = request_static(address, port, '/small.txt', timeout=2)
            require(result[0] == len(b'preload-http-ok\n'),
                f'small response length differs: {result}')
            return result, attempts - 1
        except (OSError, RuntimeError) as error:
            last_error = repr(error)
            time.sleep(0.05)
    raise RuntimeError(f'no successful small HTTP response within {timeout}s: {last_error}')


def run_tcp_observer_frontend(args, rpc_path, broker, cap_fds, root):
    ack_read, ack_write = os.pipe()
    client = None
    peer = None
    try:
        client = subprocess.Popen([str(args.observer_client), str(rpc_path),
            str(cap_fds[0]), str(cap_fds[1]), str(cap_fds[2]), str(ack_read),
            str(args.preload_library.resolve())],
            pass_fds=tuple(cap_fds) + (ack_read,), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        os.close(ack_read); ack_read = -1
        for fd in cap_fds:
            os.close(fd)
        cap_fds.clear()
        require(read_line(client.stdout, 15, client) == 'OBSERVER_WAIT_ACCEPT',
            'observer client did not reach its original-Linux accept')
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        peer.settimeout(20)
        peer.connect(('198.18.0.2', 4097))
        require(read_line(client.stdout, 15, client) == 'OBSERVER_ACCEPTED',
            'observer client did not accept the connected IPv4 TCP stream')
        inbound = bytes((index * 17 + 5) & 0xff for index in range(16384))
        peer.sendall(inbound)
        require(read_line(client.stdout, 20, client) == 'OBSERVER_EXEC_SNAPSHOT_OK',
            'preloaded exec child did not retain/snapshot the inherited metadata capability')
        require(read_line(client.stdout, 20, client) == 'OBSERVER_EXEC_CAP_RETAINED',
            'parent observer capability was not usable after the preloaded exec exited')
        observer_status = read_line(client.stdout, 20, client)
        require(observer_status == 'OBSERVER_RX_DRAINED',
            f'observer failed to report/drain original Linux receive queue: {observer_status!r}')
        line = read_line(client.stdout, 20, client)
        require(line.startswith('OBSERVER_CAPS_CLOSED '),
            f'observer did not close all TCP capabilities after real backpressure: {line}')
        queued = int(line.split()[1])
        require(queued > 0, 'observer backpressure accepted no TCP payload')
        expected = bytes((index * 29 + 3) & 0xff for index in range(4096))
        received = recv_exact(peer, queued)
        require(received == (expected * ((queued + len(expected) - 1) // len(expected)))[:queued],
            'queued original-Linux TCP payload changed while the observer held metadata only')
        require(peer.recv(1) == b'', 'closing all TCP capability refs did not deliver normal FIN EOF')
        peer.close(); peer = None
        os.write(ack_write, b'A')
        os.close(ack_write); ack_write = -1
        final = read_line(client.stdout, 20, client)
        require(final.startswith('OBSERVER_FINAL '),
            f'observer did not return final TIME_WAIT/absence identity: {final}')
        output, errors = client.communicate(timeout=20)
        require(client.returncode == 0,
            f'observer SDK consumer failed: stdout={output!r}; stderr={errors.decode(errors="replace")}')
        try:
            output, errors = broker.communicate(timeout=30)
        except subprocess.TimeoutExpired as error:
            broker.kill(); output, errors = broker.communicate(timeout=10)
            raise RuntimeError(f'broker did not release observer metadata after close: '
                f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
        require(b'BROKER_DONE' in output and broker.returncode == 0,
            f'broker did not finalize after observer close: {output!r}; {errors.decode(errors="replace")}')
        stats = json.loads((root / 'stats.json').read_text())
        require(stats.get('outstanding') == 0,
            f'packet-buffer accounting did not return to zero: {stats!r}')
        print(f'PASS: original INET_DIAG observer cookie={final.split("cookie=")[-1]} '
            f'queued_bytes={queued}; real receive/send queues observed; TCP refs closed; pool=0')
    finally:
        if peer is not None:
            peer.close()
        for fd in (ack_read, ack_write):
            if fd >= 0:
                try: os.close(fd)
                except OSError: pass
        if client is not None and client.poll() is None:
            client.kill(); client.wait()


def run_nginx_preloaded(args, rpc_path, capabilities, root, broker):
    binary = args.nginx_binary.resolve()
    fstack_profile = args.fstack_runtime is not None
    selected_preload = str(args.preload_library.resolve())
    if fstack_profile:
        selected_preload = f'{args.fstack_runtime.resolve()}:{selected_preload}'
    if args.fstack_worker_shim:
        selected_preload = f'{args.fstack_worker_shim.resolve()}:{selected_preload}'
    selected_runtime_env = os.environ | {
        'LD_PRELOAD': selected_preload,
        'KER_SOCKET_BROKER_PATH': str(rpc_path),
    }
    version = subprocess.run([str(binary), '-V'], capture_output=True, check=True,
        env=selected_runtime_env)
    has_ff_module = b'--with-ff_module' in version.stderr or b'--with-ff_module' in version.stdout
    require(has_ff_module == fstack_profile,
        'nginx build must match the selected no-FF or bounded FF runtime profile')
    prefix = root / 'nginx'; html = prefix / 'html'; logs = prefix / 'logs'
    html.mkdir(parents=True); logs.mkdir()
    large = bytes((index * 17 + 3) & 0xff for index in range(8 * 1024 * 1024))
    (html / 'large.bin').write_bytes(large)
    (html / 'small.txt').write_bytes(b'preload-http-ok\n')
    config = prefix / 'nginx.conf'
    runtime_trace = prefix / 'fstack-runtime.trace'
    fstack_config = prefix / 'fstack.ini'
    if fstack_profile:
        fstack_config.write_text(f'''[ker_socket_broker]
version=1
path={rpc_path}

[dpdk]
graceful_reload=0
''')
    runtime_config = (f'fstack_conf {fstack_config};\ntimer_resolution 1ms;\nenv KER_FSTACK_RUNTIME_TRACE;\n'
        if fstack_profile else '')
    sendfile = 'off' if fstack_profile else 'on'
    reuseport = ' reuseport' if fstack_profile else ''
    unsupported_listener_option = ' rcvbuf=4096' if args.nginx_test_unsupported_option else ''
    worker_count = args.nginx_workers or (2 if not fstack_profile else 1)
    if args.fstack_worker_shim:
        require(fstack_profile and worker_count == 2,
            'the worker ownership shim requires the FF runtime and exactly two Nginx workers')
    access_log = logs / 'worker-pids.log'
    worker_log_config = (
        f"log_format ker_worker_pid '$pid $request_uri';\n" if args.fstack_worker_shim else '')
    access_log_config = (
        f'access_log {access_log} ker_worker_pid;\n' if args.fstack_worker_shim else '')
    config.write_text(f'''daemon on;
master_process on;
worker_processes {worker_count};
{runtime_config}pid {logs / 'nginx.pid'};
error_log {logs / 'error.log'} notice;
env LD_PRELOAD;
env KER_SOCKET_BROKER_PATH;
events {{ worker_connections 1024; use epoll; }}
http {{
    {worker_log_config}    access_log off;
    sendfile {sendfile};
    tcp_nopush off;
    keepalive_timeout 0;
    server {{
        listen 198.18.0.2:4098{reuseport}{unsupported_listener_option};
        server_name ker.test;
        root {html};
        {access_log_config}
    }}
}}
''')
    env = selected_runtime_env.copy()
    if fstack_profile:
        env['KER_FSTACK_RUNTIME_TRACE'] = str(runtime_trace)
    command = [str(binary), '-p', str(prefix) + '/', '-c', str(config)]
    startup = subprocess.run(command, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    require(startup.returncode == 0,
        f'nginx did not daemonize cleanly: {startup.stderr.decode(errors="replace")}')
    pidfile = logs / 'nginx.pid'; oldbin = Path(str(pidfile) + '.oldbin')
    master = None; new_master = None
    stage = 'startup'
    try:
        wait_for_path(pidfile, 20, 'initial nginx pidfile')
        master = int(pidfile.read_text().strip())
        if args.nginx_test_unsupported_option:
            deadline = time.monotonic() + 10
            error_log = logs / 'error.log'
            while time.monotonic() < deadline:
                current_log = error_log.read_text() if error_log.exists() else ''
                if 'refusing profile: receive-buffer option' in current_log:
                    break
                time.sleep(0.02)
            require('refusing profile: receive-buffer option' in current_log,
                f'unsupported listener option was not rejected by the shim: {current_log!r}')
            require(not runtime_trace.exists() or not any(
                line.startswith(('ff_init ', 'nginx_worker_shim '))
                for line in runtime_trace.read_text().splitlines()),
                'unsupported listener option reached runtime commit or listener apply')
            stop_frontend_children((master,))
            master = None
            for fd in capabilities:
                try: os.close(fd)
                except OSError: pass
            capabilities.clear()
            print('NGINX_FSTACK_UNSUPPORTED_LISTENER_REJECTED option=rcvbuf runtime_committed=false')
            return {'master': None}
        children_path = Path(f'/proc/{master}/task/{master}/children')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            initial_workers = children_path.read_text().split() if children_path.exists() else []
            if len(initial_workers) == worker_count: break
            time.sleep(0.02)
        require(len(initial_workers) == worker_count,
            f'nginx did not start exactly {worker_count} workers: {initial_workers!r}')
        initial_worker_pids = {int(pid) for pid in initial_workers}
        deadline = time.monotonic() + 20
        stage = 'initial HTTP request'
        first_request_error = None
        while time.monotonic() < deadline:
            try:
                response = request_static('198.18.0.2', 4098, '/small.txt')
                require(response[0] == len(b'preload-http-ok\n'), f'small response length differs: {response}')
                break
            except (OSError, RuntimeError) as error:
                first_request_error = repr(error)
                time.sleep(0.05)
        else:
            error_log = (logs / 'error.log').read_text() if (logs / 'error.log').exists() else '<missing>'
            trace = runtime_trace.read_text() if runtime_trace.exists() else '<missing>'
            raise RuntimeError('nginx did not serve its first request through the selected broker caller; '
                f'last_request_error={first_request_error}; error_log={error_log!r}; runtime_trace={trace!r}')
        if args.fstack_worker_shim:
            prove_nginx_workers_serve(access_log, initial_worker_pids, 'initial startup')
        require(len(capabilities) == 2,
            f'broker bootstrap returned {len(capabilities)} capabilities, expected listener and epoll')
        os.close(capabilities[0])
        # Keep the bootstrap epoll capability only in the supervisor. The
        # fixture broker exits when its last object closes; retaining this
        # anchor lets a replacement FF worker reconnect after the old worker
        # releases its own sockets. Nginx never inherits or registers it.
        capabilities[:] = [capabilities[1]]

        # Hold twelve real TCP streams after body delivery starts, then HUP the
        # master while workers have backpressured original-Linux file responses.
        all_started = threading.Event(); start_count = 0; start_lock = threading.Lock()
        results = []; errors = []
        transition_retries = {}
        def mark_started():
            nonlocal start_count
            with start_lock:
                start_count += 1
                if start_count == 12:
                    all_started.set()
        def active_stream():
            try:
                connection = socket.create_connection(('198.18.0.2', 4098), timeout=20)
                connection.sendall(b'GET /large.bin HTTP/1.1\r\nHost: ker.test\r\nConnection: close\r\n\r\n')
                length, digest = read_http_response(connection, pause_before_body=2.0,
                    on_body_start=mark_started)
                connection.close(); results.append((length, digest))
            except BaseException as error:
                errors.append(error)
        threads = [threading.Thread(target=active_stream) for _ in range(12)]
        stage = 'HUP active streams'
        for thread in threads: thread.start()
        if not all_started.wait(20):
            error_log = (logs / 'error.log').read_text() if (logs / 'error.log').exists() else '<missing>'
            trace = runtime_trace.read_text() if runtime_trace.exists() else '<missing>'
            raise RuntimeError(f'only {start_count} of 12 streams received initial body bytes; '
                f'errors={errors!r}; error_log={error_log!r}; runtime_trace={trace!r}')
        os.kill(master, signal.SIGHUP)
        for thread in threads: thread.join(timeout=60)
        require(not any(thread.is_alive() for thread in threads), 'active nginx streams did not finish after HUP')
        require(not errors, f'active stream failed during HUP: {errors!r}')
        expected_digest = hashlib.sha256(large).hexdigest()
        require(len(results) == 12 and all(value == (len(large), expected_digest) for value in results),
            f'active stream length/hash mismatch: {results!r}')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            current_workers = children_path.read_text().split() if children_path.exists() else []
            if len(current_workers) == worker_count and not (set(initial_workers) & set(current_workers)):
                break
            time.sleep(0.05)
        require(len(current_workers) == worker_count and not (set(initial_workers) & set(current_workers)),
            f'HUP did not replace the nginx workers: before={initial_workers!r} after={current_workers!r}')
        hup_worker_pids = {int(pid) for pid in current_workers}
        stage = 'HTTP after HUP'
        if fstack_profile:
            _, transition_retries['hup'] = wait_for_static('198.18.0.2', 4098)
            if args.fstack_worker_shim:
                prove_nginx_workers_serve(access_log, hup_worker_pids, 'after HUP')
        else:
            response = request_static('198.18.0.2', 4098, '/small.txt')
            require(response[0] == len(b'preload-http-ok\n'), 'fresh HTTP request failed after HUP')

        # USR2 must exec the same image and publish a replacement master. The
        # no-FF caller inherits its listener across exec; the FF runtime profile
        # opens the worker-owned listener after replacement-master startup.
        stage = 'USR2 active stream'
        usr2_started = threading.Event(); usr2_result = []
        def usr2_stream():
            connection = socket.create_connection(('198.18.0.2', 4098), timeout=20)
            try:
                connection.sendall(b'GET /large.bin HTTP/1.1\r\nHost: ker.test\r\nConnection: close\r\n\r\n')
                usr2_result.append(read_http_response(connection, pause_before_body=2.0,
                    on_body_start=usr2_started.set))
            finally:
                connection.close()
        usr2_thread = threading.Thread(target=usr2_stream); usr2_thread.start()
        require(usr2_started.wait(15), 'USR2 handover stream did not begin receiving body bytes')
        os.kill(master, signal.SIGUSR2)
        wait_for_path(oldbin, 30, 'old nginx master pidfile after USR2')
        deadline = time.monotonic() + 30
        new_master = master
        while time.monotonic() < deadline:
            try: new_master = int(pidfile.read_text().strip())
            except (OSError, ValueError): new_master = master
            if new_master != master and os.path.exists(f'/proc/{new_master}'): break
            time.sleep(0.05)
        require(new_master != master and os.path.exists(f'/proc/{new_master}'),
            'USR2 did not exec a replacement nginx master')
        require(int(oldbin.read_text().strip()) == master,
            'nginx oldbin pidfile did not retain the predecessor master PID')
        replacement_children_path = Path(f'/proc/{new_master}/task/{new_master}/children')
        deadline = time.monotonic() + 20
        replacement_worker_pids = set()
        while time.monotonic() < deadline:
            replacement_children = replacement_children_path.read_text().split() \
                if replacement_children_path.exists() else []
            if len(replacement_children) == worker_count:
                replacement_worker_pids = {int(pid) for pid in replacement_children}
                break
            time.sleep(0.05)
        require(len(replacement_worker_pids) == worker_count,
            f'USR2 replacement master did not start {worker_count} workers: {replacement_children!r}')
        usr2_thread.join(timeout=40)
        require(not usr2_thread.is_alive() and usr2_result and
            usr2_result[0] == (len(large), expected_digest),
            f'active stream did not survive USR2 handover: {usr2_result!r}')
        stage = 'HTTP after USR2'
        if fstack_profile:
            _, transition_retries['usr2'] = wait_for_static('198.18.0.2', 4098)
            if args.fstack_worker_shim:
                prove_nginx_workers_serve(access_log, replacement_worker_pids, 'after USR2')
        else:
            response = request_static('198.18.0.2', 4098, '/small.txt')
            require(response[0] == len(b'preload-http-ok\n'), 'new nginx master did not serve after USR2')
        os.kill(master, signal.SIGWINCH)
        stage = 'WINCH retirement'
        deadline = time.monotonic() + 20
        old_children = []
        while time.monotonic() < deadline:
            children = Path(f'/proc/{master}/task/{master}/children')
            old_children = children.read_text().split() if children.exists() else []
            if old_children == [str(new_master)]: break
            time.sleep(0.05)
        children = Path(f'/proc/{master}/task/{master}/children')
        old_children = children.read_text().split() if children.exists() else []
        require(old_children == [str(new_master)],
            'old nginx workers remained after WINCH: children=' +
            ' '.join(old_children) +
            '; error_log=' + (logs / 'error.log').read_text())
        if args.fstack_worker_shim:
            new_children = replacement_children_path.read_text().split() \
                if replacement_children_path.exists() else []
            require({int(pid) for pid in new_children} == replacement_worker_pids,
                f'WINCH changed replacement worker ownership unexpectedly: {new_children!r}')
        stage = 'HTTP after WINCH'
        if fstack_profile:
            _, transition_retries['winch'] = wait_for_static('198.18.0.2', 4098)
            if args.fstack_worker_shim:
                prove_nginx_workers_serve(access_log, replacement_worker_pids, 'after WINCH')
        else:
            response = request_static('198.18.0.2', 4098, '/small.txt')
            require(response[0] == len(b'preload-http-ok\n'),
                'replacement nginx master stopped serving after old workers retired')
        os.kill(master, signal.SIGQUIT); os.kill(new_master, signal.SIGQUIT)
        reap_frontend_child(master, 20)
        reap_frontend_child(new_master, 20)
        require(broker.poll() is None and rpc_path.exists(),
            'supervisor epoll anchor did not keep the RPC broker alive after nginx retirement')
        time.sleep(0.05)
        require(broker.poll() is None and rpc_path.exists(),
            'supervisor epoll anchor did not preserve the broker endpoint over its bounded lifetime check')
        for fd in capabilities:
            os.close(fd)
        capabilities.clear()
        if fstack_profile:
            trace_lines = runtime_trace.read_text().splitlines()
            init_lines = [line for line in trace_lines if line.startswith('ff_init ')]
            leaf_lines = [line for line in trace_lines if line.startswith('ff_epoll_ctl ')
                and 'target=ff ' in line and 'result=0' in line]
            api_lines = [line for line in trace_lines if line.startswith('ff_leaf ')]
            require(len(init_lines) >= 3 and all('graceful_reload=0 attached=0 active=0 target=0' in line
                for line in init_lines), f'FF runtime did not retain the original detached graceful-off view: {init_lines!r}')
            if args.fstack_worker_shim:
                role_by_pid = {}
                for line in init_lines:
                    match = re.search(r'ff_init pid=(\d+) proc_id=(\d+) proc_type=(primary|secondary)', line)
                    if match:
                        role_by_pid[int(match.group(1))] = (int(match.group(2)), match.group(3))
                shim_by_pid = {}
                for line in trace_lines:
                    match = re.search(r'nginx_worker_shim pid=(\d+) worker=(\d+) workers=2 listeners=2 ignored_worker=(\d+)', line)
                    if match:
                        shim_by_pid[int(match.group(1))] = (int(match.group(2)), int(match.group(3)))
                expected_worker_pids = initial_worker_pids | hup_worker_pids | replacement_worker_pids
                require(expected_worker_pids <= role_by_pid.keys(),
                    f'not every observed Nginx worker has a native FF role trace: {role_by_pid!r}')
                require(expected_worker_pids <= shim_by_pid.keys(),
                    f'not every observed Nginx worker has a listener-shim trace: {shim_by_pid!r}')
                for pid in expected_worker_pids:
                    worker = 0 if role_by_pid[pid] == (0, 'primary') else 1 \
                        if role_by_pid[pid] == (1, 'secondary') else -1
                    require(worker in (0, 1) and shim_by_pid[pid] ==
                        (worker, 1 - worker),
                        f'Nginx worker {pid} role/shim ownership mismatch: '
                        f'role={role_by_pid[pid]!r}; shim={shim_by_pid[pid]!r}')
            require(leaf_lines, 'Nginx did not register any offset FF descriptors through the runtime adapter')
            for api in ('ff_socket', 'ff_bind', 'ff_listen', 'ff_accept', 'ff_recv', 'ff_writev'):
                require(any(f'name={api} ' in line and 'first=success' in line for line in api_lines),
                    f'Nginx did not reach a successful original FF leaf {api}: {api_lines!r}')
            clear_masks = [int(match.group(1), 16) for line in trace_lines
                if (match := re.search(r'ff_epoll_ctl .*events=(0x[0-9a-fA-F]+)', line))]
            require(any(mask & 0x80000000 and not (mask & 0x20) for mask in clear_masks),
                f'FF EV_CLEAR was not adapted to Linux EPOLLET: {clear_masks!r}')
            print(f'NGINX_FSTACK_RUNTIME_OK workers={worker_count} active_streams=12 body_bytes={len(large)} sha256={expected_digest} '
                f'ff_epoll_ctl_successes={len(leaf_lines)} ff_api_trace_events={len(api_lines)} init_calls={len(init_lines)} '
                f'post_transition_retries={transition_retries} sendfile=off')
            if args.fstack_worker_shim:
                print(f'NGINX_FSTACK_WORKER_OWNERSHIP_OK initial_workers={sorted(initial_worker_pids)} '
                    f'hup_workers={sorted(hup_worker_pids)} usr2_workers={sorted(replacement_worker_pids)} '
                    f'active_workers_after_winch={sorted(replacement_worker_pids)} '
                    f'worker_serving_access_log={access_log}')
        else:
            print(f'NGINX_POSIX_PRELOAD_OK active_streams=12 body_bytes={len(large)} sha256={expected_digest} '
                f'old_master={master} new_master={new_master} sendfile=on')
        return {'master': None}
    except BaseException as error:
        stop_frontend_children((master, new_master))
        for fd in capabilities:
            try: os.close(fd)
            except OSError: pass
        capabilities.clear()
        stats_path = root / 'stats.json'
        deadline = time.monotonic() + 8
        while not stats_path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        stats = stats_path.read_text() if stats_path.exists() else '<not finalized>'
        error_log = (logs / 'error.log').read_text() if (logs / 'error.log').exists() else '<missing>'
        trace = runtime_trace.read_text() if runtime_trace.exists() else '<missing>'
        raise RuntimeError(f'{error}; stage={stage}; error_log={error_log!r}; '
            f'runtime_trace={trace!r}; broker_stats={stats}') from error


def inside(args):
    for command in (
        ['ip', 'link', 'set', 'lo', 'up'],
        ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
        ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
        ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
        ['ip', 'link', 'set', 'kerhost', 'up'],
        ['ip', 'link', 'set', 'kerlink', 'up'],
        ['ip', 'link', 'set', 'kerpeer', 'up'],
    ):
        subprocess.run(command, check=True)
    cpu = min(os.sched_getaffinity(0))
    eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
        f'--iova-mode=va -m 64 -d {shlex.quote(str(args.dpdk_plugin_dir / "librte_net_tap.so"))} '
        '--vdev=net_tap0,iface=kerpeer,remote=kerlink')
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, 'could not become a child subreaper')
    broker = client_process = None
    child_pid = None
    cap_fds = []
    try:
        with tempfile.TemporaryDirectory(prefix='ker-native-socket-broker-') as directory:
            root = Path(directory)
            rpc_path = root / 'rpc.sock'
            bootstrap_path = root / 'bootstrap.sock'
            stats_path = root / 'stats.json'
            if args.member_census_runtime_test:
                run_payload_snapshot_wire_probe(args, eal, root)
                stats = json.loads(stats_path.read_text())
                require(stats.get('outstanding') == 0,
                    f'member census runtime did not finalize its LKL/DPDK worker: {stats!r}')
                return 0
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as bootstrap:
                bootstrap.bind(str(bootstrap_path)); os.chmod(bootstrap_path, 0o600); bootstrap.listen(1)
                if args.generation_worker:
                    selected_broker = args.generation_broker
                elif args.reuseport_group_client or args.member_census_client:
                    selected_broker = args.group_broker
                else:
                    selected_broker = args.broker
                command = [sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                    '--port', 'net_tap0', '--eal', eal, '--stats', str(stats_path), '--',
                    str(selected_broker), str(rpc_path), str(bootstrap_path)]
                if args.observer_client:
                    command.append('observer')
                environment = os.environ | {
                    'PYTHONDONTWRITEBYTECODE': '1',
                    'RUNTIME_DIRECTORY': str(root),
                }
                broker = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0,
                    start_new_session=True)
                bootstrap.settimeout(30)
                try:
                    connection, _ = bootstrap.accept()
                except TimeoutError as error:
                    if broker.poll() is None:
                        broker.kill()
                    output, errors = broker.communicate(timeout=10)
                    raise RuntimeError(f'broker did not connect bootstrap; exit={broker.returncode}; '
                        f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
                with connection:
                    cap_fds = receive_group_bootstrap(connection) if (
                        args.reuseport_group_client or args.member_census_client or
                        args.generation_worker) else receive_bootstrap(connection)
                    connection.settimeout(5)
                    if not (args.reuseport_group_client or args.member_census_client or
                            args.generation_worker):
                        send_host_socket_probe(connection)
                broker_line = read_line(broker.stdout, 15, broker)
                require(broker_line == 'BROKER_READY', f'broker failed to enter its request loop: {broker_line}')

                if args.ff_owner_payload_client:
                    run_ff_owner_payload_probe(args, rpc_path, cap_fds)
                    cap_fds.clear()
                    output, errors = broker.communicate(timeout=30)
                    require(broker.returncode == 0 and b'BROKER_DONE' in output,
                        f'FF owner broker did not release all metadata: '
                        f'stdout={output!r}; stderr={errors.decode(errors="replace")}')
                    stats = json.loads(stats_path.read_text())
                    require(stats.get('tx', 0) > 0 and stats.get('rx', 0) > 0 and
                        stats.get('outstanding') == 0 and
                        stats.get('native', {}).get('active_opens', 0) >= 2,
                        f'FF owner traffic or cleanup evidence missing: {stats!r}')
                    return 0

                if args.reuseport_group_client:
                    run_reuseport_group_client(args, rpc_path, broker, cap_fds[0])
                    cap_fds.clear()
                    try:
                        output, errors = broker.communicate(timeout=30)
                    except subprocess.TimeoutExpired as error:
                        broker.kill(); output, errors = broker.communicate(timeout=10)
                        raise RuntimeError(f'broker did not release reuseport group after all capabilities closed: '
                            f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
                    require(broker.returncode == 0 and b'BROKER_DONE' in output,
                        f'broker did not finalize reuseport group: {output!r} {errors.decode(errors="replace")}')
                    stats = json.loads(stats_path.read_text())
                    native = stats.get('native', {})
                    require(stats.get('tx', 0) > 0 and stats.get('rx', 0) > 0 and
                        stats.get('outstanding') == 0 and native.get('passive_opens', 0) >= 3,
                        f'original-Linux reuseport traffic or cleanup evidence missing: {stats!r}')
                    print('PASS: broker-created two-member original-Linux reuseport cBPF group, selector transitions, '
                        'group/member lifetime and accepted-stream teardown')
                    return 0
                if args.member_census_client:
                    run_member_census_client(args, rpc_path, broker, cap_fds.pop(0))
                    cap_fds.clear()
                    output, errors = broker.communicate(timeout=30)
                    require(broker.returncode == 0 and b'BROKER_DONE' in output,
                        f'member census broker did not release all metadata: '
                        f'stdout={output!r}; stderr={errors.decode(errors="replace")}')
                    stats = json.loads(stats_path.read_text())
                    native = stats.get('native', {})
                    require(stats.get('outstanding') == 0 and native.get('passive_opens', 0) >= 2,
                        f'member census traffic or native cleanup evidence missing: {stats!r}')
                    return 0
                if args.generation_worker:
                    group_fd = cap_fds.pop(0)
                    run_generation_handoff(args, rpc_path, broker, group_fd, root)
                    return 0
                if args.observer_client:
                    run_tcp_observer_frontend(args, rpc_path, broker, cap_fds, root)
                    return 0

                if args.nginx_binary:
                    run_nginx_preloaded(args, rpc_path, cap_fds, root, broker)
                    try:
                        output, errors = broker.communicate(timeout=40)
                    except subprocess.TimeoutExpired as error:
                        broker.kill(); output, errors = broker.communicate(timeout=10)
                        raise RuntimeError(f'original-Linux broker failed to release nginx descriptors: '
                            f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
                    require(broker.returncode == 0 and b'BROKER_DONE' in output,
                        f'broker did not finalize nginx sockets: {output!r} {errors.decode(errors="replace")}')
                    stats = json.loads(stats_path.read_text())
                    native = stats.get('native', {})
                    if args.nginx_test_unsupported_option:
                        require(stats.get('outstanding') == 0 and
                            native.get('active_opens', 0) == 0 and native.get('passive_opens', 0) == 0,
                            f'unsupported listener option reached socket creation: {stats!r}')
                        print('NGINX_FSTACK_UNSUPPORTED_LISTENER_NO_SOCKET_CREATED')
                        return 0
                    require(stats.get('tx', 0) > 0 and stats.get('rx', 0) > 0 and
                        stats.get('outstanding') == 0 and native.get('passive_opens', 0) >= 13,
                        f'original-Linux TCP/DPDK traffic or cleanup evidence missing: {stats!r}')
                    print(f'NGINX_ORIGINAL_LINUX_STATS tx={stats.get("tx")} rx={stats.get("rx")} '
                        f'passive_opens={native.get("passive_opens")} outstanding={stats.get("outstanding")}')
                    return 0

                if args.fstack_client:
                    run_fstack_bridge_frontend(args, rpc_path, cap_fds)
                    try:
                        output, errors = broker.communicate(timeout=30)
                    except subprocess.TimeoutExpired as error:
                        broker.kill(); output, errors = broker.communicate(timeout=10)
                        raise RuntimeError(f'broker did not stop after FF bridge closed capabilities: '
                            f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
                    require(broker.returncode == 0 and b'BROKER_DONE' in output,
                        f'broker did not finalize FF leaf sockets: {output!r} {errors.decode(errors="replace")}')
                    stats = json.loads(stats_path.read_text())
                    native = stats.get('native', {})
                    require(stats.get('tx', 0) > 0 and stats.get('rx', 0) > 0 and
                        stats.get('outstanding') == 0 and native.get('active_opens', 0) >= 1,
                        f'original-Linux TCP/DPDK traffic or cleanup evidence missing: {stats!r}')
                    print('PASS: selected original F-Stack leaf APIs used namespaced preload entry points, '
                        'preserved a 4097-byte external TCP stream, rejected unsupported leaves, and '
                        'released the original-Linux socket')
                    return 0

                if args.fstack_drain_failure_client:
                    run_fstack_drain_failure_frontend(args, rpc_path, broker, cap_fds)
                    return 0

                if args.preload_client:
                    run_preloaded_frontend(args, rpc_path, broker, cap_fds)
                    try:
                        output, errors = broker.communicate(timeout=30)
                    except subprocess.TimeoutExpired as error:
                        broker.kill(); output, errors = broker.communicate(timeout=10)
                        raise RuntimeError(f'broker failed to stop after preload caller closed capabilities: '
                            f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
                    require(broker.returncode == 0 and b'BROKER_DONE' in output,
                        f'broker did not close/finalize cleanly: {output!r} {errors.decode(errors="replace")}')
                    stats = json.loads(stats_path.read_text())
                    native = stats.get('native', {})
                    require(stats.get('tx', 0) > 0 and stats.get('rx', 0) > 0 and
                        stats.get('outstanding') == 0 and native.get('passive_opens', 0) >= 2,
                        f'original-Linux TCP/DPDK traffic or cleanup evidence missing: {stats!r}')
                    print('PASS: client-only POSIX preload kept host AF_UNIX/files/eventfd separate, '
                        'merged host and original-Linux epoll readiness, and preserved an active TCP stream '
                        'plus listener across fork/exec')
                    return 0

                # A malformed unauthenticated frame must close only that session.
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as malformed:
                    malformed.settimeout(5); malformed.connect(str(rpc_path)); malformed.send(b'bad')
                    require(malformed.recv(64) == b'', 'malformed RPC did not fail closed')
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as empty_with_rights:
                    empty_with_rights.settimeout(5); empty_with_rights.connect(str(rpc_path))
                    cap_array = array.array('i', [cap_fds[0]])
                    require(empty_with_rights.sendmsg([b''], [
                        (socket.SOL_SOCKET, socket.SCM_RIGHTS, cap_array)]) == 0,
                        'zero-length rights-bearing RPC send unexpectedly had payload bytes')
                    require(empty_with_rights.recv(64) == b'',
                        'zero-length rights-bearing RPC did not close its session')

                client_process = subprocess.Popen([str(args.client), 'parent', str(rpc_path),
                    str(cap_fds[0]), str(cap_fds[1])], pass_fds=tuple(cap_fds),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                for fd in cap_fds:
                    os.close(fd)
                cap_fds.clear()
                first_line = read_line(client_process.stdout, 15, client_process)
                require(first_line == 'WAIT_ACCEPT', f'client did not exercise empty nonblocking accept: {first_line}')
                first_peer = socket.create_connection(('198.18.0.2', 4097), timeout=10)
                first_peer.settimeout(10)
                parent_exit = False
                child_ready = False
                pre_fork_done = False
                maximum_send_done = False
                preexec_reconnected = False
                preexec_error = None
                observed = []
                while not parent_exit:
                    line = read_line(client_process.stdout, 15, client_process)
                    observed.append(line)
                    if line.startswith('CHILD_PID '):
                        child_pid = int(line.split()[1])
                    elif line == 'PARENT_EXIT':
                        parent_exit = True
                    elif line == 'CHILD_READY':
                        child_ready = True
                    elif line == 'PREEXEC_RECONNECTED':
                        preexec_reconnected = True
                    elif line.startswith('PREEXEC_ERROR '):
                        preexec_error = line
                    elif line == 'PRE_FORK_WAIT':
                        first_peer.sendall(b'BEFORE-FORK')
                        require(recv_exact(first_peer, 11) == b'PRE-FORK-OK',
                            'predecessor failed to use the original accepted stream before exec')
                        pre_fork_done = True
                    elif line == 'PRE_FORK_OK':
                        require(pre_fork_done, 'pre-fork response arrived before host transfer')
                    elif line == 'MAX_SEND_OK':
                        maximum_payload = bytes((index * 31 + 7) & 0xff for index in range(4096))
                        require(recv_exact(first_peer, len(maximum_payload)) == maximum_payload,
                            '4096-byte maximum SEND payload differs')
                        maximum_send_done = True
                require(pre_fork_done, 'accepted stream was not active before fork/exec')
                require(maximum_send_done, 'client did not exercise the full documented SEND payload size')
                deadline = time.monotonic() + 15
                while not preexec_reconnected and preexec_error is None and time.monotonic() < deadline:
                    line = read_line(client_process.stdout, max(0.1, deadline - time.monotonic()), client_process)
                    observed.append(line)
                    if line == 'PREEXEC_RECONNECTED':
                        preexec_reconnected = True
                    elif line.startswith('PREEXEC_ERROR '):
                        preexec_error = line
                    elif line == 'CHILD_READY':
                        child_ready = True
                require(preexec_reconnected,
                    f'forked process did not reconnect using the inherited client context before exec: '
                    f'{preexec_error}; lines={observed!r}')
                require(child_pid is not None, 'forked frontend did not publish its child PID')
                require(client_process.wait(timeout=5) == 0,
                    'predecessor frontend did not exit after closing its session and capability copies')
                if not child_ready:
                    require(read_line(client_process.stdout, 15, client_process) == 'CHILD_READY',
                        'exec replacement did not reconnect as a fresh RPC session')

                expected = bytes((index * 31 + 7) & 0xff for index in range(4097))
                first_peer.sendall(expected)
                require(recv_exact(first_peer, len(expected)) == expected,
                    'continued accepted stream payload differs after fork/exec')
                first_peer.shutdown(socket.SHUT_WR)
                require(read_line(client_process.stdout, 15, client_process) == 'FIRST_STREAM_OK',
                    'replacement did not observe stream EOF through inherited epoll capability')

                second_peer = socket.create_connection(('198.18.0.2', 4097), timeout=10)
                second_peer.settimeout(10)
                require(read_line(client_process.stdout, 15, client_process) == 'SECOND_ACCEPTED',
                    'replacement did not accept a fresh connection through inherited listener capability')
                second_peer.sendall(b'FRESH-ACCEPT')
                require(recv_exact(second_peer, 9) == b'REPLY-TWO', 'fresh accepted stream reply differs')
                second_peer.shutdown(socket.SHUT_WR)
                require(read_line(client_process.stdout, 15, client_process) == 'CHILD_DONE',
                    'exec replacement did not close all capabilities cleanly')
                require(first_peer.recv(1) == b'', 'continued stream returned extra bytes or missed peer EOF')
                require(second_peer.recv(1) == b'', 'fresh stream returned extra bytes or missed peer EOF')
                first_peer.close()
                second_peer.close()
                reap_frontend_child(child_pid, 10)
                child_pid = None

                try:
                    output, errors = broker.communicate(timeout=30)
                except subprocess.TimeoutExpired as error:
                    broker.kill()
                    output, errors = broker.communicate(timeout=10)
                    raise RuntimeError(f'broker failed to stop after capabilities closed: '
                        f'stdout={output!r}; stderr={errors.decode(errors="replace")}') from error
                require(broker.returncode == 0 and b'BROKER_DONE' in output,
                    f'broker did not close/finalize cleanly: {output!r} {errors.decode(errors="replace")}')
                stats = json.loads(stats_path.read_text())
                native = stats.get('native', {})
                require(stats.get('tx', 0) > 0 and stats.get('rx', 0) > 0 and
                    stats.get('outstanding') == 0 and native.get('passive_opens', 0) >= 2,
                    f'original-Linux TCP/DPDK traffic or cleanup evidence missing: {stats!r}')
                print('PASS: original-Linux accepted TCP and epoll capabilities survive frontend fork+exec; '
                    'replacement continues the exact stream, accepts a fresh peer, and releases all objects')
    finally:
        for fd in cap_fds:
            try: os.close(fd)
            except OSError: pass
        if child_pid is not None:
            try: os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: os.waitpid(child_pid, 0)
            except ChildProcessError: pass
        if client_process is not None and client_process.poll() is None:
            client_process.kill(); client_process.wait()
        if broker is not None and broker.poll() is None:
            broker.kill(); broker.wait()
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'broker', 'client', 'dpdk-plugin-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--preload-client', type=Path)
    parser.add_argument('--fstack-client', type=Path)
    parser.add_argument('--fstack-drain-failure-client', type=Path)
    parser.add_argument('--observer-client', type=Path)
    parser.add_argument('--preload-library', type=Path)
    parser.add_argument('--nginx-binary', type=Path)
    parser.add_argument('--fstack-runtime', type=Path)
    parser.add_argument('--fstack-worker-shim', type=Path)
    parser.add_argument('--nginx-workers', type=int, choices=(1, 2))
    parser.add_argument('--nginx-test-unsupported-option', action='store_true')
    parser.add_argument('--group-broker', type=Path)
    parser.add_argument('--reuseport-group-client', type=Path)
    parser.add_argument('--inherited-group-probe', type=Path)
    parser.add_argument('--member-census-client', type=Path)
    parser.add_argument('--member-census-runtime-test', type=Path)
    parser.add_argument('--member-census-test-library', type=Path)
    parser.add_argument('--ff-owner-payload-client', type=Path)
    parser.add_argument('--generation-broker', type=Path)
    parser.add_argument('--generation-worker', type=Path)
    parser.add_argument('--generation-controller', type=Path)
    args = parser.parse_args()
    if args.reuseport_group_client and (not args.inherited_group_probe or not args.preload_library):
        parser.error('reuseport group test requires inherited group probe and preload library')
    if args.observer_client and not args.preload_library:
        parser.error('TCP observer test requires the socket preload library for inherited capability validation')
    if args.fstack_drain_failure_client and not args.preload_library:
        parser.error('F-Stack drain-count failure test requires the socket preload library')
    if args.generation_worker and not (args.generation_broker and args.generation_controller):
        parser.error('generation handoff test requires broker factory and SDK controller')
    if args.member_census_runtime_test and not args.member_census_test_library:
        parser.error('member census runtime test requires its noninstalled isolated runtime')
    if args.ff_owner_payload_client and not (args.fstack_runtime and args.preload_library):
        parser.error('FF owner payload test requires the F-Stack runtime and preload library')
    if args.fstack_worker_shim and not (args.nginx_binary and args.fstack_runtime and
        args.preload_library and args.nginx_workers == 2):
        parser.error('F-Stack worker shim requires nginx, runtime, preload, and --nginx-workers=2')
    if args.nginx_test_unsupported_option and not args.fstack_worker_shim:
        parser.error('unsupported listener option test requires the F-Stack worker shim')
    if args.nginx_workers and not args.nginx_binary:
        parser.error('--nginx-workers requires --nginx-binary')
    if not args.inside:
        if args.nginx_binary:
            command = ['unshare', '-Un', '--keep-caps', f'--map-user={os.getuid()}',
                f'--map-group={os.getgid()}', sys.executable, str(Path(__file__).resolve()), '--inside']
        else:
            command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'broker', 'client', 'dpdk-plugin-dir'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        if args.preload_client:
            command += ['--preload-client', str(args.preload_client.resolve())]
        if args.fstack_client:
            command += ['--fstack-client', str(args.fstack_client.resolve())]
        if args.fstack_drain_failure_client:
            command += ['--fstack-drain-failure-client',
                str(args.fstack_drain_failure_client.resolve())]
        if args.observer_client:
            command += ['--observer-client', str(args.observer_client.resolve())]
        if args.preload_library:
            command += ['--preload-library', str(args.preload_library.resolve())]
        if args.nginx_binary:
            command += ['--nginx-binary', str(args.nginx_binary.resolve())]
        if args.fstack_runtime:
            command += ['--fstack-runtime', str(args.fstack_runtime.resolve())]
        if args.fstack_worker_shim:
            command += ['--fstack-worker-shim', str(args.fstack_worker_shim.resolve())]
        if args.nginx_workers:
            command += ['--nginx-workers', str(args.nginx_workers)]
        if args.nginx_test_unsupported_option:
            command.append('--nginx-test-unsupported-option')
        if args.group_broker:
            command += ['--group-broker', str(args.group_broker.resolve())]
        if args.reuseport_group_client:
            command += ['--reuseport-group-client', str(args.reuseport_group_client.resolve())]
        if args.inherited_group_probe:
            command += ['--inherited-group-probe', str(args.inherited_group_probe.resolve())]
        if args.member_census_client:
            command += ['--member-census-client', str(args.member_census_client.resolve())]
        if args.member_census_runtime_test:
            command += ['--member-census-runtime-test',
                str(args.member_census_runtime_test.resolve())]
        if args.member_census_test_library:
            command += ['--member-census-test-library',
                str(args.member_census_test_library.resolve())]
        if args.ff_owner_payload_client:
            command += ['--ff-owner-payload-client', str(args.ff_owner_payload_client.resolve())]
        if args.generation_broker:
            command += ['--generation-broker', str(args.generation_broker.resolve())]
        if args.generation_worker:
            command += ['--generation-worker', str(args.generation_worker.resolve())]
        if args.generation_controller:
            command += ['--generation-controller', str(args.generation_controller.resolve())]
        return subprocess.run(command).returncode
    try:
        return inside(args)
    except BaseException as error:
        print(f'native socket broker integration failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
