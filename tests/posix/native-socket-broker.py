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
        require(len(fill0) == 6 and fill0[0] == 'FILL' and fill0[1] == '0' and
            int(fill0[2]) > 0 and int(fill0[3]) > 0 and int(fill0[4]) == 0 and int(fill0[5]) == 0,
            f'original Linux member0 sender did not reach EAGAIN: {fill0!r}')
        sent0 = int(fill0[2])
        observer_fds.append(receive_metadata_fds(supervisor, 'O', 0, count=1)[0])
        require(census_command(client, 'CLOSE 0') == 'CLOSE 0 0 0',
            'could not close old accepted TCP descriptor after native send pressure')

        fresh = socket.create_connection(('198.18.0.2', 4097), timeout=8)
        fresh.settimeout(8); fresh.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096); peers.append(fresh)
        census_accept(client, 1, 1)
        fill1 = census_command(client, 'FILL 1', 30).split()
        require(len(fill1) == 6 and fill1[0] == 'FILL' and fill1[1] == '1' and
            int(fill1[2]) > 0 and int(fill1[3]) > 0 and int(fill1[4]) == 0 and int(fill1[5]) == 0,
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
        pass_fds=(capability,), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    os.close(capability)
    try:
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
    except BaseException:
        if client.poll() is None:
            client.kill(); client.wait()
        raise


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


def read_http_response(connection, expected_body=None, pause_before_body=0, on_body_start=None):
    connection.settimeout(30)
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
        return read_http_response(connection, pause_before_body=pause_before_body)
    finally:
        connection.close()


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
    worker_count = 1 if fstack_profile else 2
    config.write_text(f'''daemon on;
master_process on;
worker_processes {worker_count};
{runtime_config}pid {logs / 'nginx.pid'};
error_log {logs / 'error.log'} notice;
env LD_PRELOAD;
env KER_SOCKET_BROKER_PATH;
events {{ worker_connections 1024; use epoll; }}
http {{
    access_log off;
    sendfile {sendfile};
    tcp_nopush off;
    keepalive_timeout 0;
    server {{
        listen 198.18.0.2:4098{reuseport};
        server_name ker.test;
        root {html};
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
        children_path = Path(f'/proc/{master}/task/{master}/children')
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            initial_workers = children_path.read_text().split() if children_path.exists() else []
            if len(initial_workers) == worker_count: break
            time.sleep(0.02)
        require(len(initial_workers) == worker_count,
            f'nginx did not start exactly {worker_count} workers: {initial_workers!r}')
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
        stage = 'HTTP after HUP'
        if fstack_profile:
            _, transition_retries['hup'] = wait_for_static('198.18.0.2', 4098)
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
        usr2_thread.join(timeout=40)
        require(not usr2_thread.is_alive() and usr2_result and
            usr2_result[0] == (len(large), expected_digest),
            f'active stream did not survive USR2 handover: {usr2_result!r}')
        stage = 'HTTP after USR2'
        if fstack_profile:
            _, transition_retries['usr2'] = wait_for_static('198.18.0.2', 4098)
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
        stage = 'HTTP after WINCH'
        if fstack_profile:
            _, transition_retries['winch'] = wait_for_static('198.18.0.2', 4098)
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
                command = [sys.executable, str(args.launcher), '--library',
                    str(args.member_census_test_library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                    '--port', 'net_tap0', '--eal', eal, '--stats', str(stats_path), '--',
                    str(args.member_census_runtime_test)]
                environment = os.environ | {
                    'PYTHONDONTWRITEBYTECODE': '1',
                    'RUNTIME_DIRECTORY': str(root),
                }
                result = subprocess.run(command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                    timeout=90, text=True)
                require(result.returncode == 0 and 'MEMBER_CENSUS_RUNTIME_OK' in result.stdout,
                    f'member census runtime lifecycle failed: stdout={result.stdout!r}; '
                    f'stderr={result.stderr!r}')
                stats = json.loads(stats_path.read_text())
                require(stats.get('outstanding') == 0,
                    f'member census runtime did not finalize its LKL/DPDK worker: {stats!r}')
                print(result.stdout.strip())
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
    parser.add_argument('--group-broker', type=Path)
    parser.add_argument('--reuseport-group-client', type=Path)
    parser.add_argument('--inherited-group-probe', type=Path)
    parser.add_argument('--member-census-client', type=Path)
    parser.add_argument('--member-census-runtime-test', type=Path)
    parser.add_argument('--member-census-test-library', type=Path)
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
