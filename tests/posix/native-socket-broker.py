#!/usr/bin/env python3
"""Original-Linux socket and epoll capabilities survive frontend fork+exec."""
import argparse
import array
import ctypes
import json
import os
from pathlib import Path
import select
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
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


def receive_bootstrap(connection):
    data, ancillary, flags, _ = connection.recvmsg(16, socket.CMSG_SPACE(2 * array.array('i').itemsize),
        socket.MSG_CMSG_CLOEXEC)
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), 'bootstrap capability frame was truncated')
    require(data == struct.pack('=IHH', 0x4b534243, 1, 2), f'bootstrap record differs: {data!r}')
    fds = []
    for level, kind, payload in ancillary:
        require(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS,
            'bootstrap carried an unexpected ancillary record')
        values = array.array('i'); values.frombytes(payload[:len(payload) - len(payload) % values.itemsize])
        fds.extend(values.tolist())
    if len(fds) != 2:
        for fd in fds:
            os.close(fd)
        raise RuntimeError(f'bootstrap delivered {len(fds)} capabilities, expected exactly two')
    return fds


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
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as bootstrap:
                bootstrap.bind(str(bootstrap_path)); os.chmod(bootstrap_path, 0o600); bootstrap.listen(1)
                command = [sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                    '--port', 'net_tap0', '--eal', eal, '--stats', str(stats_path), '--',
                    str(args.broker), str(rpc_path), str(bootstrap_path)]
                environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1'}
                broker = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
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
                    cap_fds = receive_bootstrap(connection)
                    connection.settimeout(5)
                    send_host_socket_probe(connection)
                broker_line = read_line(broker.stdout, 15, broker)
                require(broker_line == 'BROKER_READY', f'broker failed to enter its request loop: {broker_line}')

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
                require(pre_fork_done, 'accepted stream was not active before fork/exec')
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
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'broker', 'client', 'dpdk-plugin-dir'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        return subprocess.run(command).returncode
    try:
        return inside(args)
    except BaseException as error:
        print(f'native socket broker integration failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
