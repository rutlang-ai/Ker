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


def run_reuseport_group_client(args, rpc_path, broker, capability):
    client = subprocess.Popen([str(args.reuseport_group_client), str(rpc_path), str(capability)],
        pass_fds=(capability,), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    os.close(capability)
    try:
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
    environment = os.environ | {
        'LD_PRELOAD': str(args.preload_library.resolve()),
        'KER_SOCKET_BROKER_PATH': str(rpc_path),
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    host_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    host_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    host_listener.bind(('198.18.0.1', 4097)); host_listener.listen(1); host_listener.settimeout(15)
    frontend = subprocess.Popen([str(args.fstack_client)], pass_fds=tuple(capabilities),
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
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as bootstrap:
                bootstrap.bind(str(bootstrap_path)); os.chmod(bootstrap_path, 0o600); bootstrap.listen(1)
                selected_broker = args.group_broker if args.reuseport_group_client else args.broker
                command = [sys.executable, str(args.launcher), '--library', str(args.library),
                    '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
                    '--port', 'net_tap0', '--eal', eal, '--stats', str(stats_path), '--',
                    str(selected_broker), str(rpc_path), str(bootstrap_path)]
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
                    cap_fds = receive_group_bootstrap(connection) if args.reuseport_group_client else receive_bootstrap(connection)
                    connection.settimeout(5)
                    if not args.reuseport_group_client:
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
    parser.add_argument('--preload-library', type=Path)
    parser.add_argument('--nginx-binary', type=Path)
    parser.add_argument('--fstack-runtime', type=Path)
    parser.add_argument('--group-broker', type=Path)
    parser.add_argument('--reuseport-group-client', type=Path)
    args = parser.parse_args()
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
        return subprocess.run(command).returncode
    try:
        return inside(args)
    except BaseException as error:
        print(f'native socket broker integration failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
