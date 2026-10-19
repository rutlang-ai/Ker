#!/usr/bin/env python3
"""Test imported Linux TCP against an independent host TCP endpoint over DPDK."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.server
from contextlib import contextmanager
import json
import os
from pathlib import Path
import selectors
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def ready(process, port):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(20):
            raise RuntimeError('server did not become ready')
        line = process.stdout.readline().strip()
    if line != f'READY {port}':
        raise RuntimeError('server startup failed: ' + line)


@contextmanager
def server(command, port, log, env, captured=None):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True, env=env)
    try:
        ready(process, port)
        yield process
        output, _ = process.communicate(timeout=30)
        if captured is not None:
            captured.append(output)
        if process.returncode:
            raise RuntimeError(f'server exited {process.returncode}: {output}')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def client(command, env):
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=40)
    if result.returncode or 'PASS:' not in result.stdout:
        raise RuntimeError(f'client exited {result.returncode}: {result.stdout}\n{result.stderr}')
    print(result.stdout.strip(), flush=True)
    return result.stdout


def dualstack(args, launcher, work, env, log):
    if not args.dualstack_app:
        return
    baseline = client([str(args.dualstack_app), 'loopback'], env)
    stats_path = work / 'dualstack-loopback.json'
    observed = client([*launcher, '--stats', str(stats_path), '--', str(args.dualstack_app), 'loopback'], env)
    if observed != baseline:
        raise RuntimeError('native IPv6 loopback differs from host reference')
    stats = json.loads(stats_path.read_text())
    if stats['outstanding'] or stats['native']['active_opens'] < 2 or stats['native']['passive_opens'] < 2:
        raise RuntimeError('IPv6 loopback missed original Linux TCP opens')
    for index, role in enumerate(('host-reference', 'client', 'server')):
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        peer = '198.18.0.1' if native_server else '198.18.0.2'
        if role == 'host-reference':
            address = peer = '127.0.0.1'
        port = 27800 + index
        stats_path = work / ('dualstack-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        listen = [str(args.dualstack_app), 'server', address, str(port), peer]
        connect = [str(args.dualstack_app), 'client', address, str(port), peer]
        if role == 'server':
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('dual-stack server did not validate traffic')
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            counter = 'passive_opens' if native_server else 'active_opens'
            if not stats['tx'] or not stats['rx'] or stats['outstanding'] or not stats['native'][counter]:
                raise RuntimeError('mapped IPv4 socket missed original Linux/DPDK traffic')
        print('PASS: IPv4-mapped dual-stack ' + role, flush=True)


def udp_cork(args, launcher, work, env, log):
    if not args.udp_cork_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27000 + 4 * index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_cork_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_cork_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-cork-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP cork peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 4 or udp['udp_in_datagrams'] < 4 or
                    udp['udp_in_errors'] or udp['udp_no_ports'] or
                    udp['passive_opens' if native_server else 'active_opens'] < 1):
                raise RuntimeError('UDP cork scenarios missed native traffic: ' + str(stats))
            print('native UDP cork ' + role + ': ' + json.dumps(stats), flush=True)


def application_compat(args, launcher, work, env):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'Ker native Linux TCP via unmodified curl\n'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            pass
    if args.curl:
        httpd = http.server.ThreadingHTTPServer(('198.18.0.1', 25011), Handler)
        thread = threading.Thread(target=httpd.serve_forever)
        thread.start()
        try:
            result = subprocess.run([*launcher, '--stats', str(work / 'curl.json'), '--',
                str(args.curl), '--noproxy', '*', '--fail', '--silent', '--show-error',
                '--max-time', '10', 'http://198.18.0.1:25011/'], env=env, text=True,
                capture_output=True, timeout=20)
            if result.returncode or result.stdout != 'Ker native Linux TCP via unmodified curl\n':
                raise RuntimeError('unmodified curl failed: ' + result.stdout + result.stderr)
            print('PASS: unmodified curl HTTP over native TCP', flush=True)
        finally:
            httpd.shutdown(); thread.join(); httpd.server_close()
    if args.redis_server:
        def request(*parts):
            return ('*' + str(len(parts)) + '\r\n' + ''.join(
                '$' + str(len(part)) + '\r\n' + part + '\r\n' for part in parts)).encode()
        stats_path = work / 'redis.json'
        with (work / 'redis.log').open('w+') as log:
            process = subprocess.Popen([*launcher, '--stats', str(stats_path), '--',
                str(args.redis_server), '--bind', '198.18.0.2', '--port', '25012',
                '--protected-mode', 'no', '--save', '', '--appendonly', 'no',
                '--daemonize', 'no', '--dir', str(work)], env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        with socket.create_connection(('198.18.0.2', 25012), timeout=.25) as peer:
                            peer.sendall(request('PING'))
                            if peer.recv(128) != b'+PONG\r\n':
                                raise RuntimeError('unexpected PING response')
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError('unmodified Redis/Valkey did not become ready')
                        time.sleep(.025)
                def exercise(index):
                    with socket.create_connection(('198.18.0.2', 25012), timeout=10) as peer:
                        stream = peer.makefile('rb')
                        for iteration in range(32):
                            key = f'key-{index}-{iteration}'
                            value = f'value-{index}-{iteration}'
                            peer.sendall(request('SET', key, value) + request('GET', key))
                            if (stream.readline() != b'+OK\r\n' or
                                stream.readline() != f'${len(value)}\r\n'.encode() or
                                stream.readline() != value.encode() + b'\r\n'):
                                raise RuntimeError('Redis/Valkey SET/GET response mismatch')
                        stream.close()
                with ThreadPoolExecutor(max_workers=16) as executor:
                    list(executor.map(exercise, range(32)))
                with socket.create_connection(('198.18.0.2', 25012), timeout=10) as peer:
                    peer.sendall(request('SHUTDOWN', 'NOSAVE'))
                    if peer.recv(128):
                        raise RuntimeError('unexpected SHUTDOWN response')
                if process.wait(timeout=15):
                    raise RuntimeError('Redis/Valkey did not shut down cleanly')
                stats = json.loads(stats_path.read_text())
                if stats['outstanding'] or stats['native']['passive_opens'] < 34:
                    raise RuntimeError('Redis/Valkey native connections or mbuf reclamation missing')
                print('PASS: unmodified Redis/Valkey, 32 connections, 16 concurrent, 1024 SET/GET pairs', flush=True)
            except BaseException:
                log.seek(0); sys.stderr.write(log.read()); raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait()



def stream_compat(args, launcher, work, env, log):
    if not args.stream_app:
        return
    for index, api in enumerate(['vector', 'message', 'batch']):
        for native_server in [True, False]:
            role = 'passive' if native_server else 'active'
            port = 25020 + 2 * index + (0 if native_server else 1)
            address = '198.18.0.2' if native_server else '198.18.0.1'
            stats_path = work / ('stream-' + api + '-' + role + '.json')
            listen = [str(args.stream_app), 'server', address, str(port), api]
            connect = [str(args.stream_app), 'client', address, str(port), api]
            native = [*launcher, '--stats', str(stats_path), '--']
            if native_server:
                listen = native + listen
            else:
                connect = native + connect
            captured = []
            with server(listen, port, log, env, captured=captured):
                client(connect, env)
            server_output = "".join(captured)
            if "PASS:" not in server_output:
                raise RuntimeError("stream server did not confirm the byte stream: " + server_output)
            print(server_output.strip(), flush=True)
            stats = json.loads(stats_path.read_text())
            opens = 'passive_opens' if native_server else 'active_opens'
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    not stats['native'][opens]):
                raise RuntimeError('stream I/O missed native TCP/DPDK or leaked: ' + str(stats))
            print('native F-Stack stream ' + api + ' ' + role + ': ' + json.dumps(stats), flush=True)



def udp_lowwater(args, launcher, work, env, log):
    if not args.udp_lowwater_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27200 + 4 * index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_lowwater_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_lowwater_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-lowwater-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP lowwater peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 6 or udp['udp_in_datagrams'] < 6 or
                    udp['udp_in_errors'] or udp['udp_no_ports'] or
                    udp['passive_opens' if native_server else 'active_opens'] < 1):
                raise RuntimeError('UDP lowwater scenarios missed native traffic: ' + str(stats))
            print('native UDP lowwater ' + role + ': ' + json.dumps(stats), flush=True)


def udp_waitforone(args, launcher, work, env, log):
    if not args.udp_waitforone_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27100 + 4 * index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_waitforone_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_waitforone_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-waitforone-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP WAITFORONE peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 3 or udp['udp_in_datagrams'] < 3 or
                    udp['udp_in_errors'] or udp['udp_no_ports'] or
                    udp['passive_opens' if native_server else 'active_opens'] < 1):
                raise RuntimeError('UDP WAITFORONE scenarios missed native traffic: ' + str(stats))
            print('native UDP WAITFORONE ' + role + ': ' + json.dumps(stats), flush=True)


def udp_receive_truncation(args, launcher, work, env, log):
    if not args.udp_receive_truncation_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26900 + index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_receive_truncation_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_receive_truncation_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-receive-truncation-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP receive truncation peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < (17 if native_server else 13) or
                    udp['udp_in_datagrams'] < (13 if native_server else 17) or
                    udp['udp_in_errors'] or udp['udp_no_ports']):
                raise RuntimeError('UDP receive truncation scenarios missed native traffic: ' + str(stats))
            print('native UDP receive truncation ' + role + ': ' + json.dumps(stats), flush=True)


def udp_mtu(args, launcher, work, env, log):
    if not args.udp_mtu_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 25400 + index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_mtu_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_mtu_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-mtu-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP MTU peer did not verify datagrams')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            native_stats = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    native_stats['udp_out_datagrams'] < 5 or native_stats['udp_in_datagrams'] < 5 or
                    native_stats['udp_in_errors'] or native_stats['udp_no_ports'] or
                    native_stats['ip_frag_ok'] < 3 or native_stats['ip_frag_creates'] < 50 or
                    native_stats['ip_reasm_ok'] < 3 or native_stats['ip_reasm_fails']):
                raise RuntimeError('UDP MTU scenarios missed native fragmentation: ' + str(stats))
            print('native UDP MTU ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_reuseport(args, launcher, work, env, log):
    if not args.reuseport_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26000 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.reuseport_app), 'server', address, str(port)]
        connect = [str(args.reuseport_app), 'client', address, str(port)]
        stats_path = work / ('tcp-reuseport-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP reuseport server did not verify listener retirement')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    13):
                raise RuntimeError('TCP reuseport scenario missed native traffic: ' + str(stats))
            print('native TCP reuseport ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_fd_modes(args, launcher, work, env, log):
    if not args.fd_modes_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26700 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.fd_modes_app), 'server', address, str(port)]
        connect = [str(args.fd_modes_app), 'client', address, str(port)]
        stats_path = work / ('tcp-fd-modes-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP fd modes server did not verify both directions')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    2):
                raise RuntimeError('TCP fd modes scenario missed native traffic: ' + str(stats))
            print('native TCP fd modes ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_urgent(args, launcher, work, env, log):
    if not args.urgent_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26100 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.urgent_app), 'server', address, str(port)]
        connect = [str(args.urgent_app), 'client', address, str(port)]
        stats_path = work / ('tcp-urgent-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP urgent server did not verify both modes')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    3):
                raise RuntimeError('TCP urgent scenario missed native traffic: ' + str(stats))
            print('native TCP urgent ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_shutdown_write(args, launcher, work, env, log):
    if not args.shutdown_write_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26300 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.shutdown_write_app), 'server', address, str(port)]
        connect = [str(args.shutdown_write_app), 'client', address, str(port)]
        stats_path = work / ('tcp-shutdown-write-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP shutdown server did not verify EPIPE and reverse I/O')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    2):
                raise RuntimeError('TCP shutdown scenario missed native traffic: ' + str(stats))
            print('native TCP shutdown write ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_receive_queue(args, launcher, work, env, log):
    if not args.receive_queue_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26200 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.receive_queue_app), 'server', address, str(port)]
        connect = [str(args.receive_queue_app), 'client', address, str(port)]
        stats_path = work / ('tcp-receive-queue-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP receive queue server did not verify both directions')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    2):
                raise RuntimeError('TCP receive queue scenario missed native traffic: ' + str(stats))
            print('native TCP receive queue ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_linger(args, launcher, work, env, log):
    if not args.linger_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27300 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.linger_app), 'server', address, str(port)]
        connect = [str(args.linger_app), 'client', address, str(port)]
        stats_path = work / ('tcp-linger-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP linger server did not verify both directions')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    7):
                raise RuntimeError('TCP linger scenario missed native traffic: ' + str(stats))
            print('native TCP linger ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_listener_restart(args, launcher, work, env, log):
    if not args.listener_restart_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26600 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.listener_restart_app), 'server', address, str(port)]
        connect = [str(args.listener_restart_app), 'client', address, str(port)]
        stats_path = work / ('tcp-listener-restart-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP listener restart server did not verify old/new streams')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    3):
                raise RuntimeError('TCP listener restart scenario missed native traffic: ' + str(stats))
            print('native TCP listener restart ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_defer_accept(args, launcher, work, env, log):
    if not args.defer_accept_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 25900 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.defer_accept_app), 'server', address, str(port)]
        connect = [str(args.defer_accept_app), 'client', address, str(port)]
        stats_path = work / ('tcp-defer-accept-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP deferred accept server did not verify both phases')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    3):
                raise RuntimeError('TCP deferred accept scenario missed native traffic: ' + str(stats))
            print('native TCP deferred accept ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_connect_lifecycle(args, launcher, work, env, log):
    if not args.connect_lifecycle_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 25800 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.connect_lifecycle_app), 'server', address, str(port)]
        connect = [str(args.connect_lifecycle_app), 'client', address, str(port)]
        stats_path = work / ('tcp-connect-lifecycle-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP reconnect server did not verify reset and recovery')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    (2 if native_server else 3)):
                raise RuntimeError('TCP reconnect scenario missed native traffic: ' + str(stats))
            print('native TCP connect lifecycle ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_lowwater(args, launcher, work, env, log):
    if not args.tcp_lowwater_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27500 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.tcp_lowwater_app), 'server', address, str(port)]
        connect = [str(args.tcp_lowwater_app), 'client', address, str(port)]
        stats_path = work / ('tcp-lowwater-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP lowwater server did not verify both directions')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    2):
                raise RuntimeError('TCP lowwater scenario missed native traffic: ' + str(stats))
            print('native TCP lowwater ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_receive_timeouts(args, launcher, work, env, log):
    if not args.receive_timeouts_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 25600 + index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.receive_timeouts_app), 'server', address, str(port)]
        connect = [str(args.receive_timeouts_app), 'client', address, str(port)]
        stats_path = work / ('tcp-receive-timeouts-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP timeout server did not verify recovery')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    not stats['native']['passive_opens' if native_server else 'active_opens']):
                raise RuntimeError('TCP timeout scenario missed native traffic: ' + str(stats))
            print('native TCP receive timeouts ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_send_timeouts(args, launcher, work, env, log):
    if not args.send_timeouts_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 25700 + index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.send_timeouts_app), 'server', address, str(port)]
        connect = [str(args.send_timeouts_app), 'client', address, str(port)]
        stats_path = work / ('tcp-send-timeouts-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP send-timeout server did not verify recovery')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] < 2):
                raise RuntimeError('TCP send-timeout scenario missed native traffic: ' + str(stats))
            print('native TCP send timeouts ' + role + ': ' + json.dumps(stats), flush=True)


def udp_reuseport(args, launcher, work, env, log):
    if not args.udp_reuseport_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26800 + 4 * index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_reuseport_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_reuseport_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-reuseport-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP reuseport peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 4 or udp['udp_in_datagrams'] < 4 or
                    udp['udp_in_errors'] or udp['udp_no_ports']):
                raise RuntimeError('UDP reuseport scenarios missed native traffic: ' + str(stats))
            print('native UDP reuseport ' + role + ': ' + json.dumps(stats), flush=True)


def udp_receive_timeouts(args, launcher, work, env, log):
    if not args.udp_receive_timeouts_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27400 + 4 * index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_receive_timeouts_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_receive_timeouts_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-timeouts-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP receive timeouts peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 3 or udp['udp_in_datagrams'] < 3 or
                    udp['udp_in_errors'] or udp['udp_no_ports'] or
                    udp['passive_opens' if native_server else 'active_opens'] < 1):
                raise RuntimeError('UDP receive timeouts scenarios missed native traffic: ' + str(stats))
            print('native UDP receive timeouts ' + role + ': ' + json.dumps(stats), flush=True)


def udp_multicast(args, launcher, work, env, log):
    if not args.udp_multicast_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 25500 + index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_multicast_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_multicast_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-multicast-' + role + '.json')
        native = [*launcher, '--all-multicast', '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP multicast receiver did not verify datagrams and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 2 or
                    udp['udp_in_datagrams'] < (3 if native_server else 2) or
                    udp['udp_in_errors'] or udp['udp_no_ports']):
                raise RuntimeError('UDP multicast scenarios missed native traffic: ' + str(stats))
            print('native UDP multicast ' + role + ': ' + json.dumps(stats), flush=True)


def udp_connect(args, launcher, work, env, log):
    if not args.udp_connect_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26500 + 4 * index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_connect_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_connect_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-connect-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP connect peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < (8 if native_server else 5) or
                    udp['udp_in_datagrams'] < (5 if native_server else 6) or
                    udp['udp_in_errors'] or
                    (udp['udp_no_ports'] != 0 if native_server else udp['udp_no_ports'] < 2)):
                raise RuntimeError('UDP connect scenarios missed native traffic: ' + str(stats))
            print('native UDP connect ' + role + ': ' + json.dumps(stats), flush=True)


def udp_broadcast(args, launcher, work, env, log):
    if not args.udp_broadcast_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 26400 + index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_broadcast_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_broadcast_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-broadcast-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP broadcast peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 4 or udp['udp_in_datagrams'] < 4 or
                    udp['udp_in_errors'] or udp['udp_no_ports']):
                raise RuntimeError('UDP broadcast scenarios missed native traffic: ' + str(stats))
            print('native UDP broadcast ' + role + ': ' + json.dumps(stats), flush=True)


def udp_ancillary(args, launcher, work, env, log):
    if not args.udp_ancillary_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 25300 + index
        native_server = role == 'server'
        server_address = '198.18.0.2' if native_server else '198.18.0.1'
        client_address = '198.18.0.2' if role == 'client' else '198.18.0.1'
        listen = [str(args.udp_ancillary_app), 'server', server_address, client_address, str(port)]
        connect = [str(args.udp_ancillary_app), 'client', client_address, server_address, str(port)]
        stats_path = work / ('udp-ancillary-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('UDP ancillary peer did not verify payload and metadata')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_out_datagrams'] < 3 or udp['udp_in_datagrams'] < 3 or
                    udp['udp_in_errors'] or udp['udp_no_ports']):
                raise RuntimeError('UDP ancillary scenarios missed native traffic: ' + str(stats))
            print('native UDP ancillary ' + role + ': ' + json.dumps(stats), flush=True)


def udp_errors(args, launcher, work, env, log):
    if not args.udp_errors_app:
        return
    # This isolated namespace owns these fixed ports; no listener uses the
    # adjacent missing port. The host kernel generates the ICMP error itself.
    for index, mode in enumerate(['unconnected', 'connected']):
        for native in [False, True]:
            port = 25200 + 4 * index + (2 if native else 0)
            command = [str(args.udp_errors_app)]
            suffix = ['198.18.0.1', str(port), str(port + 1), mode]
            stats_path = work / ('udp-errors-' + mode + '.json')
            connect = command + ['client', *suffix]
            if native:
                connect = [*launcher, '--stats', str(stats_path), '--', *connect]
            captured = []
            with server(command + ['server', *suffix], port, log, env, captured=captured):
                client(connect, env)
            if 'PASS:' not in ''.join(captured):
                raise RuntimeError('UDP recovery peer did not verify payload')
            print(''.join(captured).strip(), flush=True)
            if native:
                stats = json.loads(stats_path.read_text())
                udp = stats['native']
                if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                        udp['udp_out_datagrams'] < 2 or udp['udp_in_datagrams'] < 1 or
                        udp['udp_in_errors'] or udp['udp_no_ports']):
                    raise RuntimeError('UDP error recovery missed native traffic: ' + str(stats))
                print('native UDP error queue ' + mode + ': ' + json.dumps(stats), flush=True)


def udp_compat(args, launcher, work, env, log):
    if not args.udp_app:
        return
    for index, mode in enumerate(['basic', 'message', 'batch']):
        for native_server in [True, False]:
            role = 'server' if native_server else 'client'
            port = 25100 + 2 * index + (0 if native_server else 1)
            address = '198.18.0.2' if native_server else '198.18.0.1'
            stats_path = work / ('udp-' + mode + '-' + role + '.json')
            listen = [str(args.udp_app), 'server', address, str(port), mode]
            connect = [str(args.udp_app), 'client', address, str(port), mode]
            native = [*launcher, '--stats', str(stats_path), '--']
            if native_server:
                listen = native + listen
            else:
                connect = native + connect
            captured = []
            with server(listen, port, log, env, captured=captured):
                client(connect, env)
            output = ''.join(captured)
            if 'PASS:' not in output:
                raise RuntimeError('UDP server did not confirm datagrams: ' + output)
            print(output.strip(), flush=True)
            stats = json.loads(stats_path.read_text())
            udp = stats['native']
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    udp['udp_in_datagrams'] < 4 or udp['udp_out_datagrams'] < 4 or
                    udp['udp_in_errors'] or udp['udp_no_ports']):
                raise RuntimeError('UDP scenarios missed native traffic or failed: ' + str(stats))
            print('native F-Stack UDP ' + mode + ' ' + role + ': ' + json.dumps(stats), flush=True)


def verify_capture(directory, stats):
    for direction in ('tx', 'rx'):
        paths = list(directory.glob('ker-' + direction + '-*.pcap'))
        if not paths or len(paths) > 10:
            raise RuntimeError('missing or unbounded capture files')
        count = tcp = truncated = 0
        for path in paths:
            data = path.read_bytes()
            if len(data) < 24:
                raise RuntimeError('short PCAP header')
            endian = '<' if data[:4] == b'\x4d\x3c\xb2\xa1' else '>'
            magic, major, minor, zone, accuracy, snaplen, linktype = struct.unpack(endian + 'IHHIIII', data[:24])
            if (magic, major, minor, zone, accuracy, snaplen, linktype) != (0xa1b23c4d, 2, 4, 0, 0, 96, 1):
                raise RuntimeError('incorrect PCAP header')
            offset = 24
            while offset < len(data):
                if offset + 16 > len(data):
                    raise RuntimeError('truncated PCAP record header')
                sec, fraction, captured, original = struct.unpack(endian + 'IIII', data[offset:offset + 16])
                offset += 16
                if not sec or fraction >= 1000000000 or captured != min(96, original) or offset + captured > len(data):
                    raise RuntimeError('invalid PCAP timestamp or lengths')
                frame = data[offset:offset + captured]
                offset += captured
                count += 1
                truncated += original > captured
                tcp += len(frame) >= 34 and frame[12:14] == b'\x08\x00' and frame[23] == 6
        if count != stats[direction] or not tcp or not truncated:
            raise RuntimeError(f'PCAP {direction} missed worker traffic: {count=} {tcp=} {truncated=} {stats[direction]=}')
    print('PASS: native TX/RX PCAP record counts, Ethernet TCP bytes and snaplen', flush=True)


def inside(args):
    with tempfile.TemporaryDirectory(prefix='ker-native-tcp-') as temporary:
        work = Path(temporary)
        env = dict(os.environ, RUNTIME_DIRECTORY=str(work))
        commands = [
            ['ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'tuntap', 'add', 'dev', 'kerpeer', 'mode', 'tap', 'multi_queue'],
            ['ip', 'link', 'add', 'kerhost', 'type', 'veth', 'peer', 'name', 'kerlink'],
            ['ip', 'addr', 'add', '198.18.0.1/24', 'dev', 'kerhost'],
            ['ip', 'link', 'set', 'kerhost', 'up'],
            ['ip', 'link', 'set', 'kerlink', 'up'],
            ['ip', 'link', 'set', 'kerpeer', 'up'],
        ]
        if args.udp_mtu_app:
            # The host-reference endpoints share loopback; match the wire MTU.
            commands.append(['ip', 'link', 'set', 'lo', 'mtu', '1500'])
        if args.faults:
            for device in ['kerlink', 'kerhost']:
                commands.append(['tc', 'qdisc', 'add', 'dev', device, 'root', 'netem',
                    'delay', '2ms', '1ms', 'loss', '2%', 'reorder', '20%', '50%', 'seed', '42'])
        for command in commands:
            subprocess.run(command, check=True, env=env)
        if args.errors_app:
            subprocess.run(['tc', 'qdisc', 'add', 'dev', 'kerhost', 'clsact'], check=True)
            subprocess.run(['tc', 'filter', 'add', 'dev', 'kerhost', 'ingress', 'protocol', 'ip',
                'flower', 'ip_proto', 'tcp', 'dst_port', '25010', 'action', 'drop'], check=True)
        cpu = min(os.sched_getaffinity(0))
        eal = f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --iova-mode=va --no-telemetry -m 64 --vdev=net_tap0,iface=kerpeer,remote=kerlink'
        launcher = [sys.executable, str(args.launcher), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal]
        if not args.installed_defaults:
            launcher += ['--library', str(args.library), '--io-worker', str(args.io_worker)]
        app = str(args.app)
        with (work / 'server.log').open('w+') as log:
            try:
                for native_server in [True, False]:
                    stats_path = work / ('passive.json' if native_server else 'active.json')
                    capture_options = []
                    if args.capture:
                        capture_dir = work / ('pcap-passive' if native_server else 'pcap-active')
                        capture_dir.mkdir()
                        capture_options = ['--pcap-dir', str(capture_dir), '--pcap-snaplen', '96',
                            '--pcap-max-bytes', '1073741824', '--pcap-nsec']
                    log_options = []
                    if args.worker_log:
                        log_dir = work / ('logs-passive' if native_server else 'logs-active')
                        log_dir.mkdir()
                        log_options = ['--log-dir', str(log_dir), '--log-level', '7']
                    native = [*launcher, *capture_options, *log_options, '--stats', str(stats_path), '--']
                    address = '198.18.0.2' if native_server else '198.18.0.1'
                    port = 25001 if native_server else 25002
                    listen = [app, 'slow-server' if args.zero_window and not native_server else 'server', address, str(port)]
                    connect = [app, 'slow-client' if args.zero_window and native_server else 'client', address, str(port)]
                    if native_server:
                        listen = native + listen
                    else:
                        connect = native + connect
                    with server(listen, port, log, env):
                        received = client(connect, env)
                        if args.faults and not native_server:
                            match = re.search(r"TCP_INFO total_retrans=(\d+)", received)
                            if not match or int(match[1]) == 0:
                                raise RuntimeError("native TCP retransmission was not exercised")
                    stats = json.loads(stats_path.read_text())
                    if not (stats['tx'] > 0 and stats['rx'] > 0 and stats['outstanding'] == 0):
                        raise RuntimeError('no verified DPDK traffic or incomplete reclamation: ' + str(stats))
                    if args.capture:
                        verify_capture(capture_dir, stats)
                    if args.worker_log:
                        files = list(log_dir.glob('ker-io-*.log'))
                        if len(files) != 1 or not re.fullmatch(r'ker-io-[0-9]+\.log', files[0].name):
                            raise RuntimeError('worker log filename or count is invalid')
                        text = files[0].read_text()
                        if 'ker.io ready port=net_tap0' not in text or 'ker.io stopped status=0' not in text:
                            raise RuntimeError('worker lifecycle log is missing: ' + text)
                    native_stats = stats['native']
                    if not native_stats['passive_opens' if native_server else 'active_opens']:
                        raise RuntimeError('native kernel did not record the TCP open')
                    if args.faults and (not native_stats['retransmitted_segments'] or not native_stats['out_of_order_queued']):
                        raise RuntimeError('native retransmission/reordering was not exercised: ' + str(native_stats))
                    if args.zero_window and not native_stats['zero_window_probes']:
                        raise RuntimeError('native zero-window probing was not exercised: ' + str(native_stats))
                    print(('native passive' if native_server else 'native active') + ': ' + json.dumps(stats), flush=True)
                if args.capture:
                    full = work / 'pcap-full'
                    full.mkdir()
                    for direction in ('tx', 'rx'):
                        (full / ('ker-' + direction + '-0.pcap')).symlink_to('/dev/full')
                    for directory in (work / 'missing-capture-directory', full):
                        failure = subprocess.run([*launcher, '--pcap-dir', str(directory), '--', '/bin/true'],
                            capture_output=True, text=True, env=env, timeout=30)
                        if failure.returncode != 125 or 'capture' not in failure.stderr:
                            raise RuntimeError(f'capture I/O failure was masked: {failure.returncode} {failure.stderr}')
                    print('PASS: capture startup and buffered-close failures propagate status 125', flush=True)
                if args.worker_log:
                    failure = subprocess.run([*launcher, '--log-dir', str(work / 'missing-logs'), '--', '/bin/true'],
                        capture_output=True, text=True, env=env, timeout=30)
                    if failure.returncode != 125 or 'worker log' not in failure.stderr:
                        raise RuntimeError('log open failure was masked: ' + failure.stderr)
                    # This wrapper only prepares an erroring file for the actual
                    # worker PID, then execs the real binary with unchanged args.
                    wrapper = work / 'full-log-worker'
                    wrapper.write_text('#!' + sys.executable + '\nimport os, sys\nfrom pathlib import Path\n'
                        + 'directory = Path(sys.argv[sys.argv.index("--log-dir") + 1])\n'
                        + 'os.symlink("/dev/full", directory / ("ker-io-%d.log" % os.getpid()))\n'
                        + 'os.execv(' + repr(str(args.io_worker.resolve())) + ', sys.argv)\n')
                    wrapper.chmod(0o700)
                    (work / 'ker-app').symlink_to(args.io_worker.resolve().parent / 'ker-app')
                    full = work / 'full-logs'; full.mkdir()
                    failure = subprocess.run([*launcher, '--io-worker', str(wrapper), '--log-dir', str(full), '--', '/bin/true'],
                        capture_output=True, text=True, env=env, timeout=30)
                    if failure.returncode != 125 or 'worker log' not in failure.stderr:
                        raise RuntimeError('log write failure was masked: ' + failure.stderr)
                    print('PASS: actual worker logging with native TCP in both roles; log I/O errors return 125', flush=True)
                if args.errors_app:
                    stats_path = work / 'errors.json'
                    with server([str(args.errors_app), 'peer'], 25008, log, env):
                        client([*launcher, '--stats', str(stats_path), '--', str(args.errors_app), 'native'], env)
                    stats = json.loads(stats_path.read_text())
                    if not stats['native']['retransmitted_segments'] or stats['outstanding']:
                        raise RuntimeError('native SYN timeout did not retransmit or I/O leaked: ' + str(stats))
                    print('native errors: ' + json.dumps(stats), flush=True)
                for name, scenario_app, minimum_opens in [
                        ('epoll', args.epoll_app, 13), ('message-io', args.message_app, 6)]:
                    if not scenario_app:
                        continue
                    baseline = client([str(scenario_app)], env)
                    stats_path = work / ('fstack-' + name + '.json')
                    observed = client([*launcher, '--stats', str(stats_path), '--', str(scenario_app)], env)
                    if observed != baseline:
                        raise RuntimeError('native ' + name + ' scenarios differ from the host baseline')
                    stats = json.loads(stats_path.read_text())
                    if (stats['outstanding'] or stats['native']['active_opens'] < minimum_opens or
                            stats['native']['passive_opens'] < minimum_opens):
                        raise RuntimeError(name + ' scenarios did not use native TCP or leaked: ' + str(stats))
                    print('native F-Stack ' + name + ': ' + json.dumps(stats), flush=True)
                dualstack(args, launcher, work, env, log)
                tcp_listener_restart(args, launcher, work, env, log)
                tcp_shutdown_write(args, launcher, work, env, log)
                tcp_receive_queue(args, launcher, work, env, log)
                tcp_linger(args, launcher, work, env, log)
                tcp_urgent(args, launcher, work, env, log)
                tcp_reuseport(args, launcher, work, env, log)
                tcp_defer_accept(args, launcher, work, env, log)
                tcp_connect_lifecycle(args, launcher, work, env, log)
                tcp_lowwater(args, launcher, work, env, log)
                tcp_receive_timeouts(args, launcher, work, env, log)
                tcp_send_timeouts(args, launcher, work, env, log)
                tcp_fd_modes(args, launcher, work, env, log)
                udp_mtu(args, launcher, work, env, log)
                udp_receive_timeouts(args, launcher, work, env, log)
                udp_multicast(args, launcher, work, env, log)
                udp_connect(args, launcher, work, env, log)
                udp_broadcast(args, launcher, work, env, log)
                udp_ancillary(args, launcher, work, env, log)
                udp_errors(args, launcher, work, env, log)
                udp_reuseport(args, launcher, work, env, log)
                udp_compat(args, launcher, work, env, log)
                udp_lowwater(args, launcher, work, env, log)
                udp_waitforone(args, launcher, work, env, log)
                udp_receive_truncation(args, launcher, work, env, log)
                stream_compat(args, launcher, work, env, log)
                application_compat(args, launcher, work, env)
                udp_cork(args, launcher, work, env, log)
                if args.fd_app:
                    stats_path = work / 'fd-app.json'
                    client([*launcher, '--stats', str(stats_path), '--', str(args.fd_app)], env)
                    stats = json.loads(stats_path.read_text())
                    if (stats['outstanding'] or not stats['native']['active_opens'] or
                            not stats['native']['passive_opens']):
                        raise RuntimeError('fd scenarios did not use native TCP or leaked: ' + str(stats))
                    print('native fd scenarios: ' + json.dumps(stats), flush=True)
                if args.fd_app:
                    invalid_library = work / 'invalid.so'
                    invalid_library.write_text('not an ELF shared object\n')
                    for boundary_args in [
                        ['--library', str(invalid_library)], ['--port', 'missing-ethdev']]:
                        rejected = subprocess.run([*launcher, *boundary_args, '--', '/bin/true'],
                            capture_output=True, text=True, timeout=25, env=env)
                        if rejected.returncode != 125:
                            raise RuntimeError('startup failure escaped the native boundary: ' +
                                str(rejected.returncode) + rejected.stderr)
                    print('PASS: missing preload and invalid ethdev fail closed with exit 125', flush=True)
                # Same port in the host and imported loopback domains rules out
                # an accidental fallback to host-kernel TCP for the native side.
                with socket.socket() as occupied:
                    occupied.bind(('127.0.0.1', 0))
                    occupied.listen()
                    client([*launcher, '--', app, 'loopback', '127.0.0.1',
                        str(occupied.getsockname()[1])], env)
            except BaseException:
                log.seek(0)
                sys.stderr.write(log.read())
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['launcher', 'library', 'io-worker', 'app']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--worker-log', action='store_true')
    parser.add_argument('--faults', action='store_true')
    parser.add_argument('--zero-window', action='store_true')
    parser.add_argument('--udp-cork-app', type=Path)
    parser.add_argument('--fd-app', type=Path)
    parser.add_argument('--dualstack-app', type=Path)
    parser.add_argument('--epoll-app', type=Path)
    parser.add_argument('--message-app', type=Path)
    parser.add_argument('--stream-app', type=Path)
    parser.add_argument('--udp-app', type=Path)
    parser.add_argument('--fd-modes-app', type=Path)
    parser.add_argument('--udp-errors-app', type=Path)
    parser.add_argument('--udp-ancillary-app', type=Path)
    parser.add_argument('--udp-mtu-app', type=Path)
    parser.add_argument('--udp-connect-app', type=Path)
    parser.add_argument('--udp-broadcast-app', type=Path)
    parser.add_argument('--udp-reuseport-app', type=Path)
    parser.add_argument('--udp-receive-timeouts-app', type=Path)
    parser.add_argument('--udp-multicast-app', type=Path)
    parser.add_argument('--tcp-lowwater-app', type=Path)
    parser.add_argument('--receive-timeouts-app', type=Path)
    parser.add_argument('--send-timeouts-app', type=Path)
    parser.add_argument('--listener-restart-app', type=Path)
    parser.add_argument('--shutdown-write-app', type=Path)
    parser.add_argument('--linger-app', type=Path)
    parser.add_argument('--receive-queue-app', type=Path)
    parser.add_argument('--urgent-app', type=Path)
    parser.add_argument('--reuseport-app', type=Path)
    parser.add_argument('--defer-accept-app', type=Path)
    parser.add_argument('--connect-lifecycle-app', type=Path)
    parser.add_argument('--errors-app', type=Path)
    parser.add_argument('--udp-lowwater-app', type=Path)
    parser.add_argument('--udp-waitforone-app', type=Path)
    parser.add_argument('--udp-receive-truncation-app', type=Path)
    parser.add_argument('--installed-defaults', action='store_true')
    parser.add_argument('--curl', type=Path)
    parser.add_argument('--redis-server', type=Path)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()),
            '--inside', *sys.argv[1:]]
        result = subprocess.run(command)
        if result.returncode:
            print('native TCP integration failed; see the error above. Environment prerequisites include user/network namespaces and the DPDK net_tap PMD.', file=sys.stderr)
        return result.returncode
    inside(args)
    return 0


if __name__ == '__main__':
    sys.exit(main())
