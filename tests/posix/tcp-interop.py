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
    for index, api in enumerate(['vector', 'message', 'batch', 'batch-zc']):
        for native_server in [True, False]:
            role = 'passive' if native_server else 'active'
            port = 25020 + 2 * index + (0 if native_server else 1)
            address = '198.18.0.2' if native_server else '198.18.0.1'
            stats_path = work / ('stream-' + api + '-' + role + '.json')
            listen = [str(args.stream_app), 'server', address, str(port), api]
            connect = [str(args.stream_app), 'client', address, str(port), api]
            native = [*launcher, '--stats', str(stats_path), '--']
            if api == 'batch-zc':
                if native_server:
                    listen.append('require-short')
                else:
                    connect.append('require-short')
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


def tcp_peek_offset_plan(probe_status):
    if probe_status == 0:
        return [('host-reference', True, True), ('client', False, True), ('server', True, False)]
    if probe_status == 77:
        return [('client', False, True), ('server', True, False)]
    raise RuntimeError(f'SO_PEEK_OFF capability probe failed unexpectedly with status {probe_status}')


def tcp_peek_offset(args, launcher, work, env, log):
    if not args.peek_offset_app:
        return
    probe = subprocess.run([str(args.peek_offset_app), 'probe'], capture_output=True,
        text=True, env=env, timeout=5)
    plan = tcp_peek_offset_plan(probe.returncode)
    if probe.returncode == 77:
        print('SKIP host-reference SO_PEEK_OFF: ' + probe.stdout.strip(), flush=True)
    for index, (role, server_peek, client_peek) in enumerate(plan):
        port = 27900 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.peek_offset_app), 'server', address, str(port),
                  'peek' if server_peek else 'ordinary']
        connect = [str(args.peek_offset_app), 'client', address, str(port),
                   'peek' if client_peek else 'ordinary']
        stats_path = work / ('tcp-peek-offset-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client_output = client(connect, env)
        server_output = ''.join(captured)
        if 'PASS:' not in server_output:
            raise RuntimeError('TCP peek offset server did not verify both directions')
        native_output = server_output if native_server else client_output
        peer_output = client_output if native_server else server_output
        if role != 'host-reference' and 'SO_PEEK_OFF cursor' not in native_output:
            raise RuntimeError('native TCP peek offset role did not execute cursor assertions')
        if role != 'host-reference' and 'ordinary peek' not in peer_output:
            raise RuntimeError('host TCP peek offset peer did not execute ordinary receive checks')
        if role == 'host-reference' and ('SO_PEEK_OFF cursor' not in server_output or
                                         'SO_PEEK_OFF cursor' not in client_output):
            raise RuntimeError('host-reference SO_PEEK_OFF assertions were not executed')
        print(server_output.strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    2):
                raise RuntimeError('TCP peek offset scenario missed native traffic: ' + str(stats))
            print('native TCP peek offset ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_notsent_lowat(args, launcher, work, env, log):
    if not args.notsent_lowat_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 28200 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.notsent_lowat_app), 'server', address, str(port),
                  'send' if native_server else 'receive']
        connect = [str(args.notsent_lowat_app), 'client', address, str(port),
                   'receive' if native_server else 'send']
        stats_path = work / ('tcp-notsent-lowat-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client_output = client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP notsent lowat server did not verify both directions')
        sender_output = ''.join(captured) if native_server else client_output
        if 'threshold-only POLLOUT toggle' not in sender_output:
            raise RuntimeError('TCP notsent lowat sender missed threshold-only backpressure proof')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    2):
                raise RuntimeError('TCP notsent lowat scenario missed native traffic: ' + str(stats))
            print('native TCP notsent lowat ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_user_timeout(args, launcher, work, env, log):
    if not args.user_timeout_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 28100 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.user_timeout_app), 'server', address, str(port),
                  'send' if native_server else 'receive']
        connect = [str(args.user_timeout_app), 'client', address, str(port),
                   'receive' if native_server else 'send']
        stats_path = work / ('tcp-user-timeout-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client_output = client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP user timeout server did not verify both directions')
        sender_output = ''.join(captured) if native_server else client_output
        if 'POLLERR/ETIMEDOUT' not in sender_output:
            raise RuntimeError('TCP user timeout sender missed actual timeout error')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    not stats['native']['zero_window_probes'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    2):
                raise RuntimeError('TCP user timeout scenario missed native traffic: ' + str(stats))
            print('native TCP user timeout ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_congestion(args, launcher, work, env, log):
    if not args.congestion_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 28900 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.congestion_app), 'server', address, str(port)]
        connect = [str(args.congestion_app), 'client', address, str(port)]
        stats_path = work / ('tcp-congestion-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client_output = client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP congestion server did not verify both directions')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            native_output = ''.join(captured) if native_server else client_output
            if 'default=cubic reno=verified restored=cubic' not in native_output:
                raise RuntimeError('native congestion did not qualify Reno-to-CUBIC restoration')
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    1):
                raise RuntimeError('TCP congestion scenario missed native traffic: ' + str(stats))
            print('native TCP congestion ' + role + ': ' + json.dumps(stats), flush=True)


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


def tcp_keepalive(args, launcher, work, env, log):
    if not args.keepalive_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27800 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.keepalive_app), 'server', address, str(port)]
        connect = [str(args.keepalive_app), 'client', address, str(port)]
        stats_path = work / ('tcp-keepalive-' + role + '.json')
        capture = work / ('tcp-keepalive-' + role); capture.mkdir()
        native = [*launcher, '--stats', str(stats_path), '--pcap-dir', str(capture),
                  '--pcap-snaplen', '65535', '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP keepalive server missed stream verification')
        if role == 'host-reference':
            continue
        stats = json.loads(stats_path.read_text())
        if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                not stats['native']['passive_opens' if native_server else 'active_opens']):
            raise RuntimeError('TCP keepalive missed native traffic: ' + str(stats))
        probes = 0
        data_end = None
        for path in sorted(capture.glob('ker-tx-*.pcap')):
            data = path.read_bytes()
            if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                raise RuntimeError('invalid keepalive PCAP header')
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            offset = 24
            while offset < len(data):
                if offset + 16 > len(data):
                    raise RuntimeError('truncated keepalive record')
                _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + length]; offset += length
                if len(frame) != length or length != original:
                    raise RuntimeError('truncated keepalive frame')
                if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
                    continue
                ihl = (frame[14] & 15) * 4
                total = struct.unpack_from('!H', frame, 16)[0]
                tcp = 14 + ihl
                if ihl < 20 or total < ihl + 20 or 14 + total > len(frame):
                    raise RuntimeError('invalid keepalive IP length')
                if port not in struct.unpack_from('!HH', frame, tcp):
                    continue
                header = (frame[tcp + 12] >> 4) * 4
                if header < 20 or ihl + header > total or struct.unpack_from('!H', frame, 20)[0] & 0x3fff:
                    raise RuntimeError('invalid keepalive TCP packet')
                flags = frame[tcp + 13]
                seq = struct.unpack_from('!I', frame, tcp + 4)[0]
                payload = total - ihl - header
                if payload:
                    data_end = (seq + payload) & 0xffffffff
                elif flags == 16 and data_end is not None and seq == (data_end - 1) & 0xffffffff:
                    probes += 1
        if probes < 1:
            raise RuntimeError('missing native ACK-only keepalive probe at SND.NXT-1')
        print('PASS: native TCP keepalive ' + role + ', probes=' + str(probes), flush=True)


def tcp_ip_options(args, launcher, work, env, log):
    if not args.ip_options_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 28000 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.ip_options_app), 'server', address, str(port)]
        connect = [str(args.ip_options_app), 'client', address, str(port)]
        stats_path = work / ('tcp-ip-options-' + role + '.json')
        capture = work / ('tcp-ip-options-' + role); capture.mkdir()
        native = [*launcher, '--stats', str(stats_path), '--pcap-dir', str(capture),
                  '--pcap-snaplen', '65535', '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP IP options server missed stream verification')
        if role == 'host-reference':
            continue
        stats = json.loads(stats_path.read_text())
        if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                not stats['native']['passive_opens' if native_server else 'active_opens']):
            raise RuntimeError('TCP IP options missed native traffic: ' + str(stats))
        seen_syn = seen_initial = seen_updated = False
        for path in capture.glob('ker-tx-*.pcap'):
            data = path.read_bytes()
            if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                raise RuntimeError('invalid IP options PCAP header')
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            offset = 24
            while offset < len(data):
                if offset + 16 > len(data):
                    raise RuntimeError('truncated IP options PCAP record')
                _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + length]; offset += length
                if len(frame) != length or length != original:
                    raise RuntimeError('truncated IP options frame')
                if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
                    continue
                ihl = (frame[14] & 15) * 4
                total = struct.unpack_from('!H', frame, 16)[0]
                tcp = 14 + ihl
                if ihl < 20 or total < ihl + 20 or 14 + total > len(frame):
                    raise RuntimeError('invalid IP options IP length')
                if port not in struct.unpack_from('!HH', frame, tcp):
                    continue
                header = (frame[tcp + 12] >> 4) * 4
                if header < 20 or ihl + header > total or struct.unpack_from('!H', frame, 20)[0] & 0x3fff:
                    raise RuntimeError('invalid IP options TCP packet')
                flags = frame[tcp + 13]
                payload = frame[tcp + header:14 + total]
                initial = (0x48, 43) if native_server else (0x28, 42)
                updated = (0x88, 53) if native_server else (0x68, 52)
                actual = (frame[15] & 0xfc, frame[22])
                if flags & 2:
                    if actual != initial:
                        raise RuntimeError('native handshake TOS/TTL mismatch: ' + str(actual))
                    seen_syn = True
                if payload:
                    expected = updated if payload == (b'A' if native_server else b'P') else initial
                    if actual != expected:
                        raise RuntimeError('native data TOS/TTL mismatch: ' + str(actual))
                    if expected == updated:
                        seen_updated = True
                    else:
                        seen_initial = True
        if not all((seen_syn, seen_initial, seen_updated)):
            raise RuntimeError('missing native handshake/initial/updated TOS and TTL evidence')
        print('PASS: native TCP IPv4 TOS/TTL ' + role + ', handshake and live data update', flush=True)


def tcp_window_clamp(args, launcher, work, env, log):
    if not args.window_clamp_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 28700 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.window_clamp_app), 'server', address, str(port)]
        connect = [str(args.window_clamp_app), 'client', address, str(port)]
        stats_path = work / ('tcp-window-clamp-' + role + '.json')
        capture = work / ('tcp-window-clamp-' + role); capture.mkdir()
        native = [*launcher, '--stats', str(stats_path), '--pcap-dir', str(capture),
                  '--pcap-snaplen', '65535', '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP window clamp server missed stream verification')
        if role == 'host-reference':
            continue
        stats = json.loads(stats_path.read_text())
        if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                stats['native']['passive_opens' if native_server else 'active_opens'] < 2):
            raise RuntimeError('TCP window clamp missed native traffic: ' + str(stats))
        frames = []
        local_scale = remote_scale = None
        seen_syn = seen_peer_syn = False
        for path in capture.glob('*.pcap'):
            data = path.read_bytes()
            if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                raise RuntimeError('invalid clamp PCAP header')
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            offset = 24
            while offset < len(data):
                if offset + 16 > len(data):
                    raise RuntimeError('truncated clamp PCAP record')
                _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + length]; offset += length
                if len(frame) != length or length != original:
                    raise RuntimeError('truncated clamp frame')
                if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
                    continue
                ihl = (frame[14] & 15) * 4
                total = struct.unpack_from('!H', frame, 16)[0]
                tcp = 14 + ihl
                if ihl < 20 or total < ihl + 20 or 14 + total > len(frame):
                    raise RuntimeError('invalid clamp IP length')
                if port + 1 not in struct.unpack_from('!HH', frame, tcp):
                    continue
                header = (frame[tcp + 12] >> 4) * 4
                if header < 20 or ihl + header > total or struct.unpack_from('!H', frame, 20)[0] & 0x3fff:
                    raise RuntimeError('invalid clamp TCP packet')
                native_tx = path.name.startswith('ker-tx-')
                flags = frame[tcp + 13]
                window = struct.unpack_from('!H', frame, tcp + 14)[0]
                if flags & 2:
                    scales = []
                    position = tcp + 20
                    while position < tcp + header:
                        kind = frame[position]
                        if kind == 0:
                            break
                        if kind == 1:
                            position += 1
                            continue
                        if position + 2 > tcp + header:
                            raise RuntimeError('short clamp TCP option')
                        size = frame[position + 1]
                        if size < 2 or position + size > tcp + header:
                            raise RuntimeError('invalid clamp TCP option')
                        if kind == 3:
                            if size != 3 or frame[position + 2] > 14:
                                raise RuntimeError('invalid window scale option')
                            scales.append(frame[position + 2])
                        position += size
                    if len(scales) > 1:
                        raise RuntimeError('duplicate window scale option')
                    if native_tx:
                        if not 0 < window <= 4096:
                            raise RuntimeError('native initial window exceeded clamp')
                        seen_syn = True
                        local_scale = scales[0] if scales else None
                    else:
                        seen_peer_syn = True
                        remote_scale = scales[0] if scales else None
                elif native_tx:
                    frames.append((flags, window, total - ihl - header))
        negotiated_scale = local_scale if local_scale is not None and remote_scale is not None else 0
        acknowledged = payload_bytes = max_window = 0
        for flags, window, payload in frames:
            if flags & 16:
                max_window = max(max_window, window << negotiated_scale)
                if window:
                    acknowledged += 1
            payload_bytes += payload
        if not seen_syn or not seen_peer_syn or acknowledged < 2 or payload_bytes < 16385:
            raise RuntimeError('missing clamp handshake/window/stream evidence')
        print('PASS: native TCP window clamp ' + role + ', initial<=4096, observed post-handshake max=' + str(max_window), flush=True)


def tcp_mss(args, launcher, work, env, log):
    if not args.mss_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27700 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.mss_app), 'server', address, str(port)]
        connect = [str(args.mss_app), 'client', address, str(port)]
        stats_path = work / ('tcp-mss-' + role + '.json')
        capture = work / ('tcp-mss-' + role); capture.mkdir()
        native = [*launcher, '--stats', str(stats_path), '--pcap-dir', str(capture),
                  '--pcap-snaplen', '65535', '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP MSS server missed stream verification')
        if role == 'host-reference':
            continue
        stats = json.loads(stats_path.read_text())
        if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                not stats['native']['passive_opens' if native_server else 'active_opens']):
            raise RuntimeError('TCP MSS missed native traffic: ' + str(stats))
        seen_syn = seen_synack = False
        payload_bytes = payload_packets = 0
        for path in capture.glob('*.pcap'):
            data = path.read_bytes()
            if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                raise RuntimeError('invalid MSS PCAP header')
            endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
            offset = 24
            while offset < len(data):
                if offset + 16 > len(data):
                    raise RuntimeError('truncated MSS record header')
                _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset)
                offset += 16
                frame = data[offset:offset + length]; offset += length
                if len(frame) != length or length != original:
                    raise RuntimeError('truncated MSS frame')
                if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
                    continue
                ihl = (frame[14] & 15) * 4
                total = struct.unpack_from('!H', frame, 16)[0]
                tcp = 14 + ihl
                if ihl < 20 or total < ihl + 20 or 14 + total > len(frame):
                    raise RuntimeError('invalid MSS IP length')
                if port not in struct.unpack_from('!HH', frame, tcp):
                    continue
                if struct.unpack_from('!H', frame, 20)[0] & 0x3fff:
                    raise RuntimeError('unexpected fragmented MSS TCP packet')
                header = (frame[tcp + 12] >> 4) * 4
                if header < 20 or ihl + header > total:
                    raise RuntimeError('invalid MSS TCP header')
                flags = frame[tcp + 13]
                if flags & 2:
                    values = []
                    position = tcp + 20
                    while position < tcp + header:
                        kind = frame[position]
                        if kind == 0:
                            break
                        if kind == 1:
                            position += 1
                            continue
                        if position + 2 > tcp + header:
                            raise RuntimeError('short MSS option')
                        size = frame[position + 1]
                        if size < 2 or position + size > tcp + header:
                            raise RuntimeError('invalid MSS option size')
                        if kind == 2:
                            if size != 4:
                                raise RuntimeError('invalid MSS option')
                            values.append(struct.unpack_from('!H', frame, position + 2)[0])
                        position += size
                    expected = 700 if flags & 16 else 600
                    if values != [expected]:
                        raise RuntimeError('wrong advertised MSS: ' + str(values))
                    if flags & 16:
                        seen_synack = True
                    else:
                        seen_syn = True
                payload = total - ihl - header
                # Qualify actual native egress; host RX may legitimately arrive
                # with host segmentation/aggregation metadata outside this test.
                if path.name.startswith('ker-tx-') and payload:
                    if payload > 600:
                        raise RuntimeError('native segment exceeded negotiated MSS')
                    payload_bytes += payload; payload_packets += 1
        if not seen_syn or not seen_synack or payload_bytes < 16385 or payload_packets < 28:
            raise RuntimeError('missing MSS handshake/native segmentation evidence')
        print('PASS: native TCP MSS ' + role + ', SYN600/SYN-ACK700 and native payload<=600', flush=True)


def tcp_cork(args, launcher, work, env, log):
    if not args.cork_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 27600 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.cork_app), 'server', address, str(port)]
        connect = [str(args.cork_app), 'client', address, str(port)]
        stats_path = work / ('tcp-cork-' + role + '.json')
        native = [*launcher, '--stats', str(stats_path), '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP cork server did not verify both directions')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    5):
                raise RuntimeError('TCP cork scenario missed native traffic: ' + str(stats))
            print('native TCP cork ' + role + ': ' + json.dumps(stats), flush=True)


def tcp_linger2(args, launcher, work, env, log):
    if not args.linger2_app:
        return
    for index, role in enumerate(['host-reference', 'client', 'server']):
        port = 28800 + 4 * index
        native_server = role == 'server'
        address = '198.18.0.2' if native_server else '198.18.0.1'
        listen = [str(args.linger2_app), 'server', address, str(port)]
        connect = [str(args.linger2_app), 'client', address, str(port)]
        stats_path = work / ('tcp-linger2-' + role + '.json')
        capture = work / ('tcp-linger2-' + role); capture.mkdir()
        native = [*launcher, '--stats', str(stats_path), '--pcap-dir', str(capture),
                  '--pcap-snaplen', '65535', '--']
        if native_server:
            listen = native + listen
        elif role == 'client':
            connect = native + connect
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('TCP linger2 server did not verify both directions')
        print(''.join(captured).strip(), flush=True)
        if role != 'host-reference':
            stats = json.loads(stats_path.read_text())
            if (not stats['tx'] or not stats['rx'] or stats['outstanding'] or
                    stats['native']['passive_opens' if native_server else 'active_opens'] <
                    3):
                raise RuntimeError('TCP linger2 scenario missed native traffic: ' + str(stats))
            print('native TCP linger2 ' + role + ': ' + json.dumps(stats), flush=True)

            evidence = {'tx': set(), 'rx': set()}
            for path in capture.glob('*.pcap'):
                direction = 'tx' if path.name.startswith('ker-tx-') else 'rx'
                data = path.read_bytes()
                if len(data) < 24 or data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                    raise RuntimeError('invalid linger2 PCAP header')
                endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
                offset = 24
                while offset < len(data):
                    if offset + 16 > len(data):
                        raise RuntimeError('truncated linger2 record')
                    _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset)
                    offset += 16
                    frame = data[offset:offset + length]; offset += length
                    if len(frame) != length or length != original:
                        raise RuntimeError('truncated linger2 frame')
                    if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
                        continue
                    ihl = (frame[14] & 15) * 4
                    total = struct.unpack_from('!H', frame, 16)[0]
                    tcp = 14 + ihl
                    if ihl < 20 or total < ihl + 20 or 14 + total > len(frame):
                        raise RuntimeError('invalid linger2 IPv4 length')
                    if port + 1 not in struct.unpack_from('!HH', frame, tcp):
                        continue
                    header = (frame[tcp + 12] >> 4) * 4
                    if header < 20 or ihl + header > total or struct.unpack_from('!H', frame, 20)[0] & 0x3fff:
                        raise RuntimeError('invalid linger2 TCP packet')
                    flags = frame[tcp + 13]
                    if flags & 1:
                        evidence[direction].add('FIN')
                    if flags & 4:
                        evidence[direction].add('RST')
            if any(flags != {'FIN', 'RST'} for flags in evidence.values()):
                raise RuntimeError('missing bidirectional FIN/RST capture evidence: ' + str(evidence))
            print('PASS: native TCP linger2 ' + role + ', FIN_WAIT2 teardown FIN/RST in TX and RX', flush=True)


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


def jumbo_mtu(args, launcher, work, env, log):
    if not args.jumbo_app:
        return
    for index, role in enumerate(('host-reference', 'client', 'server')):
        address = '127.0.0.1' if role == 'host-reference' else ('198.18.0.2' if role == 'server' else '198.18.0.1')
        port = 27900 + index
        command = [str(args.jumbo_app)]
        listen = [*command, 'server', address, str(port)]
        connect = [*command, 'client', address, str(port)]
        stats_path = work / ('jumbo-' + role + '.json')
        capture = work / ('jumbo-pcap-' + role); capture.mkdir()
        native = [*launcher, '--stats', str(stats_path), '--pcap-dir', str(capture),
            '--pcap-snaplen', '9014', '--', *command]
        if role == 'server':
            listen = [*native, 'server', address, str(port)]
        elif role == 'client':
            connect = [*native, 'client', address, str(port)]
        captured = []
        with server(listen, port, log, env, captured=captured):
            client(connect, env)
        if 'PASS:' not in ''.join(captured):
            raise RuntimeError('jumbo peer did not confirm payload')
        if role == 'host-reference':
            continue
        stats = json.loads(stats_path.read_text())
        if (stats['io']['mtu'] != 9000 or stats['outstanding'] or
                stats['native']['udp_out_datagrams'] < 4 or stats['native']['udp_in_datagrams'] < 4
                or stats['native']['ip_frag_ok'] or stats['native']['ip_reasm_ok']):
            raise RuntimeError('jumbo datagrams missed native path: ' + str(stats))
        expected_mode = 'scatter' if args.mbuf_scatter else 'large'
        if stats['io']['mbuf_mode'] != expected_mode:
            raise RuntimeError('worker ignored configured mbuf mode: ' + str(stats))
        if args.mbuf_scatter and (stats['tx_multiseg'] < 1 or stats['rx_multiseg'] < 1):
            raise RuntimeError('jumbo traffic did not exercise both mbuf chain directions: ' + str(stats))
        if not args.mbuf_scatter and (stats['tx_multiseg'] or stats['rx_multiseg']):
            raise RuntimeError('large mode unexpectedly used mbuf chains: ' + str(stats))
        for direction in ('tx', 'rx'):
            found = False
            for path in capture.glob('ker-' + direction + '-*.pcap'):
                data = path.read_bytes()
                endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
                offset = 24
                while offset < len(data):
                    _, _, length, original = struct.unpack_from(endian + 'IIII', data, offset)
                    offset += 16
                    frame = data[offset:offset + length]; offset += length
                    if len(frame) >= 34 and frame[12:14] == b'\x08\x00' and frame[23] == 17:
                        total, fragment = struct.unpack_from('!H2xH', frame, 16)
                        if total == 9000:
                            if original != 9014 or length != 9014 or fragment & 0x3fff:
                                raise RuntimeError('jumbo capture was truncated or fragmented')
                            found = True
            if not found:
                raise RuntimeError('missing actual 9014-byte jumbo frame: ' + direction)
        print('PASS: actual jumbo Ethernet frames, native UDP and zero outstanding ' + role, flush=True)


def tcp_ecn(args, launcher, work, env, log):
    if not args.ecn_app:
        return
    # inside() is entered in the test's private user/network namespace.
    Path('/proc/sys/net/ipv4/tcp_ecn').write_text('1\n')
    app = str(args.ecn_app)
    with server([app, 'server', '127.0.0.1', '28000', '1'], 28000, log, env):
        client([app, 'client', '127.0.0.1', '28000', '1'], env)
    for index, mode in enumerate(('default', 'off', 'passive', 'on')):
        for native_server in (False, True):
            role = 'server' if native_server else 'client'
            address = '198.18.0.2' if native_server else '198.18.0.1'
            port = 28010 + index * 2 + int(native_server)
            negotiated = mode == 'on' or (native_server and mode in ('default', 'passive'))
            expected = str(int(negotiated))
            listen = [app, 'server', address, str(port), expected]
            connect = [app, 'client', address, str(port), expected]
            stats_path = work / ('ecn-' + mode + '-' + role + '.json')
            capture = work / ('ecn-pcap-' + mode + '-' + role); capture.mkdir()
            options = []
            if mode != 'default':
                config = work / ('ecn-' + mode + '.ini')
                config.write_text('[network]\ntcp_ecn=' + mode + '\n')
                options = ['--config', str(config)]
            native = [*launcher, *options, '--stats', str(stats_path), '--pcap-dir', str(capture),
                '--pcap-snaplen', '128', '--']
            if native_server: listen = native + listen
            else: connect = native + connect
            # The launcher must not inherit an internal override when omitted.
            case_env = dict(env, KER_NATIVE_TCP_ECN='0')
            captured = []
            with server(listen, port, log, case_env, captured=captured):
                client(connect, case_env)
            if 'PASS:' not in ''.join(captured):
                raise RuntimeError('ECN peer did not verify negotiated state')
            stats = json.loads(stats_path.read_text())
            policy = {'default': 2, 'off': 0, 'passive': 2, 'on': 1}[mode]
            if (stats['native']['tcp_ecn'] != policy or stats['outstanding'] or not stats['tx'] or not stats['rx']
                    or not stats['native']['passive_opens' if native_server else 'active_opens']):
                raise RuntimeError('native ECN policy/counters mismatch: ' + str(stats))
            observed_syn = observed_ack = False
            request_ecn = native_server or mode == 'on'
            for path in capture.glob('*.pcap'):
                data = path.read_bytes()
                endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
                offset = 24
                while offset < len(data):
                    _, _, length, _ = struct.unpack_from(endian + 'IIII', data, offset)
                    offset += 16
                    frame = data[offset:offset + length]; offset += length
                    if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
                        continue
                    tcp = 14 + (frame[14] & 15) * 4
                    if len(frame) < tcp + 20 or port not in struct.unpack_from('!HH', frame, tcp):
                        continue
                    flags = frame[tcp + 13]
                    if not flags & 2:
                        continue
                    if flags & 16:
                        if bool(flags & 64) != negotiated or flags & 128:
                            raise RuntimeError('incorrect ECN SYN-ACK flags')
                        observed_ack = True
                    else:
                        if flags & 192 != (192 if request_ecn else 0):
                            raise RuntimeError('incorrect ECN SYN request flags')
                        observed_syn = True
            if not observed_syn or not observed_ack:
                raise RuntimeError('missing actual SYN/SYN-ACK capture')
            print('PASS: native ECN ' + mode + ' ' + role + ', TCP_INFO, SYN flags and cleanup', flush=True)


def verify_capture(directory, stats):
    for direction in ('tx', 'rx'):
        paths = list(directory.glob('ker-' + direction + '-*.pcap'))
        if not paths or len(paths) > 10:
            raise RuntimeError('missing or unbounded capture files')
        count = tcp = truncated = total_bytes = 0
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
                total_bytes += original
                truncated += original > captured
                tcp += len(frame) >= 34 and frame[12:14] == b'\x08\x00' and frame[23] == 6
        if count != stats[direction] or total_bytes != stats[direction + '_bytes'] or not tcp or not truncated:
            raise RuntimeError(f'PCAP {direction} missed worker traffic: {count=} {tcp=} {truncated=} {stats[direction]=}')
    print('PASS: native TX/RX PCAP record counts, Ethernet TCP bytes and snaplen', flush=True)


def inside(args):
    with tempfile.TemporaryDirectory(prefix='ker-native-tcp-') as temporary:
        work = Path(temporary)
        env = dict(os.environ, RUNTIME_DIRECTORY=str(work))
        lifetime_violations = work / 'dpdk-log-lifetime-violations.txt'
        if args.worker_log:
            if not args.log_lifetime_probe:
                raise RuntimeError('worker log lifetime probe was not configured')
            preload = [str(args.log_lifetime_probe)]
            if env.get('LD_PRELOAD'):
                preload.append(env['LD_PRELOAD'])
            env['LD_PRELOAD'] = ':'.join(preload)
            env['KER_DPDK_LOG_LIFETIME_VIOLATION'] = str(lifetime_violations)
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
        if args.jumbo_app:
            for device in ('lo', 'kerpeer', 'kerhost', 'kerlink'):
                commands.append(['ip', 'link', 'set', device, 'mtu', '9000'])
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
        if args.lcore_config:
            # The pinned DPDK build supports lcore IDs below 128. Require two
            # available physical CPUs for a genuine multi-bit EAL run.
            selected_cpus = sorted(cpu for cpu in os.sched_getaffinity(0) if cpu < 128)[:2]
            if len(selected_cpus) != 2:
                raise RuntimeError('lcore-mask integration needs two available CPUs below 128')
            selected_mask = sum(1 << cpu for cpu in selected_cpus)
            eal = eal.replace(f'--lcores=0@{cpu} ', '', 1)
            core_config = work / 'lcores.ini'
            core_config.write_text('[dpdk]\nlcore_mask= 0X' + format(selected_mask, 'X') + '  \n')
            launcher = [sys.executable, str(args.launcher), '--address', '198.18.0.2/24',
                '--port', 'net_tap0', '--eal', eal, '--config', str(core_config)]
        if args.launcher_config:
            config_path = work / 'launcher.ini'
            config_logs = work / 'configured-logs'; config_logs.mkdir()
            config_capture = work / 'configured-capture'; config_capture.mkdir()
            config_path.write_text('[network]\naddress=198.19.0.99/24\naddress=198.18.0.2/24\n'
                '[dpdk]\nport=earlier-port\nport=must-be-overridden\neal=--invalid-earlier-eal\neal=' + eal.replace(' --vdev=', '\n  --vdev=') + '\n'
                '[sysctl]\nnet.ipv4.ip_unprivileged_port_start=0\n'
                'net.ipv4.ip_local_port_range=45000 45999\n'
                '[sysctl]\nnet.ipv4.ip_unprivileged_port_start=40000\n'
                '[logging]\ndirectory=unused-earlier-logs\ndirectory=configured-logs\nlevel=7\n'
                '[capture]\ndirectory=configured-capture\nsnaplen=96\nmax_bytes=1073741824\nnsec=yes\n'
                '[runtime]\nstats=unused-default.json\nshutdown_timeout_ms=5000\n')
            launcher = [sys.executable, str(args.launcher), '--config', str(config_path), '--port', 'net_tap0']
        if not args.installed_defaults:
            launcher += ['--library', str(args.library), '--io-worker', str(args.io_worker)]
        if args.startup_app:
            marker = work / 'application-started'
            startup_stats = work / 'startup.json'
            observed = client([*launcher, '--stats', str(startup_stats), '--',
                str(args.startup_app), str(marker)], env)
            if not marker.exists() or 'native interfaces ready' not in observed:
                raise RuntimeError('native startup probe did not execute')
            marker.unlink()
            stats = json.loads(startup_stats.read_text())
            io = stats['io']
            if (io['port_count'] != 1 or io['port_id'] != 0 or io['socket_id'] < -1
                    or io['process_type'] != 'primary' or io['link_up'] is not True
                    or io['mtu'] != 1500 or stats['outstanding'] != 0 or 'native' not in stats):
                raise RuntimeError('invalid real startup diagnostics: ' + str(stats))
            for options, expected, diagnostic in [
                    (['--eal=--invalid-ker-eal-option'], 125, 'unknown argument --invalid-ker-eal-option'),
                    (['--port', 'missing-ethdev'], 125, 'unknown ethdev'),
                    (['--config', str(work / 'missing.ini')], 2, 'missing.ini')]:
                rejected = subprocess.run([*launcher, *options, '--', str(args.startup_app), str(marker)],
                    env=env, capture_output=True, text=True, timeout=30)
                if rejected.returncode != expected or marker.exists() or diagnostic not in rejected.stderr:
                    raise RuntimeError('startup failure reached app or wrong failure: ' + rejected.stderr)
            print('native startup and pre-application failures verified', flush=True)
        if args.jumbo_app:
            jumbo_config = work / 'jumbo.ini'
            jumbo_config.write_text('[network]\nmtu=9000\nmax_mtu=2000\n')
            rejected = subprocess.run([*launcher, '--config', str(jumbo_config),
                '--library', str(work / 'must-not-resolve-library'), '--', '/bin/true'],
                env=env, capture_output=True, text=True, timeout=10)
            if (rejected.returncode != 2 or '--mtu must not exceed --max-mtu' not in rejected.stderr
                    or 'Traceback' in rejected.stderr):
                raise RuntimeError('custom MTU ceiling did not reject before launch: ' + rejected.stderr)
            if args.mbuf_scatter:
                with jumbo_config.open('a') as configuration:
                    configuration.write('[dpdk]\nmbuf_mode=scatter\n')
            launcher += ['--config', str(jumbo_config), '--max-mtu', '9000']
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
                    core_options = []
                    if args.lcore_config and not native_server:
                        core_options = ['--lcore-mask', format(1 << selected_cpus[1], 'x')]
                    native = [*launcher, *capture_options, *log_options, *core_options, '--stats', str(stats_path), '--']
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
                    if args.lcore_config:
                        expected_count = 2 if native_server else 1
                        expected_main = selected_cpus[0] if native_server else selected_cpus[1]
                        if (stats['io']['lcore_count'] != expected_count or
                                stats['io']['main_lcore'] != expected_main or
                                stats['io']['main_cpu'] != expected_main):
                            raise RuntimeError('EAL did not apply INI mask/CLI precedence: ' + str(stats))
                        print('PASS: actual EAL lcore count/main match configured mask and CLI override', flush=True)
                    if args.startup_app and (stats['io']['port_count'] != 1 or stats['io']['process_type'] != 'primary'):
                        raise RuntimeError('traffic worker startup diagnostics missing')
                    if args.capture:
                        verify_capture(capture_dir, stats)
                    if args.launcher_config:
                        verify_capture(config_capture, stats)
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
                if args.launcher_config:
                    files = list(config_logs.glob('ker-io-*.log'))
                    if len(files) != 2 or any('ker.io ready port=net_tap0' not in f.read_text()
                            or 'ker.io stopped status=0' not in f.read_text() for f in files):
                        raise RuntimeError('configuration did not reach both actual workers')
                    if (work / 'unused-earlier-logs').exists():
                        raise RuntimeError('earlier duplicate logging directory was used')
                    if (work / 'unused-default.json').exists():
                        raise RuntimeError('CLI stats option did not override configuration')
                    print('PASS: repeated INI keys use final address/EAL/log directory in real DPDK/native TCP, with CLI overrides', flush=True)
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
                    startup_logs = work / 'startup-error-logs'
                    startup_logs.mkdir()
                    startup_launcher = list(launcher)
                    eal_argument = startup_launcher.index('--eal') + 1
                    startup_launcher[eal_argument] += ' --ker-invalid-eal-argument'
                    failure = subprocess.run([*startup_launcher, '--log-dir', str(startup_logs),
                        '--', '/bin/true'], capture_output=True, text=True,
                        env=env, timeout=30)
                    startup_files = list(startup_logs.glob('ker-io-*.log'))
                    if failure.returncode != 125 or len(startup_files) != 1:
                        raise RuntimeError('EAL startup failure did not close the worker log: '
                            + f'{failure.returncode} {failure.stderr}')
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
                    if (failure.returncode != 125 or 'worker log' not in failure.stderr or
                            'write worker log failed during EAL startup' not in failure.stderr):
                        raise RuntimeError('log write failure was masked: ' + failure.stderr)
                    events = lifetime_violations.read_text() if lifetime_violations.exists() else ''
                    if 'rte_eal_cleanup\n' not in events:
                        raise RuntimeError('lifetime probe did not observe real rte_eal_cleanup calls')
                    if 'rte_openlog_stream after rte_eal_cleanup\n' in events:
                        raise RuntimeError('DPDK log stream was changed after EAL cleanup: ' + events)
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
                    # Nine IPv4 combinations each send an empty and a one-byte datagram.
                    # IPv6 loopback scenarios share the app but use separate kernel counters.
                    if name == 'epoll' and (stats['native']['udp_in_datagrams'] < 18 or
                            stats['native']['udp_out_datagrams'] < 18):
                        raise RuntimeError('empty datagram scenarios missed native UDP: ' + str(stats))
                    print('native F-Stack ' + name + ': ' + json.dumps(stats), flush=True)
                tcp_ecn(args, launcher, work, env, log)
                dualstack(args, launcher, work, env, log)
                tcp_listener_restart(args, launcher, work, env, log)
                tcp_shutdown_write(args, launcher, work, env, log)
                tcp_peek_offset(args, launcher, work, env, log)
                tcp_notsent_lowat(args, launcher, work, env, log)
                tcp_user_timeout(args, launcher, work, env, log)
                tcp_congestion(args, launcher, work, env, log)
                tcp_receive_queue(args, launcher, work, env, log)
                tcp_keepalive(args, launcher, work, env, log)
                tcp_ip_options(args, launcher, work, env, log)
                tcp_window_clamp(args, launcher, work, env, log)
                tcp_mss(args, launcher, work, env, log)
                tcp_cork(args, launcher, work, env, log)
                tcp_linger2(args, launcher, work, env, log)
                tcp_linger(args, launcher, work, env, log)
                tcp_urgent(args, launcher, work, env, log)
                tcp_reuseport(args, launcher, work, env, log)
                tcp_defer_accept(args, launcher, work, env, log)
                tcp_connect_lifecycle(args, launcher, work, env, log)
                tcp_lowwater(args, launcher, work, env, log)
                tcp_receive_timeouts(args, launcher, work, env, log)
                tcp_send_timeouts(args, launcher, work, env, log)
                tcp_fd_modes(args, launcher, work, env, log)
                jumbo_mtu(args, launcher, work, env, log)
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
                    fd_output = client([*launcher, '--stats', str(stats_path), '--', str(args.fd_app)], env)
                    stats = json.loads(stats_path.read_text())
                    if args.fd_coexistence:
                        if ('PASS: independent host/native UDP same tuple, mixed epoll and both close orders' not in fd_output
                                or stats['native']['udp_in_datagrams'] != 3
                                or stats['native']['udp_out_datagrams'] != 3):
                            raise RuntimeError('host/native coexistence missed isolated kernel UDP accounting: ' + str(stats))
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
    parser.add_argument('--ecn-app', type=Path)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--worker-log', action='store_true')
    parser.add_argument('--launcher-config', action='store_true')
    parser.add_argument('--lcore-config', action='store_true')
    parser.add_argument('--startup-app', type=Path)
    parser.add_argument('--log-lifetime-probe', type=Path)
    parser.add_argument('--faults', action='store_true')
    parser.add_argument('--zero-window', action='store_true')
    parser.add_argument('--udp-cork-app', type=Path)
    parser.add_argument('--fd-app', type=Path)
    parser.add_argument('--fd-coexistence', action='store_true')
    parser.add_argument('--dualstack-app', type=Path)
    parser.add_argument('--epoll-app', type=Path)
    parser.add_argument('--message-app', type=Path)
    parser.add_argument('--stream-app', type=Path)
    parser.add_argument('--udp-app', type=Path)
    parser.add_argument('--fd-modes-app', type=Path)
    parser.add_argument('--udp-errors-app', type=Path)
    parser.add_argument('--udp-ancillary-app', type=Path)
    parser.add_argument('--udp-mtu-app', type=Path)
    parser.add_argument('--jumbo-app', type=Path)
    parser.add_argument('--mbuf-scatter', action='store_true')
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
    parser.add_argument('--peek-offset-app', type=Path)
    parser.add_argument('--keepalive-app', type=Path)
    parser.add_argument('--notsent-lowat-app', type=Path)
    parser.add_argument('--user-timeout-app', type=Path)
    parser.add_argument('--ip-options-app', type=Path)
    parser.add_argument('--window-clamp-app', type=Path)
    parser.add_argument('--mss-app', type=Path)
    parser.add_argument('--cork-app', type=Path)
    parser.add_argument('--congestion-app', type=Path)
    parser.add_argument('--linger2-app', type=Path)
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
