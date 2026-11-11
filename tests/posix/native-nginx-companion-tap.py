#!/usr/bin/env python3
"""Real pinned Nginx traffic/HUP/settlement through ker-run's companion."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import select
import shlex
import signal
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


BODY = b'ker-c35-companion-http\n'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_source_classifier_frame(record, owner):
    frame = bytes.fromhex(record['hex'])
    af = int(record['af'])
    require(int(record['pid']) == owner['pid'] and int(record['tid']) == owner['tid'],
        'source-family frame was not generated on the authenticated owner thread')
    require(int(record['bytes']) == len(frame) and len(frame) >= 54,
        'source-family frame length metadata is invalid')

    def checksum_ok(data):
        if len(data) & 1:
            data += b'\0'
        total = sum((data[index] << 8) | data[index + 1]
            for index in range(0, len(data), 2))
        while total >> 16:
            total = (total & 0xffff) + (total >> 16)
        return total == 0xffff

    if af == 4:
        require(frame[12:14] == b'\x08\x00' and frame[14] == 0x45 and
            struct.unpack_from('!H', frame, 16)[0] == len(frame) - 14 and
            frame[23] == 6 and checksum_ok(frame[14:34]),
            'source IPv4 fixture is not a complete checksummed IPv4/TCP frame')
        tcp_offset = 34
        pseudo = frame[26:34] + b'\0\x06' + struct.pack('!H', len(frame) - tcp_offset)
        expected_source_port = 43127
    elif af == 6:
        require(frame[12:14] == b'\x86\xdd' and frame[14] >> 4 == 6 and
            struct.unpack_from('!H', frame, 18)[0] == len(frame) - 54 and
            frame[20] == 6,
            'source IPv6 fixture does not have a complete TCP payload')
        tcp_offset = 54
        pseudo = (frame[22:54] + struct.pack('!I', len(frame) - tcp_offset) +
            b'\0\0\0\x06')
        expected_source_port = 43128
    else:
        raise RuntimeError(f'unsupported source frame family {af}')
    require(frame[tcp_offset + 12] >> 4 == 5 and
        struct.unpack_from('!HH', frame, tcp_offset) ==
            (expected_source_port, 8080) and
        checksum_ok(pseudo + frame[tcp_offset:]),
        'source TCP fixture tuple, header, or checksum is invalid')
    return frame


def set_up_network():
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


def child_pids(pid):
    path = Path(f'/proc/{pid}/task/{pid}/children')
    try:
        return [int(value) for value in path.read_text().split()]
    except FileNotFoundError:
        return []


def process_command(pid):
    try:
        return Path(f'/proc/{pid}/cmdline').read_bytes().replace(b'\0', b' ').decode(
            errors='replace')
    except OSError:
        return ''


def wait_worker(master, previous, timeout):
    path = Path(f'/proc/{master}/task/{master}/children')
    deadline = time.monotonic() + timeout
    last = []
    while time.monotonic() < deadline:
        if not Path(f'/proc/{master}').exists():
            raise RuntimeError('pinned Nginx master exited before its worker was ready')
        try:
            last = [int(value) for value in path.read_text().split()]
        except FileNotFoundError:
            last = []
        if len(last) == 1 and (previous is None or last[0] != previous):
            return last[0]
        time.sleep(0.02)
    raise RuntimeError(f'Nginx did not publish the expected worker: {last!r}')


def http_get(path='/', return_source_port=False):
    connection = socket.create_connection(('198.18.0.2', 80), timeout=5)
    try:
        source_port = connection.getsockname()[1]
        request = f'GET {path} HTTP/1.1\r\nHost: ker.test\r\n'.encode('ascii')
        connection.sendall(request +
            b'Connection: close\r\n\r\n')
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        header, separator, body = bytes(response).partition(b'\r\n\r\n')
        require(separator and b' 200 ' in header.split(b'\r\n', 1)[0],
            f'original-Linux Nginx request did not return HTTP 200: {header!r}')
        require(body == BODY, f'original-Linux response body changed: {body!r}')
        return (bytes(response), source_port) if return_source_port else bytes(response)
    finally:
        connection.close()


def wait_http(timeout=20, path='/'):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            return http_get(path)
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    raise RuntimeError(f'original-Linux Nginx did not serve HTTP before deadline: {last_error}')


def pidfd_dead(fd, timeout=0):
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(int(timeout * 1000)))


def run(args):
    with tempfile.TemporaryDirectory(prefix='ker-c35-nginx-', dir='/dev/shm') as directory:
        root = Path(directory)
        rpc_path = root / 'broker.sock'
        stats_path = root / 'stats.json'
        stop_marker = root / 'pending-stop.txt'
        owner_hold_release = root / 'owner-callback-release'
        probe_token = secrets.token_hex(12)
        source_probe_port = 0
        probe_source_port = 0
        if args.rx_owner_relay_source_flowmap:
            port_reserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port_reserver.bind(('127.0.0.1', 0))
            source_probe_port = port_reserver.getsockname()[1]
            port_reserver.close()
        prefix = root / 'nginx'
        logs = prefix / 'logs'
        html = prefix / 'html'
        logs.mkdir(parents=True)
        html.mkdir()
        (html / 'index.html').write_bytes(BODY)
        ini = prefix / 'fstack.ini'
        ini.write_text(f'[ker_socket_broker]\nversion=1\npath={rpc_path}\n\n'
            '[dpdk]\ngraceful_reload=0\n', encoding='utf-8')
        config = prefix / 'nginx.conf'
        module_config = (f'load_module {args.owner_activation_module.resolve()};\n'
            if args.owner_activation_module is not None else '')
        ready_environment = ('env KER_FSTACK_NGINX_INI;\n'
            if args.owner_activation_module is not None else '')
        if args.rx_owner_relay:
            ready_environment += ('env KER_NGINX_RX_OWNER_RELAY_FD;\n'
                'env KER_NGINX_RX_OWNER_RELAY_SUPERVISOR_PID;\n'
                'env KER_NGINX_RX_OWNER_RELAY_NONCE;\n'
                'env KER_NGINX_RX_OWNER_RELAY_EPOCH;\n')
        if args.rx_owner_relay_source_flowmap:
            ready_environment += 'env KER_NGINX_SOURCE_FLOWMAP_TEST;\n'
        config.write_text(f'''{module_config}daemon off;
master_process on;
worker_processes 1;
fstack_conf "fstack.ini";
timer_resolution 1ms;
pid {logs / 'nginx.pid'};
error_log {logs / 'error.log'} notice;
env LD_PRELOAD;
env KER_SOCKET_BROKER_PATH;
{ready_environment}events {{ worker_connections 256; use epoll; }}
http {{
    access_log off;
    sendfile off;
    tcp_nopush off;
    keepalive_timeout 0;
    server {{
        listen 198.18.0.2:80 reuseport;
        server_name ker.test;
        root {html};
        index index.html;
    }}
}}
''', encoding='utf-8')

        cpu = min(os.sched_getaffinity(0))
        plugin = args.dpdk_plugin_dir / 'librte_net_tap.so'
        eal = (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
            f'--iova-mode=va -m 64 -d {plugin} '
            '--vdev=net_tap0,iface=kerpeer,remote=kerlink')
        control_env = (
            f'LD_PRELOAD={args.fstack_runtime.resolve()}:{args.preload_library.resolve()}',
            f'KER_SOCKET_BROKER_PATH={rpc_path}',
            f'KER_FSTACK_NGINX_INI={ini}',
        )
        if args.owner_activation_module is not None:
            require(args.worker_shim is not None,
                'owner READY integration requires the C22 worker activation shim')
            control_env = (f'LD_PRELOAD={args.worker_shim.resolve()}:'
                f'{args.fstack_runtime.resolve()}:{args.preload_library.resolve()}',
                f'KER_SOCKET_BROKER_PATH={rpc_path}', f'KER_FSTACK_NGINX_INI={ini}')
        command = [sys.executable, str(args.launcher.resolve()),
            '--library', str(args.library.resolve()),
            '--io-worker', str(args.worker.resolve()),
            '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', eal,
            '--runtime-service', '--broker-readiness',
            '--control-nginx-binary', str(args.nginx.resolve()),
            '--control-nginx-config', str(config),
            '--control-nginx-prefix', str(prefix), '--stats', str(stats_path)]
        if args.owner_activation_module is not None:
            command += ['--control-nginx-owner-ready',
                '--control-nginx-owner-module', str(args.owner_activation_module.resolve())]
        if args.rx_owner_relay:
            command += ['--rx-decision', '--control-nginx-rx-relay']
        if args.rx_owner_relay_source_flowmap:
            command += ['--control-nginx-env', 'KER_NGINX_SOURCE_FLOWMAP_TEST=1']
        for item in control_env:
            command += ['--control-nginx-env', item]
        relay_application = args.rx_owner_relay_app if args.rx_owner_relay else args.broker
        command += ['--', str(relay_application.resolve()), str(rpc_path)]

        output_path = root / 'ker-run.log'
        pid_path = logs / 'nginx.pid'
        pidfds = []
        launch_env = os.environ.copy()
        if args.rx_owner_relay:
            launch_env['KER_RX_OWNER_RELAY_PROBE_TOKEN'] = probe_token
        if args.rx_owner_relay_source_flowmap:
            launch_env['KER_RX_OWNER_RELAY_SOURCE_FLOWMAP_TEST'] = '1'
            launch_env['KER_RX_OWNER_RELAY_SOURCE_FLOWMAP_PORT'] = str(source_probe_port)
        if args.rx_owner_relay_stop_pending:
            launch_env['KER_RX_OWNER_RELAY_TEST_STOP_MARKER'] = str(stop_marker)
            launch_env['KER_RX_OWNER_RELAY_TEST_STOP_RELEASE'] = str(owner_hold_release)
        with output_path.open('wb') as output:
            supervisor = subprocess.Popen(command, stdout=output,
                stderr=subprocess.STDOUT, start_new_session=True, env=launch_env)
            helper_pidfd = -1
            master_pidfd = -1
            worker_pidfds = []
            scenario_cleanup_complete = False
            try:
                deadline = time.monotonic() + 45
                while time.monotonic() < deadline:
                    if supervisor.poll() is not None:
                        output.flush()
                        raise RuntimeError('ker-run exited before the pinned Nginx master '
                            f'started: {output_path.read_text(errors="replace")}')
                    output.flush()
                    startup_log = output_path.read_text(errors='replace')
                    if ('ker-nginx-companion:' in startup_log or
                            'helper credentials ' in startup_log):
                        raise RuntimeError('Nginx companion startup failed before pidfile: ' +
                            startup_log)
                    if pid_path.is_file() and pid_path.read_text().strip():
                        break
                    time.sleep(0.02)
                else:
                    raise RuntimeError('pinned Nginx did not publish its pidfile')
                master = int(pid_path.read_text().strip())
                master_pidfd = os.pidfd_open(master, 0)
                worker = wait_worker(master, None, 20)
                worker_pidfds.append(os.pidfd_open(worker, 0))
                # Record the dedicated helper as a direct ker-run child. It is
                # separate from the worker and application children.
                deadline = time.monotonic() + 2
                seen_direct_children = set()
                while time.monotonic() < deadline:
                    direct = child_pids(supervisor.pid)
                    for pid in direct:
                        if pid in seen_direct_children:
                            continue
                        try:
                            fd = os.pidfd_open(pid, 0)
                        except ProcessLookupError:
                            continue
                        pidfds.append(fd)
                        seen_direct_children.add(pid)
                    if len(pidfds) >= 3:
                        break
                    time.sleep(0.02)
                if not args.rx_owner_relay_source_flowmap:
                    try:
                        wait_http()
                    except BaseException as error:
                        output.flush()
                        raise RuntimeError(f'{error}; ker-run output: '
                            f'{output_path.read_text(errors="replace")}') from error

                # Exercise the launcher signal path: it must consume and clear
                # the pending flag, relay HUP through the pinned companion,
                # and leave the existing ker-run reactor available for STOP.
                if args.owner_activation_module is None:
                    os.kill(supervisor.pid, signal.SIGHUP)
                    replacement = wait_worker(master, worker, 30)
                    worker_pidfds.append(os.pidfd_open(replacement, 0))
                    wait_http()
                else:
                    ready_lines = []
                    ready_deadline = time.monotonic() + 5
                    while time.monotonic() < ready_deadline:
                        if supervisor.poll() is not None:
                            break
                        output.flush()
                        ready_lines = [line for line in output_path.read_text(
                            errors='replace').splitlines()
                            if line.startswith('KER_NGINX_OWNER_READY ')]
                        if ready_lines:
                            break
                        time.sleep(0.01)
                    require(len(ready_lines) == 1,
                        'ker-run did not publish exactly one authenticated owner READY record')
                    ready = json.loads(ready_lines[0].split(' ', 1)[1])
                    require(ready.get('pid') == worker and ready.get('master_pid') == master and
                        ready.get('tid', 0) > 0 and ready.get('role') == 0 and
                        ready.get('slot_device', 0) > 0 and ready.get('slot_inode', 0) > 0 and
                        ready.get('cookie', 0) > 0 and
                        ready.get('source') == 'authenticated-C22-worker-READY',
                        f'authenticated READY did not identify the actual ff_run worker: {ready!r}')
                    if args.rx_owner_relay:
                        expected_auth_lines = [line for line in output_path.read_text(
                            errors='replace').splitlines()
                            if line.startswith('KER_RX_OWNER_EXPECTED_AUTH ')]
                        require(len(expected_auth_lines) == 1,
                            'C31 app did not ACK exactly one supervisor-authenticated owner record')
                        expected_auth = json.loads(expected_auth_lines[0].split(' ', 1)[1])
                        require(all(expected_auth.get(key) == ready.get(key) for key in
                            ('pid', 'start_ticks', 'tid', 'role', 'slot_device',
                             'slot_inode', 'cookie')),
                            f'supervisor owner AUTH and C22 READY differ: {expected_auth!r} vs {ready!r}')
                        auth_ack_lines = []
                        auth_ack_deadline = time.monotonic() + 5
                        while time.monotonic() < auth_ack_deadline:
                            output.flush()
                            auth_ack_lines = [line for line in output_path.read_text(
                                errors='replace').splitlines()
                                if line.startswith('RX_OWNER_RELAY_AUTH_ACK ')]
                            if auth_ack_lines:
                                break
                            require(supervisor.poll() is None,
                                'relay supervisor exited before authenticated owner ACK')
                            time.sleep(0.01)
                        require(len(auth_ack_lines) == 1,
                            'relay app did not report exactly one validated owner AUTH_ACK')
                        auth_ack = dict(item.split('=', 1) for item in
                            auth_ack_lines[0].split()[1:])
                        require(int(auth_ack['pid']) == ready['pid'] and
                            int(auth_ack['tid']) == ready['tid'] and
                            int(auth_ack['start']) == ready['start_ticks'],
                            f'relay AUTH_ACK identity disagrees with C22 READY: {auth_ack!r} vs {ready!r}')
                        if args.rx_owner_relay_source_flowmap:
                            probe_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            probe_socket.settimeout(5)
                            probe_socket.bind(('0.0.0.0', source_probe_port))
                            probe_socket.connect(('198.18.0.2', 80))
                            probe_source_port = probe_socket.getsockname()[1]
                            witness_deadline = time.monotonic() + 8
                            witness_lines = []
                            while time.monotonic() < witness_deadline:
                                output.flush()
                                witness_lines = [line for line in output_path.read_text(
                                    errors='replace').splitlines()
                                    if line.startswith('RX_OWNER_RELAY_PROBE_FRAME ')]
                                nginx_log = (logs / 'error.log').read_text(errors='replace')
                                if witness_lines and 'SOURCE_FLOWMAP_CYCLE ' in nginx_log:
                                    break
                                require(supervisor.poll() is None,
                                    'source-flowmap relay process exited before its witness')
                                time.sleep(0.01)
                            require(len(witness_lines) == 1,
                                'source-mode probe did not produce one relayed TCP frame witness')
                            witness = dict(item.split('=', 1) for item in
                                witness_lines[0].split()[1:])
                            witness_frame = bytes.fromhex(witness['frame_hex'])
                            require(int(witness['bytes']) == len(witness_frame) and
                                int(witness['packet_id']) > 0 and
                                len(witness_frame) >= 54 and
                                int(witness_frame[34]) * 256 + witness_frame[35] ==
                                    source_probe_port and
                                bool(witness_frame[47] & 0x10) and
                                not bool(witness_frame[47] & 0x02),
                                'source-mode witness was not the unique IPv4 client ACK flow')
                        # This distinct request is correlated with its exact TCP frame
                        # and source port in the owner relay fixture.
                        if args.rx_owner_relay_stop_pending:
                            probe_socket = socket.create_connection(('198.18.0.2', 80), timeout=5)
                            probe_source_port = probe_socket.getsockname()[1]
                            probe_socket.sendall(
                                f'GET /?probe={probe_token} HTTP/1.1\r\n'
                                'Host: ker.test\r\nConnection: close\r\n\r\n'.encode('ascii'))
                            deadline = time.monotonic() + 5
                            while time.monotonic() < deadline and not stop_marker.is_file():
                                output.flush()
                                require(supervisor.poll() is None,
                                    'supervisor exited before pending relay STOP barrier')
                                time.sleep(0.005)
                            require(stop_marker.is_file(),
                                'did not observe the actual deferred lease before STOP')
                            pending_id, original_deadline = map(int,
                                stop_marker.read_text(encoding='ascii').split())
                            require(pending_id > 0 and original_deadline > time.monotonic_ns(),
                                'pending relay marker did not contain a live lease deadline')
                            # The app has requested C31 STOP while this exact lease
                            # remains outstanding. Also stop ker-run while the owner
                            # callback is deliberately held, then release only after
                            # the unchanged packet deadline.
                            retained_children = {}
                            for pid in child_pids(supervisor.pid):
                                command_line = process_command(pid)
                                if (str(args.worker.resolve()) in command_line or
                                        str(args.rx_owner_relay_app.resolve()) in command_line):
                                    try:
                                        child_fd = os.pidfd_open(pid, 0)
                                    except ProcessLookupError:
                                        continue
                                    pidfds.append(child_fd)
                                    retained_children[pid] = child_fd
                            require(len(retained_children) == 2,
                                f'could not pin both native worker and C31 app before STOP: '
                                f'{retained_children!r}')
                            os.kill(supervisor.pid, signal.SIGTERM)
                            require(supervisor.poll() is None and
                                not pidfd_dead(master_pidfd) and
                                not pidfd_dead(worker_pidfds[-1]) and
                                all(not pidfd_dead(fd) for fd in retained_children.values()),
                                'native owner/application actor exited before pending lease release')
                            time.sleep(0.025)
                            output.flush()
                            pre_release_log = output_path.read_text(errors='replace')
                            require('BROKER_DONE' not in pre_release_log and
                                'KER_NATIVE_DONE' not in pre_release_log and
                                not any(line.startswith('RX_OWNER_RELAY_RESULT ')
                                    for line in pre_release_log.splitlines()),
                                'native/app reported healthy completion before pending lease disposition')
                            while time.monotonic_ns() <= original_deadline:
                                time.sleep(0.001)
                            owner_hold_release.write_text('release after original deadline\n',
                                encoding='ascii')
                            outcome_deadline = time.monotonic() + 5
                            pending_log = ''
                            while time.monotonic() < outcome_deadline:
                                output.flush()
                                pending_log = output_path.read_text(errors='replace')
                                if ('companion shutdown UNRESOLVED' in pending_log or
                                        supervisor.poll() is not None):
                                    break
                                time.sleep(0.02)
                            require('RX_OWNER_RELAY_STOP_REQUEST pending=1' in pre_release_log,
                                f'app did not request STOP with a deferred packet: {pre_release_log}')
                            require('RX_OWNER_RELAY_STOP_REQUEST pending=1' in pending_log,
                                'pending-stop marker disappeared from final log')
                            result_line = next((line for line in pending_log.splitlines()
                                if line.startswith('RX_OWNER_RELAY_RESULT ')), '')
                            result = dict(item.split('=', 1) for item in result_line.split()[1:]) \
                                if result_line else {}
                            require('ker: RX decision lease failed closed: Connection timed out' in
                                    pending_log and
                                'ker-run: native Linux shutdown did not complete' in pending_log and
                                int(result.get('deferred', '0')) >
                                    int(result.get('completed', '0')) and
                                int(result.get('deferred', '0')) -
                                    int(result.get('completed', '0')) == 1 and
                                int(result.get('broker', '0')) != 0 and
                                int(result.get('run', '0')) != 0,
                                f'expected unresolved lease/IO timeout was not reported: {pending_log}')
                            require('KER_NATIVE_DONE\n' not in pending_log and
                                'BROKER_DONE' not in pending_log and
                                result_line and (int(result.get('broker', '0')) != 0 or
                                    int(result.get('run', '0')) != 0),
                                f'central C31/native ownership was reported settled without disposition: {pending_log}')
                            stats = json.loads(stats_path.read_text(encoding='utf-8')) \
                                if stats_path.exists() else None
                            if stats is not None:
                                require(stats.get('outstanding', 0) > 0 or
                                    stats.get('rx_decision_settled') is not True,
                                    f'native stats falsely report a settled zero-outstanding run: {stats!r}')
                            probe_socket.close()
                            targets = worker_pidfds + pidfds
                            if master_pidfd >= 0:
                                targets.append(master_pidfd)
                            for fd in targets:
                                try:
                                    signal.pidfd_send_signal(fd, signal.SIGTERM)
                                except OSError:
                                    pass
                            cleanup_deadline = time.monotonic() + 2
                            while time.monotonic() < cleanup_deadline and any(
                                    not pidfd_dead(fd) for fd in targets):
                                time.sleep(0.02)
                            for fd in targets:
                                if not pidfd_dead(fd):
                                    try:
                                        signal.pidfd_send_signal(fd, signal.SIGKILL)
                                    except OSError:
                                        pass
                            if supervisor.poll() is None:
                                try:
                                    supervisor.wait(timeout=3)
                                except subprocess.TimeoutExpired:
                                    os.killpg(supervisor.pid, signal.SIGKILL)
                                    supervisor.wait(timeout=3)
                            require(all(pidfd_dead(fd) for fd in targets),
                                'pending STOP fixture did not clean all pidfd-owned children')
                            scenario_cleanup_complete = True
                            print('RX_OWNER_RELAY_PENDING_STOP exact_lease=%d original_deadline_ns=%d '
                                'pre_release_native_app_owner_alive=1 owner_released_after_deadline=1 '
                                'timeout_failclosed=1 deferred=%s completed=%s broker=%s run=%s stats=%s: PASS' %
                                (pending_id, original_deadline, result.get('deferred'),
                                 result.get('completed'), result.get('broker'), result.get('run'),
                                 json.dumps(stats, sort_keys=True) if stats is not None else 'not-written'))
                            return
                        if not args.rx_owner_relay_source_flowmap:
                            probe_response, probe_source_port = http_get(
                                f'/?probe={probe_token}', return_source_port=True)

                if args.break_helper:
                    helper = None
                    for pid in child_pids(supervisor.pid):
                        if 'ker-nginx-companion' in process_command(pid):
                            helper = pid
                            break
                    require(helper is not None, 'could not identify the pinned companion helper')
                    helper_pidfd = os.pidfd_open(helper, 0)
                    pidfds.append(helper_pidfd)
                    io_worker = None
                    app_pid = None
                    for pid in child_pids(supervisor.pid):
                        command_line = process_command(pid)
                        if str(args.worker.resolve()) in command_line:
                            io_worker = pid
                        if str(args.broker.resolve()) in command_line:
                            app_pid = pid
                    require(io_worker is not None and app_pid is not None,
                        'could not identify live broker app and DPDK worker among ker-run children: '
                        f'{[(pid, process_command(pid)) for pid in child_pids(supervisor.pid)]!r}')
                    io_worker_pidfd = os.pidfd_open(io_worker, 0)
                    app_pidfd = os.pidfd_open(app_pid, 0)
                    pidfds.extend((io_worker_pidfd, app_pidfd))
                    signal.pidfd_send_signal(helper_pidfd, signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        output.flush()
                        if 'companion shutdown UNRESOLVED' in output_path.read_text(
                                errors='replace'):
                            break
                        time.sleep(0.02)
                    else:
                        raise RuntimeError('helper death did not put ker-run in unresolved retention')
                    require(pidfd_dead(helper_pidfd, 1), 'killed helper remained alive')
                    signal_number = signal.SIGINT if args.shutdown_signal == 'int' else signal.SIGTERM
                    os.kill(supervisor.pid, signal_number)
                    time.sleep(0.25)
                    require(supervisor.poll() is None,
                        'ker-run exited after companion loss instead of retaining native resources')
                    require(Path(f'/proc/{master}').exists() and
                        not pidfd_dead(master_pidfd) and not pidfd_dead(io_worker_pidfd) and
                        not pidfd_dead(app_pidfd) and
                        not pidfd_dead(worker_pidfds[-1]),
                        'native app/DPDK worker/Nginx workers stopped despite unresolved companion')
                    output.flush()
                    retained_log = output_path.read_text(errors='replace')
                    require('BROKER_DONE' not in retained_log and 'KER_NATIVE_DONE' not in retained_log and
                        'worker_exit_code' not in retained_log and not stats_path.exists(),
                        'native cleanup completed despite unresolved companion ownership')
                    # The test harness owns teardown after proving retention.
                    os.kill(supervisor.pid, signal.SIGKILL)
                    supervisor.wait(timeout=5)
                    for fd in worker_pidfds + [master_pidfd, io_worker_pidfd, app_pidfd]:
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except OSError:
                            pass
                    time.sleep(0.2)
                    for fd in worker_pidfds + [master_pidfd, io_worker_pidfd, app_pidfd]:
                        if not pidfd_dead(fd):
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except OSError:
                                pass
                    cleanup_targets = worker_pidfds + [master_pidfd, io_worker_pidfd,
                        app_pidfd, helper_pidfd]
                    cleanup_deadline = time.monotonic() + 3
                    while (time.monotonic() < cleanup_deadline and
                            any(not pidfd_dead(fd) for fd in cleanup_targets)):
                        time.sleep(0.02)
                    require(all(pidfd_dead(fd) for fd in cleanup_targets),
                        'test-owned teardown did not reap every pinned target')
                    scenario_cleanup_complete = True
                    print(f'C35 unresolved-companion retention with SIG{signal.Signals(signal_number).name}: '
                        'PASS; harness forcibly terminated retained processes (not normal shutdown)')
                    return

                if args.owner_death:
                    helper = next((pid for pid in child_pids(supervisor.pid)
                        if 'ker-nginx-companion' in process_command(pid)), None)
                    require(helper is not None, 'could not identify the pinned companion helper')
                    helper_pidfd = os.pidfd_open(helper, 0)
                    pidfds.append(helper_pidfd)
                    io_worker = app_pid = None
                    for pid in child_pids(supervisor.pid):
                        command_line = process_command(pid)
                        if str(args.worker.resolve()) in command_line:
                            io_worker = pid
                        if str(args.broker.resolve()) in command_line:
                            app_pid = pid
                    require(io_worker is not None and app_pid is not None,
                        'could not identify live native broker children for owner-death control')
                    io_worker_pidfd = os.pidfd_open(io_worker, 0)
                    app_pidfd = os.pidfd_open(app_pid, 0)
                    pidfds.extend((io_worker_pidfd, app_pidfd))
                    signal.pidfd_send_signal(worker_pidfds[-1], signal.SIGKILL)
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        output.flush()
                        if 'companion shutdown UNRESOLVED' in output_path.read_text(
                                errors='replace'):
                            break
                        time.sleep(0.02)
                    else:
                        raise RuntimeError('delegated owner death did not trigger containment failure')
                    require(pidfd_dead(worker_pidfds[-1], 1) and
                        pidfd_dead(master_pidfd, 1) and pidfd_dead(helper_pidfd, 1),
                        'owner-death containment did not settle the pinned Nginx subtree')
                    signal_number = signal.SIGTERM
                    os.kill(supervisor.pid, signal_number)
                    time.sleep(0.25)
                    require(supervisor.poll() is None and
                        not pidfd_dead(io_worker_pidfd) and not pidfd_dead(app_pidfd),
                        'ker-run released native resources after owner-death containment failure')
                    output.flush()
                    retained_log = output_path.read_text(errors='replace')
                    require('BROKER_DONE' not in retained_log and
                        'KER_NATIVE_DONE' not in retained_log and
                        'worker_exit_code' not in retained_log and not stats_path.exists(),
                        'native cleanup completed despite unresolved owner-death containment')
                    os.kill(supervisor.pid, signal.SIGKILL)
                    supervisor.wait(timeout=5)
                    for fd in (io_worker_pidfd, app_pidfd):
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except OSError:
                            pass
                    time.sleep(0.2)
                    for fd in (io_worker_pidfd, app_pidfd):
                        if not pidfd_dead(fd):
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except OSError:
                                pass
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline and any(
                            not pidfd_dead(fd) for fd in (io_worker_pidfd, app_pidfd)):
                        time.sleep(0.02)
                    require(all(pidfd_dead(fd) for fd in
                        (worker_pidfds[-1], master_pidfd, helper_pidfd,
                         io_worker_pidfd, app_pidfd)),
                        'owner-death fixture left a test-owned process alive')
                    scenario_cleanup_complete = True
                    print('C35 delegated owner idle-death containment: PASS; '
                        'helper detected pidfd death, settled Nginx, retained native resources')
                    return

                signal_number = signal.SIGINT if args.shutdown_signal == 'int' else signal.SIGTERM
                os.kill(supervisor.pid, signal_number)
                supervisor.wait(timeout=35)
                if args.rx_owner_relay_source_flowmap:
                    probe_socket.close()
                output.flush()
                log = output_path.read_text(errors='replace')
                nginx_log = (logs / 'error.log').read_text(errors='replace')
                if args.owner_activation_module is None:
                    require('signal 1 (SIGHUP) received' in nginx_log,
                        'actual pinned Nginx did not record the ker-run reload signal')
                else:
                    require('signal 1 (SIGHUP) received' not in nginx_log,
                        'owner READY opt-in unexpectedly delivered an unauthenticated reload')
                require(supervisor.returncode == 128 + signal_number,
                    f'ker-run exit status after orderly companion STOP: '
                    f'{supervisor.returncode}; {log}')
                require('BROKER_DONE' in log,
                    f'broker did not report native cleanup completion: {log}')
                if args.rx_owner_relay:
                    result_line = next((line for line in log.splitlines()
                        if line.startswith('RX_OWNER_RELAY_RESULT ')), '')
                    result = dict(item.split('=', 1) for item in result_line.split()[1:])
                    callbacks = int(result.get('callbacks', '0'))
                    deferred = int(result.get('deferred', '0'))
                    completed = int(result.get('completed', '0'))
                    startup_drops = int(result.get('startup_drops', '-1'))
                    require(result_line and callbacks > 0 and callbacks == deferred == completed and
                        result.get('broker') == '0' and result.get('run') == '0',
                        f'C31 owner relay did not report settled frame results: {log}')
                    if args.rx_owner_relay_source_flowmap:
                        require(int(result.get('probe_witnesses', '0')) == 1 and
                            int(result.get('probe_packet_id', '0')) > 0 and
                            int(result.get('probe_source_port', '0')) == source_probe_port and
                            int(result.get('probe_frame_hash', '0')) > 0 and
                            int(result.get('probe_dispatcher_result', '0')) == -3,
                            f'source classifier did not return PEER for the unique frame: {result!r}')
                    else:
                        require(int(result.get('probe_witnesses', '0')) == 1 and
                            int(result.get('probe_packet_id', '0')) > 0 and
                            int(result.get('probe_source_port', '0')) == probe_source_port and
                            int(result.get('probe_frame_hash', '0')) > 0,
                            f'unique post-READY HTTP request did not map to one exact relayed frame: {result!r}')
                    probe_frames = [line for line in log.splitlines()
                        if line.startswith('RX_OWNER_RELAY_PROBE_FRAME ')]
                    require(len(probe_frames) == 1,
                        'owner callback did not return exactly one full-frame probe witness')
                    frame_record = dict(item.split('=', 1) for item in
                        probe_frames[0].split()[1:])
                    probe_frame = bytes.fromhex(frame_record['frame_hex'])
                    require(int(frame_record['packet_id']) ==
                            int(result['probe_packet_id']) and
                        int(frame_record['bytes']) == len(probe_frame),
                        'full-frame witness metadata does not match the completed packet lease')
                    if args.rx_owner_relay_source_flowmap:
                        require(len(probe_frame) >= 54 and
                            int(probe_frame[34]) * 256 + probe_frame[35] ==
                                source_probe_port and
                            bool(probe_frame[47] & 0x10) and
                            not bool(probe_frame[47] & 0x02),
                            'source-flowmap witness was not the unique client TCP ACK flow')
                    else:
                        require(f'GET /?probe={probe_token} HTTP/1.1'.encode('ascii') in
                            probe_frame,
                            'full-frame witness does not contain the unique post-READY HTTP request')
                    probe_frame_sha256 = hashlib.sha256(probe_frame).hexdigest()
                    require(len(probe_frame_sha256) == 64,
                        'full-frame witness SHA-256 encoding is invalid')
                stats = json.loads(stats_path.read_text(encoding='utf-8'))
                require(stats.get('outstanding') == 0 and stats.get('tx', 0) > 0 and
                    stats.get('rx', 0) > 0 and stats.get('control_eof') is True and
                    stats.get('worker_exit_code') == 0 and
                    stats.get('run_shutdown') is True and
                    stats.get('run_shutdown_ack') is True,
                    f'worker/native cleanup accounting was incomplete: {stats!r}')
                if args.rx_owner_relay:
                    leases = stats.get('rx_decision_leases', -1)
                    forwarded = stats.get('rx_decision_forwarded', -1)
                    local = stats.get('rx_decision_local', -1)
                    drops = stats.get('rx_decision_drops', -1)
                    cancelled = stats.get('rx_decision_local_cancelled', -1)
                    if args.rx_owner_relay_source_flowmap:
                        require(leases == local + drops and forwarded == local and
                            drops > startup_drops and drops >= 1 and cancelled == 0 and
                            stats.get('rx_decision_settled') is True,
                            f'PEER did not map to an explicit C31 DROP: {stats!r}')
                    else:
                        require(leases == local + drops and forwarded == local and
                            local == completed and drops == startup_drops and cancelled == 0 and
                            stats.get('rx_decision_settled') is True,
                        f'C31 disposition counters do not reconcile with relay completions: {stats!r}')
                require(not Path(f'/proc/{master}').exists(),
                    'Nginx master remained alive after companion SETTLED')
                require(pidfd_dead(master_pidfd, 2),
                    'pinned Nginx master did not exit after companion SETTLED')
                for fd in worker_pidfds + pidfds:
                    require(pidfd_dead(fd, 2),
                        'Nginx worker/helper/runtime child remained alive after ker-run exit')
                if args.rx_owner_relay:
                    receipt_path = os.environ.get('KER_RX_OWNER_RELAY_RECEIPT')
                    if receipt_path:
                        repository = Path(__file__).resolve().parents[2]
                        source_paths = {
                            'owner_module': repository / 'src/posix/fstack-nginx-owner-activation-module.c',
                            'runtime': repository / 'src/posix/fstack-nginx-runtime.c',
                            'preload': repository / 'src/posix/socket-broker-preload.c',
                            'wire': repository / 'src/posix/rx-owner-relay-wire.h',
                            'ker_run': Path(args.launcher),
                            'test_fixture': repository / 'tests/posix/socket-broker-rx-owner-relay-fixture.c',
                            'candidate_admission': repository / 'src/posix/nginx-candidate-admission.c',
                            'source_flowmap_fixture': repository / 'src/posix/nginx-source-flowmap-fixture.c',
                            'source_flowmap_wrapper': repository / 'src/posix/nginx-original-flowmap-source.c',
                            'native_linux_cmake': repository / 'cmake/NativeLinux.cmake',
                            'nginx_companion_cmake': repository / 'cmake/NginxCompanionTests.cmake',
                            'tap': Path(__file__).resolve(),
                        }
                        if args.source_nginx_module_source:
                            source_paths['pinned_nginx_flowmap_module'] = \
                                args.source_nginx_module_source.resolve()
                        binary_paths = {
                            'app': args.rx_owner_relay_app,
                            'worker': args.worker,
                            'library': args.library,
                            'nginx': args.nginx,
                            'runtime_library': args.fstack_runtime,
                            'preload_library': args.preload_library,
                            'owner_module': args.owner_activation_module,
                            'worker_shim': args.worker_shim,
                        }
                        sha256 = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                        receipt = {
                            'candidate_head': subprocess.run(['git', '-C', str(repository),
                                'rev-parse', 'HEAD'], check=True, capture_output=True,
                                text=True).stdout.strip(),
                            'source_sha256': {name: sha256(path)
                                for name, path in source_paths.items()},
                            'binary_sha256': {name: sha256(path)
                                for name, path in binary_paths.items()},
                            'ready': ready,
                            'expected_owner_auth': expected_auth,
                            'auth_ack': auth_ack,
                            'result': result,
                            'worker_stats': stats,
                            'probe': {
                                'token': probe_token,
                                'source_port': probe_source_port,
                                'packet_id': int(frame_record['packet_id']),
                                'bytes': len(probe_frame),
                                'frame_hex': probe_frame.hex(),
                                'sha256': probe_frame_sha256,
                            },
                        }
                        if args.rx_owner_relay_source_flowmap:
                            cycle_lines = [line for line in nginx_log.splitlines()
                                if line.startswith('SOURCE_FLOWMAP_CYCLE ')]
                            require(len(cycle_lines) == 1,
                                'source callback did not emit exactly one authenticated classifier cycle')
                            cycle_fields = dict(item.split('=', 1) for item in
                                cycle_lines[0].split()[1:])
                            require(int(cycle_fields['pid']) == ready['pid'] and
                                int(cycle_fields['tid']) == ready['tid'] and
                                cycle_fields.get('owner') == 'authenticated',
                                'source classifier cycle did not run on the authenticated READY owner')
                            frame_lines = [line for line in nginx_log.splitlines()
                                if line.startswith('SOURCE_FLOWMAP_FRAME ')]
                            require(len(frame_lines) == 2,
                                'source classifier did not preserve both IPv4/IPv6 fixture frames')
                            source_frames = []
                            for line in frame_lines:
                                frame_record = dict(item.split('=', 1) for item in
                                    line.split()[1:])
                                frame = validate_source_classifier_frame(frame_record, ready)
                                source_frames.append({
                                    'family': int(frame_record['af']),
                                    'bytes': len(frame),
                                    'hex': frame.hex(),
                                    'sha256': hashlib.sha256(frame).hexdigest(),
                                })
                            require({item['family'] for item in source_frames} == {4, 6},
                                'source classifier cycle lacks one fixture frame per family')
                            receipt['source_flowmap_cycle'] = {
                                'log': cycle_lines[0],
                                'owner_pid': int(cycle_fields['pid']),
                                'owner_tid': int(cycle_fields['tid']),
                                'families': {'ipv4': cycle_fields['v4'],
                                    'ipv6': cycle_fields['v6']},
                                'input_frames': source_frames,
                                'classification_result': int(result['probe_dispatcher_result']),
                                'relay_disposition': 'C31 DROP for FF_DISPATCH_PEER',
                                'claim_boundary': 'fixture-only unprefixed source map; no broker SYN admission',
                            }
                        receipt_path = Path(receipt_path)
                        receipt_path.parent.mkdir(parents=True, exist_ok=True)
                        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n',
                            encoding='utf-8')
                        print('RX_OWNER_RELAY_QUALIFICATION ' + json.dumps({
                            'ready': ready, 'auth_ack': auth_ack, 'result': result,
                            'probe_packet_id': receipt['probe']['packet_id'],
                            'probe_source_port': probe_source_port,
                            'probe_sha256': probe_frame_sha256,
                            'source_sha256': receipt['source_sha256'],
                            'binary_sha256': receipt['binary_sha256'],
                        }, sort_keys=True))
                scenario_cleanup_complete = True
            finally:
                if not scenario_cleanup_complete:
                    # Failure runs are unqualified. Stop the supervisor and
                    # then target its separately-sessioned helper/master by
                    # pidfd so a failed assertion cannot leak Nginx into later
                    # tests or leave a live child holding native resources.
                    if supervisor.poll() is None:
                        try:
                            supervisor.send_signal(signal.SIGTERM)
                            supervisor.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            os.killpg(supervisor.pid, signal.SIGKILL)
                            supervisor.wait(timeout=3)
                    targets = worker_pidfds + pidfds
                    if master_pidfd >= 0:
                        targets.append(master_pidfd)
                    for fd in targets:
                        try:
                            signal.pidfd_send_signal(fd, signal.SIGTERM)
                        except (OSError, ProcessLookupError):
                            pass
                    deadline = time.monotonic() + 2
                    while time.monotonic() < deadline and any(
                            not pidfd_dead(fd) for fd in targets):
                        time.sleep(0.02)
                    for fd in targets:
                        if not pidfd_dead(fd):
                            try:
                                signal.pidfd_send_signal(fd, signal.SIGKILL)
                            except (OSError, ProcessLookupError):
                                pass
                for fd in worker_pidfds + pidfds + ([master_pidfd] if master_pidfd >= 0 else []):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                if not scenario_cleanup_complete:
                    archive = Path('/dev/shm/ker-c35-last-failure')
                    archive.mkdir(exist_ok=True)
                    if output_path.exists():
                        shutil.copy2(output_path, archive / 'ker-run.log')
                    error_log = logs / 'error.log'
                    if error_log.exists():
                        shutil.copy2(error_log, archive / 'nginx-error.log')
                    if stats_path.exists():
                        shutil.copy2(stats_path, archive / 'stats.json')
                    print(f'UNQUALIFIED diagnostic archive: {archive}', file=sys.stderr)
                    if (archive / 'nginx-error.log').exists():
                        print((archive / 'nginx-error.log').read_text(errors='replace')[-12000:],
                            file=sys.stderr)
        if args.owner_activation_module is None:
            print('C35 real pinned Nginx HTTP/HUP/worker-replacement/companion-SETTLED/native-DONE: PASS')
        else:
            print('C35 real pinned Nginx HTTP/C22 owner READY/companion-SETTLED/native-DONE: PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--broker', type=Path, required=True)
    parser.add_argument('--rx-owner-relay-app', type=Path)
    parser.add_argument('--nginx', type=Path, required=True)
    parser.add_argument('--source-nginx-module-source', type=Path)
    parser.add_argument('--fstack-runtime', type=Path, required=True)
    parser.add_argument('--preload-library', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--shutdown-signal', choices=('term', 'int'), default='term')
    parser.add_argument('--break-helper', action='store_true')
    parser.add_argument('--owner-activation-module', type=Path)
    parser.add_argument('--worker-shim', type=Path)
    parser.add_argument('--owner-death', action='store_true')
    parser.add_argument('--rx-owner-relay', action='store_true')
    parser.add_argument('--rx-owner-relay-source-flowmap', action='store_true')
    parser.add_argument('--rx-owner-relay-stop-pending', action='store_true')
    args = parser.parse_args()
    if not args.inside:
        command = ['unshare', '-Un', '--keep-caps',
            f'--map-user={os.getuid()}', f'--map-group={os.getgid()}',
            sys.executable, str(Path(__file__).resolve()), '--inside']
        for name in ('launcher', 'library', 'worker', 'broker', 'nginx',
                'fstack-runtime', 'preload-library', 'dpdk-plugin-dir'):
            command += ['--' + name, str(getattr(args, name.replace('-', '_')).resolve())]
        if args.source_nginx_module_source is not None:
            command += ['--source-nginx-module-source',
                str(args.source_nginx_module_source.resolve())]
        if args.rx_owner_relay_app is not None:
            command += ['--rx-owner-relay-app', str(args.rx_owner_relay_app.resolve())]
        if args.rx_owner_relay:
            command.append('--rx-owner-relay')
        if args.rx_owner_relay_source_flowmap:
            command.append('--rx-owner-relay-source-flowmap')
        if args.rx_owner_relay_stop_pending:
            command.append('--rx-owner-relay-stop-pending')
        if args.owner_activation_module is not None:
            command += ['--owner-activation-module',
                str(args.owner_activation_module.resolve())]
        if args.owner_death:
            command.append('--owner-death')
        if args.worker_shim is not None:
            command += ['--worker-shim', str(args.worker_shim.resolve())]
        command += ['--shutdown-signal', args.shutdown_signal]
        if args.break_helper:
            command.append('--break-helper')
        subprocess.run(command, check=True)
        return 0
    if args.owner_death and args.owner_activation_module is None:
        raise ValueError('--owner-death requires the authenticated owner READY profile')
    if args.rx_owner_relay and (args.owner_activation_module is None or
            args.worker_shim is None or args.rx_owner_relay_app is None):
        raise ValueError('--rx-owner-relay requires the alias module, worker shim and combined app')
    if args.rx_owner_relay_stop_pending and not args.rx_owner_relay:
        raise ValueError('--rx-owner-relay-stop-pending requires --rx-owner-relay')
    if args.rx_owner_relay_source_flowmap and not args.rx_owner_relay:
        raise ValueError('--rx-owner-relay-source-flowmap requires --rx-owner-relay')
    set_up_network()
    run(args)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'C35 Nginx companion TAP failed: {error}', file=sys.stderr)
        raise
