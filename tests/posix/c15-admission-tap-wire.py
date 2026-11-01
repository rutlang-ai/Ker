#!/usr/bin/env python3
"""Prove original LKL holds a real TAP SYN-ACK until flow-map admission."""
import argparse
import errno
import importlib.util
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def send_command(prefix, value):
    target = Path(str(prefix) + '.command')
    staging = Path(str(prefix) + '.command.tmp')
    staging.write_text(value + '\n')
    os.replace(staging, target)


def normalize_tcp_options(encoded):
    options = bytearray.fromhex(encoded)
    offset = 0
    while offset < len(options):
        kind = options[offset]
        if kind == 0:  # End of option list.
            break
        if kind == 1:  # NOP.
            offset += 1
            continue
        require(offset + 2 <= len(options), 'truncated TCP option header')
        length = options[offset + 1]
        require(length >= 2 and offset + length <= len(options),
            'invalid TCP option length')
        if kind == 8:
            require(length == 10, 'invalid TCP timestamp option length')
            options[offset + 2:offset + length] = bytes(length - 2)
        offset += length
    return bytes(options)


def wait_state(prefix, expected, process, timeout=15):
    path = Path(str(prefix) + '.state')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            state = path.read_text().strip()
            if state == expected or state.startswith(expected + ' '):
                return state
        if process.poll() is not None:
            out, err = process.communicate()
            raise RuntimeError(f'C15 client exited before {expected}: rc={process.returncode}; '
                f'state={path.read_text().strip() if path.exists() else "<missing>"}; '
                f'stdout={out!r}; stderr={err!r}')
        time.sleep(.005)
    raise RuntimeError(f'timed out waiting for {expected}: '
        f'{path.read_text().strip() if path.exists() else "<missing>"}')


def wait_process_stopped(process, timeout=5):
    status_path = Path(f'/proc/{process.pid}/status')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None or not status_path.exists():
            raise RuntimeError(f'owner exited before test stop gate: pid={process.pid}')
        for line in status_path.read_text().splitlines():
            if line.startswith('State:') and line.split()[1] in ('T', 't'):
                return
        time.sleep(.005)
    raise RuntimeError(f'owner did not stop at prepared response gate: pid={process.pid}')


def wait_file(path, process, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return path.read_text().strip()
        if process.poll() is not None:
            out, err = process.communicate()
            raise RuntimeError(f'C15 client exited before {path.name}: rc={process.returncode}; '
                f'stdout={out!r}; stderr={err!r}')
        time.sleep(.005)
    raise RuntimeError(f'timed out waiting for {path}')


def wait_owner_identity(prefix, process, owner_prefix, owner):
    connecting = wait_file(Path(str(prefix) + '.pid'), process)
    require(connecting.startswith('CONNECTING pid='),
        f'malformed controller identity bootstrap: {connecting!r}')
    identity_fields = dict(item.split('=', 1) for item in connecting.split()[1:])
    owner_controller = Path(str(owner_prefix) + '.controller')
    controller_staging = owner_controller.with_suffix('.controller.tmp')
    controller_staging.write_text(
        f"{identity_fields['pid']} {identity_fields['lease']}\n")
    os.replace(controller_staging, owner_controller)
    try:
        wait_state(str(owner_prefix), 'OWNER_CONNECTED', owner)
    except RuntimeError as error:
        if owner.poll() is not None:
            out, err = owner.communicate()
            raise RuntimeError(f'{error}; controller prefix={prefix}; identity={connecting!r}; '
                f'owner prefix={owner_prefix}; owner stdout={out!r}; stderr={err!r}') from error
        owner_identity = Path(str(owner_prefix) + '.controller')
        identity_text = owner_identity.read_text().strip() if owner_identity.exists() else '<missing>'
        raise RuntimeError(f'{error}; controller prefix={prefix}; identity={connecting!r}; '
            f'owner prefix={owner_prefix}; owner controller={identity_text}') from error


def run_probe(args, eal, root, native):
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    peers = []
    process = None
    prefix = root / 'c15-admission-control'
    owner_prefix = root / 'c15-owner'
    owner_path = root / 'owner.sock'
    owner = None
    try:
        capture.bind(('kerhost', 0))
        capture.settimeout(.01)
        require(len(os.fsencode(owner_path)) < 108,
            f'private owner socket path exceeds AF_UNIX limit: {owner_path}')
        owner = subprocess.Popen([str(args.owner), str(owner_path), str(owner_prefix)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_state(str(owner_prefix), 'OWNER_READY', owner)
        command = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal, '--stats', str(root / 'stats.json'),
            '--', str(args.client)]
        environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
            'RUNTIME_DIRECTORY': str(root), 'KER_C15_ADMISSION_CONTROL': str(prefix),
            'KER_C15_OWNER_PATH': str(owner_path),
            'KER_C15_OWNER_PID': str(owner.pid)}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
        wait_owner_identity(prefix, process, owner_prefix, owner)
        wait_state(prefix, 'READY', process)
        revoke_source = Path(__file__).with_name('tcp-request-revoke-wire.py')
        revoke_spec = importlib.util.spec_from_file_location('ker_c14_wire_helpers', revoke_source)
        revoke_module = importlib.util.module_from_spec(revoke_spec)
        revoke_spec.loader.exec_module(revoke_module)
        collision_ports = (1132, 1354, 2031, 3027, 3769, 4125, 5963, 6537, 6708,
            7356, 7512, 8925, 9382, 9604, 10735, 10970, 11392)
        for index, source_port in enumerate(collision_ports, 1):
            peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer.bind(('198.18.0.1', source_port))
            peer.setblocking(False)
            peers.append(peer)
            connect_result = peer.connect_ex(('198.18.0.2', 8080))
            require(connect_result in (0, errno.EINPROGRESS, errno.EALREADY),
                f'flow {index} did not enter SYN_SENT: {connect_result}')
            held = wait_state(prefix, f'HELD index={index}', process)
            fields = dict(item.split('=', 1) for item in held.split()[1:])
            host_syn = server_synack = None
            synack_seen = False
            # Keep an independent wire observation window after HELD while
            # leaving most of the absolute 250 ms NFQUEUE deadline for the
            # owner-map decision and verdict.
            deadline = time.monotonic() + .005
            while time.monotonic() < deadline:
                try:
                    frame, _ = capture.recvfrom(65535)
                except TimeoutError:
                    continue
                packet = native.ipv4_tcp_frame(frame)
                if not packet:
                    continue
                if packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
                        packet['sport'] == source_port and packet['dport'] == 8080 and \
                        packet['flags'] & 0x02:
                    host_syn = packet
                if packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                        packet['sport'] == 8080 and packet['dport'] == source_port and \
                        packet['flags'] & 0x12 == 0x12:
                    synack_seen = True
                    server_synack = packet
            require(host_syn is not None, f'flow {index} had no captured host SYN')
            require(not synack_seen,
                f'flow {index} real TAP SYN-ACK escaped before map admission')
            send_command(prefix, 'ADMIT')
            if index <= 16:
                wait_state(prefix, f'ADMITTED index={index}', process)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and server_synack is None:
                    try:
                        frame, _ = capture.recvfrom(65535)
                    except TimeoutError:
                        continue
                    packet = native.ipv4_tcp_frame(frame)
                    if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                            packet['sport'] == 8080 and packet['dport'] == source_port and \
                            packet['flags'] & 0x12 == 0x12:
                        server_synack = packet
                require(server_synack is not None,
                    f'flow {index} map admission did not release a real TAP SYN-ACK')
                _, writable, exceptional = select.select([], [peer], [peer], 5)
                require(bool(writable) and not exceptional and
                    peer.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
                    f'flow {index} host handshake failed after SYN-ACK release')
            else:
                rejected = wait_state(prefix, 'REJECTED index=17', process)
                require('map_full=true' in rejected and 'request_revoked=true' in rejected,
                    f'17th colliding real handshake was not refused with exact revocation: {rejected}')
                deadline = time.monotonic() + .08
                while time.monotonic() < deadline:
                    try:
                        frame, _ = capture.recvfrom(65535)
                    except TimeoutError:
                        continue
                    packet = native.ipv4_tcp_frame(frame)
                    if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                            packet['sport'] == 8080 and packet['dport'] == source_port and \
                            packet['flags'] & 0x12 == 0x12:
                        raise RuntimeError('17th colliding flow emitted SYN-ACK despite map rejection')
                if server_synack is None:
                    server_synack = {'seq': int(fields['server_seq']),
                        'options': bytes.fromhex(fields['options'])}
                capture.send(revoke_module.request_ack(host_syn, server_synack))
                reset_seen = False
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not reset_seen:
                    try:
                        frame, _ = capture.recvfrom(65535)
                    except TimeoutError:
                        continue
                    packet = native.ipv4_tcp_frame(frame)
                    if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                            packet['sport'] == 8080 and packet['dport'] == source_port and \
                            packet['flags'] & 0x04:
                        reset_seen = True
                require(reset_seen,
                    'late ACK for C14-revoked 17th request did not receive original Linux RST')

        Path(str(prefix) + '.command').write_text('STOP\n')
        wait_state(prefix, 'DONE', process)
        output, errors = process.communicate(timeout=15)
        owner_output, owner_errors = owner.communicate(timeout=10)
        require(process.returncode == 0 and 'C15_TAP_ADMISSION_POSITIVE_OK' in output,
            f'C15 TAP runtime failed: rc={process.returncode}; stdout={output!r}; '
            f'stderr={errors!r}')
        require(owner.returncode == 0,
            f'original flow-map owner failed: rc={owner.returncode}; '
            f'stdout={owner_output!r}; stderr={owner_errors!r}')
        owner_state = Path(str(owner_prefix) + '.state').read_text().strip()
        require(owner_state.startswith('OWNER_DONE inserted=16 duplicates=0 full=1') and
            'capacity=1024' in owner_state and 'revoked=0' in owner_state,
            f'original map growth/full/revocation counters were unexpected: {owner_state!r}')
        for peer in peers:
            peer.close()
        peers.clear()
        run_unread_accept_ack_probe(args, eal, root, native)
        run_stopped_owner_timeout_probe(args, eal, root, native)
        run_prepared_accept_expiry_probe(args, eal, root, native)
        run_prepared_accept_expiry_probe(args, eal, root, native, late_reply=True)
        run_duplicate_admission_probe(args, eal, root, native)
        run_duplicate_admission_probe(args, eal, root, native, expire_after_prepared=True)
        run_duplicate_admission_probe(args, eal, root, native, late_prepared_reply=True)
        print('C15_TAP_ADMISSION_OK original_lkl=true held_synack=true '
            'map_admit=real_ff_flow_map collision_flows=16 mapfull=17 '
            'exact_c14_revoke=true late_ack_rst=true host_handshake=true '
            'unread_accept_ack=map_retained=true')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if owner is not None and owner.poll() is None:
            owner.kill()
            owner.wait()
        for peer in peers:
            peer.close()
        capture.close()


def run_unread_accept_ack_probe(args, eal, root, native):
    root = root / 'c15-unread-ack'
    root.mkdir(mode=0o700)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    owner = process = peer = None
    prefix = root / 'control'
    owner_prefix = root / 'owner'
    owner_path = root / 'owner.sock'
    try:
        capture.bind(('kerhost', 0))
        capture.settimeout(.01)
        owner = subprocess.Popen([str(args.owner), str(owner_path), str(owner_prefix)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_state(str(owner_prefix), 'OWNER_READY', owner)
        command = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal, '--stats', str(root / 'stats.json'),
            '--', str(args.client)]
        environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
            'RUNTIME_DIRECTORY': str(root), 'KER_C15_ADMISSION_CONTROL': str(prefix),
            'KER_C15_OWNER_PATH': str(owner_path), 'KER_C15_OWNER_PID': str(owner.pid),
            'KER_C15_UNREAD_ACCEPT_ACK': '1'}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
        wait_owner_identity(prefix, process, owner_prefix, owner)
        wait_state(prefix, 'READY', process)
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.bind(('198.18.0.1', 11999))
        peer.setblocking(False)
        result = peer.connect_ex(('198.18.0.2', 8080))
        require(result in (0, errno.EINPROGRESS, errno.EALREADY),
            f'unread-ACK flow did not enter SYN_SENT: {result}')
        wait_state(prefix, 'HELD index=1', process)
        send_command(prefix, 'ADMIT')
        wait_state(prefix, 'ACCEPT_SENT_UNCERTAIN map_retained=true', process)
        synack = False
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not synack:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            synack = bool(packet and packet['src'] == '198.18.0.2' and
                packet['dst'] == '198.18.0.1' and packet['sport'] == 8080 and
                packet['dport'] == 11999 and packet['flags'] & 0x12 == 0x12)
        require(synack, 'full NF_ACCEPT send with unread ACK did not release the real SYN-ACK')
        _, writable, exceptional = select.select([], [peer], [peer], 5)
        require(bool(writable) and not exceptional and
            peer.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
            'unread-ACK accepted flow did not complete its real TCP handshake')
        Path(str(prefix) + '.command').write_text('STOP\n')
        wait_state(prefix, 'DONE', process)
        output, errors = process.communicate(timeout=15)
        owner_output, owner_errors = owner.communicate(timeout=10)
        require(process.returncode == 0 and 'C15_TAP_ADMISSION_POSITIVE_OK' in output,
            f'unread-ACK controller failed: rc={process.returncode}; '
            f'stdout={output!r}; stderr={errors!r}')
        require(owner.returncode == 0,
            f'unread-ACK map owner failed: rc={owner.returncode}; '
            f'stdout={owner_output!r}; stderr={owner_errors!r}')
        owner_state = Path(str(owner_prefix) + '.state').read_text().strip()
        require(owner_state.startswith('OWNER_DONE inserted=1 duplicates=0 full=0') and
            'revoked=0' in owner_state,
            f'owner rolled back a possibly accepted flow with unread ACK: {owner_state!r}')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if owner is not None and owner.poll() is None:
            owner.kill()
            owner.wait()
        if peer is not None:
            peer.close()
        capture.close()


def run_stopped_owner_timeout_probe(args, eal, root, native):
    root = root / 'c15-owner-stopped'
    root.mkdir(mode=0o700)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    owner = process = peer = None
    prefix = root / 'control'
    owner_prefix = root / 'owner'
    owner_path = root / 'owner.sock'
    try:
        capture.bind(('kerhost', 0))
        capture.settimeout(.01)
        owner = subprocess.Popen([str(args.owner), str(owner_path), str(owner_prefix)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        wait_state(str(owner_prefix), 'OWNER_READY', owner)
        command = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal, '--stats', str(root / 'stats.json'),
            '--', str(args.client)]
        environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
            'RUNTIME_DIRECTORY': str(root), 'KER_C15_ADMISSION_CONTROL': str(prefix),
            'KER_C15_OWNER_PATH': str(owner_path), 'KER_C15_OWNER_PID': str(owner.pid),
            'KER_C15_STOP_OWNER_TIMEOUT': '1'}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
        wait_owner_identity(prefix, process, owner_prefix, owner)
        wait_state(prefix, 'READY', process)
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.bind(('198.18.0.1', 12001))
        peer.setblocking(False)
        result = peer.connect_ex(('198.18.0.2', 8080))
        require(result in (0, errno.EINPROGRESS, errno.EALREADY),
            f'stopped-owner flow did not enter SYN_SENT: {result}')
        held = wait_state(prefix, 'HELD index=1', process)
        fields = dict(item.split('=', 1) for item in held.split()[1:])
        host_syn = None
        synack_seen = False
        deadline = time.monotonic() + .03
        while time.monotonic() < deadline:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            if packet and packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
                    packet['sport'] == 12001 and packet['dport'] == 8080 and packet['flags'] & 0x02:
                host_syn = packet
            if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['sport'] == 8080 and packet['dport'] == 12001 and \
                    packet['flags'] & 0x12 == 0x12:
                synack_seen = True
        require(host_syn is not None and not synack_seen,
            'stopped-owner flow was not held before SYN-ACK transmission')
        os.kill(owner.pid, signal.SIGSTOP)
        send_command(prefix, 'ADMIT')
        wait_state(prefix, 'OWNER_TIMEOUT', process, timeout=5)
        deadline = time.monotonic() + .08
        while time.monotonic() < deadline:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['sport'] == 8080 and packet['dport'] == 12001 and \
                    packet['flags'] & 0x12 == 0x12:
                synack_seen = True
        require(not synack_seen,
            'owner deadline did not fail closed while the separate map owner was SIGSTOP')

        revoke_source = Path(__file__).with_name('tcp-request-revoke-wire.py')
        revoke_spec = importlib.util.spec_from_file_location('ker_c14_timeout_helpers', revoke_source)
        revoke_module = importlib.util.module_from_spec(revoke_spec)
        revoke_spec.loader.exec_module(revoke_module)
        server_synack = {'seq': int(fields['server_seq']),
            'options': bytes.fromhex(fields['options'])}
        capture.send(revoke_module.request_ack(host_syn, server_synack))
        reset_seen = False
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not reset_seen:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            reset_seen = bool(packet and packet['src'] == '198.18.0.2' and
                packet['dst'] == '198.18.0.1' and packet['sport'] == 8080 and
                packet['dport'] == 12001 and packet['flags'] & 0x04)
        require(reset_seen, 'late ACK after owner timeout/revoke did not receive original Linux RST')
        os.kill(owner.pid, signal.SIGCONT)
        Path(str(prefix) + '.command').write_text('STOP\n')
        wait_state(prefix, 'DONE', process, timeout=8)
        output, errors = process.communicate(timeout=15)
        owner_output, owner_errors = owner.communicate(timeout=10)
        require(process.returncode == 0 and 'C15_TAP_ADMISSION_POSITIVE_OK' in output,
            f'stopped-owner controller failed: rc={process.returncode}; '
            f'stdout={output!r}; stderr={errors!r}')
        require(owner.returncode == 0,
            f'stopped owner failed: rc={owner.returncode}; '
            f'stdout={owner_output!r}; stderr={owner_errors!r}')
        owner_state = Path(str(owner_prefix) + '.state').read_text().strip()
        require(owner_state.startswith('OWNER_DONE inserted=0 duplicates=0 full=0') and
            'revoked=0' in owner_state,
            f'late owner command mutated map after deadline: {owner_state!r}')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if owner is not None and owner.poll() is None:
            try:
                os.kill(owner.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            owner.kill()
            owner.wait()
        if peer is not None:
            peer.close()
        capture.close()


def run_prepared_accept_expiry_probe(args, eal, root, native, late_reply=False):
    root = root / ('c15-late-prepared-reply' if late_reply else 'c15-prepared-accept-expiry')
    root.mkdir(mode=0o700)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    owner = process = peer = None
    prefix = root / 'control'
    owner_prefix = root / 'owner'
    owner_path = root / 'owner.sock'
    try:
        capture.bind(('kerhost', 0))
        capture.settimeout(.01)
        owner_environment = os.environ.copy()
        if late_reply:
            owner_environment['KER_C15_HOLD_PREPARED_INDEX'] = '1'
        owner = subprocess.Popen([str(args.owner), str(owner_path), str(owner_prefix)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=owner_environment, text=True)
        wait_state(str(owner_prefix), 'OWNER_READY', owner)
        command = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal, '--stats', str(root / 'stats.json'),
            '--', str(args.client)]
        environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
            'RUNTIME_DIRECTORY': str(root), 'KER_C15_ADMISSION_CONTROL': str(prefix),
            'KER_C15_OWNER_PATH': str(owner_path), 'KER_C15_OWNER_PID': str(owner.pid)}
        if late_reply:
            environment['KER_C15_LATE_PREPARED_INDEX'] = '1'
        else:
            environment['KER_C15_EXPIRE_AFTER_PREPARED'] = '1'
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
        wait_owner_identity(prefix, process, owner_prefix, owner)
        wait_state(prefix, 'READY', process)
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.bind(('198.18.0.1', 12003))
        peer.setblocking(False)
        result = peer.connect_ex(('198.18.0.2', 8080))
        require(result in (0, errno.EINPROGRESS, errno.EALREADY),
            f'prepared-expiry flow did not enter SYN_SENT: {result}')
        held = wait_state(prefix, 'HELD index=1', process)
        fields = dict(item.split('=', 1) for item in held.split()[1:])
        host_syn = None
        synack_seen = False
        deadline = time.monotonic() + .03
        while time.monotonic() < deadline:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            if packet and packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
                    packet['sport'] == 12003 and packet['dport'] == 8080 and packet['flags'] & 0x02:
                host_syn = packet
            if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['sport'] == 8080 and packet['dport'] == 12003 and \
                    packet['flags'] & 0x12 == 0x12:
                synack_seen = True
        require(host_syn is not None and not synack_seen,
            'fresh flow was not held before the prepared-accept timeout')
        send_command(prefix, 'ADMIT')
        if late_reply:
            owner_prepared = wait_state(str(owner_prefix), 'OWNER_PREPARED_HELD', owner)
            require('prepared=1 status=0 allowed=1 created=1' in owner_prepared,
                f'owner did not prepare the fresh map entry before delaying PREPARED: {owner_prepared!r}')
            wait_state(prefix, 'CANCEL_UNSENT_SENT', process)
            wait_process_stopped(owner)
            os.kill(owner.pid, signal.SIGCONT)
            expiration_state = 'EXPIRED_PREPARE_REPLY index=1'
        else:
            expiration_state = 'EXPIRED_PREPARED index=1'
        expired = wait_state(prefix, expiration_state, process)
        require('accept_sent=0' in expired and 'request_revoked=1' in expired and
            'owner_cancelled=1' in expired and 'drop_sent=1' in expired,
            f'prepared accept timeout did not prove unsent rollback: {expired!r}')
        deadline = time.monotonic() + .08
        while time.monotonic() < deadline:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['sport'] == 8080 and packet['dport'] == 12003 and \
                    packet['flags'] & 0x12 == 0x12:
                synack_seen = True
        require(not synack_seen,
            'fresh flow emitted SYN-ACK after a definitely unsent expired NF_ACCEPT')
        revoke_source = Path(__file__).with_name('tcp-request-revoke-wire.py')
        revoke_spec = importlib.util.spec_from_file_location('ker_c15_prepared_expiry', revoke_source)
        revoke_module = importlib.util.module_from_spec(revoke_spec)
        revoke_spec.loader.exec_module(revoke_module)
        server_synack = {'seq': int(fields['server_seq']), 'options': bytes.fromhex(fields['options'])}
        capture.send(revoke_module.request_ack(host_syn, server_synack))
        reset_seen = False
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not reset_seen:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            reset_seen = bool(packet and packet['src'] == '198.18.0.2' and
                packet['dst'] == '198.18.0.1' and packet['sport'] == 8080 and
                packet['dport'] == 12003 and packet['flags'] & 0x04)
        require(reset_seen,
            'late ACK after prepared-expiry request revocation did not receive original Linux RST')
        send_command(prefix, 'STOP')
        wait_state(prefix, 'DONE', process)
        output, errors = process.communicate(timeout=15)
        owner_output, owner_errors = owner.communicate(timeout=10)
        require(process.returncode == 0 and 'C15_TAP_ADMISSION_POSITIVE_OK' in output,
            f'prepared-expiry controller failed: rc={process.returncode}; stdout={output!r}; stderr={errors!r}')
        require(owner.returncode == 0,
            f'prepared-expiry map owner failed: rc={owner.returncode}; stdout={owner_output!r}; stderr={owner_errors!r}')
        owner_state = Path(str(owner_prefix) + '.state').read_text().strip()
        require(owner_state.startswith('OWNER_DONE inserted=1 duplicates=0 full=0') and
            'revoked=1' in owner_state,
            f'fresh prepared map entry was not rolled back exactly once: {owner_state!r}')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if owner is not None and owner.poll() is None:
            owner.kill()
            owner.wait()
        if peer is not None:
            peer.close()
        capture.close()


def run_duplicate_admission_probe(args, eal, root, native, expire_after_prepared=False,
				  late_prepared_reply=False):
    if expire_after_prepared and late_prepared_reply:
        raise ValueError('duplicate test modes are mutually exclusive')
    directory = 'c15-duplicate-late-prepared' if late_prepared_reply else \
        'c15-duplicate-expired' if expire_after_prepared else 'c15-duplicate'
    root = root / directory
    root.mkdir(mode=0o700)
    table = f'ker_c15_dup_{os.getpid()}'
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    owner = process = peer = None
    table_created = False
    prefix = root / 'control'
    owner_prefix = root / 'owner'
    owner_path = root / 'owner.sock'
    peer_port = 12006 if late_prepared_reply else 12004 if expire_after_prepared else 12002
    try:
        capture.bind(('kerhost', 0))
        capture.settimeout(.01)
        native.census_nft('add', 'table', 'inet', table)
        table_created = True
        native.census_nft('add', 'chain', 'inet', table, 'output', '{', 'type', 'filter',
            'hook', 'output', 'priority', 'filter;', 'policy', 'accept;', '}')
        native.census_nft('add', 'rule', 'inet', table, 'output', 'oifname', 'kerhost',
            'ip', 'saddr', '198.18.0.1', 'ip', 'daddr', '198.18.0.2',
            'tcp', 'dport', '8080', 'tcp', 'flags', '&',
            '(fin', '|', 'syn', '|', 'rst', '|', 'ack)', '==', 'ack', 'counter', 'drop')
        owner_environment = os.environ.copy()
        if late_prepared_reply:
            owner_environment['KER_C15_HOLD_PREPARED_INDEX'] = '2'
        owner = subprocess.Popen([str(args.owner), str(owner_path), str(owner_prefix)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=owner_environment, text=True)
        wait_state(str(owner_prefix), 'OWNER_READY', owner)
        command = [sys.executable, str(args.launcher), '--library', str(args.library),
            '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
            '--port', 'net_tap0', '--eal', eal, '--stats', str(root / 'stats.json'),
            '--', str(args.client)]
        environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
            'RUNTIME_DIRECTORY': str(root), 'KER_C15_ADMISSION_CONTROL': str(prefix),
            'KER_C15_OWNER_PATH': str(owner_path), 'KER_C15_OWNER_PID': str(owner.pid),
            'KER_C15_DUPLICATE_MODE': '1'}
        if expire_after_prepared:
            environment['KER_C15_EXPIRE_AFTER_PREPARED'] = '2'
        if late_prepared_reply:
            environment['KER_C15_LATE_PREPARED_INDEX'] = '2'
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
        wait_owner_identity(prefix, process, owner_prefix, owner)
        wait_state(prefix, 'READY', process)
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.bind(('198.18.0.1', peer_port))
        peer.setblocking(False)
        result = peer.connect_ex(('198.18.0.2', 8080))
        require(result in (0, errno.EINPROGRESS, errno.EALREADY),
            f'duplicate flow did not enter SYN_SENT: {result}')
        held1 = wait_state(prefix, 'HELD index=1', process)
        fields1 = dict(item.split('=', 1) for item in held1.split()[1:])
        host_syn = None
        deadline = time.monotonic() + .04
        while time.monotonic() < deadline:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            if packet and packet['src'] == '198.18.0.1' and packet['dst'] == '198.18.0.2' and \
                    packet['sport'] == peer_port and packet['dport'] == 8080 and packet['flags'] & 0x02:
                host_syn = packet
        require(host_syn is not None, 'duplicate-flow fixture did not capture original host SYN')
        send_command(prefix, 'ADMIT')
        wait_state(prefix, 'ADMITTED index=1 map_created=1', process)

        first_synack = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and first_synack is None:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['sport'] == 8080 and packet['dport'] == peer_port and \
                    packet['flags'] & 0x12 == 0x12:
                first_synack = packet
        require(first_synack is not None, 'first real SYN-ACK was not released')
        deadline = time.monotonic() + 5
        ack_drops = 0
        while time.monotonic() < deadline:
            chain = native.census_nft('list', 'chain', 'inet', table, 'output')
            match = __import__('re').search(r'counter packets (\d+)', chain)
            if match:
                ack_drops = int(match.group(1))
                if ack_drops:
                    break
            time.sleep(.01)
        require(ack_drops > 0, 'host third handshake ACK was not actually dropped')
        require(peer.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
            'host active-open reported an error after emitting the dropped third ACK')

        send_command(prefix, 'NEXT')
        held2 = wait_state(prefix, 'HELD index=2', process, timeout=8)
        fields2 = dict(item.split('=', 1) for item in held2.split()[1:])
        require(fields2['server_seq'] == fields1['server_seq'] and
            normalize_tcp_options(fields2['options']) ==
            normalize_tcp_options(fields1['options']),
            f'original TCP retransmission changed SYN-ACK sequence or non-timestamp options: '
            f'{held1!r} {held2!r}')
        duplicate_synack_seen = False
        deadline = time.monotonic() + .04
        while time.monotonic() < deadline:
            try:
                frame, _ = capture.recvfrom(65535)
            except TimeoutError:
                continue
            packet = native.ipv4_tcp_frame(frame)
            if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                    packet['sport'] == 8080 and packet['dport'] == peer_port and \
                    packet['flags'] & 0x12 == 0x12:
                duplicate_synack_seen = True
        require(not duplicate_synack_seen,
            'retransmitted SYN-ACK escaped before duplicate map result')
        native.census_nft('flush', 'chain', 'inet', table, 'output')
        send_command(prefix, 'ADMIT')
        if expire_after_prepared:
            expired = wait_state(prefix, 'EXPIRED_PREPARED index=2', process)
            require('accept_sent=0' in expired and 'request_revoked=1' in expired and
                'owner_cancelled=1' in expired and 'drop_sent=1' in expired,
                f'duplicate prepared accept did not fail before verdict send: {expired!r}')
            duplicate_synack_seen = False
            deadline = time.monotonic() + .08
            while time.monotonic() < deadline:
                try:
                    frame, _ = capture.recvfrom(65535)
                except TimeoutError:
                    continue
                packet = native.ipv4_tcp_frame(frame)
                if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                        packet['sport'] == 8080 and packet['dport'] == peer_port and \
                        packet['flags'] & 0x12 == 0x12:
                    duplicate_synack_seen = True
            require(not duplicate_synack_seen,
                'duplicate retransmission emitted SYN-ACK after definitely unsent NF_ACCEPT')
        elif late_prepared_reply:
            owner_prepared = wait_state(str(owner_prefix), 'OWNER_PREPARED_HELD', owner)
            require('prepared=1 status=0 allowed=1 created=0' in owner_prepared,
                f'owner did not prepare the duplicate map entry before delaying PREPARED: {owner_prepared!r}')
            wait_state(prefix, 'CANCEL_UNSENT_SENT', process)
            wait_process_stopped(owner)
            os.kill(owner.pid, signal.SIGCONT)
            expired = wait_state(prefix, 'EXPIRED_PREPARE_REPLY index=2', process)
            require('accept_sent=0' in expired and 'request_revoked=1' in expired and
                'owner_cancelled=1' in expired and 'drop_sent=1' in expired,
                f'delayed duplicate PREPARED did not prove unsent cleanup: {expired!r}')
            duplicate_synack_seen = False
            deadline = time.monotonic() + .08
            while time.monotonic() < deadline:
                try:
                    frame, _ = capture.recvfrom(65535)
                except TimeoutError:
                    continue
                packet = native.ipv4_tcp_frame(frame)
                if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                        packet['sport'] == 8080 and packet['dport'] == peer_port and \
                        packet['flags'] & 0x12 == 0x12:
                    duplicate_synack_seen = True
            require(not duplicate_synack_seen,
                'duplicate SYN-ACK escaped after definitely unsent delayed PREPARED')
        else:
            wait_state(prefix, 'ADMITTED index=2 map_created=0', process)
            duplicate_synack = None
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and duplicate_synack is None:
                try:
                    frame, _ = capture.recvfrom(65535)
                except TimeoutError:
                    continue
                packet = native.ipv4_tcp_frame(frame)
                if packet and packet['src'] == '198.18.0.2' and packet['dst'] == '198.18.0.1' and \
                        packet['sport'] == 8080 and packet['dport'] == peer_port and \
                        packet['flags'] & 0x12 == 0x12:
                    duplicate_synack = packet
            require(duplicate_synack is not None,
                'duplicate map result did not release original TCP retransmission')
            _, writable, exceptional = select.select([], [peer], [peer], 5)
            require(bool(writable) and not exceptional and
                peer.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
                'duplicate map path did not complete the real host handshake')
        Path(str(prefix) + '.command').write_text('STOP\n')
        wait_state(prefix, 'DONE', process)
        output, errors = process.communicate(timeout=15)
        owner_output, owner_errors = owner.communicate(timeout=10)
        require(process.returncode == 0 and 'C15_TAP_ADMISSION_POSITIVE_OK' in output,
            f'duplicate controller failed: rc={process.returncode}; '
            f'stdout={output!r}; stderr={errors!r}')
        require(owner.returncode == 0,
            f'duplicate map owner failed: rc={owner.returncode}; '
            f'stdout={owner_output!r}; stderr={owner_errors!r}')
        owner_state = Path(str(owner_prefix) + '.state').read_text().strip()
        require(owner_state.startswith('OWNER_DONE inserted=1 duplicates=1 full=0') and
            'revoked=0' in owner_state,
            f'duplicate map lifecycle counters were unexpected: {owner_state!r}')
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if owner is not None and owner.poll() is None:
            owner.kill()
            owner.wait()
        if peer is not None:
            peer.close()
        if table_created:
            try:
                native.census_nft('delete', 'table', 'inet', table)
            except BaseException:
                pass
        capture.close()


def invoke_inside(args):
    native_path = Path(__file__).with_name('native-socket-broker.py')
    spec = importlib.util.spec_from_file_location('ker_native_socket_broker', native_path)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    native.run_payload_snapshot_wire_probe = lambda runner_args, eal, root: run_probe(
        runner_args, eal, root, native)
    runner_args = SimpleNamespace(dpdk_plugin_dir=args.dpdk_plugin_dir,
        launcher=args.launcher, library=args.library, worker=args.worker,
        client=args.client, owner=args.owner, member_census_runtime_test=args.client,
        member_census_test_library=args.library)
    return native.inside(runner_args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--owner', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if args.inside:
        return invoke_inside(args)
    command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
    for option in ('launcher', 'library', 'worker', 'dpdk_plugin_dir', 'client', 'owner'):
        command += ['--' + option.replace('_', '-'), str(getattr(args, option).resolve())]
    return subprocess.run(command).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'C15 TAP admission fixture failed: {error}', file=sys.stderr)
        raise SystemExit(1)
