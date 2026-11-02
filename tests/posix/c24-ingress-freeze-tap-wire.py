#!/usr/bin/env python3
"""Exercise the private q88 primitive with real TAP TCP SYNs."""
import argparse
import importlib.util
import errno
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def send_command(prefix, command):
    target = Path(str(prefix) + '.command')
    staging = Path(str(prefix) + '.command.tmp')
    staging.write_text(command + '\n')
    os.replace(staging, target)


def wait_state(prefix, expected, process, timeout=15):
    path = Path(str(prefix) + '.state')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            state = path.read_text().strip()
            if state == expected or state.startswith(expected + ' '):
                return state
            if state.startswith('FAILED '):
                output, errors = process.communicate(timeout=5)
                raise RuntimeError(f'C24 runtime failed before {expected}: {state}; '
                    f'rc={process.returncode}; stdout={output!r}; stderr={errors!r}')
        if process.poll() is not None:
            output, errors = process.communicate()
            raise RuntimeError(f'C24 client exited before {expected}: rc={process.returncode}; '
                f'state={path.read_text().strip() if path.exists() else "<missing>"}; '
                f'stdout={output!r}; stderr={errors!r}')
        time.sleep(.005)
    raise RuntimeError(f'timed out waiting for {expected}: '
        f'{path.read_text().strip() if path.exists() else "<missing>"}')


def wait_held(prefix, process, capture, native, peer_port, timeout=12):
    path = Path(str(prefix) + '.state')
    deadline = time.monotonic() + timeout
    synack_seen = False
    while time.monotonic() < deadline:
        if path.exists():
            state = path.read_text().strip()
            if state.startswith('HELD '):
                return state
            if state.startswith('FAILED '):
                output, errors = process.communicate(timeout=5)
                raise RuntimeError(f'q88 did not report its exact original packet ID: {state}; '
                    f'synack_escaped={synack_seen}; rc={process.returncode}; '
                    f'stdout={output!r}; stderr={errors!r}')
        if process.poll() is not None:
            output, errors = process.communicate()
            raise RuntimeError(f'C24 client exited before HELD: rc={process.returncode}; '
                f'synack_escaped={synack_seen}; stdout={output!r}; stderr={errors!r}')
        try:
            frame, _ = capture.recvfrom(65535)
        except TimeoutError:
            continue
        if is_tuple_synack(frame, native, peer_port):
            synack_seen = True
    raise RuntimeError(f'timed out waiting for q88 HELD; synack_escaped={synack_seen}')


def is_tuple_synack(frame, native, peer_port):
    packet = native.ipv4_tcp_frame(frame)
    return bool(packet and packet['src'] == '198.18.0.2' and
        packet['dst'] == '198.18.0.1' and packet['sport'] == 8081 and
        packet['dport'] == peer_port and packet['flags'] & 0x12 == 0x12)


def is_tuple_syn(frame, native, peer_port):
    packet = native.ipv4_tcp_frame(frame)
    return bool(packet and packet['src'] == '198.18.0.1' and
        packet['dst'] == '198.18.0.2' and packet['sport'] == peer_port and
        packet['dport'] == 8081 and packet['flags'] & 0x02 and
        not packet['flags'] & 0x10)


def observe_synack(capture, native, peer_port, timeout, expect):
    seen = False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            frame, _ = capture.recvfrom(65535)
        except TimeoutError:
            continue
        if is_tuple_synack(frame, native, peer_port):
            seen = True
    require(seen == expect,
        f'original-Linux SYN-ACK observation differs for {peer_port}: expected={expect}')


def capture_syn_ports(capture, native, expected_ports, timeout=5):
    seen = set()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and seen != expected_ports:
        try:
            frame, _ = capture.recvfrom(65535)
        except TimeoutError:
            continue
        packet = native.ipv4_tcp_frame(frame)
        if (packet and packet['src'] == '198.18.0.1' and
                packet['dst'] == '198.18.0.2' and packet['dport'] == 8081 and
                packet['sport'] in expected_ports and packet['flags'] & 0x02 and
                not packet['flags'] & 0x10):
            seen.add(packet['sport'])
    return seen


def observe_no_synack_ports(capture, native, peer_ports, timeout=.15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            frame, _ = capture.recvfrom(65535)
        except TimeoutError:
            continue
        packet = native.ipv4_tcp_frame(frame)
        if (packet and packet['src'] == '198.18.0.2' and
                packet['dst'] == '198.18.0.1' and packet['sport'] == 8081 and
                packet['dport'] in peer_ports and packet['flags'] & 0x12 == 0x12):
            raise RuntimeError(f'original Linux emitted SYN-ACK for held/quarantined port {packet["dport"]}')


def make_peer(blocking=True):
    peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer.bind(('198.18.0.1', 0))
    peer.setblocking(blocking)
    if blocking:
        peer.settimeout(5)
    result = peer.connect_ex(('198.18.0.2', 8081))
    require(result in (0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK),
        f'host connection did not enter SYN_SENT: {result}')
    return peer


def start_client(args, eal, root, mode):
    prefix = root / f'c24-{mode}'
    stats_name = {'release': 'stats.json', 'expiry': 'stats-expire.json',
        'disarm-abort': 'stats-disarm-abort.json',
        'overflow': 'stats-overflow.json'}[mode]
    stats_path = root / stats_name
    command = [sys.executable, str(args.launcher), '--library', str(args.library),
        '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
        '--port', 'net_tap0', '--eal', eal, '--stats', str(stats_path), '--',
        str(args.client)]
    environment = os.environ | {'PYTHONDONTWRITEBYTECODE': '1',
        'RUNTIME_DIRECTORY': str(root), 'KER_C24_INGRESS_CONTROL': str(prefix)}
    if mode == 'expiry':
        environment['KER_C24_INGRESS_EXPIRE'] = '1'
    elif mode == 'disarm-abort':
        environment['KER_C24_INGRESS_DISARM_ABORT'] = '1'
    elif mode == 'overflow':
        environment['KER_C24_INGRESS_OVERFLOW'] = '1'
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, text=True)
    return prefix, process, stats_path


def run_case(args, eal, root, native, mode):
    expire = mode == 'expiry'
    abort = mode == 'disarm-abort'
    overflow = mode == 'overflow'
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind(('kerhost', 0))
    capture.settimeout(.01)
    old = new = extra = None
    overflow_peers = []
    process = None
    try:
        prefix, process, stats_path = start_client(args, eal, root, mode)
        wait_state(prefix, 'READY', process)
        print(f'C24_CASE_READY mode={mode}', flush=True)
        try:
            old = make_peer()
        except TimeoutError as error:
            state_path = Path(str(prefix) + '.state')
            raise RuntimeError(f'initial Linux handshake timed out; '
                f'runtime_state={state_path.read_text().strip() if state_path.exists() else "<missing>"}') from error
        try:
            old.sendall(b'old')
            old_echo = old.recv(8)
        except TimeoutError as error:
            state_path = Path(str(prefix) + '.state')
            raise RuntimeError(f'initial reuseport member-0 echo timed out; '
                f'runtime_state={state_path.read_text().strip() if state_path.exists() else "<missing>"}') from error
        require(old_echo == b'echo:old', 'established original-Linux echo failed')
        print('C24_OLD_STREAM_ECHO_OK', flush=True)
        wait_state(prefix, 'OLD_ECHO', process)
        send_command(prefix, 'ARM')
        wait_state(prefix, 'ARMED', process)
        print('C24_Q88_ARMED', flush=True)

        if overflow:
            overflow_peers = [make_peer(blocking=False) for _ in range(65)]
            overflow_ports = {peer.getsockname()[1] for peer in overflow_peers}
            seen_ports = capture_syn_ports(capture, native, overflow_ports)
            require(seen_ports == overflow_ports,
                f'host emitted only {len(seen_ports)}/65 actual initial SYNs')
            count_state = wait_state(prefix, 'OVERFLOW_COUNT64', process, timeout=12)
            held_id = int(count_state.split('first_id=', 1)[1].split()[0])
            held = f'HELD id={held_id}'
            print(f'C24_Q88_OVERFLOW ids=64 actual_syns={len(seen_ports)}', flush=True)
            observe_no_synack_ports(capture, native, overflow_ports)
        else:
            new = make_peer(blocking=False)
            peer_port = new.getsockname()[1]
            syn_seen = capture_syn_ports(capture, native, {peer_port}, timeout=1)
            require(syn_seen == {peer_port},
                f'host did not emit the exact TAP SYN for source port {peer_port}')
            held = wait_held(prefix, process, capture, native, peer_port)
            print(f'C24_Q88_HELD {held}', flush=True)
            require('id=' in held, f'q88 did not report an exact held packet ID: {held!r}')
            held_id = int(held.split('id=', 1)[1].split()[0])
            observe_synack(capture, native, peer_port, .12, False)

        old.sendall(b'alive')
        require(old.recv(5) == b'alive',
            'an established original-Linux stream stopped while q88 held a new SYN')

        if expire:
            wait_state(prefix, 'EXPIRED_QUARANTINED', process, timeout=40)
            observe_synack(capture, native, peer_port, .15, False)
            extra = make_peer(blocking=False)
            extra_port = extra.getsockname()[1]
            require(capture_syn_ports(capture, native, {extra_port}, timeout=1) == {extra_port},
                'host did not emit a future SYN after expiry quarantine')
            observe_synack(capture, native, extra_port, .2, False)
            old.sendall(b'alive')
            require(old.recv(5) == b'alive',
                'terminal q88 quarantine disturbed the established original-Linux stream')
            send_command(prefix, 'STOP')
        elif overflow:
            send_command(prefix, 'OVERFLOW_CUTOFF')
            wait_state(prefix, 'OVERFLOW_QUARANTINED', process)
            observe_no_synack_ports(capture, native, overflow_ports)
            extra = make_peer(blocking=False)
            extra_port = extra.getsockname()[1]
            require(capture_syn_ports(capture, native, {extra_port}, timeout=1) == {extra_port},
                'host did not emit a future SYN after overflow quarantine')
            observe_synack(capture, native, extra_port, .2, False)
            old.sendall(b'alive')
            require(old.recv(5) == b'alive',
                'overflow quarantine disturbed the established original-Linux stream')
            send_command(prefix, 'STOP')
        elif abort:
            send_command(prefix, 'ABORT')
            wait_state(prefix, 'DISARMED_QUARANTINED', process)
            observe_synack(capture, native, peer_port, .15, False)
            extra = make_peer(blocking=False)
            extra_port = extra.getsockname()[1]
            require(capture_syn_ports(capture, native, {extra_port}, timeout=1) == {extra_port},
                'host did not emit a future SYN after disarm/quarantine')
            observe_synack(capture, native, extra_port, .2, False)
            old.sendall(b'alive')
            require(old.recv(5) == b'alive',
                'disarmed q88 abort disturbed the established original-Linux stream')
            send_command(prefix, 'STOP')
        else:
            send_command(prefix, 'SELECT1')
            wait_state(prefix, 'SELECTED1', process)
            print('C24_LINUX_REUSEPORT_SELECTOR1', flush=True)
            observe_synack(capture, native, peer_port, .05, False)
            send_command(prefix, 'RELEASE')
            print('C24_Q88_RELEASED_TO_LINUX', flush=True)
            _, writable, exceptional = select.select([], [new], [new], 5)
            require(bool(writable) and not exceptional and
                new.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0,
                'unchanged original SYN did not complete after q88 NF_ACCEPT')
            observe_synack(capture, native, peer_port, .1, True)
            wait_state(prefix, 'ACCEPTED_MEMBER1', process)
            new.settimeout(5)
            try:
                new.sendall(b'new')
                wait_state(prefix, 'MEMBER1_DATA_READY', process)
                new_echo = new.recv(8)
            except TimeoutError as error:
                state_path = Path(str(prefix) + '.state')
                raise RuntimeError(f'member-1 echo timed out; '
                    f'runtime_state={state_path.read_text().strip() if state_path.exists() else "<missing>"}') from error
            require(new_echo == b'echo:new',
                'released original SYN did not reach the Linux listener accept path')
            old.sendall(b'alive')
            require(old.recv(5) == b'alive',
                'established original-Linux stream stopped after q88 release')
            send_command(prefix, 'STOP')

        wait_state(prefix, 'DONE', process)
        output, errors = process.communicate(timeout=15)
        require(process.returncode == 0 and 'C24_TAP_INGRESS_FREEZE_POSITIVE_OK' in output,
            f'C24 runtime failed: rc={process.returncode}; stdout={output!r}; stderr={errors!r}')
        evidence_path = Path(str(prefix) + '.evidence')
        require(evidence_path.exists(), 'C24 runtime omitted durable case evidence')
        evidence = evidence_path.read_text().strip()
        require(f'first_id={held_id}' in evidence or f'ids={held_id}' in evidence,
            f'C24 runtime evidence did not preserve exact NFQUEUE ID {held_id}: {evidence!r}')
        if mode == 'release':
            require('q87_accept_sent=1' in evidence and 'q87_ids=' in evidence,
                f'C20 q87 did not accept an observed SYNACK while q88 was active: {evidence!r}')
        if abort:
            require(f'first_id={held_id}' in evidence and
                'drain=clean quarantine=disarmed abort_before_select=1' in evidence,
                f'abort evidence omitted exact held ID or terminal state: {evidence!r}')
        if overflow:
            fields = dict(token.split('=', 1) for token in evidence.split()
                if '=' in token)
            ids = fields.get('ids', '').split(',')
            require(fields.get('held_ids') == '64' and len(ids) == 64 and
                len(set(ids)) == 64 and int(fields.get('attempts', '0')) > 64 and
                int(fields.get('expired', '1')) == 0 and
                int(fields.get('inventory_errors', '1')) == 0 and
                int(fields.get('drain_error', '0')) in (-errno.EOVERFLOW, -errno.EUCLEAN),
                f'overflow did not fail closed on exact kernel counter mismatch: {evidence!r}')
            require(len(overflow_ports) == 65,
                'overflow case did not originate at least 65 distinct host TCP SYNs')
        require(stats_path.exists(), f'ker-run omitted case stats: {stats_path}')
        stats = json.loads(stats_path.read_text())
        require(stats.get('outstanding') == 0,
            f'C24 {"expiry" if expire else "release"} case leaked runtime resources: {stats!r}')
        require(stats.get('worker_exit_code') == 0 and
            stats.get('shutdown_timed_out') is False,
            f'C24 {mode} case did not report a clean broker worker exit: {stats!r}')
        case = {'mode': mode, 'held_packet_id': held_id,
            'runtime_evidence': evidence, 'stats': stats,
            'old_stream_echo_before_and_after': True,
            'synack_held_before_cutover': True,
            'released_to_member1': mode == 'release',
            'terminal_quarantine': expire or abort or overflow,
            'host_syn_count': len(overflow_peers) if overflow else 1,
            'client_stdout': output.strip(),
            'client_stderr': errors.strip()}
        Path(f'/dev/shm/ker-c24-case-{case["mode"]}-evidence.json').write_text(
            json.dumps(case, indent=2) + '\n')
        return case
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if old is not None:
            old.close()
        if new is not None:
            new.close()
        if extra is not None:
            extra.close()
        capture.close()


def run_probe(args, eal, root, native):
    cases = [run_case(args, eal, root, native, mode='release'),
        run_case(args, eal, root, native, mode='expiry'),
        run_case(args, eal, root, native, mode='disarm-abort'),
        run_case(args, eal, root, native, mode='overflow')]
    evidence = {'schema': 1, 'qualification': 'primitive-only',
        'native_fingerprint': '22813a0c8cdd737a714a131d519098a62cb3df90a63d50c3eb4fc7f29b737327',
        'cases': cases,
        'limits': ['raw original-Linux reuseport cBPF selector only',
            'q87/q88 queue coexistence uses raw q87 SYNACK verdict, not F-Stack map admission',
            'no broker selector/FF map or Nginx graceful reload claim']}
    Path('/dev/shm/ker-c24-wire-evidence.json').write_text(
        json.dumps(evidence, indent=2) + '\n')
    print('C24_TAP_INGRESS_FREEZE_OK original_linux=true q88_original_ids=true '
        'held_synack=true established_stream_live=true unchanged_syn_release=true '
            'expired_terminal_quarantine=true disarmed_abort=true '
            'overflow_attempt_mismatch=true q87_q88_coexistence=true '
            'selector_handover=raw-linux-only')


def invoke_inside(args):
    source = Path(__file__).with_name('native-socket-broker.py')
    spec = importlib.util.spec_from_file_location('ker_native_socket_broker', source)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    native.run_payload_snapshot_wire_probe = lambda runner_args, eal, root: run_probe(
        runner_args, eal, root, native)
    runner_args = SimpleNamespace(dpdk_plugin_dir=args.dpdk_plugin_dir,
        launcher=args.launcher, library=args.library, worker=args.worker,
        client=args.client, member_census_runtime_test=args.client)
    return native.inside(runner_args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--worker', type=Path, required=True)
    parser.add_argument('--dpdk-plugin-dir', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--inside', action='store_true')
    args = parser.parse_args()
    if args.inside:
        return invoke_inside(args)
    command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside']
    for option in ('launcher', 'library', 'worker', 'dpdk_plugin_dir', 'client'):
        command += ['--' + option.replace('_', '-'), str(getattr(args, option).resolve())]
    return subprocess.run(command).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'C24 TAP ingress-freeze fixture failed: {error}', file=sys.stderr)
        raise SystemExit(1)
