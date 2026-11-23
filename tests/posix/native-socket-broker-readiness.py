#!/usr/bin/env python3
"""TAP proof for the opt-in socket-broker READY/STOP control path."""
import argparse
import ctypes
import errno
import importlib.machinery
import importlib.util
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
import threading
import time

WIRE_PATH = Path(__file__).resolve().parents[2] / 'tools' / 'broker_readiness_wire.py'
WIRE_SPEC = importlib.util.spec_from_file_location('_c34_broker_wire', WIRE_PATH)
wire = importlib.util.module_from_spec(WIRE_SPEC)
WIRE_SPEC.loader.exec_module(wire)
RELAY_WIRE_PATH = Path(__file__).resolve().parents[2] / 'tools' / 'ker_run_control_wire.py'
RELAY_WIRE_SPEC = importlib.util.spec_from_file_location('_c36_relay_wire', RELAY_WIRE_PATH)
relay_wire = importlib.util.module_from_spec(RELAY_WIRE_SPEC)
RELAY_WIRE_SPEC.loader.exec_module(relay_wire)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def start_ticks(pid):
    text = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    close = text.rfind(')')
    require(close >= 0, f'cannot parse /proc/{pid}/stat for {pid}')
    fields = text[close + 2:].split()
    require(len(fields) > 19, f'incomplete /proc/{pid}/stat for {pid}')
    return int(fields[19], 10)


def process_alive(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    return not poller.poll(0)


def receive_record(endpoint, expected_size, timeout):
    endpoint.settimeout(timeout)
    packet, ancillary, flags, _ = endpoint.recvmsg(
        expected_size + 1, socket.CMSG_SPACE(struct.calcsize('3i')) +
        socket.CMSG_SPACE(16 * struct.calcsize('i')))
    creds = []
    rights = []
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET:
            continue
        if kind == socket.SCM_CREDENTIALS:
            if len(data) == struct.calcsize('3i'):
                creds.append(struct.unpack('3i', data))
        elif kind == socket.SCM_RIGHTS:
            fds = struct.unpack(f'{len(data) // struct.calcsize("i")}i', data)
            rights.extend(fds)
    for fd in rights:
        os.close(fd)
    require(not rights, f'broker control packet unexpectedly carried descriptors: {rights!r}')
    require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
        f'broker control packet was truncated: flags={flags}')
    require(len(creds) == 1, f'expected exactly one SCM_CREDENTIALS, got {creds!r}')
    return packet, creds[0]


def send_test_packet(endpoint, packet, rights=()):
    ancillary = []
    if rights:
        values = struct.pack(f'{len(rights)}i', *rights)
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, values))
    sent = endpoint.sendmsg([packet], ancillary, getattr(socket, 'MSG_NOSIGNAL', 0))
    require(sent == len(packet), f'short test STOP send: {sent} of {len(packet)}')


def verify_request(nonce, epoch, sequence):
    packet = bytearray(64)
    struct.pack_into('<IHHII', packet, 0, wire.MAGIC, wire.VERSION, 4, 64, 0)
    packet[16:32] = nonce
    struct.pack_into('<QQ', packet, 32, epoch, sequence)
    return bytes(packet)


def verify_result(endpoint, broker_pid, expected_sequence, watch_fd, nonce, epoch):
    send_test_packet(endpoint, verify_request(nonce, epoch, expected_sequence), (watch_fd,))
    return receive_verify_result(endpoint, broker_pid, expected_sequence, nonce, epoch)


def receive_verify_result(endpoint, broker_pid, expected_sequence, nonce, epoch):
    packet = receive_verify_result_packet(endpoint, broker_pid, expected_sequence, nonce, epoch)
    return struct.unpack_from('<I', packet, 12)[0], struct.unpack_from('<I', packet, 124)[0]


def receive_verify_result_packet(endpoint, broker_pid, expected_sequence, nonce, epoch):
    packet, credentials = receive_record(endpoint, 128, 6)
    require(credentials[0] == broker_pid,
        f'watch result came from unexpected process credentials: {credentials!r}')
    require(len(packet) == 128 and struct.unpack_from('<IHHII', packet, 0) ==
        (wire.MAGIC, wire.VERSION, 5, 128, struct.unpack_from('<I', packet, 12)[0]),
        f'malformed watch result header: {packet!r}')
    require(packet[16:32] == nonce and struct.unpack_from('<Q', packet, 32)[0] == epoch and
        struct.unpack_from('<Q', packet, 40)[0] == expected_sequence,
        'watch result identity/sequence mismatch')
    return packet


def load_ker_run(path):
    loader = importlib.machinery.SourceFileLoader('_c34_test_ker_run', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None or spec.loader is None:
        raise ImportError(f'cannot load ker-run Python source from {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_eal(args):
    cpu = min(os.sched_getaffinity(0))
    plugin = args.dpdk_plugin_dir / 'librte_net_tap.so'
    return (f'--lcores=0@{cpu} --no-huge --no-pci --no-shconf --no-telemetry '
        f'--iova-mode=va -m 64 -d {shlex.quote(str(plugin))} '
        '--vdev=net_tap0,iface=kerpeer,remote=kerlink')


def supervisor(args, notify_fd=-1, retain_endpoint=False):
    if args.mode == 'generation-watch-relay-no-bootstrap':
        return supervisor_relay_startup_failure(args, notify_fd)
    if args.mode in ('generation-watch-relay-close-cancel', 'generation-watch-relay-happy'):
        return supervisor_relay_close_cancel(args, notify_fd)
    ker_run = load_ker_run(args.launcher)
    state = {'manager': None, 'app': None, 'retainer_pid': -1}
    original_manager = ker_run.broker_readiness.BrokerReadiness
    barrier_listener = None
    barrier_channel = None
    barrier_path = args.rpc_path.with_name(args.rpc_path.stem + '.verify-barrier.sock')
    if args.mode in ('generation-watch-stop-cancel', 'generation-watch-close-cancel'):
        barrier_listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        barrier_listener.bind(str(barrier_path))
        os.chmod(barrier_path, 0o600)
        barrier_listener.listen(1)

    # The retainer is forked before ker-run starts worker/runtime threads. It
    # receives only a duplicate of the real readiness endpoint later.
    retainer_channel = None
    if retain_endpoint:
        retainer_parent, retainer_child = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | getattr(socket, 'SOCK_CLOEXEC', 0))
        retainer_pid = os.fork()
        if retainer_pid == 0:
            try:
                retainer_parent.close()
                packet, ancillary, _, _ = retainer_child.recvmsg(1,
                    socket.CMSG_SPACE(struct.calcsize('i')))
                fds = []
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        fds.extend(struct.unpack(f'{len(data) // struct.calcsize("i")}i', data))
                require(packet == b'R' and len(fds) == 1,
                    'retainer did not receive exactly one readiness endpoint')
                held_endpoint_fd = fds[0]
                fds.clear()
                retainer_child.send(b'H')
                time.sleep(60)
            finally:
                if 'held_endpoint_fd' in locals():
                    os.close(held_endpoint_fd)
                for fd in locals().get('fds', []):
                    os.close(fd)
                os._exit(0)
        retainer_child.close()
        retainer_channel = retainer_parent
        retainer_channel.settimeout(5)
        state['retainer_pid'] = retainer_pid

    supervisor_pid = os.getpid()

    def observed_manager(*manager_args, **manager_kwargs):
        manager = original_manager(*manager_args, **manager_kwargs)
        state['manager'] = manager
        if retainer_channel is not None:
            values = struct.pack('i', manager.parent.fileno())
            retainer_channel.sendmsg([b'R'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, values)])
            require(retainer_channel.recv(1) == b'H',
                'retainer did not acknowledge holding the readiness endpoint')
            retainer_channel.close()
            state['retainer_held'] = True
        original_child_started = manager.child_started

        def child_started(process, expected_executable_hash):
            result = original_child_started(process, expected_executable_hash)
            state['app'] = process
            if notify_fd >= 0:
                message = {'event': 'APP', 'pid': process.pid,
                    'start_ticks': manager.app[3], 'retainer_pid': state['retainer_pid'],
                    'retainer_held': state.get('retainer_held', False)}
                os.write(notify_fd, (json.dumps(message) + '\n').encode())
            return result

        manager.child_started = child_started
        return manager

    ker_run.broker_readiness.BrokerReadiness = observed_manager
    control_errors = []
    control_result = {}

    def control_thread():
        try:
            manager = None
            deadline = time.monotonic() + 25
            while manager is None and time.monotonic() < deadline:
                manager = state['manager']
                if manager is None:
                    time.sleep(0.001)
            require(manager is not None, 'broker readiness manager was not created')
            app = None
            while app is None and time.monotonic() < deadline:
                app = state['app']
                if app is None:
                    time.sleep(0.001)
            require(app is not None, 'broker application Popen did not complete')
            if args.mode in ('generation-watch-stop-cancel', 'generation-watch-close-cancel'):
                barrier_listener.settimeout(10)
                barrier_channel, _ = barrier_listener.accept()
                barrier_channel.settimeout(5)
            if args.mode == 'no-bootstrap':
                wait_deadline = time.monotonic() + 15
                while app.poll() is None and time.monotonic() < wait_deadline:
                    time.sleep(0.005)
                require(app.poll() is not None and not manager.ready,
                    'missing bootstrap unexpectedly reached READY')
                control_result['no_ready'] = True
                return

            ready_deadline = time.monotonic() + 20
            while not manager.ready and time.monotonic() < ready_deadline:
                if app.poll() is not None:
                    break
                time.sleep(0.001)
            require(manager.ready,
                f'ker-run did not accept authenticated READY; app_status={app.poll()}')
            if notify_fd >= 0:
                os.write(notify_fd, (json.dumps({'event': 'READY', 'pid': manager.app[0],
                    'start_ticks': manager.app[3],
                    'retainer_pid': state['retainer_pid'],
                    'retainer_held': state.get('retainer_held', False)}) + '\n').encode())
            if args.mode == 'parent-death':
                return
            if args.mode in ('generation-watch', 'generation-watch-replay',
                             'generation-watch-rights', 'generation-watch-stop-cancel',
                             'generation-watch-close-cancel'):
                actor_path = args.generation_watch_actor.resolve()
                watch_path = args.rpc_path.with_name(args.rpc_path.stem + '.watch.sock')
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as cap_listener:
                    cap_listener.bind(str(watch_path))
                    os.chmod(watch_path, 0o600)
                    cap_listener.listen(1)
                    actor = subprocess.Popen([str(actor_path), str(args.rpc_path),
                        str(watch_path)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, close_fds=True)
                    state['watch_actor'] = actor
                    cap_listener.settimeout(15)
                    try:
                        channel, _ = cap_listener.accept()
                    except TimeoutError as error:
                        if actor.poll() is None:
                            actor.kill()
                        actor_output, actor_errors = actor.communicate(timeout=5)
                        raise RuntimeError('watch actor did not connect its capability channel: '
                            f'rc={actor.returncode}; stdout={actor_output!r}; '
                            f'stderr={actor_errors.decode(errors="replace")!r}') from error
                    with channel:
                        channel.settimeout(10)
                        payload, ancillary, flags, _ = channel.recvmsg(32,
                            socket.CMSG_SPACE(struct.calcsize('i')))
                        watch_fds = []
                        for level, kind, data in ancillary:
                            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                watch_fds.extend(struct.unpack(
                                    f'{len(data) // struct.calcsize("i")}i', data))
                        require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
                            len(payload) == 12 and len(watch_fds) == 1,
                            'actor did not transfer exactly one watch capability')
                        magic, actor_pid, port, reserved = struct.unpack('<IIHH', payload)
                        require(magic == 0x57415443 and actor_pid == actor.pid and
                            port == 4127 and reserved == 0,
                            f'actor watch identity mismatch: {payload!r}, pid={actor.pid}')
                        watch_fd = watch_fds.pop()
                        state['watch_fd'] = watch_fd
                        watch_alias_fd = -1
                        if args.mode == 'generation-watch-close-cancel':
                            watch_alias_fd = os.dup(watch_fd)
                            state['watch_alias_fd'] = watch_alias_fd
                        status, state_code = verify_result(manager.parent, app.pid, 1,
                            watch_fd, manager.nonce, manager.epoch)
                        require(status == errno.EBUSY and state_code == 0,
                            f'live owner was not denied retirement: status={status}, state={state_code}')
                        if args.mode == 'generation-watch':
                            reserved = subprocess.run([str(actor_path),
                                '--expect-port-reserved', str(args.rpc_path), str(port)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True, timeout=10)
                            require(reserved.returncode == 0,
                                'live non-metadata owner stopped reserving its port: '
                                f'rc={reserved.returncode}, out={reserved.stdout!r}, '
                                f'err={reserved.stderr.decode(errors="replace")!r}')
                            control_result['live_port_reservation_retained'] = True
                        channel.sendall(b'C')
                        require(channel.recv(1) == b'C',
                            'actor did not confirm closing every listener alias')
                        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        probe.settimeout(1)
                        try:
                            probe.connect(('127.0.0.1', port))
                        except OSError as error:
                            require(error.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH),
                                f'closed listener probe failed unexpectedly: {error!r}')
                        else:
                            raise RuntimeError('watch metadata retained a live listener alias')
                        finally:
                            probe.close()
                        status, _ = verify_result(manager.parent, app.pid, 2,
                            watch_fd, manager.nonce, manager.epoch)
                        require(status == errno.EBUSY,
                            f'live owner with closed listener was accepted: status={status}')
                        os.kill(actor.pid, signal.SIGKILL)
                        actor.wait(timeout=5)
                        require(actor.returncode == -signal.SIGKILL,
                            f'owner actor was not reaped as requested: {actor.returncode}')
                        if args.mode in ('generation-watch-stop-cancel',
                                         'generation-watch-close-cancel'):
                            send_test_packet(manager.parent,
                                verify_request(manager.nonce, manager.epoch, 3), (watch_fd,))
                            require(barrier_channel.recv(1) == b'P',
                                'asynchronous census did not reach the test barrier')
                            if args.mode == 'generation-watch-close-cancel':
                                os.close(watch_fd)
                                watch_fd = -1
                                state.pop('watch_fd', None)
                                describe_path = args.rpc_path.with_name(
                                    args.rpc_path.stem + '.watch-describe.sock')
                                with socket.socket(socket.AF_UNIX,
                                        socket.SOCK_SEQPACKET) as describe_listener:
                                    describe_listener.bind(str(describe_path))
                                    os.chmod(describe_path, 0o600)
                                    describe_listener.listen(1)
                                    describe_actor = subprocess.Popen(
                                        [str(actor_path), '--describe-watch',
                                            str(args.rpc_path), str(describe_path)],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, close_fds=True)
                                    state['watch_describe_actor'] = describe_actor
                                    describe_listener.settimeout(5)
                                    describe_channel, _ = describe_listener.accept()
                                    with describe_channel:
                                        describe_channel.settimeout(5)
                                        describe_channel.sendmsg([b'W'], [(socket.SOL_SOCKET,
                                            socket.SCM_RIGHTS,
                                            struct.pack('i', watch_alias_fd))])
                                        describe_result = describe_channel.recv(1)
                                    if describe_result != b'D':
                                        describe_actor.wait(timeout=5)
                                        out, err = describe_actor.communicate(timeout=5)
                                        raise RuntimeError(
                                            'public SDK describe did not accept retained alias: '
                                            f'{describe_result!r}; rc={describe_actor.returncode}; '
                                            f'out={out!r}; err={err.decode(errors="replace")!r}')
                                    describe_actor.wait(timeout=5)
                                    describe_output, describe_errors = describe_actor.communicate(
                                        timeout=5)
                                    require(describe_actor.returncode == 0,
                                        'public SDK alias describe actor failed: '
                                        f'rc={describe_actor.returncode}, '
                                        f'out={describe_output!r}, '
                                        f'err={describe_errors.decode(errors="replace")!r}')
                                    state.pop('watch_describe_actor', None)
                                readable, _, _ = select.select([manager.parent], [], [], 0)
                                require(not readable,
                                    'VERIFY canceled before the final public alias closed')
                                os.close(watch_alias_fd)
                                watch_alias_fd = -1
                                state.pop('watch_alias_fd', None)
                                status, state_code = receive_verify_result(
                                    manager.parent, app.pid, 3, manager.nonce, manager.epoch)
                                require(status == errno.ECANCELED and state_code == 0,
                                    'closing the final watch capability did not cancel VERIFY')
                                # The cancellation freed the metadata slot. Allocate a
                                # replacement before releasing the test barrier so stale
                                # completion cannot act on the reused watch slot.
                                reuse_path = args.rpc_path.with_name(
                                    args.rpc_path.stem + '.watch-reuse.sock')
                                with socket.socket(socket.AF_UNIX,
                                        socket.SOCK_SEQPACKET) as reuse_listener:
                                    reuse_listener.bind(str(reuse_path))
                                    os.chmod(reuse_path, 0o600)
                                    reuse_listener.listen(1)
                                    reused_actor = subprocess.Popen(
                                        [str(actor_path), str(args.rpc_path), str(reuse_path)],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, close_fds=True)
                                    state['watch_actor'] = reused_actor
                                    reuse_listener.settimeout(10)
                                    reuse_channel, _ = reuse_listener.accept()
                                    with reuse_channel:
                                        reuse_channel.settimeout(5)
                                        payload, ancillary, flags, _ = reuse_channel.recvmsg(32,
                                            socket.CMSG_SPACE(struct.calcsize('i')))
                                        reused_fds = []
                                        for level, kind, data in ancillary:
                                            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                                reused_fds.extend(struct.unpack(
                                                    f'{len(data) // struct.calcsize("i")}i', data))
                                        require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
                                            len(payload) == 12 and len(reused_fds) == 1,
                                            'replacement actor did not transfer one watch capability')
                                        magic, reused_pid, reused_port, reserved = struct.unpack(
                                            '<IIHH', payload)
                                        require(magic == 0x57415443 and
                                            reused_pid == reused_actor.pid and reused_port == port and
                                            reserved == 0,
                                            'replacement watch identity was malformed')
                                        reused_watch_fd = reused_fds.pop()
                                        status, state_code = verify_result(manager.parent, app.pid,
                                            4, reused_watch_fd, manager.nonce, manager.epoch)
                                        require(status == errno.EBUSY and state_code == 0,
                                            'replacement live owner watch was affected by stale completion')
                                        barrier_channel.sendall(b'R')
                                        readable, _, _ = select.select(
                                            [manager.parent], [], [], 0)
                                        require(not readable,
                                            'stale completion escaped after replacement watch allocation')
                                        reuse_channel.sendall(b'C')
                                        require(reuse_channel.recv(1) == b'C',
                                            'replacement actor did not close listener capabilities')
                                        status, _ = verify_result(manager.parent, app.pid, 5,
                                            reused_watch_fd, manager.nonce, manager.epoch)
                                        require(status == errno.EBUSY,
                                            'replacement watch lost its live-owner binding')
                                        os.kill(reused_actor.pid, signal.SIGKILL)
                                        reused_actor.wait(timeout=5)
                                        require(reused_actor.returncode == -signal.SIGKILL,
                                            'replacement owner was not reaped')
                                        status, state_code = verify_result(manager.parent,
                                            app.pid, 6, reused_watch_fd,
                                            manager.nonce, manager.epoch)
                                        require(status == 0 and state_code == 1,
                                            'replacement watch was mutated by canceled query completion')
                                        status, state_code = verify_result(manager.parent,
                                            app.pid, 7, reused_watch_fd,
                                            manager.nonce, manager.epoch)
                                        require(status == 0 and state_code == 1,
                                            'replacement terminal query was not idempotent')
                                        os.close(reused_watch_fd)
                                    state.pop('watch_actor', None)
                                control_result['replacement_watch_unaffected'] = True
                            stop = wire.pack_stop(wire.STOP, manager.nonce, manager.epoch,
                                supervisor_pid, os.getuid(), os.getgid(), manager.supervisor[3])
                            send_test_packet(manager.parent, stop)
                            if args.mode == 'generation-watch-stop-cancel':
                                status, state_code = receive_verify_result(manager.parent, app.pid,
                                    3, manager.nonce, manager.epoch)
                                require(status == errno.ECANCELED and state_code == 0,
                                    f'in-flight verification was not canceled: {status}, {state_code}')
                            ack_packet, ack_credentials = receive_record(manager.parent, 104, 6)
                            wire.unpack_stop(ack_packet, wire.STOP_ACK)
                            require(ack_credentials[0] == app.pid,
                                f'STOP_ACK credentials mismatch: {ack_credentials!r}')
                            manager.stopped = True
                            stop_deadline = time.monotonic() + 10
                            while app.poll() is None and time.monotonic() < stop_deadline:
                                time.sleep(0.005)
                            require(app.poll() is not None and app.returncode == 0,
                                'canceled verification did not cleanly settle broker shutdown')
                        else:
                            status, state_code = verify_result(manager.parent, app.pid, 3,
                                watch_fd, manager.nonce, manager.epoch)
                            require(status == 0 and state_code == 1,
                                f'reaped owner did not reach OLD_RETIRED: {status}, {state_code}')
                            send_test_packet(manager.parent,
                                verify_request(manager.nonce, manager.epoch, 4), (watch_fd,))
                            terminal_record = receive_verify_result_packet(
                                manager.parent, app.pid, 4, manager.nonce, manager.epoch)
                            status = struct.unpack_from('<I', terminal_record, 12)[0]
                            state_code = struct.unpack_from('<I', terminal_record, 124)[0]
                            require(status == 0 and state_code == 1,
                                'terminal retirement query was not idempotent')
                            if args.mode == 'generation-watch':
                                reuse_path = args.rpc_path.with_name(
                                    args.rpc_path.stem + '.same-port-owner.sock')
                                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as reuse_listener:
                                    reuse_listener.bind(str(reuse_path))
                                    os.chmod(reuse_path, 0o600)
                                    reuse_listener.listen(1)
                                    reuse_actor = subprocess.Popen([str(actor_path),
                                        '--same-port-owner', str(args.rpc_path), str(reuse_path),
                                        str(port)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, close_fds=True)
                                    state['watch_actor'] = reuse_actor
                                    reuse_listener.settimeout(10)
                                    reuse_channel, _ = reuse_listener.accept()
                                    with reuse_channel:
                                        reuse_channel.settimeout(10)
                                        require(reuse_channel.recv(1) == b'R',
                                            'same-port replacement owner did not bind/listen')
                                        send_test_packet(manager.parent,
                                            verify_request(manager.nonce, manager.epoch, 5),
                                            (watch_fd,))
                                        replacement_record = receive_verify_result_packet(
                                            manager.parent, app.pid, 5, manager.nonce, manager.epoch)
                                        require(struct.unpack_from('<I', replacement_record, 12)[0] == 0 and
                                            struct.unpack_from('<I', replacement_record, 124)[0] == 1 and
                                            replacement_record[48:128] == terminal_record[48:128],
                                            'new same-port owner contaminated the retained OLD_RETIRED receipt')
                                        reuse_channel.sendall(b'C')
                                    reuse_output, reuse_errors = reuse_actor.communicate(timeout=10)
                                    require(reuse_actor.returncode == 0,
                                        'same-port replacement owner failed to settle: '
                                        f'rc={reuse_actor.returncode}, out={reuse_output!r}, '
                                        f'err={reuse_errors.decode(errors="replace")!r}')
                                    state.pop('watch_actor', None)
                                control_result['same_port_reused_old_receipt_stable'] = True
                        if args.mode == 'generation-watch-replay':
                            send_test_packet(manager.parent,
                                verify_request(manager.nonce, manager.epoch, 4), (watch_fd,))
                        elif args.mode == 'generation-watch-rights':
                            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                            try:
                                send_test_packet(manager.parent,
                                    verify_request(manager.nonce, manager.epoch, 5),
                                    (watch_fd, read_fd))
                            finally:
                                os.close(read_fd)
                                os.close(write_fd)
                        elif args.mode == 'generation-watch':
                            os.kill(supervisor_pid, signal.SIGTERM)
                            stop_deadline = time.monotonic() + 10
                            while not manager.stopped and time.monotonic() < stop_deadline:
                                time.sleep(0.001)
                            require(manager.stopped,
                                'watch test did not complete authenticated STOP/ACK')
                            app_deadline = time.monotonic() + 10
                            while app.poll() is None and time.monotonic() < app_deadline:
                                time.sleep(0.005)
                            require(app.poll() is not None and app.returncode == 0,
                                'watch test did not complete clean broker shutdown')
                        if args.mode in ('generation-watch-replay', 'generation-watch-rights'):
                            app_deadline = time.monotonic() + 10
                            while app.poll() is None and time.monotonic() < app_deadline:
                                time.sleep(0.005)
                            require(app.poll() is not None and app.returncode != 0,
                                f'{args.mode} verification input was not rejected')
                        control_result.update({'live_owner_denied': True,
                            'listener_alias_closed': True, 'owner_reaped': True,
                            'reaped_owner_retired': args.mode not in (
                                'generation-watch-stop-cancel', 'generation-watch-close-cancel'),
                            'terminal_idempotent': args.mode not in (
                                'generation-watch-stop-cancel', 'generation-watch-close-cancel'),
                            'replay_rejected': args.mode == 'generation-watch-replay',
                            'ancillary_rejected': args.mode == 'generation-watch-rights',
                            'verify_canceled': args.mode == 'generation-watch-stop-cancel',
                            'watch_close_canceled': args.mode == 'generation-watch-close-cancel',
                            'replacement_watch_unaffected': args.mode ==
                                'generation-watch-close-cancel' and
                                control_result.get('replacement_watch_unaffected'),
                            'clean_stop': args.mode in ('generation-watch',
                                'generation-watch-stop-cancel', 'generation-watch-close-cancel'),
                            'app_returncode': app.returncode})
                        if watch_fd >= 0:
                            os.close(watch_fd)
                            state.pop('watch_fd', None)
                    return
            if args.mode in ('bad-stop', 'rights-stop', 'truncated-stop'):
                if args.mode == 'bad-stop':
                    bad = wire.pack_stop(wire.STOP,
                        bytes([manager.nonce[0] ^ 1]) + manager.nonce[1:], manager.epoch,
                        supervisor_pid, os.getuid(), os.getgid(), manager.supervisor[3])
                elif args.mode == 'rights-stop':
                    bad = wire.pack_stop(wire.STOP, manager.nonce, manager.epoch,
                        supervisor_pid, os.getuid(), os.getgid(), manager.supervisor[3])
                    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
                    try:
                        send_test_packet(manager.parent, bad, (read_fd,))
                    finally:
                        os.close(read_fd)
                        os.close(write_fd)
                    bad = None
                else:
                    bad = wire.pack_stop(wire.STOP, manager.nonce, manager.epoch,
                        supervisor_pid, os.getuid(), os.getgid(), manager.supervisor[3]) + b'\0'
                if bad is not None:
                    send_test_packet(manager.parent, bad)
                wait_deadline = time.monotonic() + 15
                while app.poll() is None and time.monotonic() < wait_deadline:
                    time.sleep(0.005)
                require(app.poll() is not None,
                    'malformed STOP did not terminate the broker application')
                key = {'bad-stop': 'bad_stop_rejected', 'rights-stop': 'rights_stop_rejected',
                    'truncated-stop': 'truncated_stop_rejected'}[args.mode]
                control_result[key] = True
                return

            shutdown_signal = (signal.SIGINT if args.mode == 'healthy-sigint'
                else signal.SIGTERM)
            os.kill(supervisor_pid, shutdown_signal)
            stop_deadline = time.monotonic() + 15
            while not manager.stopped and time.monotonic() < stop_deadline:
                time.sleep(0.001)
            require(manager.stopped,
                'ker-run signal path did not complete authenticated STOP/ACK')
            control_result['ack'] = True
            app_deadline = time.monotonic() + 15
            while app.poll() is None and time.monotonic() < app_deadline:
                time.sleep(0.001)
            require(app.poll() is not None,
                'broker application did not exit after authenticated STOP')
            control_result['app_returncode'] = app.returncode
            require(app.returncode == 0,
                f'broker application shutdown was not clean: {app.returncode}')
        except BaseException as error:
            control_errors.append(error)
            app = state.get('app')
            if app is not None and app.poll() is None:
                app.kill()
            actor = state.get('watch_actor')
            if actor is not None and actor.poll() is None:
                actor.kill()
            describe_actor = state.get('watch_describe_actor')
            if describe_actor is not None and describe_actor.poll() is None:
                describe_actor.kill()
            watch_fd = state.pop('watch_fd', None)
            if watch_fd is not None:
                os.close(watch_fd)
            watch_alias_fd = state.pop('watch_alias_fd', None)
            if watch_alias_fd is not None:
                os.close(watch_alias_fd)

    thread = threading.Thread(target=control_thread, name='broker-readiness-test-control')
    thread.start()
    arguments = [str(args.launcher), '--library', str(args.library),
        '--io-worker', str(args.worker), '--address', '198.18.0.2/24',
        '--port', 'net_tap0', '--eal', build_eal(args), '--runtime-service',
        '--broker-readiness', '--stats', str(args.stats), '--',
        str(args.broker), str(args.rpc_path)]
    if args.mode == 'no-bootstrap':
        arguments.append('--skip-bootstrap')
    if args.mode in ('generation-watch-stop-cancel', 'generation-watch-close-cancel'):
        arguments += ['--verify-barrier', str(barrier_path)]
    old_argv = sys.argv
    try:
        sys.argv = arguments
        launcher_result = ker_run.main()
    finally:
        sys.argv = old_argv
        ker_run.broker_readiness.BrokerReadiness = original_manager
        if barrier_channel is not None:
            barrier_channel.close()
        if barrier_listener is not None:
            barrier_listener.close()
        if retainer_channel is not None:
            retainer_channel.close()
    thread.join(timeout=25)
    if thread.is_alive():
        raise RuntimeError('broker readiness controller did not terminate')
    if control_errors:
        raise RuntimeError(f'broker readiness controller failed: {control_errors[0]!r}')
    if args.mode == 'parent-death':
        raise RuntimeError('parent-death supervisor unexpectedly returned')
    stats = json.loads(Path(args.stats).read_text()) if Path(args.stats).exists() else None
    result = {'event': 'RESULT', 'mode': args.mode, 'launcher_result': launcher_result,
        'control': control_result, 'stats': stats}
    if notify_fd >= 0:
        os.write(notify_fd, (json.dumps(result) + '\n').encode())
    if args.mode in ('healthy', 'healthy-sigint'):
        expected_exit = 130 if args.mode == 'healthy-sigint' else 143
        require(launcher_result == expected_exit and control_result.get('ack') and
            control_result.get('app_returncode') == 0 and
            stats and stats.get('outstanding') == 0 and
            stats.get('run_shutdown') is True and
            stats.get('run_shutdown_ack') is True,
            f'healthy READY/STOP did not complete native run-control shutdown: {result!r}')
    elif args.mode in ('bad-stop', 'rights-stop', 'truncated-stop'):
        expected_key = {'bad-stop': 'bad_stop_rejected',
            'rights-stop': 'rights_stop_rejected',
            'truncated-stop': 'truncated_stop_rejected'}[args.mode]
        require(launcher_result != 0 and control_result.get(expected_key) and
            stats and stats.get('outstanding') == 0,
            f'{args.mode} was not rejected with worker cleanup: {result!r}')
    elif args.mode == 'no-bootstrap':
        require(launcher_result != 0 and control_result.get('no_ready') and
            stats and stats.get('outstanding') == 0,
            f'no-bootstrap path did not fail before READY and clean up: {result!r}')
    elif args.mode in ('generation-watch', 'generation-watch-replay',
                       'generation-watch-rights', 'generation-watch-stop-cancel',
                       'generation-watch-close-cancel'):
        expected_result = (launcher_result == 143 and control_result.get('clean_stop') and
            control_result.get('app_returncode') == 0) if args.mode == 'generation-watch' else (
            launcher_result != 0 and control_result.get('app_returncode') != 0)
        if args.mode in ('generation-watch-stop-cancel', 'generation-watch-close-cancel'):
            expected_result = launcher_result == 0 and control_result.get('clean_stop') and \
                control_result.get('app_returncode') == 0 and (
                    control_result.get('verify_canceled') if
                    args.mode == 'generation-watch-stop-cancel' else
                    control_result.get('watch_close_canceled'))
        require(expected_result and control_result.get('live_owner_denied') and
            control_result.get('listener_alias_closed') and
            (args.mode in ('generation-watch-stop-cancel', 'generation-watch-close-cancel') or
                control_result.get('reaped_owner_retired')) and
            (args.mode in ('generation-watch-stop-cancel', 'generation-watch-close-cancel') or
                control_result.get('terminal_idempotent')) and
            (args.mode != 'generation-watch-replay' or control_result.get('replay_rejected')) and
            (args.mode != 'generation-watch-rights' or control_result.get('ancillary_rejected')) and
            (args.mode != 'generation-watch-close-cancel' or
                control_result.get('replacement_watch_unaffected')) and
            (args.mode != 'generation-watch' or
                (control_result.get('same_port_reused_old_receipt_stable') and
                    control_result.get('live_port_reservation_retained'))) and
            stats and stats.get('outstanding') == 0,
            f'generation watch did not enforce retirement evidence: {result!r}')
    return 0


def supervisor_relay_startup_failure(args, notify_fd=-1):
    """Pre-READY broker death retains resources and never publishes settlement."""
    outer, child_channel = socket.socketpair(
        socket.AF_UNIX, socket.SOCK_SEQPACKET | getattr(socket, 'SOCK_CLOEXEC', 0))
    outer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    nonce = os.urandom(16)
    while not any(nonce):
        nonce = os.urandom(16)
    epoch = int.from_bytes(os.urandom(8), 'little') or 1
    env = os.environ.copy()
    env.update(KER_RUN_CONTROL_FD=str(child_channel.fileno()),
        KER_RUN_CONTROL_NONCE=nonce.hex(), KER_RUN_CONTROL_EPOCH=str(epoch),
        PYTHONUNBUFFERED='1')
    command = [sys.executable, str(args.launcher.resolve()),
        '--library', str(args.library.resolve()), '--io-worker', str(args.worker.resolve()),
        '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', build_eal(args),
        '--runtime-service', '--broker-readiness', '--stats', str(args.stats), '--',
        str(args.broker.resolve()), str(args.rpc_path), '--skip-bootstrap']
    log_path = args.stats.with_name('generation-watch-relay-no-bootstrap.inner.log')
    evidence_path = Path('/dev/shm') / f'c36-relay-startup-failure-{os.getpid()}.log'
    result_path = Path('/dev/shm') / f'c36-relay-startup-failure-{os.getpid()}.json'
    log_file = log_path.open('wb')
    inner = None
    worker_pid = app_pid = None
    inner_pidfd = worker_pidfd = app_pidfd = -1
    result = None

    def pin_direct_child(executable, role, deadline):
        expected = executable.resolve()
        while time.monotonic() < deadline and inner.poll() is None:
            try:
                children = [int(item) for item in Path(
                    f'/proc/{inner.pid}/task/{inner.pid}/children').read_text().split()]
            except (FileNotFoundError, ProcessLookupError):
                children = []
            for candidate in children:
                try:
                    stat = Path(f'/proc/{candidate}/stat').read_text(encoding='ascii')
                    close = stat.rfind(')')
                    fields = stat[close + 2:].split() if close >= 0 else ()
                    if (len(fields) <= 1 or int(fields[1], 10) != inner.pid or
                            Path(f'/proc/{candidate}/exe').resolve() != expected):
                        continue
                    ticks = start_ticks(candidate)
                    pidfd = os.pidfd_open(candidate, 0)
                    if start_ticks(candidate) == ticks and process_alive(pidfd):
                        return candidate, ticks, pidfd
                    os.close(pidfd)
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
            time.sleep(0.005)
        raise RuntimeError(f'could not pin exact direct-child {role} before deadline')

    try:
        inner = subprocess.Popen(command, env=env, pass_fds=(child_channel.fileno(),),
            stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=True)
        inner_pidfd = os.pidfd_open(inner.pid, 0)
        child_channel.close()
        if notify_fd >= 0:
            os.write(notify_fd, (json.dumps({'event': 'STARTED', 'pid': inner.pid}) + '\n').encode())
        deadline = time.monotonic() + 15
        worker_pid, worker_start, worker_pidfd = pin_direct_child(args.worker,
            'physical DPDK worker', deadline)
        app_pid, app_start, app_pidfd = pin_direct_child(args.broker,
            'broker application', deadline)
        require(process_alive(inner_pidfd) and process_alive(worker_pidfd) and
            process_alive(app_pidfd), 'pinned process identity died before failure injection')
        readable, _, _ = select.select([outer], [], [], 0)
        require(not readable, 'relay published READY before broker readiness')
        # The fixture was launched without bootstrap. Kill only its pinned
        # process identity and inspect the real retained-resource outcome.
        signal.pidfd_send_signal(app_pidfd, signal.SIGKILL)
        app_poller = select.poll()
        app_poller.register(app_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        require(app_poller.poll(5000), 'killed broker app did not exit via its pinned pidfd')
        # A missing broker READY makes continuation unsafe. The expected result
        # is an unresolved inner that retains its worker and the parent channel.
        wait_deadline = time.monotonic() + 10
        diagnostic = ''
        while time.monotonic() < wait_deadline:
            log_file.flush()
            diagnostic = log_path.read_text(errors='replace')
            if 'companion shutdown UNRESOLVED; retaining native broker and worker resources' in diagnostic:
                break
            require(process_alive(inner_pidfd) and process_alive(worker_pidfd),
                f'inner/worker exited instead of retaining unresolved resources: {diagnostic!r}')
            time.sleep(0.01)
        require('companion shutdown UNRESOLVED; retaining native broker and worker resources' in diagnostic,
            f'pre-READY failure did not enter unresolved retention: {diagnostic!r}')
        require(process_alive(inner_pidfd) and process_alive(worker_pidfd) and inner.poll() is None,
            'unresolved relay did not keep the inner and physical worker alive')
        readable, _, _ = select.select([outer], [], [], 0)
        require(not readable,
            'pre-READY failure emitted INNER_READY, STOP_ACCEPTED, SETTLED, or EOF')
        # Exact identity data is retained as proof; cleanup below is test-owned
        # forced process cleanup and is explicitly not a normal settlement.
        result = {'event': 'RESULT', 'mode': args.mode,
            'inner_returncode_before_cleanup': None, 'worker_pid': worker_pid,
            'worker_start_ticks': worker_start, 'broker_pid': app_pid,
            'broker_start_ticks': app_start, 'ready_absent': True,
            'stop_accepted_absent': True, 'settled_absent': True,
            'worker_live_unresolved': True, 'replacement_permission': False,
            'outer_channel_had_no_record_or_eof': True,
            'cleanup_unqualified': True,
            'cleanup': 'test-owned SIGKILL via exact pidfds; not qualified settlement',
            'diagnostic_log': str(evidence_path), 'result_path': str(result_path)}
        log_file.flush()
        evidence_path.write_text(diagnostic, encoding='utf-8')
        result_path.write_text(json.dumps(result, sort_keys=True) + '\n', encoding='utf-8')
        if notify_fd >= 0:
            os.write(notify_fd, (json.dumps(result) + '\n').encode())
        return 0
    finally:
        outer.close()
        child_channel.close()
        # This is explicit test-owned cleanup of the deliberately unresolved
        # state; none of these SIGKILLs count as a normal shutdown proof.
        for pidfd in (app_pidfd, inner_pidfd, worker_pidfd):
            if pidfd >= 0:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if inner is not None:
            try:
                inner.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if inner_pidfd >= 0:
                    signal.pidfd_send_signal(inner_pidfd, signal.SIGKILL)
                inner.wait(timeout=5)
        for label, pidfd in (('broker app', app_pidfd), ('worker', worker_pidfd)):
            if pidfd >= 0:
                poller = select.poll()
                poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                if not poller.poll(5000):
                    raise RuntimeError(f'test-owned {label} pidfd cleanup did not complete')
        for pidfd in (app_pidfd, inner_pidfd, worker_pidfd):
            if pidfd >= 0:
                os.close(pidfd)
        if inner is not None and inner.returncode == -signal.SIGKILL:
            for pid in (app_pid, worker_pid):
                if pid is None:
                    continue
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
        log_file.close()


def supervisor_relay_close_cancel(args, notify_fd=-1):
    """Exercise real relay capability lifetime and retirement outcomes."""
    cancel_mode = args.mode == 'generation-watch-relay-close-cancel'
    barrier_path = args.rpc_path.with_name(args.rpc_path.stem + '.relay-verify-barrier.sock')
    barrier_listener = None
    if cancel_mode:
        barrier_listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        barrier_listener.bind(str(barrier_path))
        os.chmod(barrier_path, 0o600)
        barrier_listener.listen(1)
        barrier_listener.settimeout(10)
    barrier_channel = None
    cap_listener = None
    actor = None
    watch_fd = -1
    inner = None
    control_parent = None
    control_child = None
    log_file = None
    try:
        control_parent, control_child = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | getattr(socket, 'SOCK_CLOEXEC', 0))
        control_parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = os.urandom(16)
        while not any(nonce):
            nonce = os.urandom(16)
        epoch = int.from_bytes(os.urandom(8), 'little') or 1
        env = os.environ.copy()
        env.update(KER_RUN_CONTROL_FD=str(control_child.fileno()),
            KER_RUN_CONTROL_NONCE=nonce.hex(), KER_RUN_CONTROL_EPOCH=str(epoch))
        inner_args = [sys.executable, str(args.launcher.resolve()),
            '--library', str(args.library.resolve()), '--io-worker', str(args.worker.resolve()),
            '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal', build_eal(args),
            '--runtime-service', '--broker-readiness', '--stats', str(args.stats), '--',
            str(args.broker.resolve()), str(args.rpc_path)]
        if cancel_mode:
            inner_args += ['--verify-barrier', str(barrier_path)]
        log_path = args.stats.with_name('generation-watch-relay-close-cancel.inner.log')
        log_file = log_path.open('wb')
        inner = subprocess.Popen(inner_args, env=env, pass_fds=(control_child.fileno(),),
            stdin=subprocess.DEVNULL, stdout=log_file, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=True)
        control_child.close()
        control_child = None

        def recv_inner(expected_size, timeout=20):
            packet, credentials = receive_record(control_parent, expected_size, timeout)
            require(credentials == (inner.pid, os.getuid(), os.getgid()),
                f'relay response credentials mismatch: {credentials!r}')
            return packet

        ready_packet = recv_inner(relay_wire.READY.size)
        ready = relay_wire.unpack_ready(ready_packet)
        require(ready[0] == nonce and ready[1] == epoch,
            'INNER_READY relay context mismatch')
        broker_nonce, broker_epoch, profile = ready[2], ready[3], ready[4]
        app_identity, worker_identity = ready[7], ready[8]
        require(app_identity[0] > 0 and worker_identity[0] > 0 and
            start_ticks(app_identity[0]) == app_identity[3] and
            start_ticks(worker_identity[0]) == worker_identity[3],
            'INNER_READY did not identify the actual app and worker processes')
        if notify_fd >= 0:
            os.write(notify_fd, (json.dumps({'event': 'READY', 'pid': inner.pid,
                'app_pid': app_identity[0], 'worker_pid': worker_identity[0]}) + '\n').encode())

        actor_path = args.generation_watch_actor.resolve()
        watch_path = args.rpc_path.with_name(args.rpc_path.stem + '.relay-watch.sock')
        cap_listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        cap_listener.bind(str(watch_path))
        os.chmod(watch_path, 0o600)
        cap_listener.listen(1)
        cap_listener.settimeout(15)
        actor = subprocess.Popen([str(actor_path), str(args.rpc_path), str(watch_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True)
        channel, _ = cap_listener.accept()
        with channel:
            channel.settimeout(10)
            payload, ancillary, flags, _ = channel.recvmsg(32,
                socket.CMSG_SPACE(struct.calcsize('i')))
            watch_fds = []
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    watch_fds.extend(struct.unpack(
                        f'{len(data) // struct.calcsize("i")}i', data))
            require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and
                len(payload) == 12 and len(watch_fds) == 1,
                'actor did not transfer exactly one generation-watch alias')
            magic, actor_pid, port, reserved = struct.unpack('<IIHH', payload)
            require(magic == 0x57415443 and actor_pid == actor.pid and
                port == 4127 and reserved == 0,
                'actor generation-watch identity mismatch')
            watch_fd = watch_fds.pop()

            def relay_verify(sequence):
                passed_fd = os.dup(watch_fd)
                try:
                    sent = control_parent.sendmsg(
                        [relay_wire.pack_verify(nonce, epoch, sequence)],
                        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', passed_fd))],
                        getattr(socket, 'MSG_NOSIGNAL', 0))
                    require(sent == relay_wire.VERIFY_REQUEST.size,
                        'short outer relay VERIFY send')
                finally:
                    os.close(passed_fd)
                packet = recv_inner(relay_wire.VERIFY_REPLY_PREFIX.size + 128, 8)
                status, broker_result = relay_wire.unpack_verify_result(packet, nonce,
                    epoch, sequence, broker_nonce, broker_epoch, profile)
                return status, relay_wire._unpack_broker_result(broker_result, sequence)

            observed_identity = None
            if not cancel_mode:
                status, first_result = relay_verify(1)
                require(status == errno.EBUSY and first_result[0] == errno.EBUSY and
                    first_result[-1] == 0 and first_result[4] == actor.pid,
                    f'live generation owner was not rejected with its identity: {first_result!r}')
                observed_identity = first_result[4:10] + (first_result[10],)

            channel.sendall(b'C')
            require(channel.recv(1) == b'C',
                'actor did not close its listener and watch aliases')
            if not cancel_mode:
                status, second_result = relay_verify(2)
                require(status == errno.EBUSY and second_result[0] == errno.EBUSY and
                    second_result[-1] == 0 and
                    (second_result[4:10] + (second_result[10],)) == observed_identity,
                    'closed listener changed the live generation owner identity')
            os.kill(actor.pid, signal.SIGKILL)
            actor.wait(timeout=5)
            require(actor.returncode == -signal.SIGKILL,
                'watch owner actor was not reaped')

            # Close each transport duplicate after handoff, but retain the
            # outer's public alias until the broker confirms the query is
            # actually pending at its private progress barrier.
            if cancel_mode:
                passed_fd = os.dup(watch_fd)
                sent = control_parent.sendmsg(
                    [relay_wire.pack_verify(nonce, epoch, 1)],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', passed_fd))],
                    getattr(socket, 'MSG_NOSIGNAL', 0))
                require(sent == relay_wire.VERIFY_REQUEST.size,
                    'short outer relay VERIFY send')
                os.close(passed_fd)
                barrier_channel, _ = barrier_listener.accept()
                barrier_channel.settimeout(8)
                require(barrier_channel.recv(1) == b'P',
                    'real inner broker did not reach pending census barrier')
                os.close(watch_fd)
                watch_fd = -1
                packet = recv_inner(relay_wire.VERIFY_REPLY_PREFIX.size + 128, 8)
                status, _ = relay_wire.unpack_verify_result(packet, nonce, epoch, 1,
                    broker_nonce, broker_epoch, profile)
                require(status == errno.ECANCELED,
                    f'closing final public alias did not cancel relay VERIFY: {status}')
                barrier_channel.close()
                barrier_channel = None
                stop_sequence = 2
            else:
                status, retired_result = relay_verify(3)
                require(status == 0 and retired_result[0] == 0 and
                    retired_result[-1] == 1 and
                    (retired_result[4:10] + (retired_result[10],)) == observed_identity,
                    f'owner retirement did not preserve exact broker identity: {retired_result!r}')
                os.close(watch_fd)
                watch_fd = -1
                stop_sequence = 4

            sent = control_parent.send(relay_wire.pack_stop(nonce, epoch, stop_sequence))
            require(sent == relay_wire.STOP_REQUEST.size, 'short relay STOP send')
            accepted_packet = recv_inner(relay_wire.STOP_REPLY.size, 10)
            relay_wire.unpack_stop_reply(accepted_packet, relay_wire.STOP_ACCEPTED,
                nonce, epoch, stop_sequence)
            settled_packet = recv_inner(relay_wire.SETTLED_RECORD.size, 20)
            relay_wire.unpack_settled(settled_packet, ready, nonce, epoch, stop_sequence)

        inner.wait(timeout=10)
        log_file.flush()
        require(inner.returncode == 0,
            f'inner ker-run did not settle after relay STOP: {inner.returncode}; '
            f'{log_path.read_text(errors="replace")!r}')
        stats = json.loads(args.stats.read_text())
        require(stats.get('outstanding') == 0 and stats.get('run_shutdown') is True and
            stats.get('run_shutdown_ack') is True,
            f'inner native runtime did not report completed shutdown: {stats!r}')
        record = {'event': 'RESULT', 'mode': args.mode,
            'relay_verify_canceled': cancel_mode,
            'relay_old_retired': not cancel_mode,
            'settled': True, 'inner_returncode': inner.returncode, 'stats': stats}
        if notify_fd >= 0:
            os.write(notify_fd, (json.dumps(record) + '\n').encode())
        return 0
    finally:
        if watch_fd >= 0:
            os.close(watch_fd)
        if actor is not None and actor.poll() is None:
            actor.kill()
            actor.wait(timeout=5)
        if inner is not None and inner.poll() is None:
            inner.kill()
            inner.wait(timeout=5)
        if control_parent is not None:
            control_parent.close()
        if control_child is not None:
            control_child.close()
        if barrier_channel is not None:
            barrier_channel.close()
        if barrier_listener is not None:
            barrier_listener.close()
        if cap_listener is not None:
            cap_listener.close()
        if log_file is not None:
            log_file.close()

def enable_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER failed')


def read_line_bounded(stream, timeout, description, max_bytes=4096):
    deadline = time.monotonic() + timeout
    result = bytearray()
    while len(result) < max_bytes:
        remaining = deadline - time.monotonic()
        require(remaining > 0, f'timed out waiting for {description}')
        readable, _, _ = select.select([stream], [], [], remaining)
        require(readable, f'timed out waiting for {description}')
        chunk = os.read(stream.fileno(), 1)
        require(chunk, f'EOF waiting for {description}')
        result.extend(chunk)
        if chunk == b'\n':
            return bytes(result)
    raise RuntimeError(f'{description} exceeded {max_bytes}-byte line bound')


def spawn_supervisor(args, mode, timeout=45):
    notify_read, notify_write = os.pipe2(os.O_CLOEXEC)
    command = [sys.executable, str(Path(__file__).resolve()), '--supervisor',
        '--mode', mode, '--notify-fd', str(notify_write)]
    for name in ('launcher', 'library', 'worker', 'broker', 'dpdk-plugin-dir'):
        command += ['--' + name,
            str(getattr(args, name.replace('-', '_')).resolve())]
    command += ['--stats', str(args.root / f'{mode}.json'),
        '--rpc-path', str(args.root / f'{mode}.sock')]
    if mode in ('generation-watch', 'generation-watch-replay', 'generation-watch-rights',
                'generation-watch-stop-cancel', 'generation-watch-close-cancel',
                'generation-watch-relay-close-cancel', 'generation-watch-relay-happy'):
        command += ['--generation-watch-actor', str(args.generation_watch_actor.resolve())]
    retain = mode == 'parent-death'
    log_path = args.root / f'{mode}.supervisor.log'
    log_file = log_path.open('wb')
    process = subprocess.Popen(command, pass_fds=(notify_write,), stdout=log_file,
        stderr=subprocess.STDOUT, start_new_session=True)
    os.close(notify_write)
    try:
        with os.fdopen(notify_read, 'rb', buffering=0) as stream:
            first_record = json.loads(read_line_bounded(stream, 10,
                f'{mode} supervisor startup report'))
            if retain:
                require(first_record.get('event') == 'APP',
                    f'parent-death helper did not publish broker identity: {first_record!r}')
                require(first_record.get('retainer_held') is True,
                    'endpoint retainer did not acknowledge the held descriptor')
                ready_record = json.loads(read_line_bounded(stream, 20,
                    'parent-death broker READY'))
                require(ready_record.get('event') == 'READY',
                    f'parent-death helper did not reach authenticated READY: {ready_record!r}')
                require(ready_record.get('retainer_held') is True,
                    'parent-death READY was published before endpoint retention')
                broker_pid = ready_record['pid']
                broker_pidfd = os.pidfd_open(broker_pid, 0)
                retainer_pid = ready_record['retainer_pid']
                require(retainer_pid > 0, 'endpoint retainer did not retain supervisor endpoint')
                try:
                    os.kill(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    require(process.returncode == -signal.SIGKILL,
                        f'supervisor did not die as requested: {process.returncode}')
                    require(os.path.exists(f'/proc/{retainer_pid}'),
                        'endpoint retainer exited before broker parent-death observation')
                    poller = select.poll()
                    poller.register(broker_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
                    require(poller.poll(10_000),
                        'broker did not exit after pinned parent death while channel endpoint remained open')
                    broker_status = None
                    wait_deadline = time.monotonic() + 3
                    while time.monotonic() < wait_deadline:
                        try:
                            waited_pid, status = os.waitpid(broker_pid, os.WNOHANG)
                        except ChildProcessError:
                            break
                        if waited_pid == broker_pid:
                            broker_status = status
                            break
                        time.sleep(0.01)
                    broker_log_path = args.root / 'parent-death.supervisor.log'
                    diagnostic = broker_log_path.read_text(errors='replace')
                    require('BROKER_PARENT_CHECK_ERROR=3' in diagnostic,
                        f'broker did not record ESRCH from pinned parent check: {diagnostic!r}')
                    require(broker_status is not None and
                            ((os.WIFEXITED(broker_status) and os.WEXITSTATUS(broker_status) != 0) or
                             os.WIFSIGNALED(broker_status)),
                        f'broker did not fail after parent-death ESRCH: {broker_status!r}')
                finally:
                    os.close(broker_pidfd)
                return
            output_tail = []
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                readable, _, _ = select.select([stream], [], [],
                    max(0, deadline - time.monotonic()))
                if not readable:
                    break
                line = stream.readline()
                if not line:
                    break
                record = json.loads(line)
                output_tail.append(record)
                if record.get('event') == 'RESULT':
                    break
            else:
                raise RuntimeError(f'{mode} helper timed out; records={output_tail!r}')
        process.wait(timeout=10)
        log_file.flush()
        diagnostics = log_path.read_text(errors='replace')
        require(process.returncode == 0,
            f'{mode} helper failed: records={output_tail!r}; diagnostics={diagnostics!r}')
        if mode == 'generation-watch-relay-no-bootstrap':
            result = next((record for record in output_tail
                if record.get('event') == 'RESULT'), None)
            require(result is not None and result.get('ready_absent') and
                result.get('stop_accepted_absent') and result.get('settled_absent') and
                result.get('worker_live_unresolved') and
                result.get('replacement_permission') is False and
                'test-owned SIGKILL' in result.get('cleanup', ''),
                f'pre-READY broker failure was misreported as settled/reusable: {result!r}')
    finally:
        try:
            os.close(notify_read)
        except OSError:
            pass
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.returncode != 0:
            log_file.flush()
            print(log_path.read_text(errors='replace'), file=sys.stderr)
        log_file.close()

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('launcher', 'library', 'worker', 'broker', 'dpdk-plugin-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--generation-watch-actor', type=Path)
    parser.add_argument('--stats', type=Path,
        default=Path('/dev/shm/ker-broker-readiness-stats.json'))
    parser.add_argument('--rpc-path', type=Path,
        default=Path('/dev/shm/ker-broker-readiness-rpc.sock'))
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--supervisor', action='store_true')
    parser.add_argument('--mode', choices=('healthy', 'healthy-sigint', 'bad-stop', 'rights-stop',
        'truncated-stop',
        'no-bootstrap', 'parent-death', 'generation-watch', 'generation-watch-replay',
        'generation-watch-rights', 'generation-watch-stop-cancel',
        'generation-watch-close-cancel', 'generation-watch-relay-close-cancel',
        'generation-watch-relay-happy', 'generation-watch-relay-no-bootstrap'), default='healthy')
    parser.add_argument('--notify-fd', type=int, default=-1)
    args = parser.parse_args()
    if args.supervisor:
        return supervisor(args, args.notify_fd,
            retain_endpoint=args.mode == 'parent-death')
    if not args.inside:
        command = ['unshare', '-Urn', sys.executable, str(Path(__file__).resolve()), '--inside',
            '--launcher', str(args.launcher.resolve()), '--library', str(args.library.resolve()),
            '--worker', str(args.worker.resolve()), '--broker', str(args.broker.resolve()),
            '--dpdk-plugin-dir', str(args.dpdk_plugin_dir.resolve()),
            '--stats', str(args.stats.resolve()), '--rpc-path', str(args.rpc_path.resolve())]
        if args.generation_watch_actor:
            command += ['--generation-watch-actor', str(args.generation_watch_actor.resolve())]
        subprocess.run(command, check=True)
        return 0
    set_up_network()
    enable_subreaper()
    with tempfile.TemporaryDirectory(prefix='ker-broker-readiness-') as directory:
        args.root = Path(directory)
        modes = ('healthy', 'healthy-sigint', 'bad-stop', 'rights-stop', 'truncated-stop',
            'parent-death', 'no-bootstrap', 'generation-watch-relay-no-bootstrap')
        if args.generation_watch_actor:
            modes += ('generation-watch', 'generation-watch-replay',
                'generation-watch-rights', 'generation-watch-stop-cancel',
                'generation-watch-close-cancel', 'generation-watch-relay-close-cancel',
                'generation-watch-relay-happy')
        for mode in modes:
            spawn_supervisor(args, mode)
    print('BROKER_READINESS_TAP_OK authenticated_READY_STOP no-bootstrap malformed_STOP parent_pidfd_death')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'broker readiness TAP failed: {error}', file=sys.stderr)
        raise
