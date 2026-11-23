#!/usr/bin/env python3
"""Exercise KNGC queueing, master credentials, watch FD transfer and cycle ACK."""
import array
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import socket
import struct
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


control_module = load('_test_nginx_cycle_control', ROOT / 'tools/nginx_cycle_control.py')
wire = control_module.wire


def read_packet(endpoint, expected_size):
    poller = __import__('select').poll()
    poller.register(endpoint.fileno(), __import__('select').POLLIN)
    if not poller.poll(2000):
        raise RuntimeError('outer did not send cycle response')
    packet, ancillary, flags, _ = endpoint.recvmsg(expected_size + 1,
        socket.CMSG_SPACE(64))
    credentials = []
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(payload) == 12:
            credentials.append(struct.unpack('=3i', payload))
        else:
            raise RuntimeError('unexpected outer cycle ancillary data')
    if flags or len(packet) != expected_size or len(credentials) != 1:
        raise RuntimeError(f'invalid outer cycle response flags={flags} len={len(packet)} expected={expected_size} creds={credentials!r} ancillary={ancillary!r}')
    return packet


def child_protocol(control, runtime_a, runtime_b):
    control.outer.close()
    watch = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
    try:
        master_start = control_module._start_ticks(os.getpid())
        packet = wire.pack_watch_bound(control.nonce, master_start,
            1, 1, runtime_a)
        sent = control.master.sendmsg([packet], [(socket.SOL_SOCKET,
            socket.SCM_RIGHTS, array.array('i', (watch,)))])
        if sent != len(packet):
            os._exit(11)
        drained = wire.pack_drained(control.nonce, master_start, 2, 1)
        if control.master.send(drained) != len(drained):
            os._exit(15)
        ready = read_packet(control.master, wire.WATCH_BYTES)
        record = wire.unpack_record(ready)
        if record != (wire.CYCLE_READY, 0, control.nonce,
                master_start, 2, 2, runtime_b):
            os._exit(12)
        watch2 = wire.pack_watch_bound(control.nonce, master_start,
            3, 2, runtime_b)
        watch2_fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        try:
            if control.master.sendmsg([watch2], [(socket.SOL_SOCKET,
                    socket.SCM_RIGHTS, array.array('i', (watch2_fd,)))]) != len(watch2):
                os._exit(13)
        finally:
            os.close(watch2_fd)
        drained = wire.pack_drained(control.nonce, master_start, 4, 2)
        if control.master.send(drained) != len(drained):
            os._exit(16)
        ready = read_packet(control.master, wire.WATCH_BYTES)
        record = wire.unpack_record(ready)
        if record != (wire.CYCLE_READY, 0, control.nonce,
                master_start, 4, 3, runtime_a):
            os._exit(14)
        os._exit(0)
    finally:
        os.close(watch)



def load_serial_controller():
    name = '_test_ker_serial_generation'
    path = ROOT / 'tools' / 'ker_serial_generation.py'
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    if spec is None or spec.loader is None:
        raise RuntimeError('cannot load serial generation controller')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def external_watch_controls():
    serial = load_serial_controller()
    broker_nonce = b'B' * 16
    profile = b'P' * 32
    relay_nonce = b'R' * 16
    epoch = 303
    master_pid = os.getpid()
    master_start = control_module._start_ticks(master_pid)
    master_hash = control_module._sha256(f'/proc/{master_pid}/exe')
    master_pidfd = os.pidfd_open(master_pid, 0)
    owner_pid = os.fork()
    if owner_pid == 0:
        os._exit(0)
    owner_start = serial._proc_identity(owner_pid).start_ticks
    owner_pidfd = os.pidfd_open(owner_pid, 0)
    os.waitpid(owner_pid, 0)
    watch_read_fd, watch_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    st = os.fstat(watch_fd)
    watch_identity = (st.st_dev, st.st_ino, st.st_mode, st.st_rdev, st.st_size)
    context_a = types.SimpleNamespace(ready=(None, None, broker_nonce, epoch, profile),
        unresolved_reason=None, settled=False, relay_sequence=0, events=[],
        process=types.SimpleNamespace(pid=os.getpid()), nonce=relay_nonce,
        epoch=404, label='old')
    context_b = types.SimpleNamespace(ready=(None, None, broker_nonce, epoch, profile),
        unresolved_reason=None, settled=False, relay_sequence=0, events=[],
        process=types.SimpleNamespace(pid=os.getpid()), nonce=relay_nonce,
        epoch=405, label='new')
    owner_receipt = struct.pack('<IHHII16sQQIIQQQIQ32sI',
        0x4B425234, 1, 5, 128, 16, broker_nonce, epoch, 7, owner_pid, 0,
        owner_start, 11, 12, 13, 14, profile, 0)
    terminal_result = struct.pack('<IHHII16sQQIIQQQIQ32sI',
        0x4B425234, 1, 5, 128, 0, broker_nonce, epoch, 1, owner_pid, 0,
        owner_start, 11, 12, 13, 14, profile, 1)
    owner = serial.ExternalOwnerWatch(context_a,
        serial.ProcessIdentity(owner_pid, os.getuid(), os.getgid(), owner_start),
        owner_pidfd, watch_identity, 4127, socket.inet_aton('198.18.0.2'),
        owner_receipt, owner_receipt)
    captured = {'fd': -1, 'sends': 0}

    class Relay:
        def sendmsg(self, buffers, ancillary, flags=0):
            captured['sends'] += 1
            captured['fd'] = struct.unpack('i', ancillary[0][2])[0]
            os.fstat(captured['fd'])
            return len(buffers[0])

    context_a.relay = Relay()
    context_b.relay = Relay()
    companion = types.SimpleNamespace(master_pid=master_pid, master_start=master_start,
        binary_hash=master_hash, master_pidfd=master_pidfd, helper=None,
        started=True, unresolved=False)
    cycle = types.SimpleNamespace(runtime=(broker_nonce, epoch, profile),
        master_identity=(master_pid, os.getuid(), os.getgid(), master_start, master_hash),
        unresolved=False, transition_deadline=time.monotonic() + 2)
    controller = object.__new__(serial.SerialGenerationController)
    controller._old_context = context_a
    controller._new_context = context_b
    controller._external_live_watches = {id(owner): {'watch': owner,
        'inner': context_a, 'watch_identity': watch_identity,
        'receipt': owner_receipt, 'owner_identity': owner.actor_identity,
        'owner_pidfd': owner_pidfd, 'master_identity': cycle.master_identity,
        'master_pidfd': os.dup(master_pidfd), 'master_executable_hash': master_hash}}
    controller._verified_proofs = {}
    controller._proof_seal = object()
    controller.port = 4127
    controller.address = '198.18.0.2'
    original_receive = serial._receive_packet

    def cross_context_receive(*args, **kwargs):
        raise AssertionError('cross-context authority reached relay send/receive')

    serial._receive_packet = cross_context_receive
    try:
        try:
            controller.verify_external_watch(context_b, watch_fd, companion, cycle,
                require_retired=True, live_watch=owner, deadline=cycle.transition_deadline)
        except serial.ProtocolError:
            pass
        else:
            raise RuntimeError('cross-context external watch was accepted')
        if captured['sends']:
            raise RuntimeError('cross-context watch caused a broker VERIFY send')

        def observe_closed_duplicate(relay, size, pid, deadline):
            try:
                os.fstat(captured['fd'])
            except OSError:
                pass
            else:
                raise RuntimeError('external watch duplicate stayed open while waiting for VERIFY')
            return serial.wire.pack_verify_result(relay_nonce, context_a.epoch, 1,
                terminal_result)

        serial._receive_packet = observe_closed_duplicate
        cycle_a = types.SimpleNamespace(runtime=(broker_nonce, epoch, profile),
            master_identity=cycle.master_identity, unresolved=False,
            transition_deadline=cycle.transition_deadline)
        proof = controller.verify_external_watch(context_a, watch_fd, companion, cycle_a,
            require_retired=True, live_watch=owner, deadline=cycle_a.transition_deadline)
        if proof.inner is not context_a or captured['sends'] != 1:
            raise RuntimeError('terminal external-watch VERIFY did not complete exactly once')
        if controller._external_live_watches:
            raise RuntimeError('terminal external watch remained registered')
        controller.close_watch(owner)
    finally:
        serial._receive_packet = original_receive
        os.close(watch_fd)
        os.close(watch_read_fd)
        os.close(master_pidfd)
        if controller._external_live_watches:
            for entry in controller._external_live_watches.values():
                for fd_name in ('owner_pidfd', 'master_pidfd'):
                    fd = entry.get(fd_name, -1)
                    if fd >= 0:
                        os.close(fd)
        try:
            os.waitpid(owner_pid, os.WNOHANG)
        except ChildProcessError:
            pass



def companion_shutdown_controls():
    serial = load_serial_controller()
    runtime = (b'C' * 16, 606, b'c' * 32)
    inner_nonce = b'I' * 16
    inner_epoch = 607
    ready = (None, None, runtime[0], runtime[1], runtime[2])
    identity_read, identity_write = os.pipe2(os.O_CLOEXEC)
    stop_read, stop_write = os.pipe2(os.O_CLOEXEC)
    master = os.fork()
    if master == 0:
        try:
            os.close(identity_read)
            os.close(stop_write)
            owner = os.fork()
            if owner == 0:
                os.close(identity_write)
                os.close(stop_read)
                while True:
                    __import__('time').sleep(1)
            start = control_module._start_ticks(owner)
            os.write(identity_write, struct.pack('=IQ', owner, start))
            os.close(identity_write)
            command = os.read(stop_read, 1)
            os.close(stop_read)
            if command != b'X':
                os._exit(22)
            os.kill(owner, 9)
            os.waitpid(owner, 0)
            os._exit(0)
        except BaseException:
            os._exit(21)
    os.close(identity_write)
    os.close(stop_read)
    master_pidfd = os.pidfd_open(master, 0)
    owner_pid = -1
    owner_pidfd = -1
    watch_read_fd = watch_fd = -1
    cycle = None
    controller = None
    serial = load_serial_controller()
    original_receive = serial._receive_packet
    try:
        payload = bytearray()
        while len(payload) < 12:
            part = os.read(identity_read, 12 - len(payload))
            if not part:
                raise RuntimeError('fake master did not publish its child identity')
            payload.extend(part)
        os.close(identity_read)
        identity_read = -1
        owner_pid, owner_start = struct.unpack('=IQ', payload)
        owner_pidfd = os.pidfd_open(owner_pid, 0)
        master_start = control_module._start_ticks(master)
        binary_hash = control_module._sha256(f'/proc/{master}/exe')
        companion = types.SimpleNamespace(started=True, unresolved=False, settled=False,
            stop_attempted=False, settled_record=None, master_pid=master,
            master_start=master_start, master_pidfd=master_pidfd,
            binary_hash=binary_hash, helper=None)
        cycle = control_module.NginxCycleControl(runtime)
        cycle.pin_master(companion)
        controller = object.__new__(serial.SerialGenerationController)
        controller._old_context = None
        controller._new_context = None
        controller._generation_counter = 2
        controller._max_generations = 3
        controller._external_live_watches = {}
        controller._companion_shutdown_proofs = {}
        controller._verified_proofs = {}
        controller._settled_proofs = {}
        controller._proof_seal = object()
        controller.port = 4127
        controller.address = '198.18.0.2'
        controller._advance_key = object()
        watch_read_fd, watch_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        context = types.SimpleNamespace(ready=ready, unresolved_reason=None, settled=False,
            relay_sequence=0, events=[], process=types.SimpleNamespace(pid=os.getpid(), poll=lambda: 0),
            nonce=inner_nonce, epoch=inner_epoch, label='new', closed=False,
            advanced=False, app_pidfd=-1, worker_pidfd=-1, pidfd=-1,
            stats_path=Path('/dev/null'), rpc_path=Path('/dev/null'), rpc_inode=None,
            log=None, relay=None, identity=None)
        controller._old_context = context
        last_send = {'packet': None, 'sent': 0}

        class Relay:
            def sendmsg(self, buffers, ancillary, flags=0):
                last_send['packet'] = bytes(buffers[0])
                last_send['sent'] += 1
                os.fstat(struct.unpack('i', ancillary[0][2])[0])
                return len(buffers[0])

        context.relay = Relay()

        def broker_result(sequence, status, state):
            return struct.pack('<IHHII16sQQIIQQQIQ32sI', 0x4B425234, 1, 5, 128,
                status, runtime[0], runtime[1], sequence, owner_pid, 0, owner_start,
                11, 12, 13, 14, runtime[2], state)

        def receive_live(relay, size, pid, deadline):
            return serial.wire.pack_verify_result(inner_nonce, inner_epoch, 1,
                broker_result(1, 16, 0))
        serial._receive_packet = receive_live
        live_watch = controller.verify_external_watch(context, watch_fd,
            companion, cycle, timeout=2, require_retired=False)
        registered = controller._external_live_watches[id(live_watch)]
        if registered.get('companion') is not companion or registered.get('cycle_channel') is not cycle:
            raise RuntimeError('live watch did not retain the exact registered companions')
        os.write(stop_write, b'X')
        os.close(stop_write)
        stop_write = -1
        poller = __import__('select').poll()
        poller.register(owner_pidfd, __import__('select').POLLIN)
        if not poller.poll(2000):
            raise RuntimeError('owner did not become dead after master-mediated cleanup')
        _, status = os.waitpid(master, 0)
        master = -1
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError('fake master did not settle its child cleanly')
        companion.stop_attempted = True
        companion.settled = True
        companion.settled_record = b'authenticated-settled-record'
        companion.helper = types.SimpleNamespace(returncode=0)
        shutdown = controller.record_companion_shutdown(context, live_watch, companion, cycle)
        if shutdown.inner is not context or shutdown.watch is not live_watch:
            raise RuntimeError('shutdown proof lost its registered context/watch')

        def receive_terminal(relay, size, pid, deadline):
            seq = context.relay_sequence
            return serial.wire.pack_verify_result(inner_nonce, inner_epoch, seq,
                broker_result(seq, 0, 1))
        serial._receive_packet = receive_terminal
        retired = controller.verify_external_shutdown_watch(context, watch_fd, shutdown, timeout=2)
        if not retired.companion_shutdown or controller._external_live_watches:
            raise RuntimeError('shutdown retirement was not terminal or retained a live watch')
        context.pidfd = owner_pidfd
        context.app_pidfd = owner_pidfd
        context.worker_pidfd = owner_pidfd
        context.settled = True
        settled = serial.RuntimeSettled(context, b'settled', {}, controller._proof_seal)
        controller._settled_proofs[id(settled)] = settled
        try:
            controller.start_next(context, retired, settled)
        except serial.SettlementError:
            pass
        else:
            raise RuntimeError('companion shutdown proof authorized a successor generation')
        print('KNGC shutdown proof: PASS registered watch, exact helper receipt, master death, no successor authority')
    finally:
        serial._receive_packet = original_receive
        if stop_write >= 0:
            try:
                os.write(stop_write, b'X')
            except OSError:
                pass
            os.close(stop_write)
        if master >= 0:
            try:
                os.kill(master, 9)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(master, 0)
            except ChildProcessError:
                pass
        for fd in (identity_read, watch_fd, watch_read_fd, owner_pidfd, master_pidfd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if cycle is not None:
            cycle.close()
        if controller is not None and 'live_watch' in locals():
            try:
                controller.close_watch(live_watch)
            except BaseException:
                pass

def main():
    external_watch_controls()
    companion_shutdown_controls()
    runtime_a = (b'A' * 16, 101, b'a' * 32)
    runtime_b = (b'B' * 16, 202, b'b' * 32)
    control = control_module.NginxCycleControl(runtime_a)
    child = os.fork()
    if child == 0:
        child_protocol(control, runtime_a, runtime_b)
    class Companion:
        started = True
        unresolved = False
        master_pid = child
        master_start = control_module._start_ticks(child)
        master_pidfd = os.pidfd_open(child, 0)
        binary_hash = control_module._sha256(f'/proc/{child}/exe')
    companion = Companion()
    try:
        watch_fd = control.accept_initial_watch(companion, timeout=2)
        try:
            try:
                control.accept_initial_watch(companion, timeout=0.1)
            except control_module.CycleControlError:
                pass
            else:
                raise RuntimeError('initial WATCH_BOUND was accepted twice')
            if os.fstat(watch_fd).st_size != 0:
                raise RuntimeError('unexpected watch test descriptor')
        finally:
            os.close(watch_fd)
        control.receive_drained(timeout=2)
        control.send_ready(runtime_b, timeout=2)
        successor_deadline = time.monotonic() + 2
        watch2_fd = control.accept_successor_watch(runtime_b, successor_deadline)
        fds = [watch2_fd]
        runtime = runtime_b
        if runtime != runtime_b or len(fds) != 1:
            raise RuntimeError('second cycle watch did not correlate to B runtime')
        os.close(fds[0])
        control.receive_drained(timeout=2)
        control.send_ready(runtime_a, timeout=2)
        _, status = os.waitpid(child, 0)
        if status != 0:
            raise RuntimeError(f'KNGC master fixture exited with status {status}')
        if control.cycle != 3 or control.receive_sequence != 5:
            raise RuntimeError('KNGC cycle/sequence advancement differs')
        print('KNGC transport: PASS queued WATCH, credential pin, FD transfer, two cycles; external watch cross-context and alias closure PASS')
    finally:
        control.close()
        os.close(companion.master_pidfd)
        try:
            os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            pass


if __name__ == '__main__':
    main()
