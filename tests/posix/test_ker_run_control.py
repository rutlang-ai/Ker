#!/usr/bin/env python3
"""Focused process-authenticated tests for the private ker-run relay."""
import array
import ctypes
import fcntl
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import time
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'ker_run_control_test_module', ROOT / 'tools' / 'ker_run_control.py')
relay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(relay)
wire = relay.wire
BROKER_WIRE_SPEC = importlib.util.spec_from_file_location(
    'broker_readiness_wire_test_module', ROOT / 'tools' / 'broker_readiness_wire.py')
broker_wire = importlib.util.module_from_spec(BROKER_WIRE_SPEC)
BROKER_WIRE_SPEC.loader.exec_module(broker_wire)


class _Readiness:
    def __init__(self, nonce, epoch, profile):
        self.nonce = nonce
        self.epoch = epoch
        self.profile = profile
        self.ready = True
        self.stopped = False
        self.seen = []

    def begin_verify(self, fd, sequence, timeout):
        self.seen.append((sequence, timeout, fd))
        os.close(fd)

    def poll_verify(self):
        return broker_wire.pack_verify_result(self.nonce, self.epoch,
            self.seen[-1][0], 0, 81, 99, 101, 103, 105, 107,
            self.profile, 1)

    def begin_stop(self, timeout):
        self.stop_timeout = timeout

    def poll_stop(self):
        self.stopped = True
        return True


def _send_record(sock, record, fd=None):
    if fd is None:
        sock.sendall(record)
    else:
        rights = array.array('i', (fd,))
        sent = sock.sendmsg([record], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        if sent != len(record):
            raise AssertionError('short relay test record send')


class KerRunControlTests(unittest.TestCase):
    def test_startup_poll_is_nonblocking_and_rejects_early_request(self):
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inner.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = bytes.fromhex('3344556677889900aabbccddeeff1122')
        child = os.fork()
        if child == 0:
            outer.close()
            worker_pidfd = -1
            try:
                instance = relay.KerRunControl(inner.detach(), nonce, 41)
                instance.readiness = _Readiness(b'D' * 16, 43, b'P' * 32)
                instance.readiness.ready = False
                instance.worker = SimpleNamespace(pid=os.getpid())
                worker_pidfd = os.pidfd_open(os.getpid(), 0)
                instance.worker_pidfd = worker_pidfd
                instance.worker_path = Path(__file__).resolve()
                instance.app_executable_hash = b'A' * 32
                instance.worker_executable_hash = b'W' * 32
                instance.poll(lambda: None)
                if instance.state != 'STARTING':
                    os._exit(51)
                poller = select.poll()
                poller.register(instance.channel.fileno(), select.POLLIN)
                if not poller.poll(2000):
                    os._exit(52)
                try:
                    instance.poll(lambda: None)
                except PermissionError:
                    instance.channel.close()
                    os.close(instance.parent_pidfd)
                    os.close(worker_pidfd)
                    os._exit(0)
                os._exit(53)
            except BaseException:
                os._exit(54)
        inner.close()
        poller = select.poll()
        poller.register(outer.fileno(), select.POLLIN)
        self.assertFalse(poller.poll(100), 'INNER_READY was sent without C34 READY')
        read_fd, write_fd = os.pipe()
        try:
            _send_record(outer, wire.pack_verify(nonce, 41, 1), read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        outer.close()

    def test_stop_before_inner_ready_is_rejected(self):
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inner.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = bytes.fromhex('102132435465768798a9bacbdcedfe0f')
        epoch = 53
        child = os.fork()
        if child == 0:
            outer.close()
            try:
                instance = relay.KerRunControl(inner.detach(), nonce, epoch)
                instance.readiness = _Readiness(b'R' * 16, 67, b'P' * 32)
                instance.readiness.ready = False
                instance.worker = SimpleNamespace(pid=os.getpid())
                instance.worker_pidfd = os.pidfd_open(os.getpid(), 0)
                instance.worker_path = Path(__file__).resolve()
                instance.app_executable_hash = b'A' * 32
                instance.worker_executable_hash = b'W' * 32
                try:
                    instance.poll(lambda: None)
                    if instance.state != 'STARTING':
                        os._exit(61)
                    instance.poll(lambda: None)
                except PermissionError:
                    if instance.stop is not None or instance.state != 'STARTING':
                        os._exit(62)
                    instance.channel.close()
                    os.close(instance.parent_pidfd)
                    os._exit(0)
                os._exit(63)
            except BaseException:
                os._exit(64)
        inner.close()
        _send_record(outer, wire.pack_stop(nonce, epoch, 1))
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        outer.close()

    def test_post_ack_settlement_deadline_retains_without_settled(self):
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inner.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = bytes.fromhex('d00df00d1234567890abcdef11223344')
        epoch = 73
        child = os.fork()
        if child == 0:
            outer.close()
            try:
                transferred_fd = inner.detach()
                instance = relay.KerRunControl(transferred_fd, nonce, epoch)
                if instance.channel.fileno() == transferred_fd:
                    os._exit(81)
                original_stat = None
                try:
                    original_stat = os.fstat(transferred_fd)
                except OSError:
                    pass  # The consumed number may be closed or reused as pidfd.
                channel_stat = os.fstat(instance.channel.fileno())
                if (original_stat is not None and
                        (original_stat.st_dev, original_stat.st_ino) ==
                        (channel_stat.st_dev, channel_stat.st_ino)):
                    os._exit(82)
                descriptor_flags = fcntl.fcntl(instance.channel.fileno(), fcntl.F_GETFD)
                if not descriptor_flags & fcntl.FD_CLOEXEC:
                    os._exit(83)
                instance.state = 'READY'
                instance.readiness = _Readiness(b'R' * 16, 79, b'P' * 32)
                deadline = time.monotonic() + 3
                while instance.state != 'STOP_ACCEPTED' and time.monotonic() < deadline:
                    instance.poll(lambda: None)
                    time.sleep(0.001)
                if instance.state != 'STOP_ACCEPTED':
                    os._exit(84)
                instance.stop['deadline'] = time.monotonic() - 1
                instance.settle_deadline = instance.stop['deadline']
                try:
                    instance.poll(lambda: None)
                except TimeoutError:
                    if (instance.state != 'UNRESOLVED' or instance.outbound is not None or
                            'absolute deadline' not in instance.failure):
                        os._exit(85)
                    instance.channel.close()
                    os.close(instance.parent_pidfd)
                    os._exit(0)
                os._exit(86)
            except BaseException:
                os._exit(87)
        inner.close()
        _send_record(outer, wire.pack_stop(nonce, epoch, 1))
        accepted = outer.recv(wire.STOP_REPLY.size)
        self.assertEqual(wire.unpack_stop_reply(accepted, wire.STOP_ACCEPTED,
            nonce, epoch, 1), (wire.STOP_ACCEPTED, nonce, epoch, 1))
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(outer.recv(wire.SETTLED_RECORD.size + 1), b'',
            'relay emitted SETTLED after its post-ACK absolute deadline expired')
        outer.close()

    def test_parent_death_is_detected_with_peer_endpoint_retained(self):
        # The relay's direct parent creates the socketpair. A sibling process
        # keeps the peer endpoint open after that parent exits, so detection
        # must come from the pinned parent pidfd rather than EOF/HUP.
        libc = ctypes.CDLL(None, use_errno=True)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        report_r, report_w = os.pipe2(os.O_CLOEXEC)
        ids_r, ids_w = os.pipe2(os.O_CLOEXEC)
        attach_r, attach_w = os.pipe2(os.O_CLOEXEC)
        release_r, release_w = os.pipe2(os.O_CLOEXEC)
        nonce = bytes.fromhex('abcdef0123456789abcdef0123456789')
        middle = os.fork()
        if middle == 0:
            for fd in (report_r, ids_r, release_w):
                os.close(fd)
            try:
                parent_end, child_end = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET)
                child_end.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                retainer = os.fork()
                if retainer == 0:
                    child_end.close()
                    for fd in (ids_w, attach_r, attach_w):
                        os.close(fd)
                    os.write(report_w, b'R')
                    while os.read(release_r, 1) != b'X':
                        pass
                    parent_end.close()
                    os._exit(0)
                relay_pid = os.fork()
                if relay_pid == 0:
                    parent_end.close()
                    for fd in (ids_w, attach_r, release_r):
                        os.close(fd)
                    try:
                        instance = relay.KerRunControl(child_end.detach(), nonce, 59)
                        instance.state = 'FAILED'
                        os.write(attach_w, b'A')
                        os.close(attach_w)
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            try:
                                instance.poll(lambda: None)
                            except ProcessLookupError:
                                os.write(report_w, b'D')
                                instance.channel.close()
                                os.close(instance.parent_pidfd)
                                os._exit(0)
                            time.sleep(0.005)
                        os._exit(65)
                    except BaseException as error:
                        os.write(report_w, b'E' + repr(error).encode())
                        os._exit(68)
                child_end.close()
                ready_to_attach, _, _ = select.select([attach_r], [], [], 3)
                attached = os.read(attach_r, 1) if ready_to_attach else b''
                if attached != b'A':
                    _, relay_status = os.waitpid(relay_pid, 0)
                    os.write(report_w, b'F' + str(os.waitstatus_to_exitcode(relay_status)).encode())
                    os._exit(66)
                parent_end.close()
                os.write(ids_w, struct.pack('ii', relay_pid, retainer))
                os._exit(0)
            except BaseException as error:
                os.write(report_w, b'M' + repr(error).encode())
                os._exit(67)

        for fd in (report_w, ids_w, attach_r, attach_w, release_r):
            os.close(fd)
        pid_bytes = b''
        while len(pid_bytes) < 8:
            chunk = os.read(ids_r, 8 - len(pid_bytes))
            if not chunk:
                diagnostic = b''
                report_poller = select.poll()
                report_poller.register(report_r, select.POLLIN)
                if report_poller.poll(100):
                    diagnostic = os.read(report_r, 4096)
                self.fail('intermediate parent failed before publishing child IDs: ' +
                    repr(diagnostic))
            pid_bytes += chunk
        relay_pid, retainer_pid = struct.unpack('ii', pid_bytes)
        _, middle_status = os.waitpid(middle, 0)
        self.assertEqual(os.waitstatus_to_exitcode(middle_status), 0)
        retainer_pidfd = os.pidfd_open(retainer_pid, 0)
        try:
            observed = b''
            deadline = time.monotonic() + 5
            poller = select.poll()
            poller.register(report_r, select.POLLIN | select.POLLHUP)
            while b'D' not in observed and time.monotonic() < deadline:
                events = poller.poll(100)
                if events:
                    observed += os.read(report_r, 8)
            self.assertIn(b'R', observed, 'peer endpoint retainer did not report its live alias')
            self.assertIn(b'D', observed,
                'relay did not detect its direct-parent pidfd death while peer endpoint stayed open')
            alive = select.poll()
            alive.register(retainer_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            self.assertFalse(alive.poll(0), 'peer endpoint retainer died before parent-pidfd detection')
        finally:
            os.close(retainer_pidfd)
            os.write(release_w, b'X')
            os.close(release_w)
            os.close(ids_r)
            os.close(report_r)
        _, relay_status = os.waitpid(relay_pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(relay_status), 0)
        _, retainer_status = os.waitpid(retainer_pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(retainer_status), 0)

    def test_output_backpressure_expires_without_late_response(self):
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inner.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = bytes.fromhex('31415926535897932384626433832795')
        child = os.fork()
        if child == 0:
            outer.close()
            try:
                instance = relay.KerRunControl(inner.detach(), nonce, 61)
                instance.state = 'READY'
                filler = b'F' * 1024
                sent_records = 0
                while sent_records < 10000:
                    try:
                        instance.channel.send(filler)
                        sent_records += 1
                    except BlockingIOError:
                        break
                if not sent_records or sent_records == 10000:
                    os._exit(71)
                queued = wire.pack_stop_reply(wire.STOP_ACCEPTED, nonce, 61, 1)
                instance.outbound = queued
                instance.outbound_action = 'stop_accepted'
                instance.outbound_deadline = time.monotonic() + 0.05
                if instance._flush_outbound():
                    os._exit(72)
                time.sleep(0.06)
                try:
                    instance._flush_outbound()
                except TimeoutError:
                    if instance.state != 'UNRESOLVED' or instance.outbound != queued:
                        os._exit(73)
                    instance.channel.close()
                    os.close(instance.parent_pidfd)
                    os._exit(0)
                os._exit(74)
            except BaseException:
                os._exit(75)
        inner.close()
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        inner_drain = outer.dup()
        inner_drain.setblocking(False)
        seen = []
        while True:
            try:
                record = inner_drain.recv(2048)
                if not record:
                    break
                seen.append(record)
            except BlockingIOError:
                break
            except OSError:
                break
        self.assertTrue(seen)
        self.assertTrue(all(record == b'F' * 1024 for record in seen),
            'a response was sent after its absolute deadline under backpressure')
        inner_drain.close()
        outer.close()

    def test_authenticated_verify_fd_forward_and_terminal_stop(self):
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inner.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = bytes.fromhex('00112233445566778899aabbccddeeff')
        epoch = 17
        broker_nonce = bytes.fromhex('ffeeddccbbaa99887766554433221100')
        profile = b'P' * 32
        child = os.fork()
        if child == 0:
            outer.close()
            try:
                instance = relay.KerRunControl(inner.detach(), nonce, epoch)
                instance.state = 'READY'
                instance.ready_record = (nonce, epoch, broker_nonce, 19,
                    profile, b'A' * 32, b'W' * 32, (os.getpid(), os.getuid(), os.getgid(), 23),
                    (os.getpid(), os.getuid(), os.getgid(), 29))
                instance.readiness = _Readiness(broker_nonce, 19, profile)
                read_fd, write_fd = os.pipe()
                os.close(write_fd)
                for _ in range(1000):
                    instance.poll(lambda: None)
                    if instance.verify is None and instance.last_sequence == 1:
                        break
                    time.sleep(0.001)
                else:
                    os._exit(21)
                # STOP is terminal and follows exactly one mapped VERIFY.
                for _ in range(1000):
                    instance.poll(lambda: None)
                    if instance.state == 'STOP_ACCEPTED':
                        break
                    time.sleep(0.001)
                else:
                    os._exit(22)
                instance._mark_unresolved('test cleanup')
                instance.channel.close()
                os.close(instance.parent_pidfd)
                os.close(read_fd)
                os._exit(0)
            except BaseException:
                os._exit(23)
        inner.close()
        read_fd, write_fd = os.pipe()
        profile = b'P' * 32
        broker_result = broker_wire.pack_verify_result(broker_nonce, 19, 1, 0,
            81, 99, 101, 103, 105, 107, profile, 1)
        _send_record(outer, wire.pack_verify(nonce, epoch, 1), read_fd)
        os.close(read_fd)
        poller = select.poll()
        poller.register(outer.fileno(), select.POLLIN)
        self.assertTrue(poller.poll(2000))
        response = outer.recv(512)
        self.assertEqual(len(response), 176, response.hex())
        status, forwarded = wire.unpack_verify_result(response, nonce, epoch,
            1, broker_nonce, 19, profile)
        self.assertEqual(status, 0)
        self.assertEqual(forwarded, broker_result)
        with self.assertRaises(OSError):
            fcntl.fcntl(read_fd, fcntl.F_GETFD)
        _send_record(outer, wire.pack_stop(nonce, epoch, 2))
        self.assertTrue(poller.poll(2000))
        accepted = outer.recv(128)
        wire.unpack_stop_reply(accepted, wire.STOP_ACCEPTED, nonce, epoch, 2)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        os.close(write_fd)
        outer.close()

    def test_sibling_sender_cannot_use_parent_channel(self):
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inner.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = bytes.fromhex('223344556677889900aabbccddeeff11')
        child = os.fork()
        if child == 0:
            outer.close()
            try:
                instance = relay.KerRunControl(inner.detach(), nonce, 31)
                instance.state = 'READY'
                instance.readiness = _Readiness(b'C' * 16, 37, b'P' * 32)
                instance.poll(lambda: None)
                os._exit(41)
            except PermissionError:
                os._exit(0)
            except BaseException:
                os._exit(42)
        inner.close()
        sender = os.fork()
        if sender == 0:
            inner.close()
            try:
                read_fd, write_fd = os.pipe()
                record = wire.pack_verify(nonce, 31, 1)
                _send_record(outer, record, read_fd)
                os.close(read_fd)
                os.close(write_fd)
                os._exit(0)
            except BaseException:
                os._exit(43)
        outer.close()
        _, sender_status = os.waitpid(sender, 0)
        self.assertEqual(os.waitstatus_to_exitcode(sender_status), 0)
        _, child_status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(child_status), 0)

    def test_unknown_request_closes_attached_right_and_fails_closed(self):
        outer, inner = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        inner.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        nonce = bytes.fromhex('11223344556677889900aabbccddeeff')
        child = os.fork()
        if child == 0:
            outer.close()
            try:
                instance = relay.KerRunControl(inner.detach(), nonce, 23)
                instance.state = 'READY'
                instance.readiness = _Readiness(b'B' * 16, 27, b'P' * 32)
                instance.poll(lambda: None)
                os._exit(31)
            except (PermissionError, ValueError, ConnectionError):
                os._exit(0)
            except BaseException:
                os._exit(32)
        inner.close()
        read_fd, write_fd = os.pipe()
        bad = wire.COMMON.pack(wire.MAGIC, wire.VERSION, 99,
            wire.COMMON.size, 0, nonce, 23, 1)
        _send_record(outer, bad, read_fd)
        os.close(read_fd)
        _, status = os.waitpid(child, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        os.close(write_fd)
        outer.close()


if __name__ == '__main__':
    unittest.main()
