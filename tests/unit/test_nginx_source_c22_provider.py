"""Fail-closed controls for the external C22 provider boundary."""
import importlib.util
import errno
import fcntl
import os
from pathlib import Path
import array
import select
import socket
import struct
import stat
import shutil
import subprocess
import sys
import threading
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('source_c22_provider_under_test',
    ROOT / 'tools/nginx_source_c22_provider.py')
provider = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provider)


class SourceC22ProviderBoundaryTests(unittest.TestCase):
    def test_first_candidate_grant_boundaries_require_main_thread(self):
        controller_spec = importlib.util.spec_from_file_location(
            '_ker_nginx_source_shell_controller',
            ROOT / 'tools' / 'nginx_source_shell_controller.py')
        controller_module = importlib.util.module_from_spec(controller_spec)
        sys.modules[controller_spec.name] = controller_module
        controller_spec.loader.exec_module(controller_module)
        boot_spec = importlib.util.spec_from_file_location('candidate_thread_boot',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        context = object.__new__(boot.SourceBootstrapSupervisor)
        failures = []
        def invoke():
            for callback in (
                    lambda: instance.reply_first_candidate_worker(None, None,
                        None, b'', (), None, 1),
                    lambda: boot.SourceBootstrapSupervisor.reply_first_candidate_worker(
                        context, None, b'', (), None, None, 1, None, None)):
                try: callback()
                except BaseException as error: failures.append(error)
        worker = threading.Thread(target=invoke)
        worker.start(); worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 2)
        self.assertTrue(all(isinstance(error, PermissionError) for error in failures))

    def test_wire_record_has_fixed_c_abi_size(self):
        self.assertEqual(provider._RECORD.size, 108)

    def test_arbitrary_context_is_rejected_before_helper_or_fd_acquisition(self):
        context = SimpleNamespace(shell_mode=True, nonce=b'c' * 16, epoch=1,
            owner_live=lambda: None)
        readiness = SimpleNamespace(ready=True, stopped=False,
            nonce=b'b' * 16, epoch=2)
        before = set(os.listdir('/proc/self/fd'))
        with self.assertRaises(TypeError):
            provider.SourceShellC22Provider(context, readiness,
                '/must/not/be/opened', bytes(32))
        with self.assertRaisesRegex(TypeError, 'fixed-receipt'):
            provider.SourceShellC22Provider(context, readiness, '/must/not/be/opened')
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)


    def test_fixed_review_capture_holds_actual_helper_fd_without_execution(self):
        if not provider._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        before = set(os.listdir('/proc/self/fd'))
        with mock.patch.object(provider.subprocess, 'Popen',
                side_effect=AssertionError('capture must not execute the helper')):
            capture = provider.C22HelperBuildCapture.capture(
                time.monotonic_ns() + 5_000_000_000)
        self.assertEqual(capture.receipt_sha256.hex(), provider._RECEIPT_SHA256)
        self.assertEqual(capture.sha256.hex(), provider._HELPER_SHA256)
        self.assertEqual(capture.build_id, provider._HELPER_BUILD_ID)
        with self.assertRaises(AttributeError):
            capture._deadline_ns = time.monotonic_ns() + 60_000_000_000
        with self.assertRaises(AttributeError):
            capture.sha256 = bytes(32)
        held_before = set(os.listdir('/proc/self/fd'))
        self.assertEqual(len(held_before), len(before) + 1)
        self.assertGreater(os.fstat(capture._fd).st_size, 0)
        with self.assertRaises(TypeError):
            provider.C22HelperBuildCapture.capture(
                time.monotonic_ns() + 5_000_000_000, '/alternate/helper')
        with self.assertRaises(TimeoutError):
            provider.C22HelperBuildCapture.capture(time.monotonic_ns() - 1)
        self.assertEqual(set(os.listdir('/proc/self/fd')), held_before)
        helper_fd, _metadata, digest = capture._take_helper_fd(capture._deadline_ns)
        self.assertEqual(digest.hex(), provider._HELPER_SHA256)
        os.fstat(helper_fd)
        with self.assertRaises(PermissionError):
            capture._take_helper_fd(capture._deadline_ns)
        os.close(helper_fd)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_capture_rejects_symlink_fifo_and_midread_mutation_without_fd_leak(self):
        with tempfile.TemporaryDirectory(prefix='ker-c22-capture-faults-') as directory:
            root = Path(directory)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            with self.assertRaises(PermissionError):
                fd = provider._open_absolute_nofollow(fifo, os.O_RDONLY | os.O_NONBLOCK)
                try:
                    provider._stable_hash_fd(fd, time.monotonic_ns() + 1_000_000_000, 1024)
                finally:
                    os.close(fd)
            regular = root / 'regular'
            regular.write_bytes(b'original bytes')
            link = root / 'symlink'
            link.symlink_to(regular)
            with self.assertRaises(OSError):
                provider._open_absolute_nofollow(link, os.O_RDONLY | os.O_NONBLOCK)
            fd = os.open(regular, os.O_RDWR | os.O_CLOEXEC)
            try:
                real_pread = os.pread
                mutated = False
                def mutate_during_read(read_fd, size, offset):
                    nonlocal mutated
                    result = real_pread(read_fd, size, offset)
                    if not mutated:
                        os.pwrite(read_fd, b'X', 0)
                        mutated = True
                    return result
                with mock.patch.object(provider.os, 'pread', side_effect=mutate_during_read):
                    with self.assertRaises(PermissionError):
                        provider._stable_hash_fd(fd,
                            time.monotonic_ns() + 1_000_000_000, 1024)
                self.assertTrue(mutated)
            finally:
                os.close(fd)

    def test_capture_rejects_alternate_recipe_and_modified_helper_or_archive(self):
        if not provider._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        deadline = time.monotonic_ns() + 5_000_000_000
        before = set(os.listdir('/proc/self/fd'))
        receipt_path = Path(provider._RECEIPT_PATH)
        receipt = receipt_path.read_bytes()
        changed_receipt = receipt.replace(b'ker-nginx-owner-group-controller',
            b'ker-nginx-owner-group-untrusted', 1)
        self.assertNotEqual(changed_receipt, receipt)
        with tempfile.TemporaryDirectory(prefix='ker-c22-alternate-capture-') as directory:
            root = Path(directory)
            alternate_receipt = root / 'alternate-receipt.json'
            alternate_receipt.write_bytes(changed_receipt)
            with self.assertRaises(PermissionError):
                provider._read_anchor(alternate_receipt, deadline, 64 * 1024,
                    provider._RECEIPT_SHA256)
            for source_path, expected, limit, label in (
                    (Path(provider._HELPER_PATH), provider._HELPER_SHA256,
                        provider._MAX_EXECUTABLE_BYTES, 'helper'),
                    (Path(provider._ARCHIVE_PATH), provider._ARCHIVE_SHA256,
                        16 * 1024 * 1024, 'archive')):
                altered = root / f'{label}-altered'
                data = bytearray(source_path.read_bytes())
                data[-1] ^= 1
                altered.write_bytes(data)
                fd = os.open(altered, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                try:
                    digest, _info = provider._stable_hash_fd(fd, deadline, limit)
                    self.assertNotEqual(digest, expected)
                finally:
                    os.close(fd)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_failed_transfer_seek_keeps_capture_owner_and_can_retry(self):
        if not provider._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        before = set(os.listdir('/proc/self/fd'))
        capture = provider.C22HelperBuildCapture.capture(
            time.monotonic_ns() + 5_000_000_000)
        owned_fd = capture._fd
        deadline = capture._deadline_ns
        with mock.patch.object(provider.os, 'lseek',
                side_effect=OSError('injected provider transfer seek failure')):
            with self.assertRaisesRegex(OSError, 'transfer seek failure'):
                capture._take_helper_fd(deadline)
        self.assertEqual(capture._fd, owned_fd)
        self.assertFalse(capture._consumed)
        os.fstat(owned_fd)
        self.assertEqual(len(os.listdir('/proc/self/fd')), len(before) + 1)
        helper_fd, _metadata, digest = capture._take_helper_fd(deadline)
        self.assertEqual(digest.hex(), provider._HELPER_SHA256)
        self.assertEqual(capture._fd, -1)
        self.assertTrue(capture._consumed)
        os.close(helper_fd)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_worker_slots_are_limited_to_rt01_original_and_committed_candidate(self):
        context = SimpleNamespace(_unpack_request=lambda packet, op, flags: packet)
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance.context = context
        instance._used_slots = set()
        self.assertEqual(instance._slot_index([0, 1, 0, 0, 0, 0, 0, 0, 0, 0]), 0)
        self.assertEqual(instance._slot_index([0, 1, 0, 0, 0, 0, 0, 0, 1, 1]), 1)
        with self.assertRaises(PermissionError):
            instance._slot_index([0, 1, 0, 0, 0, 0, 0, 0, 0, 1])
        with self.assertRaises(PermissionError):
            instance._slot_index([0, 1, 0, 0, 0, 0, 0, 0, 0, 2])

    def test_candidate_unknown_send_burns_cap_and_slot_before_real_rights_send(self):
        controller_spec = importlib.util.spec_from_file_location(
            '_ker_nginx_source_shell_controller',
            ROOT / 'tools' / 'nginx_source_shell_controller.py')
        controller_module = importlib.util.module_from_spec(controller_spec)
        sys.modules[controller_spec.name] = controller_module
        controller_spec.loader.exec_module(controller_module)
        controller = object.__new__(controller_module.SourceShellController)
        context = SimpleNamespace(control_only=True,
            deadline_ns=time.monotonic_ns() + 3_000_000_000)
        provider_actor = provider.SourceShellC22Provider.__new__(
            provider.SourceShellC22Provider)
        provider_actor.context = context
        provider_actor.broker_readiness = object()
        provider_actor._closed = False
        provider_actor._used_slots = {0}
        provider_actor._first_candidate_pending_watch = None
        provider_actor._first_candidate_pending_ready = None
        provider_actor._first_candidate_pending_error = None
        provider_actor.slots = [-1, -1]
        provider_actor.slot_identities = ((1, 2), (3, 4))
        provider_actor._check_actor = lambda *_: None
        fields = [0] * 10
        fields[8:10] = [1, 1]
        packet = bytes(range(32))
        context._unpack_request = lambda _packet, _op, _flags: fields
        left, right = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        relay, relay_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        ready, ready_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        read_fd, slot_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        pidfd = os.pidfd_open(os.getpid(), 0)
        deadline = context.deadline_ns
        for endpoint in (left, right, relay, relay_peer, ready, ready_peer):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        transport = object()
        controller.bootstrap_context = context
        controller.initial_worker_binding = transport
        controller._first_candidate_worker_grant_consumed = False
        controller._first_candidate_worker_grant = None
        controller._validate_first_candidate_worker_grant = lambda *_: True
        cookie = controller_module.SourceShellController._first_candidate_socket_cookie
        identity = controller_module.SourceShellController._first_candidate_endpoint_identity
        controller.listener = relay_peer
        controller._accepted_candidate_worker_request = (
            controller_module._AcceptedCandidateWorkerRequest(
                controller_module._ACCEPTED_CANDIDATE_REQUEST_TOKEN, controller,
                controller.listener, identity(controller.listener), cookie(controller.listener),
                left, identity(left), cookie(left), packet,
                (os.getpid(), os.getuid(), os.getgid()), deadline, (1, 1)))
        cap = controller_module._FirstCandidateWorkerGrant(
            controller_module._FIRST_CANDIDATE_GRANT_TOKEN, controller, context,
            provider_actor, transport, left, identity(left), cookie(left), packet,
            (os.getpid(), os.getuid(), os.getgid()), relay, identity(relay),
            cookie(relay), deadline, (1, 1), object(), (os.getpid(), 1, pidfd), object())
        cap = cap._replace(accepted_request=controller._accepted_candidate_worker_request)
        controller._first_candidate_worker_grant = cap
        sends = []
        def unknown_reply(channel, raw, _credentials, provider_arg, relay_arg,
                grant_deadline, controller_arg, grant):
            controller_arg._consume_first_candidate_worker_grant(grant, context,
                provider_arg, channel, raw, (os.getpid(), os.getuid(), os.getgid()),
                relay_arg, grant_deadline)
            rights = array.array('i', (pidfd, pidfd, slot_fd,
                relay_arg.fileno(), ready.fileno()))
            channel.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            sends.append('sent-then-unknown')
            raise OSError(errno.EIO, 'injected lost grant outcome after SCM_RIGHTS send')
        context.reply_first_candidate_worker = unknown_reply
        try:
            with self.assertRaises(OSError) as generic_closed:
                provider_actor.reply_worker(left, packet, cap.credentials, relay)
            self.assertEqual(generic_closed.exception.errno, errno.ENOTSUP)
            self.assertEqual(provider_actor._used_slots, {0})
            with self.assertRaises(TimeoutError):
                provider_actor.reply_first_candidate_worker(controller, cap,
                    left, packet, cap.credentials, relay, deadline + 1)
            with self.assertRaises(TimeoutError):
                provider_actor.reply_first_candidate_worker(controller, cap,
                    left, packet, cap.credentials, relay, True)
            self.assertEqual(provider_actor._used_slots, {0})
            with self.assertRaises(OSError) as caught:
                provider_actor.reply_first_candidate_worker(controller, cap,
                    left, packet, cap.credentials, relay, deadline)
            self.assertEqual(caught.exception.errno, errno.EIO)
            self.assertEqual(sends, ['sent-then-unknown'])
            self.assertEqual(provider_actor._used_slots, {0, 1})
            self.assertTrue(controller._first_candidate_worker_grant_consumed)
            self.assertIs(controller._first_candidate_worker_grant, cap)
            self.assertTrue(controller.unresolved)
            self.assertTrue(controller._first_candidate_worker_pending)
            self.assertIsNone(provider_actor._first_candidate_pending_ready)
            self.assertIsNotNone(provider_actor._first_candidate_pending_error)
            with self.assertRaises((PermissionError, OSError)):
                provider_actor.reply_first_candidate_worker(controller, cap,
                    left, packet, cap.credentials, relay, deadline)
            data, ancillary, _flags, _address = right.recvmsg(4096,
                socket.CMSG_SPACE(3 * 4) + socket.CMSG_SPACE(5 * 4),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
            fds = []
            for level, kind, payload in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds.extend(array.array('i', payload[:len(payload) - len(payload) % 4]))
            self.assertEqual(data, packet)
            self.assertEqual(len(fds), 5)
            for fd in fds: os.close(fd)
        finally:
            for endpoint in (left, right, relay, relay_peer, ready, ready_peer):
                endpoint.close()
            for fd in (read_fd, slot_fd, pidfd):
                os.close(fd)

    def test_c34_verify_uses_duplicate_and_retains_original_watch_for_later_round(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        calls = []
        class Readiness:
            nonce = b'b' * 16
            epoch = 2
            def begin_verify(self, fd, sequence, timeout):
                calls.append((fd, sequence, timeout))
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance._closed = False
        instance.watch_fd = read_fd
        instance._verify_sequence = 0
        instance.source_epoch, instance.source_nonce = 13, b's' * 16
        instance.broker_readiness = Readiness()
        instance.broker_nonce, instance.broker_epoch = b'b' * 16, 2
        instance.context = SimpleNamespace(deadline_ns=time.monotonic_ns() + 10_000_000_000)
        instance._check_actor = lambda: None
        def close_duplicates():
            for fd, _, _ in calls:
                os.close(fd)
        self.addCleanup(close_duplicates)
        instance.begin_c34_verify(1)
        self.assertEqual(instance._verify_sequence, 1)
        self.assertNotEqual(calls[-1][0], read_fd)
        self.assertGreater(calls[-1][2], 0)
        os.fstat(read_fd)
        instance.begin_c34_verify(2)
        self.assertEqual(instance._verify_sequence, 2)
        self.assertNotEqual(calls[-1][0], read_fd)
        os.fstat(read_fd)

    def test_worker_record_round_is_distinct_from_launch_epoch(self):
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance._closed = False
        instance._used_slots = set()
        instance.source_epoch, instance.source_nonce = 13, b's' * 16
        instance.slots = [90, 91]
        instance.slot_identities = ((10, 20), (11, 21))
        instance._check_actor = lambda: None
        class Ready:
            def close(self):
                pass
        calls = []
        def reply(channel, packet, credentials, slot, relay):
            calls.append(slot)
            generation = packet[8]
            return {'source_epoch': packet[9], 'generation': generation,
                'slot_device': 10 if generation == 0 else 11,
                'slot_inode': 20 if generation == 0 else 21}, Ready()
        instance.context = SimpleNamespace(_unpack_request=lambda packet, op, flags: packet,
            reply_worker=reply)
        initial = [0] * 10
        initial[8:10] = [0, 0]
        candidate = [0] * 10
        candidate[8:10] = [1, 1]
        instance.reply_worker(None, initial, None, None)
        instance.reply_worker(None, candidate, None, None)
        self.assertEqual(calls, [90, 91])

    def test_pinned_executable_open_is_nonblocking_and_size_bounded(self):
        with tempfile.TemporaryDirectory(prefix='ker-c22-pin-') as directory:
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo)
            deadline = time.monotonic_ns() + 1_000_000_000
            before = set(os.listdir('/proc/self/fd'))
            with self.assertRaises(PermissionError):
                provider._open_pinned_executable(fifo, deadline)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            executable = Path(directory) / 'helper'
            shutil.copy2(sys.executable, executable)
            with self.assertRaises(TimeoutError):
                provider._open_pinned_executable(executable,
                    time.monotonic_ns() - 1)

    def test_broker_capability_host_fd_modes_match_real_pipe2_shape(self):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        info = provider._validate_broker_fifo(write_fd, 'test generation watch')
        self.assertTrue(stat.S_ISFIFO(info.st_mode))
        self.assertEqual(fcntl.fcntl(write_fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_WRONLY)
        with self.assertRaises(PermissionError):
            provider._validate_broker_fifo(read_fd, 'readonly watch')
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with self.assertRaises(PermissionError):
            provider._validate_broker_fifo(left.fileno(), 'socket watch')

    def test_close_command_returns_on_full_pipe_without_blocking(self):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.addCleanup(os.close, read_fd)
        try:
            while True:
                os.write(write_fd, b'x' * 4096)
        except BlockingIOError:
            pass
        stream = os.fdopen(write_fd, 'wb', buffering=0)
        self.addCleanup(stream.close)
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance.process = SimpleNamespace(poll=lambda: None, stdin=stream)
        start = time.monotonic_ns()
        self.assertFalse(instance._close_command(start + 20_000_000))
        self.assertLess(time.monotonic_ns() - start, 500_000_000)

    def test_unsettled_helper_retains_pidfd_and_helper_inode_for_cleanup_retry(self):
        class StuckProcess:
            stdin = None
            def poll(self):
                return None
            def terminate(self):
                pass
            def kill(self):
                pass
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        helper_fd = os.open(sys.executable, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        self.addCleanup(os.close, helper_fd)
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance._closed = False
        instance.slots = [-1, -1]
        instance.watch_fd = -1
        instance.process = StuckProcess()
        instance.pidfd = read_fd
        instance._helper_fd = helper_fd
        instance._channel = None
        with self.assertRaises(TimeoutError):
            instance.close(abort=True)
        self.assertFalse(instance._closed)
        os.fstat(instance.pidfd)
        os.fstat(instance._helper_fd)

    def test_constructor_sets_parent_owned_before_socket_configuration_failure(self):
        if not provider._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        closed = []
        class FakeSocket:
            def fileno(self):
                return 99
            def setsockopt(self, *args):
                raise OSError('injected SO_PASSCRED failure')
            def close(self):
                closed.append(self)
        class Origin:
            def __init__(self, context):
                self.context = context
                self.original_supervisor_identity = {'pid': 1}
                self.environment = {'KER_SOCKET_BROKER_PATH': '/broker.sock'}
                self.artifact_binding = SimpleNamespace(broker_path='/broker.sock')
            def owner_live(self):
                pass
        origin = Origin(None)
        context = SimpleNamespace(shell_mode=True, nonce=b's' * 16, epoch=3,
            deadline_ns=time.monotonic_ns() + 5_000_000_000,
            original_supervisor_identity={'pid': 1},
            owner_live=origin.owner_live)
        origin.context = context
        readiness = SimpleNamespace(ready=True, stopped=False,
            nonce=b'b' * 16, epoch=4)
        before = set(os.listdir('/proc/self/fd'))
        with mock.patch.object(provider, '_source_listener_tuple',
                return_value=('0.0.0.0', 80, 511)), \
             mock.patch.object(provider.socket, 'socketpair',
                return_value=(FakeSocket(), FakeSocket())):
            capture = provider.C22HelperBuildCapture.capture(context.deadline_ns)
            with self.assertRaisesRegex(OSError, 'injected SO_PASSCRED'):
                provider.SourceShellC22Provider(context, readiness, capture)
            self.assertEqual(capture._fd, -1)
        self.assertEqual(len(closed), 2)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_constructor_exposes_provider_when_helper_cleanup_times_out(self):
        if not provider._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        primary = RuntimeError('injected post-launch receive failure')
        class StuckProcess:
            pid = 987654
            stdin = None
            def poll(self):
                return None
            def terminate(self):
                pass
            def kill(self):
                pass
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        real_pidfd_open = os.pidfd_open
        def pidfd_open(pid, flags=0):
            if pid == os.getpid():
                return real_pidfd_open(pid, flags)
            return read_fd
        class Origin:
            def __init__(self, context):
                self.context = context
                self.original_supervisor_identity = {'pid': 1}
                self.environment = {'KER_SOCKET_BROKER_PATH': '/broker.sock'}
                self.artifact_binding = SimpleNamespace(broker_path='/broker.sock')
            def owner_live(self):
                pass
        origin = Origin(None)
        context = SimpleNamespace(shell_mode=True, nonce=b's' * 16, epoch=3,
            deadline_ns=time.monotonic_ns() + 5_000_000_000,
            original_supervisor_identity={'pid': 1}, owner_live=origin.owner_live)
        origin.context = context
        readiness = SimpleNamespace(ready=True, stopped=False,
            nonce=b'b' * 16, epoch=4)
        with mock.patch.object(provider, '_source_listener_tuple',
                return_value=('0.0.0.0', 80, 511)), \
             mock.patch.object(provider.subprocess, 'Popen', return_value=StuckProcess()), \
             mock.patch.object(provider.os, 'pidfd_open', side_effect=pidfd_open), \
             mock.patch.object(provider, '_identity',
                side_effect=lambda pid: (pid, os.getuid(), os.getgid(), 12345)), \
             mock.patch.object(provider.SourceShellC22Provider, '_check_actor',
                side_effect=primary):
            capture = provider.C22HelperBuildCapture.capture(context.deadline_ns)
            with self.assertRaises(provider.C22ProviderCleanupPending) as caught:
                provider.SourceShellC22Provider(context, readiness, capture)
        pending = caught.exception
        self.assertIs(pending.primary_error, primary)
        self.assertIs(pending.__cause__, primary)
        self.assertIsInstance(pending.cleanup_error, TimeoutError)
        self.assertFalse(pending.provider._closed)
        self.assertIsInstance(pending.provider.process, StuckProcess)
        os.fstat(pending.provider.pidfd)
        os.fstat(pending.provider._helper_fd)
        self.assertIsNotNone(pending.provider._channel)
        os.close(pending.provider._helper_fd)
        pending.provider._helper_fd = -1
        pending.provider._channel.close()
        pending.provider._channel = None

    def test_late_scm_bundle_closes_all_received_rights_before_rejection(self):
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        with tempfile.TemporaryDirectory(prefix='ker-c22-late-rights-') as directory:
            paths = [Path(directory) / name for name in ('slot0', 'slot1', 'watch')]
            for path in paths:
                os.mkfifo(path)
            slot_readers = [os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                for path in paths[:2]]
            caps = [os.open(paths[0], os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC),
                os.open(paths[1], os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)]
            for fd in slot_readers:
                self.addCleanup(os.close, fd)
            watch_r, watch_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            caps.append(watch_w)
            self.addCleanup(os.close, watch_r)
            for fd in caps:
                self.addCleanup(os.close, fd)
            stats = [os.fstat(fd) for fd in caps]
            source_nonce, broker_nonce = b's' * 16, b'b' * 16
            record = provider._RECORD.pack(provider._MAGIC, provider._VERSION,
                provider._RECORD.size, 7, 9, source_nonce, broker_nonce,
                0, 80, 511, stats[0].st_dev, stats[0].st_ino,
                stats[1].st_dev, stats[1].st_ino)
            rights = array.array('i', caps)
            child.sendmsg([record], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                rights.tobytes())])
            before = set(os.listdir('/proc/self/fd'))
            instance = provider.SourceShellC22Provider.__new__(
                provider.SourceShellC22Provider)
            instance.context = SimpleNamespace(deadline_ns=time.monotonic_ns() + 2_000_000_000)
            instance.source_epoch, instance.broker_epoch = 7, 9
            instance.source_nonce, instance.broker_nonce = source_nonce, broker_nonce
            instance.process = SimpleNamespace(pid=os.getpid())
            instance._channel = parent
            instance.slots = [-1, -1]
            instance.watch_fd = -1
            deadline = time.monotonic_ns() + 1_000_000_000
            clock_values = iter((time.monotonic_ns(), time.monotonic_ns(), deadline))
            fake_clock = SimpleNamespace(monotonic_ns=lambda: next(clock_values))
            with mock.patch.object(provider, 'time', fake_clock):
                with self.assertRaises(PermissionError):
                    instance._receive_bundle(deadline)
            self.assertEqual(instance.slots, [-1, -1])
            self.assertEqual(instance.watch_fd, -1)
            self.assertEqual(instance._last_bundle_attempt['record'], record)
            self.assertEqual(instance._last_bundle_attempt['received_fd_count'], 3)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_unknown_recvmsg_flags_reject_and_close_real_scm_rights(self):
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(parent.close)
        self.addCleanup(child.close)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        with tempfile.TemporaryDirectory(prefix='ker-c22-flags-') as directory:
            paths = [Path(directory) / name for name in ('slot0', 'slot1')]
            for path in paths:
                os.mkfifo(path)
            readers = [os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                for path in paths]
            for fd in readers:
                self.addCleanup(os.close, fd)
            caps = [os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                for path in paths]
            watch_r, watch_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            caps.append(watch_w)
            self.addCleanup(os.close, watch_r)
            for fd in caps:
                self.addCleanup(os.close, fd)
            info = [os.fstat(fd) for fd in caps]
            nonce, broker_nonce = b'n' * 16, b'k' * 16
            record = provider._RECORD.pack(provider._MAGIC, provider._VERSION,
                provider._RECORD.size, 11, 12, nonce, broker_nonce, 0, 80, 511,
                info[0].st_dev, info[0].st_ino, info[1].st_dev, info[1].st_ino)
            rights = array.array('i', caps)
            child.sendmsg([record], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())])
            unknown_flag = 1 << 24
            class FlagSocket:
                def fileno(self):
                    return parent.fileno()
                def getsockopt(self, *args):
                    return parent.getsockopt(*args)
                def recvmsg(self, *args):
                    packet, ancillary, flags, address = parent.recvmsg(*args)
                    return packet, ancillary, flags | unknown_flag, address
            instance = provider.SourceShellC22Provider.__new__(
                provider.SourceShellC22Provider)
            instance.context = SimpleNamespace(deadline_ns=time.monotonic_ns() + 2_000_000_000)
            instance.source_epoch, instance.broker_epoch = 11, 12
            instance.source_nonce, instance.broker_nonce = nonce, broker_nonce
            instance.process = SimpleNamespace(pid=os.getpid())
            instance._channel = FlagSocket()
            instance.slots = [-1, -1]
            instance.watch_fd = -1
            before = set(os.listdir('/proc/self/fd'))
            with self.assertRaises(PermissionError):
                instance._receive_bundle(instance.context.deadline_ns)
            self.assertEqual(instance._last_bundle_attempt['flags'] &
                ~getattr(socket, 'MSG_CMSG_CLOEXEC', 0), unknown_flag)
            self.assertEqual(instance._last_bundle_attempt['received_fd_count'], 3)
            self.assertEqual(instance.slots, [-1, -1])
            self.assertEqual(instance.watch_fd, -1)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)


class SourceC28CommandTransportTests(unittest.TestCase):
    def test_only_successful_retry_slot_can_transfer_two_descriptors(self):
        for operation, error, count, valid in (
                (provider._C28_RETRY_SLOT, 0, 2, True),
                (provider._C28_RETRY_SLOT, 0, 1, False),
                (provider._C28_RETRY_SLOT, 0, 0, False),
                (provider._C28_RETRY_SLOT, errno.EALREADY, 1, False),
                (provider._C28_RETRY_SLOT, errno.EALREADY, 0, True),
                (provider._C28_RETRY_ADOPT, 0, 2, False)):
            with self.subTest(operation=operation, error=error, count=count):
                parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
                with parent, child:
                    try:
                        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                        deadline = time.monotonic_ns() + 1_000_000_000
                        request = provider._encode_source_c28_request(
                            operation, 1, deadline, b'b' * 108)
                        payload = request + provider._C28_RESULT.pack(error, 0, 0, 0, 0, 0)
                        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array('i', [write] * count))] if count else []
                        child.sendmsg([payload], ancillary)
                        expected = (os.getpid(), os.getuid(), os.getgid())
                        before = set(os.listdir('/proc/self/fd'))
                        if valid:
                            reply = provider._exchange_source_c28(parent, request,
                                expected, deadline, lambda _: None)
                            self.assertEqual(reply['errno'], error)
                            fds = reply.get('fds', ())
                            try:
                                self.assertEqual(len(fds), count)
                                self.assertTrue(all(not os.get_inheritable(fd) for fd in fds))
                            finally:
                                for fd in fds:
                                    os.close(fd)
                        else:
                            with self.assertRaises(PermissionError):
                                provider._exchange_source_c28(parent, request,
                                    expected, deadline, lambda _: None)
                        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
                    finally:
                        os.close(read)
                        os.close(write)

    def test_request_and_reply_have_exact_explicit_wire_sizes_and_offsets(self):
        bundle = bytes(range(108))
        deadline = time.monotonic_ns() + 1_000_000_000
        request = provider._encode_source_c28_request(
            provider._C28_PARK, 7, deadline, bundle)
        self.assertEqual(len(request), 148)
        self.assertEqual(request[:8], b'KERSC28Q')
        self.assertEqual(struct.unpack_from('<HHIQQII', request, 8),
            (1, provider._C28_PARK, 148, 7, deadline, 0, 0))
        self.assertEqual(request[40:], bundle)
        result = provider._C28_RESULT.pack(0, 4, 0x1122334455667788,
            0x8877665544332211, 0, 0)
        decoded = provider._decode_source_c28_reply(request + result, request,
            (11, 12, 13), (11, 12, 13), 0)
        self.assertEqual(decoded, {'errno': 0, 'phase': 4,
            'lease': 0x1122334455667788,
            'listener_cookie': 0x8877665544332211,
            'received': 0, 'accepted': 0})
        with self.assertRaises(PermissionError):
            provider._decode_source_c28_reply(b'X' + request[1:] + result,
                request, (11, 12, 13), (11, 12, 13), 0)
        impossible = provider._C28_RESULT.pack(-1, 4, 1, 2, 0, 1)
        with self.assertRaises(PermissionError):
            provider._decode_source_c28_reply(request + impossible, request,
                (11, 12, 13), (11, 12, 13), 0)
        with self.assertRaises(ValueError):
            provider._encode_source_c28_request(1, 1, deadline, b'short')

    def test_old_fixed_helper_capture_cannot_authorize_new_commands(self):
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance._source_command_abi = None
        with self.assertRaises(OSError) as caught:
            instance._source_c28_command(provider._C28_PARK, time.monotonic_ns() + 1_000_000_000)
        self.assertEqual(caught.exception.errno, errno.ENOTSUP)

    def test_abort_settles_the_pending_park_lease_once(self):
        deadline = time.monotonic_ns() + 50_000_000
        reply = dict(phase=provider._C28_PHASE_ABORTED, lease=7,
            listener_cookie=0, received=3, accepted=3)
        for fault in (None, {'lease': 8}, {'received': 1, 'accepted': 1},
                {'accepted': 2}, {'listener_cookie': 9}):
            with self.subTest(fault=fault):
                instance = provider.SourceShellC22Provider.__new__(
                    provider.SourceShellC22Provider)
                instance._source_park_deadline_ns = deadline
                instance._source_park_evidence = SimpleNamespace(lease=7, received=2)
                instance._source_committed = False
                instance._source_command_unresolved = False
                instance._source_abort_result = None
                response = {**reply, **(fault or {})}
                instance._source_c28_command = mock.Mock(return_value=response)
                with self.assertRaises(PermissionError):
                    instance.abort_source_group_before(deadline + 1)
                instance._source_c28_command.assert_not_called()
                if fault:
                    with self.assertRaises(PermissionError):
                        instance.abort_source_group_before(deadline)
                    self.assertTrue(instance._source_command_unresolved)
                    self.assertIsNone(instance._source_abort_result)
                else:
                    self.assertEqual(instance.abort_source_group_before(deadline), reply)
                    with self.assertRaises(PermissionError):
                        instance.abort_source_group_before(deadline)
                    self.assertEqual(instance._source_abort_result, reply)
                instance._source_c28_command.assert_called_once_with(
                    provider._C28_ABORT, deadline)

    def test_only_correlated_initial_retire_eagain_is_retryable(self):
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance._source_command_abi = provider._C28_SOURCE_COMMAND_ABI
        instance._source_command_unresolved = False
        instance._source_command_outstanding = None
        instance._closed = False
        instance._channel = object()
        instance.process = SimpleNamespace(pid=os.getpid())
        instance.context = SimpleNamespace(deadline_ns=time.monotonic_ns() + 1_000_000_000)
        instance._last_received_bundle = {'record': b'B' * provider._RECORD.size}
        instance._check_actor = lambda _deadline: True
        instance._source_command_sequence = 0
        def decoded_retire_reply(_channel, request, credentials, _deadline,
                _check_actor, **_kwargs):
            tail = getattr(decoded_retire_reply, 'tail', (0, 0, 0, 0, 0))
            raw = request + provider._C28_RESULT.pack(errno.EAGAIN, *tail)
            return provider._decode_source_c28_reply(raw, request,
                credentials, credentials, 0)
        malformed_tails = ((1, 0, 0, 0, 0), (0, 1, 0, 0, 0),
            (0, 0, 1, 0, 0), (0, 0, 0, 1, 0), (0, 0, 0, 1, 1))
        for tail in malformed_tails:
            instance._source_command_unresolved = False
            instance._source_command_sequence = 0
            decoded_retire_reply.tail = tail
            with mock.patch.object(provider, '_exchange_source_c28',
                    side_effect=decoded_retire_reply):
                with self.assertRaises(PermissionError):
                    instance._source_c28_command(provider._C28_RETIRE_INITIAL_LISTENER,
                        time.monotonic_ns() + 500_000_000)
            self.assertTrue(instance._source_command_unresolved,
                'every nonzero RETIRE EAGAIN tail field must quarantine without retry')
            self.assertIsNone(instance._source_command_outstanding)
        instance._source_command_unresolved = False
        instance._source_command_sequence = 0
        decoded_retire_reply.tail = (0, 0, 0, 0, 0)
        with mock.patch.object(provider, '_exchange_source_c28',
                side_effect=decoded_retire_reply):
            response = instance._source_c28_command(provider._C28_RETIRE_INITIAL_LISTENER,
                time.monotonic_ns() + 500_000_000)
        self.assertEqual(response['errno'], errno.EAGAIN)
        self.assertFalse(instance._source_command_unresolved)
        self.assertIsNone(instance._source_command_outstanding)
        instance._source_command_sequence = 0
        with mock.patch.object(provider, '_exchange_source_c28', return_value={
                'errno': errno.EIO, 'phase': 0, 'lease': 0,
                'listener_cookie': 0, 'received': 0, 'accepted': 0}):
            with self.assertRaises(OSError) as caught:
                instance._source_c28_command(provider._C28_RETIRE_INITIAL_LISTENER,
                    time.monotonic_ns() + 500_000_000)
        self.assertEqual(caught.exception.errno, errno.EIO)
        self.assertTrue(instance._source_command_unresolved)

    def test_c28_commit_stays_closed_without_typed_c31_ack_handoff(self):
        instance = provider.SourceShellC22Provider.__new__(provider.SourceShellC22Provider)
        instance._source_park_deadline_ns = time.monotonic_ns() + 50_000_000
        instance._source_committed = False
        with self.assertRaises(OSError) as caught:
            instance.commit_source_group_before(instance._source_park_deadline_ns)
        self.assertEqual(caught.exception.errno, errno.ENOTSUP)

    def test_real_socketpair_child_exercises_credentials_and_echo_only(self):
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        script = r'''import socket, struct, sys
s=socket.socket(fileno=int(sys.argv[1]))
request=s.recv(149)
result=struct.pack('<iIQQII',0,1,23,0,0,0)
s.send(request+result)
time.sleep(1)
'''
        process = subprocess.Popen([sys.executable, '-c', script,
            str(child.fileno())], pass_fds=(child.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close()
        pidfd = os.pidfd_open(process.pid, 0)
        helper_fd = os.open(f'/proc/{process.pid}/exe', os.O_RDONLY | os.O_CLOEXEC)
        provider_actor = provider.SourceShellC22Provider.__new__(
            provider.SourceShellC22Provider)
        provider_actor.process = process
        provider_actor.pidfd = pidfd
        provider_actor.start_ticks = provider._identity(process.pid)[3]
        provider_actor._helper_fd = helper_fd
        held = os.fstat(helper_fd)
        provider_actor._helper_metadata = (held.st_dev, held.st_ino, held.st_size,
            held.st_mtime_ns, held.st_ctime_ns)
        _, provider_actor._helper_sha256 = provider._hash_proc_executable(
            process.pid, time.monotonic_ns() + 2_000_000_000)
        try:
            expected = (process.pid, os.getuid(), os.getgid())
            bundle = b'b' * 108
            deadline = time.monotonic_ns() + 2_000_000_000
            request = provider._encode_source_c28_request(
                provider._C28_PARK, 1, deadline, bundle)
            result = provider._exchange_source_c28(parent, request, expected,
                deadline, provider_actor._check_actor)
            self.assertEqual(result['phase'], 1)
            self.assertEqual(result['errno'], 0)
        finally:
            os.close(helper_fd)
            os.close(pidfd)
            parent.close()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=2)

    def test_late_reply_is_unknown_and_not_accepted(self):
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        script = r'''import socket, struct, sys, time
s=socket.socket(fileno=int(sys.argv[1]))
request=s.recv(149)
time.sleep(0.08)
s.send(request+struct.pack('<iIQQII',0,1,23,0,0,0))
time.sleep(1)
'''
        process = subprocess.Popen([sys.executable, '-c', script,
            str(child.fileno())], pass_fds=(child.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close()
        try:
            expected = (process.pid, os.getuid(), os.getgid())
            request = provider._encode_source_c28_request(
                provider._C28_PARK, 1, time.monotonic_ns() + 1_000_000_000, b'c' * 108)
            deadline = time.monotonic_ns() + 20_000_000
            with self.assertRaises(TimeoutError):
                provider._exchange_source_c28(parent, request, expected,
                    deadline, lambda until: self.assertLess(time.monotonic_ns(), until))
        finally:
            parent.close()
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=2)


if __name__ == '__main__':
    unittest.main()
