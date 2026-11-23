"""Focused controls for the private source-origin attach wire/API."""
from pathlib import Path
from contextlib import nullcontext
import importlib.util
import socket
import sys
import unittest
import ast
import array
import hashlib
import os
import select
import struct
import tempfile
import time
from types import SimpleNamespace
from unittest import mock

TOOLS = Path(__file__).resolve().parents[2] / 'tools'
sys.path.insert(0, str(TOOLS))

import nginx_companion_wire as wire
import nginx_companion_attach as attach_module
from nginx_companion_attach import SourceAttachment
from nginx_companion_supervisor import NginxCompanion

ORIGIN_PATH = TOOLS / 'nginx_source_origin.py'
ORIGIN_SPEC = importlib.util.spec_from_file_location(
    '_attach_origin_test_primary', ORIGIN_PATH)
origin_module = importlib.util.module_from_spec(ORIGIN_SPEC)
sys.modules[ORIGIN_SPEC.name] = origin_module
ORIGIN_SPEC.loader.exec_module(origin_module)

HELPER_PATH = TOOLS / 'ker-nginx-companion.py'
HELPER_SPEC = importlib.util.spec_from_file_location('_attach_helper_test', HELPER_PATH)
helper = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(helper)


class SourceAttachmentTests(unittest.TestCase):
    def _accepted_origin_model(self, deadline_ns=None):
        pid = os.getpid()
        pidfd = os.pidfd_open(pid, 0)
        binary_hash = helper.sha256_file(f'/proc/{pid}/exe')
        deadline_ns = deadline_ns or time.monotonic_ns() + 15_000_000_000
        nonce = b'attach-model-0001'
        master = SimpleNamespace(pid=pid, pidfd=pidfd,
            start_ticks=attach_module._start_ticks(pid),
            executable_hash=binary_hash)
        launch = object.__new__(origin_module.OriginalShellLaunch)
        launch.consumed = True
        launch.context = SimpleNamespace(master=master, binary_hash=binary_hash,
            nonce=nonce, epoch=71, deadline_ns=deadline_ns)
        launch.master_pidfd = pidfd
        launch.origin_pidfd = os.dup(pidfd)
        launch.pidfd = os.dup(pidfd)
        launch.process = SimpleNamespace(poll=lambda: None)
        launch.python = SimpleNamespace(path=sys.executable)
        launch.creator_pid = pid
        launch.creator_start = attach_module._start_ticks(pid)
        launch.nonce = nonce
        launch.epoch = 71
        launch.deadline_ns = deadline_ns
        launch.output = '/private/source-attach-fault-model'
        launch.artifact_binding = SimpleNamespace(
            config_sha256='31' * 32, ini_sha256='42' * 32)
        launch.origin_proof = object()
        launch.live_supervisor = lambda _deadline: None
        return launch, (pidfd, launch.origin_pidfd, launch.pidfd)

    def test_attach_records_are_nonce_epoch_sequence_correlated(self):
        nonce, epoch = b'a' * 16, 17
        fields = (123, 1000, 1000, 0, 42, 99, 456, 1000, 1000, 0, 43,
            b'b' * 32, b'c' * 32)
        packet = wire.pack_record(wire.ATTACHED,
            wire.ATTACHED_BODY.pack(*fields), nonce, epoch, 1)
        self.assertEqual(wire.unpack_record(packet, wire.ATTACHED, nonce,
            epoch, 1, wire.ATTACHED_BODY), fields)
        with self.assertRaises(ValueError):
            wire.unpack_record(packet, wire.ATTACHED, nonce, epoch + 1,
                1, wire.ATTACHED_BODY)
        with self.assertRaises(ValueError):
            wire.unpack_record(packet, wire.ATTACHED, nonce, epoch,
                2, wire.ATTACHED_BODY)

    def test_attach_rejects_manual_identity_and_legacy_companion(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        try:
            with self.assertRaises(TypeError):
                SourceAttachment({}, left, revoke_native_auth=lambda: None)
            with self.assertRaises(TypeError):
                SourceAttachment(object.__new__(NginxCompanion), left,
                    revoke_native_auth=lambda: None)
            with self.assertRaises(TypeError):
                SourceAttachment(object(), left, revoke_native_auth=None)
        finally:
            left.close()
            right.close()

    def test_origin_type_requires_canonical_source_file_identity(self):
        primary = object.__new__(origin_module.OriginalShellLaunch)
        self.assertTrue(attach_module._is_original_shell_launch(primary))
        second_spec = importlib.util.spec_from_file_location(
            '_attach_origin_test_second', ORIGIN_PATH)
        second = importlib.util.module_from_spec(second_spec)
        sys.modules[second_spec.name] = second
        second_spec.loader.exec_module(second)
        self.assertTrue(attach_module._is_original_shell_launch(
            object.__new__(second.OriginalShellLaunch)))
        FakeOrigin = type('OriginalShellLaunch', (), {'__module__': 'fake_origin'})
        self.assertFalse(attach_module._is_original_shell_launch(object.__new__(FakeOrigin)))

    def test_attach_wire_rejects_unexpected_record_type(self):
        nonce = b'd' * 16
        packet = wire.pack_record(wire.ATTACH,
            wire.ATTACH_BODY.pack(1, 2, 3, 0, 4, 5, 6, 2, 3, 0, 7,
                b'e' * 32, b'f' * 32), nonce, 7, 1)
        with self.assertRaises(ValueError):
            wire.unpack_record(packet, wire.ATTACHED, nonce, 7, 1,
                wire.ATTACHED_BODY)

    def test_helper_rejects_an_unpinned_attach_helper_hash(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        left.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        try:
            with self.assertRaises(PermissionError):
                helper.serve_attached_session(left, b'x' * 32, timeout=0.01)
            self.assertTrue(right.fileno() >= 0)
        finally:
            left.close()
            right.close()

    def test_modeled_attach_observes_role0_then_one_role1_ready_on_same_session(self):
        """Host process model for the fixed owner-then-first-candidate watch."""
        ready_receiver, ready_sender = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET)
        ready_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        owner_trigger_r, owner_trigger_w = os.pipe()
        owner_release_r, owner_release_w = os.pipe()
        candidate_trigger_r, candidate_trigger_w = os.pipe()
        candidate_release_r, candidate_release_w = os.pipe()
        started_r, started_w = os.pipe()
        master_ctl_r, master_ctl_w = os.pipe()
        master_pid = os.fork()
        if master_pid == 0:
            try:
                os.close(started_r); os.close(master_ctl_w)
                os.close(owner_trigger_w); os.close(owner_release_w)
                os.close(candidate_trigger_w); os.close(candidate_release_w)
                os.close(ready_receiver.fileno())

                def spawn_worker(role, trigger_r, release_r, other_trigger,
                                 other_release, slot_device, slot_inode, cookie):
                    pid = os.fork()
                    if pid == 0:
                        try:
                            os.close(master_ctl_r)
                            os.close(other_trigger); os.close(other_release)
                            start = attach_module._start_ticks(os.getpid())
                            os.write(started_w, struct.pack('=IQQ', role,
                                os.getpid(), start))
                            os.close(started_w)
                            if os.read(trigger_r, 1) != b'r':
                                os._exit(93 + role)
                            ready = helper.OWNER_READY_RECORD.pack(
                                helper.OWNER_READY_MAGIC, helper.OWNER_READY_VERSION,
                                helper.OWNER_READY_RECORD.size, role, 0,
                                slot_device, slot_inode, start, os.getpid(),
                                os.getpid(), cookie, 0)
                            ready_sender.sendmsg([ready])
                            if os.read(release_r, 1) != b'x':
                                os._exit(95 + role)
                            os._exit(0)
                        except BaseException:
                            os._exit(91)
                    return pid

                owner_pid = spawn_worker(0, owner_trigger_r, owner_release_r,
                    candidate_trigger_r, candidate_release_r, 101, 202, 303)
                candidate_pid = spawn_worker(1, candidate_trigger_r,
                    candidate_release_r, owner_trigger_r, owner_release_r,
                    404, 505, 606)
                os.close(started_w); os.close(owner_trigger_r); os.close(owner_release_r)
                os.close(candidate_trigger_r); os.close(candidate_release_r)
                ready_sender.close()
                while os.read(master_ctl_r, 1) != b'x':
                    pass
                os.waitpid(owner_pid, 0); os.waitpid(candidate_pid, 0)
                os._exit(0)
            except BaseException:
                os._exit(92)
        os.close(owner_trigger_r); os.close(owner_release_r)
        os.close(candidate_trigger_r); os.close(candidate_release_r)
        os.close(started_w); ready_sender.close()
        master_pidfd = owner_pidfd = candidate_pidfd = origin_pidfd = owner_shell_pidfd = -1
        client = None
        revoked = []
        try:
            started = {}
            for _ in range(2):
                data = b''
                while len(data) < struct.calcsize('=IQQ'):
                    data += os.read(started_r, struct.calcsize('=IQQ') - len(data))
                role, pid, start = struct.unpack('=IQQ', data)
                started[role] = (pid, start)
            owner_pid, owner_start = started[0]
            candidate_pid, candidate_start = started[1]
            master_pidfd = os.pidfd_open(master_pid, 0)
            owner_pidfd = os.pidfd_open(owner_pid, 0)
            candidate_pidfd = os.pidfd_open(candidate_pid, 0)
            origin_pidfd = os.dup(master_pidfd)
            owner_shell_pidfd = os.dup(master_pidfd)
            binary_hash = helper.sha256_file(f'/proc/{master_pid}/exe')
            nonce = b'attach-two-rdy01'
            deadline_ns = time.monotonic_ns() + 20_000_000_000
            master = SimpleNamespace(pid=master_pid, pidfd=master_pidfd,
                start_ticks=attach_module._start_ticks(master_pid),
                executable_hash=binary_hash)
            launch = object.__new__(origin_module.OriginalShellLaunch)
            launch.consumed = True
            launch.context = SimpleNamespace(master=master, binary_hash=binary_hash,
                nonce=nonce, epoch=42, deadline_ns=deadline_ns)
            launch.master_pidfd = master_pidfd
            launch.origin_pidfd = origin_pidfd
            launch.pidfd = owner_shell_pidfd
            launch.process = SimpleNamespace(poll=lambda: None)
            launch.python = SimpleNamespace(path=sys.executable)
            launch.creator_pid = os.getpid()
            launch.creator_start = attach_module._start_ticks(os.getpid())
            launch.nonce = nonce
            launch.epoch = 42
            launch.deadline_ns = deadline_ns
            launch.output = '/private/source-attach-two-ready-model'
            launch.artifact_binding = SimpleNamespace(
                config_sha256='31' * 32, ini_sha256='42' * 32)
            launch.origin_proof = object()
            launch.live_supervisor = lambda _deadline: None

            client = SourceAttachment(launch,
                revoke_native_auth=lambda: revoked.append('revoked'))
            helper_process = client.helper
            client.attach(timeout=2.0)
            owner_watch = {'pid': owner_pid, 'tid': owner_pid, 'role': 0,
                'start': owner_start, 'slot_device': 101, 'slot_inode': 202,
                'cookie': 303, 'pidfd': owner_pidfd}
            os.write(owner_trigger_w, b'r')
            owner_identity, owner_ready_pidfd = client.receive_owner_ready(
                owner_watch, ready_receiver, timeout=2.0)
            self.assertEqual(owner_ready_pidfd, client.ready[1])
            self.assertEqual(owner_identity[3], 0)
            retained_owner = client.ready

            candidate_watch = {'pid': candidate_pid, 'tid': candidate_pid,
                'role': 1, 'start': candidate_start, 'slot_device': 404,
                'slot_inode': 505, 'cookie': 606, 'pidfd': candidate_pidfd}
            os.write(candidate_trigger_w, b'r')
            candidate_identity, candidate_ready_pidfd = \
                client.receive_first_candidate_ready(candidate_watch,
                    ready_receiver, timeout=2.0)
            self.assertEqual(candidate_ready_pidfd, client.candidate_ready[1])
            self.assertEqual(candidate_identity[3], 1)
            self.assertIs(client.ready, retained_owner)
            self.assertTrue(client.check())
            duplicate_watch_body = wire.SOURCE_WATCH_BODY.pack(
                candidate_pid, candidate_pid, 1, 0, candidate_start,
                404, 505, 606)
            duplicate_watch = wire.pack_record(wire.SOURCE_WATCH,
                duplicate_watch_body, nonce, 42, client.sequence)
            client.channel.sendmsg([duplicate_watch], [(socket.SOL_SOCKET,
                socket.SCM_RIGHTS, array.array('i',
                    (ready_receiver.fileno(), candidate_pidfd)))])
            helper_process.wait(timeout=2.0)
            self.assertNotEqual(helper_process.returncode, 0,
                'helper accepted a third role-1 watch on the same observer session')
            with self.assertRaises(RuntimeError):
                client.receive_first_candidate_ready(candidate_watch,
                    ready_receiver, timeout=2.0)
            self.assertEqual(revoked, ['revoked'])
            self.assertIsNotNone(helper_process.returncode)
            self.assertTrue(attach_module._alive(master_pidfd),
                'observer duplicate rejection changed original master lifecycle')
        finally:
            if client is not None:
                client.close()
            for fd, value in ((owner_release_w, b'x'),
                    (candidate_release_w, b'x'), (master_ctl_w, b'x')):
                try: os.write(fd, value)
                except OSError: pass
            for fd in (started_r, owner_trigger_w, candidate_trigger_w,
                    owner_release_w, candidate_release_w, master_ctl_r, master_ctl_w):
                try: os.close(fd)
                except OSError: pass
            try: ready_receiver.close()
            except OSError: pass
            for fd in (master_pidfd, owner_pidfd, candidate_pidfd,
                    origin_pidfd, owner_shell_pidfd):
                if fd >= 0:
                    try: os.close(fd)
                    except OSError: pass
            if master_pid > 0:
                os.waitpid(master_pid, 0)

    def test_candidate_ready_receiver_rejects_role1_path_negative_controls(self):
        """Exercise role-1 credentialed READY parsing against a live master child."""
        baseline_fds = len(os.listdir('/proc/self/fd'))
        baseline_children = set(helper.direct_children())
        master_pid = os.getpid()
        master_pidfd = os.pidfd_open(master_pid, 0)
        master_start = attach_module._start_ticks(master_pid)
        master_hash = helper.sha256_file(f'/proc/{master_pid}/exe')
        nonce = b'role1-negative01'
        expected_slot = (707, 808)
        expected_cookie = 909
        cases = ('wrong_slot', 'wrong_cookie', 'wrong_role', 'wrong_pidfd',
            'wrong_sequence', 'extra_fd', 'late', 'eof', 'wrong_credentials')

        for case in cases:
            with self.subTest(case=case):
                receiver, sender = socket.socketpair(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET)
                receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                trigger_r, trigger_w = os.pipe()
                release_r, release_w = os.pipe()
                started_r, started_w = os.pipe()
                worker_pid = os.fork()
                if worker_pid == 0:
                    try:
                        receiver.close()
                        os.close(trigger_w); os.close(release_w); os.close(started_r)
                        worker_start = attach_module._start_ticks(os.getpid())
                        os.write(started_w, struct.pack('=Q', worker_start))
                        os.close(started_w)
                        if os.read(trigger_r, 1) != b'r':
                            os._exit(80)
                        if case == 'eof':
                            sender.close()
                        else:
                            if case == 'late':
                                time.sleep(0.08)
                            actual_role = 0 if case == 'wrong_role' else 1
                            actual_slot = ((expected_slot[0] + 1,
                                expected_slot[1]) if case == 'wrong_slot' else expected_slot)
                            actual_cookie = (expected_cookie + 1
                                if case == 'wrong_cookie' else expected_cookie)
                            record = helper.OWNER_READY_RECORD.pack(
                                helper.OWNER_READY_MAGIC, helper.OWNER_READY_VERSION,
                                helper.OWNER_READY_RECORD.size, actual_role, 0,
                                actual_slot[0], actual_slot[1], worker_start,
                                os.getpid(), os.getpid(), actual_cookie, 0)
                            sequence = 4 if case == 'wrong_sequence' else 3
                            packet = wire.pack_record(wire.OWNER_READY, record,
                                nonce, 17, sequence)
                            passed = array.array('i', [
                                os.pidfd_open(os.getpid(), 0)
                                if case != 'wrong_pidfd' else master_pidfd])
                            if case == 'extra_fd':
                                passed.append(passed[0])
                            sender.sendmsg([packet], [(socket.SOL_SOCKET,
                                socket.SCM_RIGHTS, passed)])
                            if case != 'wrong_pidfd' and case != 'extra_fd':
                                os.close(passed[0])
                            elif case == 'extra_fd':
                                os.close(passed[0])
                            if case == 'wrong_pidfd':
                                # The borrowed master PIDFD belongs to the parent.
                                pass
                        os.close(trigger_r)
                        os.read(release_r, 1)
                        os._exit(0)
                    except BaseException:
                        os._exit(81)
                os.close(trigger_r); os.close(release_r); os.close(started_w)
                worker_pidfd = -1
                try:
                    start_bytes = b''
                    while len(start_bytes) < 8:
                        start_bytes += os.read(started_r, 8 - len(start_bytes))
                    worker_start, = struct.unpack('=Q', start_bytes)
                    worker_pidfd = os.pidfd_open(worker_pid, 0)
                    expected = (worker_pid, os.getuid(), os.getgid(), 1,
                        worker_pid, 0, worker_start, expected_slot[0],
                        expected_slot[1], expected_cookie)
                    os.write(trigger_w, b'r')
                    deadline_ns = time.monotonic_ns() + 2_000_000_000
                    if case == 'late':
                        deadline_ns = time.monotonic_ns() + 20_000_000
                    credential = ((worker_pid, os.getuid(), os.getgid())
                        if case != 'wrong_credentials' else
                        (worker_pid + 1000000, os.getuid(), os.getgid()))
                    if case == 'wrong_credentials':
                        # Send from the test process so SCM_CREDENTIALS cannot
                        # accidentally match the expected candidate identity.
                        worker_start = attach_module._start_ticks(worker_pid)
                        body = helper.OWNER_READY_RECORD.pack(
                            helper.OWNER_READY_MAGIC, helper.OWNER_READY_VERSION,
                            helper.OWNER_READY_RECORD.size, 1, 0,
                            expected_slot[0], expected_slot[1], worker_start,
                            worker_pid, worker_pid, expected_cookie, 0)
                        sender.send(wire.pack_record(wire.OWNER_READY, body,
                            nonce, 17, 3))
                    with self.assertRaises((PermissionError, ValueError,
                            TimeoutError, ConnectionError)):
                        helper.receive_attached_owner_ready(receiver,
                            nonce=nonce, epoch=17, sequence=3,
                            expected_credential=credential,
                            expected_identity=expected,
                            expected_worker_pidfd=worker_pidfd,
                            worker_binary_hash=master_hash,
                            master_pidfd=master_pidfd, master_pid=master_pid,
                            master_start=master_start,
                            owner_pidfd=master_pidfd, owner_pid=master_pid,
                            owner_start=master_start,
                            deadline_ns=deadline_ns, expected_role=1)
                finally:
                    for fd, value in ((release_w, b'x'),):
                        try: os.write(fd, value)
                        except OSError: pass
                    for fd in (trigger_w, release_w, started_r, worker_pidfd):
                        if fd >= 0:
                            try: os.close(fd)
                            except OSError: pass
                    receiver.close(); sender.close()
                    try: os.waitpid(worker_pid, 0)
                    except ChildProcessError: pass
        os.close(master_pidfd)
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline_fds,
            'role-1 negative controls leaked descriptors')
        self.assertEqual(set(helper.direct_children()), baseline_children,
            'role-1 negative controls leaked child processes')

    def test_candidate_watch_order_and_identity_fail_before_send(self):
        owner_pid = os.getpid()
        owner_pidfd = os.pidfd_open(owner_pid, 0)
        owner_start = attach_module._start_ticks(owner_pid)
        context = object()
        launch = SimpleNamespace(context=context,
            deadline_ns=time.monotonic_ns() + 1_000_000_000)

        class SendSpy:
            calls = 0
            def sendmsg(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError('invalid candidate watch reached sendmsg')

        def client_stub(ready):
            client = object.__new__(SourceAttachment)
            client.attached = True
            client.launch = launch
            client.context = context
            client.owner_pid = owner_pid
            client.owner_start = owner_start
            client.owner_pidfd = owner_pidfd
            client.ready = ready
            client.candidate_ready = None
            client._candidate_watch_attempted = False
            client.nonce = b'candidate-order01'
            client.epoch = 19
            client.sequence = 3
            client.channel = SendSpy()
            client._fail_observation = lambda: None
            return client

        receiver, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            base_watch = {'pid': owner_pid, 'tid': owner_pid, 'role': 1,
                'start': owner_start, 'slot_device': 1, 'slot_inode': 2,
                'cookie': 3, 'pidfd': owner_pidfd}
            role1_first = client_stub(None)
            with self.assertRaises(RuntimeError):
                role1_first.receive_first_candidate_ready(base_watch, receiver)
            self.assertEqual(role1_first.channel.calls, 0)

            wrong_role = client_stub((('role0-proof',), owner_pidfd))
            bad_role_watch = dict(base_watch, role=0)
            with self.assertRaises(ValueError):
                wrong_role.receive_first_candidate_ready(bad_role_watch, receiver)
            self.assertEqual(wrong_role.channel.calls, 0)

            wrong_pidfd = client_stub((('role0-proof',), owner_pidfd))
            bad_pidfd_watch = dict(base_watch, pid=owner_pid + 1,
                tid=owner_pid + 1)
            with self.assertRaises((ProcessLookupError, PermissionError, OSError)):
                wrong_pidfd.receive_first_candidate_ready(bad_pidfd_watch, receiver)
            self.assertEqual(wrong_pidfd.channel.calls, 0)
        finally:
            receiver.close(); peer.close(); os.close(owner_pidfd)

    def test_attach_paths_have_no_master_lifecycle_calls(self):
        tree = ast.parse(HELPER_PATH.read_text(encoding='utf-8'))
        attach_names = {'serve_attached_session', 'receive_attached_owner_ready'}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name in attach_names]
        self.assertEqual({node.name for node in nodes}, attach_names)
        forbidden = {'Popen', 'wait', 'waitpid', 'send_signal',
            'pidfd_send_signal', 'settle_descendants', 'signal_master_and_settle'}
        calls = {node.func.id if isinstance(node.func, ast.Name) else
            node.func.attr if isinstance(node.func, ast.Attribute) else ''
            for function in nodes for node in ast.walk(function)
            if isinstance(node, ast.Call)}
        self.assertFalse(calls & forbidden)

    def test_attach_hash_stops_at_absolute_deadline(self):
        with tempfile.NamedTemporaryFile() as source:
            with mock.patch.object(attach_module.time, 'monotonic_ns',
                    side_effect=(1, 101)):
                with self.assertRaises(TimeoutError):
                    attach_module._sha256(source.name, deadline_ns=100)

    def test_close_revokes_before_wait_and_cleans_if_callback_raises(self):
        attachment = object.__new__(SourceAttachment)
        order = []
        owner_fd = os.open('/dev/null', os.O_RDONLY)
        ready_fd = os.open('/dev/null', os.O_RDONLY)
        helper_pidfd = os.pidfd_open(os.getpid(), 0)
        channel, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

        class DelayedHelper:
            def wait(self, timeout):
                order.append(('wait', timeout))
                return 0

        attachment.ready = ((1,), ready_fd)
        attachment.owner_pidfd = owner_fd
        attachment.helper_pidfd = helper_pidfd
        attachment.child_channel = None
        attachment.channel = channel
        attachment.helper = DelayedHelper()
        attachment.attached = True
        attachment._revoked = False
        def revoke():
            order.append('revoke')
            raise RuntimeError('revocation callback failure')
        attachment.revoke_native_auth = revoke
        try:
            with self.assertRaisesRegex(RuntimeError, 'revocation callback failure'):
                attachment.close()
            self.assertEqual(order[0], 'revoke')
            self.assertEqual(order[1][0], 'wait')
            self.assertFalse(attachment.attached)
            self.assertEqual(attachment.owner_pidfd, -1)
            self.assertEqual(attachment.helper_pidfd, -1)
            self.assertIsNone(attachment.channel)
            with self.assertRaises(OSError):
                os.fstat(ready_fd)
        finally:
            peer.close()

    def test_constructor_allocation_failure_revokes_and_restores_fds(self):
        before = len(os.listdir('/proc/self/fd'))
        real_hash = attach_module._sha256
        def fail_helper_hash(path, **kwargs):
            if Path(path).name == 'ker-nginx-companion.py':
                raise OSError('injected helper hash failure')
            return real_hash(path, **kwargs)
        failures = (
            ('helper path', nullcontext(), FileNotFoundError,
                'No such file', {'helper_path': '/missing/attach-helper.py'}),
            ('helper hash', mock.patch.object(attach_module, '_sha256',
                side_effect=fail_helper_hash), OSError, 'helper hash failure', {}),
            ('socketpair', mock.patch.object(attach_module.socket, 'socketpair',
                side_effect=OSError('injected socketpair failure')),
                OSError, 'socketpair failure', {}),
            ('Popen', mock.patch.object(attach_module.subprocess, 'Popen',
                side_effect=OSError('injected Popen failure')),
                OSError, 'Popen failure', {}),
        )
        for label, patcher, error_type, message, kwargs in failures:
            with self.subTest(stage=label):
                launch, launch_fds = self._accepted_origin_model()
                revoked = []
                try:
                    with patcher:
                        with self.assertRaisesRegex(error_type, message):
                            SourceAttachment(launch,
                                revoke_native_auth=lambda: revoked.append(True),
                                **kwargs)
                    self.assertEqual(revoked, [True])
                finally:
                    attach_module._close_fds(launch_fds)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_post_popen_failure_retains_delayed_helper_and_revokes_first(self):
        before = len(os.listdir('/proc/self/fd'))
        launch, launch_fds = self._accepted_origin_model()
        revoked = []
        with tempfile.TemporaryDirectory() as directory:
            helper_path = Path(directory) / 'delayed_observer.py'
            helper_path.write_text('import time\ntime.sleep(3.0)\n', encoding='utf-8')
            real_pidfd_open = os.pidfd_open
            def fail_helper_pidfd(pid, flags=0):
                if pid != os.getpid():
                    raise OSError('injected post-Popen pidfd failure')
                return real_pidfd_open(pid, flags)
            try:
                with mock.patch.object(attach_module.os, 'pidfd_open',
                        side_effect=fail_helper_pidfd):
                    with self.assertRaises(attach_module.AttachObserverUnsettled) as raised:
                        SourceAttachment(launch, helper_path=helper_path,
                            revoke_native_auth=lambda: revoked.append('revoked'))
                observer = raised.exception.attachment
                self.assertEqual(revoked, ['revoked'])
                self.assertIsNone(observer.channel)
                self.assertEqual(observer.owner_pidfd, -1)
                observer.helper.wait(timeout=3.0)
                if observer.helper_pidfd >= 0:
                    os.close(observer.helper_pidfd)
                    observer.helper_pidfd = -1
            finally:
                attach_module._close_fds(launch_fds)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_delayed_ready_hash_cannot_outlive_absolute_grant(self):
        baseline = len(os.listdir('/proc/self/fd'))
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        pid = os.getpid()
        parent_pid = os.getppid()
        worker_pidfd = os.pidfd_open(pid, 0)
        master_pidfd = os.pidfd_open(parent_pid, 0)
        owner_pidfd = os.dup(worker_pidfd)
        ready_pidfd = os.dup(worker_pidfd)
        start = attach_module._start_ticks(pid)
        parent_start = attach_module._start_ticks(parent_pid)
        identity = (pid, os.getuid(), os.getgid(), 0, pid, 0, start, 101, 202, 303)
        nonce, epoch, sequence = b'ready-delay-0001', 9, 2
        packet = wire.pack_record(wire.OWNER_READY,
            wire.OWNER_READY_BODY.pack(*identity), nonce, epoch, sequence)
        sender.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            struct.pack('i', ready_pidfd))])
        deadline_ns = time.monotonic_ns() + 15_000_000
        def delayed_hash(_path, *, deadline_ns, maximum=256 * 1024 * 1024):
            time.sleep(0.03)
            return helper.sha256_file(f'/proc/{pid}/exe')
        try:
            with mock.patch.object(helper, 'sha256_file_bounded', side_effect=delayed_hash):
                with self.assertRaises((TimeoutError, PermissionError)):
                    helper.receive_attached_owner_ready(receiver, nonce=nonce,
                        epoch=epoch, sequence=sequence,
                        expected_credential=(pid, os.getuid(), os.getgid()),
                        expected_identity=identity, expected_worker_pidfd=worker_pidfd,
                        worker_binary_hash=helper.sha256_file(f'/proc/{pid}/exe'),
                        master_pidfd=master_pidfd, master_pid=parent_pid,
                        master_start=parent_start, owner_pidfd=owner_pidfd,
                        owner_pid=pid, owner_start=start, deadline_ns=deadline_ns)
        finally:
            sender.close(); receiver.close()
            attach_module._close_fds((worker_pidfd, master_pidfd, owner_pidfd, ready_pidfd))
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline)

    def test_final_ready_hashes_cannot_outlive_short_request(self):
        """The caller request bound also covers the final executable hashes."""
        worker_pid = os.fork()
        if worker_pid == 0:
            time.sleep(2.0)
            os._exit(0)
        channel, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver, receiver_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        master_pidfd = os.pidfd_open(os.getpid(), 0)
        owner_pidfd = os.dup(master_pidfd)
        worker_pidfd = os.pidfd_open(worker_pid, 0)
        ready_pidfd = os.dup(worker_pidfd)
        binary_hash = helper.sha256_file(f'/proc/{os.getpid()}/exe')
        master_start = attach_module._start_ticks(os.getpid())
        worker_start = attach_module._start_ticks(worker_pid)
        nonce = b'ready-final-hash'
        launch_deadline = time.monotonic_ns() + 5_000_000_000
        launch = SimpleNamespace(
            deadline_ns=launch_deadline,
            live_supervisor=lambda _deadline: None)
        launch.context = launch
        attachment = object.__new__(SourceAttachment)
        attachment.attached = True
        attachment.ready = None
        attachment.launch = launch
        attachment.context = launch
        attachment.master_pidfd = master_pidfd
        attachment.master_pid = os.getpid()
        attachment.master_start = master_start
        attachment.owner_pidfd = owner_pidfd
        attachment.owner_pid = os.getpid()
        attachment.owner_start = master_start
        attachment.helper_pid = os.getpid()
        attachment.binary_hash = binary_hash
        attachment.nonce = nonce
        attachment.epoch = 12
        attachment.sequence = 4
        attachment.channel = channel
        expected = (worker_pid, os.getuid(), os.getgid(), 0, worker_pid, 0,
            worker_start, 101, 202, 303)
        request_deadlines = []
        real_hash = attach_module._sha256

        def slow_hash(path, *, deadline_ns, maximum=256 * 1024 * 1024):
            request_deadlines.append(deadline_ns)
            time.sleep(0.06)
            return real_hash(path, deadline_ns=launch_deadline, maximum=maximum)

        fake_helper = SimpleNamespace(receive_attached_owner_ready=lambda *args,
            deadline_ns, **kwargs: (expected, ready_pidfd))
        fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _module: None))
        watch = {'pid': worker_pid, 'tid': worker_pid, 'role': 0,
            'start': worker_start, 'slot_device': 101, 'slot_inode': 202,
            'cookie': 303, 'pidfd': worker_pidfd}
        try:
            with mock.patch.object(attach_module.importlib.util,
                    'spec_from_file_location', return_value=fake_spec), \
                    mock.patch.object(attach_module.importlib.util,
                        'module_from_spec', return_value=fake_helper), \
                    mock.patch.object(attach_module, '_sha256', side_effect=slow_hash):
                with self.assertRaises((TimeoutError, PermissionError)):
                    attachment._receive_owner_ready(watch, receiver, timeout=0.1)
            self.assertGreaterEqual(len(request_deadlines), 1)
            self.assertTrue(all(deadline < launch_deadline
                for deadline in request_deadlines))
            self.assertIsNone(attachment.ready,
                'READY must not be stored after its shorter caller request expires')
        finally:
            for sock in (channel, peer, receiver, receiver_peer):
                sock.close()
            attach_module._close_fds((master_pidfd, owner_pidfd, worker_pidfd))
            try:
                os.waitpid(worker_pid, 0)
            except ChildProcessError:
                pass

    def test_modeled_attach_transfers_real_ready_and_detach_only_revokes(self):
        """Exercise wire creds/FDs and a real forked master-child READY model.

        This process fixture validates the adapter protocol only; it is not an
        original Nginx run or a source-shell qualification claim.
        """
        ready_receiver, ready_sender = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET)
        ready_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        trigger_r, trigger_w = os.pipe()
        release_r, release_w = os.pipe()
        started_r, started_w = os.pipe()
        master_ctl_r, master_ctl_w = os.pipe()
        master_pid = os.fork()
        if master_pid == 0:
            try:
                os.close(started_r); os.close(master_ctl_w)
                os.close(trigger_w); os.close(release_w)
                os.close(ready_receiver.fileno())
                worker_pid = os.fork()
                if worker_pid == 0:
                    try:
                        os.close(master_ctl_r)
                        start = attach_module._start_ticks(os.getpid())
                        os.write(started_w,
                            f'{os.getpid()} {start}'.encode('ascii'))
                        os.close(started_w)
                        if os.read(trigger_r, 1) != b'r':
                            os._exit(93)
                        ready = helper.OWNER_READY_RECORD.pack(
                            helper.OWNER_READY_MAGIC, helper.OWNER_READY_VERSION,
                            helper.OWNER_READY_RECORD.size, 0, 0, 101, 202,
                            start, os.getpid(), os.getpid(), 303, 0)
                        ready_sender.sendmsg([ready])
                        if os.read(release_r, 1) != b'x':
                            os._exit(94)
                        os._exit(0)
                    except BaseException:
                        os._exit(91)
                os.close(started_w); os.close(trigger_r); os.close(release_r)
                ready_sender.close()
                while os.read(master_ctl_r, 1) != b'x':
                    pass
                os._exit(0)
            except BaseException:
                os._exit(92)
        os.close(trigger_r); os.close(release_r); os.close(started_w)
        ready_sender.close()
        worker_pidfd = master_pidfd = origin_pidfd = owner_shell_pidfd = -1
        client = None
        revoked = []
        try:
            worker_pid, worker_start = map(int,
                os.read(started_r, 64).decode('ascii').split())
            master_pidfd = os.pidfd_open(master_pid, 0)
            worker_pidfd = os.pidfd_open(worker_pid, 0)
            origin_pidfd = os.dup(master_pidfd)
            owner_shell_pidfd = os.dup(master_pidfd)
            binary_hash = helper.sha256_file(f'/proc/{master_pid}/exe')
            nonce = b'attach-model-001'
            deadline_ns = time.monotonic_ns() + 20_000_000_000
            master = SimpleNamespace(pid=master_pid, pidfd=master_pidfd,
                start_ticks=attach_module._start_ticks(master_pid),
                executable_hash=binary_hash)
            launch = object.__new__(origin_module.OriginalShellLaunch)
            launch.consumed = True
            launch.context = SimpleNamespace(master=master, binary_hash=binary_hash,
                nonce=nonce, epoch=41, deadline_ns=deadline_ns)
            launch.master_pidfd = master_pidfd
            launch.origin_pidfd = origin_pidfd
            launch.pidfd = owner_shell_pidfd
            launch.process = SimpleNamespace(poll=lambda: None)
            launch.python = SimpleNamespace(path=sys.executable)
            launch.creator_pid = os.getpid()
            launch.creator_start = attach_module._start_ticks(os.getpid())
            launch.nonce = nonce
            launch.epoch = 41
            launch.deadline_ns = deadline_ns
            launch.output = '/private/source-origin-model'
            launch.artifact_binding = SimpleNamespace(
                config_sha256='11' * 32, ini_sha256='22' * 32)
            launch.origin_proof = object()
            launch.live_supervisor = lambda _deadline: None

            client = SourceAttachment(launch,
                revoke_native_auth=lambda: revoked.append('revoked'))
            helper_process = client.helper
            attached = client.attach(timeout=2.0)
            self.assertEqual(attached[0], os.getpid())
            watch = {'pid': worker_pid, 'tid': worker_pid, 'role': 0,
                'start': worker_start, 'slot_device': 101, 'slot_inode': 202,
                'cookie': 303, 'pidfd': worker_pidfd}
            os.write(trigger_w, b'r')
            identity, received_worker_pidfd = client.receive_owner_ready(
                watch, ready_receiver, timeout=2.0)
            self.assertEqual(identity[0], worker_pid)
            self.assertEqual(received_worker_pidfd, client.ready[1])
            self.assertTrue(client.check())
            os.write(release_w, b'x')
            poller = select.poll()
            poller.register(worker_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            self.assertTrue(poller.poll(2000), 'modeled owner worker did not exit')
            with self.assertRaises((ProcessLookupError, FileNotFoundError)):
                client.check()
            self.assertEqual(revoked, ['revoked'])
            self.assertIsNotNone(helper_process.returncode,
                'attach-only helper was not reaped after actor death')
            self.assertTrue(attach_module._alive(master_pidfd),
                'observer failure changed the original master lifecycle')
        finally:
            if client is not None:
                client.close()
            for fd in (started_r, trigger_w, release_w, master_ctl_r):
                try: os.close(fd)
                except OSError: pass
            for sock in (ready_receiver, ready_sender):
                try: sock.close()
                except OSError: pass
            for fd in (master_pidfd, worker_pidfd, origin_pidfd, owner_shell_pidfd):
                if fd >= 0:
                    try: os.close(fd)
                    except OSError: pass
            if master_pid > 0:
                try:
                    os.write(master_ctl_w, b'x')
                except OSError:
                    pass
                os.close(master_ctl_w)
                os.waitpid(master_pid, 0)

if __name__ == '__main__':
    unittest.main()
