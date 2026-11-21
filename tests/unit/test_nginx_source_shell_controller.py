import importlib.util
import errno
import ipaddress
import json
import array
import fcntl
import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import sys
import subprocess
import tempfile
import threading
import time
from types import MethodType, SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
KER_RUN_PATH = ROOT / 'tools' / 'ker-run.py'
SPEC = importlib.util.spec_from_file_location('ker_run_source_controller_test', KER_RUN_PATH)
ker_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ker_run)


class BrokerPrivateStopFaultTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            's2b_broker_readiness_supervisor', ROOT / 'tools' / 'broker_readiness_supervisor.py')
        self.broker_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.broker_module)
        self.wire = self.broker_module.wire

    def _broker(self, *, fail_send=None, short_send=False):
        module = self.broker_module
        broker = object.__new__(module.BrokerReadiness)
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.addCleanup(parent.close)
        self.addCleanup(child.close)

        class TrackedSocket:
            def __init__(self, sock):
                self.sock = sock
                self.sends = 0
                self.receives = 0
                self.received_fds = []
            def fileno(self):
                return self.sock.fileno()
            def send(self, data, flags=0):
                self.sends += 1
                if fail_send == 'blocking':
                    raise BlockingIOError()
                if short_send:
                    return max(0, len(data) - 1)
                return self.sock.send(data, flags)
            def recvmsg(self, *args, **kwargs):
                self.receives += 1
                packet = self.sock.recvmsg(*args, **kwargs)
                for level, kind, payload in packet[1]:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        values = array.array('i')
                        values.frombytes(payload[:len(payload) // values.itemsize * values.itemsize])
                        self.received_fds.extend(values)
                return packet
        tracked = TrackedSocket(parent)
        broker.parent, broker.child = tracked, child
        broker.app = module._identity(os.getpid())
        broker.app_pidfd = os.pidfd_open(os.getpid(), 0)
        self.addCleanup(os.close, broker.app_pidfd)
        broker.nonce, broker.epoch = b'Q' * 16, 41
        broker.supervisor = module._identity(os.getpid())
        broker.ready, broker.stopped, broker.stop_attempted = True, False, True
        broker._private_stop_authorization_consumed = True
        deadline_ns = time.monotonic_ns() + 5_000_000_000
        authorization = SimpleNamespace(deadline_ns=deadline_ns,
            pending=SimpleNamespace(deadline_ns=deadline_ns))
        broker._private_stop_authorization = authorization
        broker._private_stop_authorization_live = lambda _authorization: True
        request = self.wire.pack_stop(self.wire.STOP, broker.nonce, broker.epoch,
            *broker.supervisor[:3], broker.supervisor[3])
        broker._stop = {'record': request,
            'deadline': deadline_ns / 1_000_000_000,
            'sent': fail_send is None and not short_send,
            'send_attempted': fail_send is None and not short_send,
            'private': True, 'authorization': authorization}
        broker._private_stop_ack_receipt = None
        broker._private_stop_ack_registry = {}
        return broker, tracked, child, authorization

    def test_private_stop_send_failures_are_consumed_and_never_replayed(self):
        for failure, short in (('blocking', False), (None, True)):
            with self.subTest(failure=failure, short=short):
                broker, tracked, _child, _authorization = self._broker(
                    fail_send=failure, short_send=short)
                request = broker._stop
                with self.assertRaises((BlockingIOError, OSError)):
                    broker.poll_stop()
                self.assertTrue(request['unresolved'])
                self.assertTrue(request['send_attempted'])
                sends, receives = tracked.sends, tracked.receives
                with self.assertRaises(ConnectionError):
                    broker.poll_stop()
                self.assertEqual((tracked.sends, tracked.receives), (sends, receives))

    def test_private_stop_rejects_bad_ack_and_closes_unexpected_rights(self):
        module = self.broker_module
        cases = ('nonce', 'epoch', 'identity', 'extra_rights', 'late')
        for fault in cases:
            with self.subTest(fault=fault):
                broker, tracked, child, authorization = self._broker()
                nonce = broker.nonce if fault != 'nonce' else b'X' * 16
                epoch = broker.epoch if fault != 'epoch' else broker.epoch + 1
                supervisor = broker.supervisor
                if fault == 'identity':
                    supervisor = (supervisor[0] + 1, *supervisor[1:])
                packet = self.wire.pack_stop(self.wire.STOP_ACK, nonce, epoch,
                    *supervisor[:3], supervisor[3])
                passed_fd = None
                if fault == 'extra_rights':
                    passed_fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
                    rights = array.array('i', (passed_fd,))
                    child.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                else:
                    child.send(packet)
                if fault == 'late':
                    with mock.patch.object(module.time, 'monotonic_ns',
                            side_effect=[authorization.deadline_ns - 1,
                                authorization.deadline_ns + 1]):
                        with self.assertRaises((PermissionError, TimeoutError)):
                            broker.poll_stop()
                else:
                    with self.assertRaises((PermissionError, ValueError)):
                        broker.poll_stop()
                self.assertTrue(broker._stop['unresolved'])
                self.assertIsNone(broker._private_stop_ack_receipt)
                self.assertEqual(broker._private_stop_ack_registry, {})
                reads = tracked.receives
                with self.assertRaises(ConnectionError):
                    broker.poll_stop()
                self.assertEqual(tracked.receives, reads,
                    'an unresolved ACK must not permit another packet read')
                if passed_fd is not None:
                    os.close(passed_fd)
                    self.assertEqual(len(tracked.received_fds), 1)
                    with self.assertRaises(OSError):
                        fcntl.fcntl(tracked.received_fds[0], fcntl.F_GETFD)


class SourceShellMainGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._c31_formatter_directory = tempfile.TemporaryDirectory(
            prefix='s4c-c31-formatter-')
        binary = Path(cls._c31_formatter_directory.name) / 'line'
        subprocess.run(['/usr/bin/cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
            '-I', str(ROOT / 'src' / 'posix'),
            str(ROOT / 'tests' / 'posix' / 'c31-shutdown-line-host.c'),
            '-o', str(binary)], check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        cls.c31_formatter_binary = binary

    @classmethod
    def tearDownClass(cls):
        cls._c31_formatter_directory.cleanup()

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
    def test_private_postcommit_old_exit_observation_uses_held_pidfds_not_attachment_check(self):
        self._exercise_private_postcommit_stop(live_run_stop=False)

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
    def test_private_run_stop_validates_io_before_releasing_waiting_app(self):
        self._exercise_private_postcommit_stop(live_run_stop=True)

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
    def test_private_run_stop_with_mismatched_io_receipt_keeps_app_waiting(self):
        self._exercise_private_postcommit_stop(live_run_stop=True, corrupt_io=True)

    def _exercise_private_postcommit_stop(self, *, live_run_stop, corrupt_io=False):
        module = ker_run._load_source_shell_controller()
        attach = module._attach_module()
        origin_name = '_ker_nginx_source_origin'
        origin = sys.modules.get(origin_name)
        if origin is None:
            origin_spec = importlib.util.spec_from_file_location(origin_name,
                ROOT / 'tools' / 'nginx_source_origin.py')
            origin = importlib.util.module_from_spec(origin_spec)
            sys.modules[origin_name] = origin
            origin_spec.loader.exec_module(origin)
        boot = origin.bootstrap
        sys.modules.setdefault(boot.__name__, boot)
        profile_module = module._c34_profile_module()
        artifacts_module = profile_module._provider()
        if not artifacts_module._BUILD_MANIFEST.exists():
            self.skipTest('fixed C34 artifact build manifest is unavailable')
        artifact_capture = artifacts_module.PrivateC34ArtifactCapture.capture(
            time.monotonic_ns() + 60_000_000_000)
        self.addCleanup(artifact_capture.close)
        old = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.05)'])
        candidate_socket_dir = tempfile.TemporaryDirectory(prefix='s1b-candidate-')
        self.addCleanup(candidate_socket_dir.cleanup)
        candidate_listener = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(candidate_listener.close)
        candidate_listener.bind(str(Path(candidate_socket_dir.name) / 'worker.sock'))
        candidate_listener.listen(1)
        candidate_relay, relay_anchor = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        self.addCleanup(relay_anchor.close)
        self.addCleanup(candidate_relay.close)
        candidate_code = r'''
import os
import socket
import struct
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as bootstrap:
    bootstrap.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    bootstrap.connect(sys.argv[1])
    print("ready", flush=True)
    request = bytes.fromhex(sys.stdin.readline().strip())
    bootstrap.send(request)
    response, ancillary, flags, _ = bootstrap.recvmsg(361, socket.CMSG_SPACE(12))
    assert not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
    assert ancillary == [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,
                          struct.pack('=3i', os.getppid(), os.getuid(), os.getgid()))]
    magic, version, _, _, _ = struct.unpack('=IHHII', request[:16])
    assert response == (struct.pack('=IHHII', magic, version, 11, 360, 0) +
                        request + struct.pack('=IIQQiI', 0, 0, 0, 37, 0, 1))
    with socket.socket(fileno=int(sys.argv[2])) as relay:
        relay.settimeout(1.0)
        assert relay.recv(1) == b''
    print("settled", flush=True)
'''
        candidate = subprocess.Popen([sys.executable, '-c', candidate_code,
            str(Path(candidate_socket_dir.name) / 'worker.sock'),
            str(candidate_relay.fileno())], pass_fds=(candidate_relay.fileno(),),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        candidate_relay.close()
        self.addCleanup(candidate.stdin.close)
        self.addCleanup(candidate.stdout.close)
        self.assertEqual(candidate.stdout.readline(), 'ready\n')
        self.addCleanup(self.cleanup_app, old)
        self.addCleanup(self.cleanup_app, candidate)
        old_fds = [os.pidfd_open(old.pid, 0) for _ in range(3)]
        candidate_fds = [os.pidfd_open(candidate.pid, 0) for _ in range(3)]
        current_fd = os.pidfd_open(os.getpid(), 0)
        for fd in old_fds + candidate_fds + [current_fd]:
            self.addCleanup(os.close, fd)
        old_start = ker_run.process_start_ticks(old.pid)
        old.wait(timeout=2)
        candidate_start = ker_run.process_start_ticks(candidate.pid)
        old_ready = (old.pid, 0, 0, 0, old.pid, 0, old_start, 101, 201, 301)
        candidate_ready = (candidate.pid, 0, 0, 1, candidate.pid, 0,
            candidate_start, 102, 202, 302)
        proof = object()
        old_record = [0] * 35
        old_record[5], old_record[6], old_record[8], old_record[9] = (
            old.pid, old.pid, 0, 0)
        old_record[11], old_record[24], old_record[25], old_record[27] = (
            old_start, 101, 201, 301)
        candidate_record = [0] * 35
        candidate_record[5], candidate_record[6], candidate_record[8], candidate_record[9] = (
            candidate.pid, candidate.pid, 1, 1)
        candidate_record[11], candidate_record[24], candidate_record[25], candidate_record[27] = (
            candidate_start, 102, 202, 302)
        old_channel, old_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        candidate_channel, _candidate_child_endpoint = candidate_listener.accept()
        candidate_channel.setblocking(False)

        class CandidateSender:
            def send(self, packet):
                candidate.stdin.write(packet.hex() + '\n')
                candidate.stdin.flush()

        candidate_peer = CandidateSender()
        attachment_channel, attachment_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        for endpoint in (old_channel, old_peer, candidate_channel,
                attachment_channel, attachment_peer):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            self.addCleanup(endpoint.close)
        context = object.__new__(boot.SourceBootstrapSupervisor)
        context.control_only = True
        context.workers = {(0, 0): (old_fds[0], tuple(old_record)),
            (1, 1): (candidate_fds[0], tuple(candidate_record))}
        context.worker_channels = {(0, 0): old_channel, (1, 1): candidate_channel}
        context._completed_retirements = {}
        context.worker_process_slots = {(0, 0): 7, (1, 1): 8}
        context.worker_proofs = {(0, 0): proof, (1, 1): object()}
        context.initial_cycle_proof = proof
        context._completed_master_barriers = {(1, 5), (1, 6)}
        context._source_shell_committed_plans = {(1, 1): {'native_current_cookie': 999}}
        context.binary_hash = b'n' * 32
        context.master = SimpleNamespace(pid=os.getpid(),
            start_ticks=ker_run.process_start_ticks(os.getpid()), pidfd=current_fd)
        provider_module = module._c22_provider_module()
        provider = object.__new__(provider_module.SourceShellC34InteropProvider)
        provider.context, provider._used_slots = context, {0, 1}
        provider._private_c34_helper_capture = artifact_capture.helper_capture
        provider._source_committed = True
        provider.slot_identities = ((101, 201), (102, 202))
        provider._check_actor = lambda _deadline=None: True
        provider._closed = False
        provider._verify_sequence = 0
        provider._source_command_abi = 1
        provider._initial_retire_started_ns = None
        provider._initial_retire_deadline_ns = None
        provider._initial_retire_attempts = 0
        provider._initial_retire_next_retry_ns = 0
        provider._initial_retire_ack = None
        provider._initial_retire_command = None
        provider._initial_verify_started = False
        provider._initial_retirement_proof = None
        provider._source_park_evidence = SimpleNamespace(lease=55, received=0, accepted=0)
        provider._source_commit_result = {'errno': 0, 'phase': 4, 'lease': 55,
            'listener_cookie': 999, 'received': 0, 'accepted': 0}
        provider._source_command_sequence = 0
        provider._source_command_unresolved = False
        provider._source_command_outstanding = None
        provider._last_received_bundle = {'record': b'B' * provider_module._RECORD.size}
        watch_fd = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, watch_fd)
        provider.watch_fd = watch_fd
        provider._watch_fd_identity = (watch_fd, *provider._fd_diagnostic(watch_fd))
        launch = object.__new__(origin.PrivateC34OriginalShellLaunch)
        launch.context = context
        launch.c34_artifact_capture = artifact_capture
        launch.master_pidfd = current_fd
        attachment = object.__new__(attach.SourceAttachment)
        attachment.launch, attachment.context, attachment.attached = launch, context, True
        attachment.ready = (old_ready, old_fds[2])
        attachment.candidate_ready = (candidate_ready, candidate_fds[2])
        attachment.channel = attachment_channel
        attachment.helper = SimpleNamespace(poll=lambda: None)
        attachment.helper_pidfd = current_fd
        attachment.master_pidfd = current_fd
        attachment.master_pid = os.getpid()
        attachment.master_start = context.master.start_ticks
        attachment.binary_hash = context.binary_hash
        attachment.check = lambda: self.fail('old worker death called live-only SourceAttachment.check')
        profile = object.__new__(profile_module.PrivateNewC34InteropProfile)
        profile._sealed = False
        profile.origin_module = origin
        profile.artifact_capture = artifact_capture
        profile.helper_capture = artifact_capture.helper_capture
        profile.deadline_ns = time.monotonic_ns() + 30_000_000_000
        profile._sealed = True
        controller = object.__new__(module.SourceShellController)
        controller.profile, controller.launch = profile, launch
        controller.c22_provider = provider
        controller.bootstrap_context = context
        controller.initial_worker_binding = None
        broker_checks = []
        broker_module = importlib.util.module_from_spec(importlib.util.spec_from_file_location(
            'r2_broker_readiness_supervisor_test', ROOT / 'tools' / 'broker_readiness_supervisor.py'))
        broker_spec = broker_module.__spec__
        broker_spec.loader.exec_module(broker_module)
        wire = broker_module.wire
        broker = object.__new__(broker_module.BrokerReadiness)
        broker.parent, broker.child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        broker.parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        broker.child.setblocking(True)
        self.addCleanup(broker.parent.close)
        self.addCleanup(broker.child.close)
        broker.app = broker_module._identity(os.getpid())
        broker.supervisor = broker_module._identity(os.getpid())
        broker.app_pidfd = os.pidfd_open(os.getpid(), 0)
        self.addCleanup(os.close, broker.app_pidfd)
        broker.expected_executable_hash = __import__('hashlib').sha256(
            Path('/proc/self/exe').read_bytes()).digest()
        broker.ready, broker.stopped, broker.stop_attempted = True, False, False
        broker._verify, broker._stop = None, None
        broker._private_stop_authorization = None
        broker._private_stop_authorization_consumed = False
        broker._private_stop_ack_receipt = None
        broker._private_stop_ack_registry = {}
        broker._verify_sequence = 0
        broker.last_verify_packet = broker.last_verify_result = None
        broker.nonce, broker.epoch, broker.profile = b'N' * 16, 7, b'P' * 32
        real_identity_check = broker._check_app_identity
        def check_broker_identity():
            broker_checks.append('check')
            return real_identity_check()
        broker._check_app_identity = check_broker_identity
        broker._private_initial_retirement_provider = provider
        with self.assertRaisesRegex(RuntimeError, 'STOP is held'):
            broker_module.BrokerReadiness.begin_stop(broker)
        verify_packet = wire.pack_verify_result(broker.nonce, broker.epoch, 1, 0,
            old.pid, old_start, 10101, 20202, 30303, 40404, broker.profile, 1)
        verify_requests = []
        broker_peer_failures = []
        def modeled_broker_peer():
            try:
                request, ancillary, flags, _ = broker.child.recvmsg(
                    wire.VERIFY_REQUEST.size, socket.CMSG_SPACE(4 * 4))
                self.assertEqual(len(request), wire.VERIFY_REQUEST.size)
                fields = wire.VERIFY_REQUEST.unpack(request)
                self.assertEqual(fields[2], wire.VERIFY_RETIRE)
                self.assertEqual(fields[5], broker.nonce)
                self.assertEqual(fields[6:8], (broker.epoch, 1))
                self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                rights = []
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        values = array.array('i'); values.frombytes(payload[:len(payload)//4*4])
                        rights.extend(values)
                self.assertEqual(len(rights), 1)
                verify_requests.append((request, os.fstat(rights[0]).st_mode))
                os.close(rights[0])
                broker.child.send(verify_packet)
            except BaseException as error:
                broker_peer_failures.append(error)
        broker_peer_thread = threading.Thread(target=modeled_broker_peer)
        broker_peer_thread.start()
        controller.broker_readiness = broker
        provider.broker_readiness = broker
        provider.broker_nonce, provider.broker_epoch = broker.nonce, broker.epoch
        controller._first_candidate_observed_ready = candidate_ready
        controller._first_candidate_observed_pidfd = candidate_fds[1]
        controller._private_initial_exit_observation = None
        controller._private_initial_exit_eof_hint_ns = None
        controller._private_initial_retirement_proof = None
        controller._private_initial_verify_started = False
        controller._first_candidate_worker_pending = True
        accepted = object()
        controller._accepted_candidate_worker_request = accepted
        controller._first_candidate_worker_grant = module._FirstCandidateWorkerGrant(
            module._FIRST_CANDIDATE_GRANT_TOKEN, controller, context, provider,
            None, candidate_channel, (), 302, b'candidate-request',
            (candidate.pid, os.getuid(), os.getgid()), candidate_channel, (), 302,
            profile.deadline_ns, (1, 1), context.worker_proofs[(1, 1)],
            (os.getpid(), context.master.start_ticks, current_fd), proof, accepted)
        controller._first_candidate_worker_grant_consumed = True
        controller._first_candidate_activation_delivered = True
        transport = object.__new__(module._SourceInitialWorkerTransport)
        transport.context, transport.broker = context, controller.broker_readiness
        transport.app, transport.app_pidfd = broker.app, broker.app_pidfd
        transport.nonce, transport.epoch = broker.nonce, broker.epoch
        controller._first_candidate_worker_grant = controller._first_candidate_worker_grant._replace(
            initial_transport=transport)
        transport.authenticated, transport.settled = True, False
        transport.attachment = attachment
        transport.worker_pidfd = old_fds[1]
        transport.ready_identity = old_ready
        transport.watch = {'pid': old.pid, 'tid': old.pid, 'role': 0,
            'start': old_start, 'slot_device': 101, 'slot_inode': 201,
            'cookie': 301, 'source_epoch': 0, 'generation': 0, 'process_slot': 7}
        transport.initial_bootstrap_channel_identity = module._source_bootstrap_channel_identity(
            old_channel)
        transport.worker_view = module._InitialOwnerAuthView(old_fds[1],
            old.pid, old.pid, 0, old_start, 101, 201, 301)
        controller.initial_worker_binding = transport
        controller._initial_transport = transport
        with self.assertRaisesRegex(RuntimeError, 'STOP is held'):
            broker_module.BrokerReadiness.begin_stop(broker)
        observation = controller._check_private_initial_worker_exit_binding(
            transport, provider, context)
        self.assertIs(type(observation), module._PrivateInitialWorkerExitObservation)
        self.assertTrue(controller._valid_private_initial_exit_observation(transport, context))
        self.assertEqual(observation.record, tuple(old_record))
        self.assertIs(observation.cycle_proof, proof)
        self.assertTrue(broker_checks, 'post-death binding must recheck native app identity')
        self.assertTrue(all(not boot.identity.process_alive(fd) for fd in old_fds))
        self.assertTrue(all(boot.identity.process_alive(fd) for fd in candidate_fds))
        with self.assertRaises(AttributeError):
            observation.pidfd = candidate_fds[0]
        now_pid = os.getpid()
        now_start = ker_run.process_start_ticks(now_pid)
        parent_pid = int(Path(f'/proc/{now_pid}/stat').read_text().rpartition(')')[2].split()[1])
        launch.process = SimpleNamespace(pid=now_pid, poll=lambda: None)
        launch.pidfd = current_fd
        launch.start = now_start
        launch.creator_pid = parent_pid
        launch.pid_namespace = os.stat(f'/proc/{now_pid}/ns/pid').st_ino
        launch.master_pidfd = current_fd
        launch.origin_pidfd = -1
        launch.native_io_pidfd = -1
        launch.backend_receipt = None
        launch.live_supervisor = lambda _deadline: None
        context.master = SimpleNamespace(pid=now_pid, start_ticks=now_start,
            pidfd=current_fd)
        context.deadline_ns = profile.deadline_ns
        context.slim_pidfd = -1
        context.live = lambda *_args: None
        context._executable_live = lambda _pid: True
        controller.io_actor = None
        controller._check_first_candidate_phase = lambda _transport: \
            controller._check_private_initial_worker_exit_binding(
                transport, provider, context)
        controller.listener = None
        controller._first_candidate_revoke_attempted = False
        controller.unresolved = False
        revoke_calls = []
        transport.auth_started = True
        transport.revoke = lambda: revoke_calls.append('revoke')
        profile.origin_module.parent_pid = lambda _pid: parent_pid
        profile.origin_module.namespace_identity = lambda _pid: launch.pid_namespace
        self.assertTrue(controller.check_live(),
            'check_live must recognize only the proof-backed pending old-exit phase')
        retained_old_channel = context.worker_channels[(0, 0)]
        context.worker_channels[(0, 0)] = candidate_channel
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'substituted old worker channel must invalidate the pending exit observation')
        context.worker_channels[(0, 0)] = retained_old_channel
        saved_slot = context.worker_process_slots[(0, 0)]
        context.worker_process_slots[(0, 0)] = saved_slot + 1
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'mutated process-slot association must invalidate old-exit proof')
        context.worker_process_slots[(0, 0)] = saved_slot
        saved_identities = provider.slot_identities
        provider.slot_identities = ((999, 999), saved_identities[1])
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'mutated READY slot tuple must invalidate old-exit proof')
        provider.slot_identities = saved_identities
        controller.broker_readiness.stopped = True
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'stopped native broker must invalidate old-exit proof')
        controller.broker_readiness.stopped = False
        controller.broker_readiness.ready = False
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'unready native broker must invalidate old-exit proof')
        controller.broker_readiness.ready = True
        original_identity_check = controller.broker_readiness._check_app_identity
        controller.broker_readiness._check_app_identity = lambda: (_ for _ in ()).throw(
            ProcessLookupError('modeled closed native app'))
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'closed native broker app must invalidate old-exit proof')
        controller.broker_readiness._check_app_identity = original_identity_check
        context._completed_master_barriers = {(1, 5)}
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'a partial op8/evidence outcome cannot keep the old-death liveness exception')
        with self.assertRaises(PermissionError):
            controller._check_private_initial_worker_exit_binding(transport, provider, context)
        context._completed_master_barriers = {(1, 5), (1, 6)}
        old_peer.close()
        provider_calls = []
        def modeled_c28(operation, deadline):
            provider_calls.append((operation, deadline))
            provider._source_command_sequence += 1
            sequence = provider._source_command_sequence
            request = provider_module._encode_source_c28_request(operation,
                sequence, deadline, provider._last_received_bundle['record'])
            result_error = errno.EAGAIN if len(provider_calls) == 1 else 0
            response_raw = request + provider_module._C28_RESULT.pack(
                result_error, 0, 0, 0, 0, 0)
            response = provider_module._decode_source_c28_reply(response_raw,
                request, (os.getpid(), os.getuid(), os.getgid()),
                (os.getpid(), os.getuid(), os.getgid()), 0)
            provider._source_last_command = (sequence, operation, deadline,
                request, response)
            return response
        provider._source_c28_command = modeled_c28
        real_finish_retirement = provider.finish_initial_listener_retirement
        def check_verify_result_integrity(packet, result):
            retained = dict(result)
            result['status'] = 1
            with self.assertRaises(PermissionError):
                real_finish_retirement(packet, result)
            self.assertIsNone(provider._initial_retirement_proof,
                'mutated decoded status must not mint a retirement proof')
            with self.assertRaisesRegex(RuntimeError, 'STOP is held'):
                broker_module.BrokerReadiness.begin_stop(broker)
            result.clear(); result.update(retained)
            corrupt_packet = bytes([packet[0] ^ 1]) + packet[1:]
            with self.assertRaises(PermissionError):
                real_finish_retirement(corrupt_packet, result)
            self.assertIsNone(provider._initial_retirement_proof,
                'raw packet mismatch must not mint a retirement proof')
            with self.assertRaisesRegex(RuntimeError, 'STOP is held'):
                broker_module.BrokerReadiness.begin_stop(broker)
            return real_finish_retirement(packet, result)
        provider.finish_initial_listener_retirement = check_verify_result_integrity
        self.assertIsNone(controller.poll_source_preexit(),
            'correlated C28 EAGAIN must remain pending without PREEXIT/retirement proof')
        with self.assertRaisesRegex(RuntimeError, 'STOP is held'):
            broker_module.BrokerReadiness.begin_stop(broker)
        self.assertIsNone(controller._private_initial_retirement_proof,
            'C28 EAGAIN alone must not mint listener-retirement proof')
        provider._initial_retire_attempts = provider_module._C28_RETIRE_MAX_ATTEMPTS
        with self.assertRaises(TimeoutError):
            provider.retire_initial_listener(observation,
                provider._initial_retire_deadline_ns)
        self.assertEqual(len(provider_calls), 1,
            'finite retry-count exhaustion must not send another C28 command')
        provider._initial_retire_attempts = 1
        retirement_deadline = provider._initial_retire_deadline_ns
        with mock.patch.object(provider_module, 'time', wraps=time) as provider_clock:
            provider_clock.monotonic_ns.return_value = retirement_deadline
            with self.assertRaises(TimeoutError):
                provider.retire_initial_listener(observation, context.deadline_ns)
        self.assertEqual(len(provider_calls), 1,
            'phase deadline exhaustion must not send another C28 command')
        retry_time = retirement_deadline - 20_000_000
        with (mock.patch.object(module, 'time', wraps=time) as controller_clock,
                mock.patch.object(provider_module, 'time', wraps=time) as provider_clock):
            controller_clock.monotonic_ns.return_value = retry_time
            provider_clock.monotonic_ns.return_value = retry_time
            self.assertIsNone(controller.poll_source_preexit(),
                'C28 success begins async C34 VERIFY; the first poll turn may remain pending')
        self.assertEqual(len(provider_calls), 2)
        self.assertEqual(provider_calls[-1][1], retirement_deadline,
            'the last C28 request must use the remaining phase budget')
        if controller._private_initial_retirement_proof is None:
            with self.assertRaisesRegex(RuntimeError, 'STOP is held'):
                broker_module.BrokerReadiness.begin_stop(broker)
        if controller._private_initial_retirement_proof is None:
            self.assertTrue(controller.wait_source_worker(0.5, current_fd),
                'pending VERIFY ACK must wake the owned worker wait through broker.parent')
            self.assertIsNone(controller.poll_source_preexit(),
                'one nonblocking C34 poll is allowed per SDK main-thread turn')
        broker_peer_thread.join(timeout=2)
        self.assertFalse(broker_peer_thread.is_alive())
        self.assertFalse(broker_peer_failures)
        self.assertEqual(len(verify_requests), 1)
        proof = controller._private_initial_retirement_proof
        self.assertIs(type(proof), provider_module.SourceInitialListenerRetirementProof)
        self.assertEqual(proof.c34_result['listener_cookie'], 40404)
        self.assertNotEqual(proof.c34_result['listener_cookie'], old_ready[9])
        self.assertNotEqual(proof.c34_result['listener_cookie'], 999,
            'native VERIFY cookie is distinct from the candidate COMMIT listener cookie')
        self.assertEqual(context._source_initial_listener_retirements[id(provider)], proof)
        self.assertEqual(provider.retire_initial_listener(observation,
            context.deadline_ns), provider._initial_retire_ack)
        self.assertEqual(len(provider_calls), 2,
            'duplicate retirement queries must not send another C28 operation')
        self.assertIs(provider._initial_retirement_proof, proof)
        self.assertIsNone(controller.poll_source_preexit(),
            'expected old-worker EOF is not PREEXIT after its pidfd exit was retained')
        self.assertFalse(controller.wait_source_worker(0.01, -1),
            'retired-phase waiting must not spin on the retained old pidfd/channel')
        # Compose the actual retained candidate channel reader with the real
        # private Context validator and Origin receipt parser. Native memory,
        # R2 retirement proof issuance, actor records, and supervisor receipts
        # remain explicit host fixtures.
        context.shell_mode = True
        context.epoch = 7
        context.nonce = b'N' * 16
        context.deadline_ns = profile.deadline_ns
        context.allow_successor = context.allow_abort_retry = False
        context.slim_pidfd = -1
        context.slim_pid = context.slim_start_ticks = 0
        context._authorized_preexits = {}
        context._pending_preexits = {}
        context._seen_preexit_ids = set()
        context.worker_ready_receivers = {}
        context._source_route_preparations = {}
        context._source_route_park_joins = {}
        context._source_initial_listener_retirements = {id(provider): proof}
        context._activated_workers = {(1, 1)}
        context._activation_attempts = {(1, 1)}
        context._source_prepared_activation_attempts = set()
        context.symbols = {'ngx_ff_reload_shm': 0x1000}
        candidate_proof = boot.SourceCycleProof(1, 0, 9, 0x300000,
            b'C' * 32, b'I' * 32)
        candidate_record = [0] * 35
        candidate_record[:11] = [boot.MAGIC, boot.SHELL_VERSION, 2,
            boot.SHELL_RECORD.size, 1, candidate.pid, candidate.pid, os.getpid(),
            1, 1, 0]
        candidate_record[11:17] = [candidate_start, context.master.start_ticks,
            0x9000, context.epoch, context.deadline_ns, context.nonce]
        candidate_record[17:29] = [os.getpid(), os.getpid(), os.getpid(), 4,
            candidate_start, context.master.start_ticks, candidate_start,
            candidate_ready[7], candidate_ready[8], 3, candidate_ready[9], 0]
        candidate_record[29:] = list(candidate_proof)
        context.workers[(1, 1)] = (candidate_fds[0], tuple(candidate_record))
        context.worker_proofs[(1, 1)] = candidate_proof
        context.worker_process_slots = {(0, 0): 7, (1, 1): 8}
        context._source_shell_committed_plans[(1, 1)] = {
            'worker_pid': candidate.pid, 'worker_start_ticks': candidate_start,
            'slot': 8, 'ready_cookie': candidate_ready[9],
            'native_current_cookie': 999, 'cycle_proof': candidate_proof,
            'source_block_address': 0x2000,
        }
        context._scalar = lambda _pid, _name, _code: 0x2000
        def fake_memory(_pid, address, size):
            if address == 0x1000 and size == 8:
                return struct.pack('=Q', 0x2000)
            if address == 0x2000 and size == 32:
                return struct.pack('=8I', 0, 0, 0, 1, 1, 1, 0, 0)
            if address == 0x2430 and size == 12:
                return struct.pack('=3I', 1, 0, 0)
            raise AssertionError(('unexpected memory observation', hex(address), size))
        boot.memory = fake_memory
        context.live = lambda *_args: None
        context._executable_live = lambda _pid: True
        park = provider._source_park_evidence
        park.context, park.provider = context, provider
        prepared = SimpleNamespace()
        registration = SimpleNamespace(context=context, park=None,
            raw_prepared_ack=b'ack', expected_prepared_record=b'ack')
        prepared._source_route_preparation = registration
        controller._first_candidate_relay_anchor = relay_anchor
        registration.endpoint = relay_anchor
        registration.endpoint_identity = boot._source_socket_identity(relay_anchor)
        context._source_route_preparations[id(prepared)] = registration
        context._source_prepared_activation_attempts = {id(prepared)}
        context._source_route_park_joins[id(prepared)] = SimpleNamespace(
            prepared=prepared, park=park)
        controller._first_candidate_source_prepared = prepared
        controller._first_candidate_pending_error = None
        controller._first_candidate_pending_ready = None
        controller._first_candidate_pending_watch = {'pid': candidate.pid,
            'process_slot': 8}
        provider._first_candidate_pending_ready = None
        provider._first_candidate_pending_watch = controller._first_candidate_pending_watch
        controller._first_candidate_observed_ready = candidate_ready
        controller._first_candidate_observed_pidfd = candidate_fds[1]
        controller._first_candidate_prepare_attempted = True
        controller._first_candidate_worker_grant = controller._first_candidate_worker_grant._replace(
            cycle_proof=candidate_proof,
            channel_identity=module.SourceShellController._first_candidate_endpoint_identity(
                candidate_channel),
            channel_cookie=module.SourceShellController._first_candidate_socket_cookie(
                candidate_channel))
        controller._check_first_candidate_phase = module.SourceShellController._check_first_candidate_phase.__get__(
            controller, module.SourceShellController)
        controller._private_initial_retirement_proof = proof
        controller._private_initial_exit_observation = observation
        controller._private_initial_exit_eof_hint_ns = None
        controller._private_candidate_preexit_pending = None
        controller._private_candidate_preexit_evidence = None
        controller._private_stop_ack_receipt = None
        launch.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
        launch.pidfd = current_fd
        launch.start = now_start
        launch.deadline_ns = profile.deadline_ns
        launch.run_id = 'fixture-run-001'
        launch.output = tempfile.mkdtemp(prefix='s1b-origin-receipts-')
        os.chmod(launch.output, 0o700)
        self.addCleanup(lambda: __import__('shutil').rmtree(launch.output,
            ignore_errors=True))
        launch.output_fd = os.open(launch.output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, launch.output_fd)
        output_stat = os.fstat(launch.output_fd)
        launch.output_identity = (output_stat.st_dev, output_stat.st_ino)
        python_stat = os.stat('/proc/self/exe')
        launch.python = SimpleNamespace(frozen=(python_stat.st_dev, python_stat.st_ino,
            python_stat.st_size, python_stat.st_mtime_ns, python_stat.st_ctime_ns),
            sha256=__import__('hashlib').sha256(Path('/proc/self/exe').read_bytes()).digest())
        launch.live_supervisor = MethodType(lambda _self, _deadline=None: None, launch)
        origin.context = context
        context.owner_live = launch.live_supervisor
        context.original_supervisor_identity = None
        context._original_supervisor_pidfd = -1
        context._original_supervisor_output_fd = -1
        launch.creator_pid = parent_pid
        launch.pid_namespace = os.stat(f'/proc/{os.getpid()}/ns/pid').st_ino
        attachment.launch = launch
        controller.launch = launch
        def receipts(phase):
            supervisor = {'pid': os.getpid(), 'start_time': now_start,
                'device': python_stat.st_dev, 'inode': python_stat.st_ino}
            snapshot = {'version': 1, 'run_id': launch.run_id,
                'supervisor': supervisor, 'controller': 1234, 'stack': 'rt01',
                'phase': phase, 'members': [{'pid': candidate.pid,
                    'start_time': candidate_start, 'role': 'target'}]}
            events = [] if phase != 'stopping' else [{'run_id': launch.run_id,
                'event': 'signal_requested', 'monotonic': time.monotonic(),
                'pid': candidate.pid, 'start_time': candidate_start, 'signal': 'TERM'}]
            for name, content in (('supervisor.json', snapshot),):
                path = Path(launch.output) / name
                path.write_text(json.dumps(content, separators=(',', ':')) + '\n')
                path.chmod(0o600)
            path = Path(launch.output) / 'ownership-events.jsonl'
            path.write_text(''.join(json.dumps(event, separators=(',', ':')) + '\n'
                for event in events))
            path.chmod(0o600)
        receipts('running')
        preexit_record = list(candidate_record)
        preexit_record[2] = boot.PREEXIT_REQUEST
        operation_deadline = time.monotonic_ns() + 100_000_000
        packet = (boot.PREEXIT_HEADER.pack(boot.PREEXIT_MAGIC,
            boot.PREEXIT_VERSION, boot.PREEXIT_REQUEST, boot.PREEXIT_RECORD_BYTES, 0) +
            boot.SHELL_RECORD.pack(*preexit_record) +
            boot.PREEXIT_TAIL.pack(8, 4, 913, operation_deadline, 999))
        candidate_peer.send(packet)
        with mock.patch.object(boot, 'memory', side_effect=fake_memory):
            self.assertIsNone(controller.poll_source_preexit(),
                'real Origin parser should leave the exact pending request on EAGAIN')
            pending = controller._private_candidate_preexit_pending
            self.assertIs(type(pending), boot.PendingSourceRetirement)
            self.assertIsNone(controller._private_candidate_preexit_evidence)
            self.assertNotIn(913, context._authorized_preexits)
            receipts('stopping')
            stop_requests = []
            ack = broker_module.wire.pack_stop(
                broker_module.wire.STOP_ACK, broker.nonce, broker.epoch,
                *broker.supervisor[:3], broker.supervisor[3])
            gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
            self.addCleanup(lambda: os.close(gate_read) if gate_read >= 0 else None)
            self.addCleanup(lambda: os.close(gate_write) if gate_write >= 0 else None)
            io_gate_read, io_gate_write = os.pipe2(os.O_CLOEXEC)
            self.addCleanup(lambda: os.close(io_gate_read) if io_gate_read >= 0 else None)
            self.addCleanup(lambda: os.close(io_gate_write) if io_gate_write >= 0 else None)
            io_done = (b'KER_IO_DONE {"outstanding":0,'
                b'"rx_decision_last_settled_packet_id":37,"rx_decision_enabled":true,'
                b'"rx_decision_settled":true,"control_eof":true}\n')
            if corrupt_io:
                io_done = io_done.replace(b'"rx_decision_last_settled_packet_id":37',
                    b'"rx_decision_last_settled_packet_id":38')
            io_child = subprocess.Popen([sys.executable, '-c',
                'import os,sys; os.write(1,b"KER_IO_READY fixture\\n"); '
                'os.read(int(sys.argv[1]),1); os.write(1,bytes.fromhex(sys.argv[2]))',
                str(io_gate_read), io_done.hex()], pass_fds=(io_gate_read,),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            self.addCleanup(self.cleanup_app, io_child)
            self.addCleanup(lambda: io_child.stdout.close()
                if io_child.stdout is not None and not io_child.stdout.closed else None)
            self.addCleanup(lambda: io_child.stderr.close()
                if io_child.stderr is not None and not io_child.stderr.closed else None)
            io_pidfd = os.pidfd_open(io_child.pid, 0)
            self.addCleanup(os.close, io_pidfd)
            io_start_ticks = ker_run.process_start_ticks(io_child.pid)
            io_pipe_identity = ker_run._private_pipe_identity(io_child.stdout.fileno())
            io_executable_hash = __import__('hashlib').sha256(
                Path(f'/proc/{io_child.pid}/exe').read_bytes()).digest()
            io_actor = SimpleNamespace(pid=io_child.pid, pidfd=io_pidfd,
                start_ticks=io_start_ticks, executable_hash=io_executable_hash)
            expected_deadline = profile.deadline_ns
            template_hash = 'a' * 64
            expected = {'record': f'v1|{template_hash}|198.18.0.2|255.255.255.0|'
                f'198.18.0.255|198.18.0.1|{expected_deadline}',
                'template_sha256': template_hash, 'address': '198.18.0.2',
                'netmask': '255.255.255.0', 'broadcast': '198.18.0.255',
                'gateway': '198.18.0.1', 'deadline_ns': expected_deadline}
            startup_prefix = (b'KER_NATIVE_READY\nKER_SOURCE_NETWORK_READBACK_V1 '
                + f'template_sha256={template_hash} ifindex=1 address=198.18.0.2 '
                f'netmask=255.255.255.0 broadcast=198.18.0.255 gateway=198.18.0.1 '
                f'route_oif=1 route_table=254 deadline_ns={expected_deadline}\n'.encode())
            native_stats = (b'KER_NATIVE_STATS {"buffer_allocations":0,'
                b'"buffer_releases":0,"buffer_shutdown_releases":0,"buffers_live":0,'
                b'"buffer_bytes":0,"buffer_option_guards_live":0}\n')
            supervisor_identity = (os.getpid(), os.getuid(), os.getgid(),
                ker_run.process_start_ticks(os.getpid()))
            c31_line = subprocess.run([str(self.c31_formatter_binary), str(io_child.pid),
                str(os.getuid()), str(os.getgid()), str(io_start_ticks),
                str(os.getpid()), str(os.getuid()), str(os.getgid()),
                str(supervisor_identity[3]), str(broker.epoch), '37',
                broker.nonce.hex()], check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE).stdout
            startup_shutdown = (b'KER_NATIVE_STOPPING\n' + native_stats + c31_line +
                b'KER_NATIVE_DONE\n')
            run_parent = run_child = None
            run_args = []
            if live_run_stop:
                run_parent, run_child = socket.socketpair(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                self.addCleanup(run_parent.close)
                self.addCleanup(run_child.close)
                run_parent.setblocking(False)
                run_args = [str(run_child.fileno())]
            child_code = r'''
import os
import socket
import sys

os.write(1, bytes.fromhex(sys.argv[4]))
with socket.socket(fileno=int(sys.argv[1])) as broker:
    broker.recv(256)
    if len(sys.argv) == 7:
        os.write(1, b'KER_RX_DECISION_READY\n')
    os.read(int(sys.argv[2]), 1)
    os.write(1, bytes.fromhex(sys.argv[5]))
    broker.send(bytes.fromhex(sys.argv[3]))
    if len(sys.argv) == 7:
        os.close(1)
        with socket.socket(fileno=int(sys.argv[6])) as run:
            run.send(b'KER_RUN_STOP\n')
            assert run.recv(64) == b'OK\n'
'''
            stop_child = subprocess.Popen([sys.executable, '-c', child_code,
                str(broker.child.fileno()), str(gate_read), ack.hex(),
                startup_prefix.hex(), startup_shutdown.hex(), *run_args],
                pass_fds=(broker.child.fileno(), gate_read, *map(int, run_args)), close_fds=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            if run_child is not None:
                run_child.close()
            self.addCleanup(self.cleanup_app, stop_child)
            self.addCleanup(lambda: stop_child.stdout.close()
                if stop_child.stdout is not None and not stop_child.stdout.closed else None)
            self.addCleanup(lambda: stop_child.stderr.close()
                if stop_child.stderr is not None and not stop_child.stderr.closed else None)
            source_startup_fd = stop_child.stdout.fileno()
            os.set_blocking(source_startup_fd, False)
            source_startup_identity = ker_run.source_network_startup.pipe_identity(
                source_startup_fd)
            startup_readback = bytearray()
            startup_deadline = time.monotonic() + 2
            while b'\n' not in startup_readback or startup_readback.count(b'\n') < 2:
                ready_read, _, _ = select.select([source_startup_fd], [], [],
                    max(0, startup_deadline - time.monotonic()))
                if not ready_read:
                    self.fail('modeled app did not publish its captured READY/proof prefix')
                startup_readback.extend(os.read(source_startup_fd, 4096))
            parsed_startup = ker_run.source_network_startup.parse_startup_prefix(
                bytes(startup_readback), expected)
            app_start_ticks = ker_run.process_start_ticks(stop_child.pid)
            app_pidfd = os.pidfd_open(stop_child.pid, 0)
            self.addCleanup(os.close, app_pidfd)
            app_executable_pin = ker_run.source_network_startup.PinnedExecutable(
                f'/proc/{stop_child.pid}/exe', profile.deadline_ns)
            self.addCleanup(app_executable_pin.close)
            retained_backend = ker_run.source_network_startup._capture_retained_backend_receipt(
                stop_child, app_pidfd, app_start_ticks, app_executable_pin,
                source_startup_fd, source_startup_identity, expected, parsed_startup,
                parsed_startup._validated_ns, None)
            self.addCleanup(retained_backend.close)
            self.addCleanup(self.cleanup_app, stop_child)
            launch.backend_receipt = retained_backend
            launch.backend_runtime_actor = SimpleNamespace(pid=stop_child.pid,
                pidfd=app_pidfd, start_ticks=app_start_ticks,
                executable_hash=app_executable_pin.sha256)
            launch._backend_expected = lambda: expected
            launch.native_io_ready = SimpleNamespace(actor=io_actor, process=io_child,
                pid=io_child.pid, start=io_start_ticks,
                pipe_identity=io_pipe_identity[:2])
            launch.native_io_stdout_fd = os.dup(io_child.stdout.fileno())
            self.addCleanup(os.close, launch.native_io_stdout_fd)
            launch.native_io_pidfd = os.dup(io_pidfd)
            self.addCleanup(os.close, launch.native_io_pidfd)
            controller.io_actor = io_actor
            context.runtime = launch.backend_runtime_actor
            context.io = io_actor
            controller._private_runtime_app_anchor = ker_run._bind_private_runtime_app(
                controller, stop_child, app_pidfd, app_start_ticks, run_channel=run_parent)
            broker_app_pidfd = os.pidfd_open(stop_child.pid, 0)
            self.addCleanup(os.close, broker_app_pidfd)
            broker.app = broker_module._identity(stop_child.pid)
            broker.app_pidfd = broker_app_pidfd
            transport.app, transport.app_pidfd = broker.app, broker.app_pidfd
            broker.expected_executable_hash = __import__('hashlib').sha256(
                Path(f'/proc/{stop_child.pid}/exe').read_bytes()).digest()
            self.assertIsNone(controller.poll_source_preexit(),
                'real Origin TERM receipt should admit one bounded STOP attempt')
            self.assertTrue(broker._stop['sent'])
            stop_requests.append(bytes(broker._stop['record']))
            if live_run_stop:
                startup_readback = bytearray(ker_run.wait_startup_marker(
                    source_startup_fd, bytes(startup_readback), b'KER_RX_DECISION_READY\n',
                    0.1, 'fixture RX decision READY'))
            os.write(gate_write, b'x')
            if live_run_stop:
                self.assertTrue(select.select([broker.parent], [], [], 0.1)[0])
                self.assertIsNone(stop_child.poll(),
                    'runtime fixture must still be waiting for run STOP acknowledgement')
                drained_receipt = controller._advance_private_candidate_stop(transport)
            else:
                stop_child.wait(timeout=1)
                drained_receipt = controller.poll_private_stop_after_app_exit(broker)
            self.assertIsNotNone(drained_receipt,
                'the existing reader must retain the authenticated STOP ACK')
            self.assertIsNotNone(controller._private_stop_ack_receipt,
                'credentialed ACK must remain bound to its pending PREEXIT')
        self.assertIs(controller._private_candidate_preexit_pending, pending)
        evidence = context._authorized_preexits[913]
        self.assertIs(type(evidence), boot.SupervisorTermEvidence)
        self.assertIs(controller._private_candidate_preexit_evidence, evidence)
        self.assertIs(context._pending_preexits[913][0], pending)
        stop_receipt = controller._private_stop_ack_receipt
        self.assertIsNotNone(stop_receipt)
        self.assertIs(broker.private_stop_ack_receipt(
            broker._private_stop_authorization), stop_receipt)
        self.assertEqual(stop_receipt.raw_ack,
            broker_module.wire.pack_stop(broker_module.wire.STOP_ACK,
                broker.nonce, broker.epoch, *broker.supervisor[:3], broker.supervisor[3]))
        self.assertEqual(len(stop_requests), 1)
        self.assertTrue(broker.stopped)
        self.assertIsNone(broker._stop)
        self.assertIs(context.authorize_private_candidate_preexit(controller, pending), pending)
        self.assertIs(context._authorized_preexits[913], evidence,
            'repeat production authorization must keep the original typed TERM receipt')
        # Compose the production shutdown collector with this test's exact
        # private controller/provider and real authenticated PREEXIT/STOP
        # receipts.  The Origin launch/profile/controller types and backend
        # startup parser/retained receipt are real; the C28/C34 native evidence
        # remains the explicit host model established above, and the I/O READY
        # proof object models the native READY observation while its process,
        # pidfd and two shutdown pipes are real kernel objects.
        releases = []

        def release_worker(deadline):
            self.assertEqual(deadline, pending.deadline_ns)
            self.assertIsNone(stop_child.poll())
            self.assertIsNone(io_child.poll())
            releases.append(deadline)
            os.write(io_gate_write, b'x')

        if not live_run_stop:
            os.write(io_gate_write, b'x')
            self.assertEqual(io_child.wait(timeout=2), 0)
        def collect_shutdown():
            return ker_run.collect_private_shutdown_streams(controller, stop_child,
                app_pidfd, io_child, io_pidfd, source_startup_fd,
                bytes(startup_readback), source_startup_identity, io_pipe_identity,
                io_start_ticks, app_start_ticks, supervisor_identity[3],
                broker.nonce, broker.epoch,
                release_worker=release_worker if live_run_stop else None)

        if corrupt_io:
            with self.assertRaisesRegex(ValueError, 'shutdown IDs or IO_DONE state do not join'):
                collect_shutdown()
            self.assertEqual(releases, [pending.deadline_ns])
            self.assertEqual(io_child.returncode, 0)
            self.assertIsNone(stop_child.poll())
            self.assertIsNone(getattr(controller, '_private_shutdown_collection_receipt', None))
            self.assertTrue(controller._private_shutdown_collection_failed)
            with self.assertRaisesRegex(PermissionError, 'unused shutdown collection'):
                ker_run._settle_private_source_shutdown(controller, None)
            self.assertNotIn((1, 1), context._completed_retirements)
            self.assertIsNone(candidate.poll())
            with self.assertRaisesRegex(PermissionError, 'collection is one-shot'):
                collect_shutdown()
            return
        startup_status, collected_stats, shutdown_receipt = collect_shutdown()
        self.assertEqual(releases, [pending.deadline_ns] if live_run_stop else [])
        self.assertEqual(stop_child.returncode, 0)
        self.assertEqual(io_child.returncode, 0)
        self.assertTrue(ker_run._private_pidfd_exited(app_pidfd))
        self.assertTrue(ker_run._private_pidfd_exited(io_pidfd))
        self.assertIs(controller._private_shutdown_collection_receipt, shutdown_receipt)
        self.assertIs(context._private_shutdown_collections[id(controller)], shutdown_receipt)
        self.assertEqual(shutdown_receipt.parsed['io'],
            ker_run._freeze_private_value(ker_run._private_io_done_record(
                shutdown_receipt.io_stdout)),
            'retained receipt keeps the raw IO_DONE projection separate from caller annotations')
        self.assertEqual(collected_stats['worker_exit_code'], 0)
        self.assertFalse(collected_stats['shutdown_timed_out'])
        self.assertTrue(startup_status.endswith(b'KER_NATIVE_DONE\n'))
        with self.assertRaises(AttributeError):
            stop_receipt.raw_ack = b'changed'
        with self.assertRaises(RuntimeError):
            broker.begin_stop(private_authorization=broker._private_stop_authorization)
        with self.assertRaises(PermissionError):
            broker.authorize_private_stop(provider,
                pending._replace(key=(0, 0)), evidence, proof)
        with self.assertRaises(PermissionError):
            broker.authorize_private_stop(object(), pending, evidence, proof)
        with mock.patch.object(broker_module.time, 'monotonic_ns',
                return_value=pending.deadline_ns + 1):
            with self.assertRaises(PermissionError):
                broker.authorize_private_stop(provider, pending, evidence, proof)
        retained_ack_entry = broker._private_stop_ack_registry[id(stop_receipt)]
        broker._private_stop_ack_registry[id(stop_receipt)] = object()
        with self.assertRaises(PermissionError):
            broker.private_stop_ack_receipt(broker._private_stop_authorization)
        with self.assertRaises(PermissionError):
            controller._advance_private_candidate_stop(transport)
        broker._private_stop_ack_registry[id(stop_receipt)] = retained_ack_entry
        self.assertIs(broker.private_stop_ack_receipt(
            broker._private_stop_authorization), stop_receipt)
        self.assertIs(controller._advance_private_candidate_stop(transport), stop_receipt)
        broker._private_stop_ack_receipt = object()
        with self.assertRaises(PermissionError):
            controller._advance_private_candidate_stop(transport)
        broker._private_stop_ack_receipt = stop_receipt
        saved_context_pending = context._pending_preexits[913]
        saved_context_evidence = context._authorized_preexits[913]
        saved_context_proof = context._source_initial_listener_retirements[id(provider)]
        for label, mutate, restore in (
                ('controller-pending-cleared',
                    lambda: setattr(controller, '_private_candidate_preexit_pending', None),
                    lambda: setattr(controller, '_private_candidate_preexit_pending', pending)),
                ('context-pending-replaced',
                    lambda: context._pending_preexits.__setitem__(913, (object(),)),
                    lambda: context._pending_preexits.__setitem__(913, saved_context_pending)),
                ('controller-evidence-replaced',
                    lambda: setattr(controller, '_private_candidate_preexit_evidence', object()),
                    lambda: setattr(controller, '_private_candidate_preexit_evidence', evidence)),
                ('context-evidence-replaced',
                    lambda: context._authorized_preexits.__setitem__(913, object()),
                    lambda: context._authorized_preexits.__setitem__(913, saved_context_evidence)),
                ('controller-proof-cleared',
                    lambda: setattr(controller, '_private_initial_retirement_proof', None),
                    lambda: setattr(controller, '_private_initial_retirement_proof', proof)),
                ('context-proof-replaced',
                    lambda: context._source_initial_listener_retirements.__setitem__(id(provider), object()),
                    lambda: context._source_initial_listener_retirements.__setitem__(id(provider), saved_context_proof)),
                ('transport-replaced',
                    lambda: setattr(controller, 'initial_worker_binding', object()),
                    lambda: setattr(controller, 'initial_worker_binding', transport)),
                ('transport-broker-replaced',
                    lambda: setattr(transport, 'broker', object()),
                    lambda: setattr(transport, 'broker', broker)),
                ('profile-replaced',
                    lambda: setattr(controller, 'profile', object()),
                    lambda: setattr(controller, 'profile', profile))):
            with self.subTest(cached_receipt_mutation=label):
                mutate()
                with self.assertRaises(PermissionError):
                    controller._advance_private_candidate_stop(transport)
                restore()
        self.assertIs(controller._advance_private_candidate_stop(transport), stop_receipt)
        self.assertEqual(revoke_calls, [])
        with mock.patch.object(ker_run.time, 'monotonic_ns',
                return_value=pending.deadline_ns):
            with self.assertRaises(TimeoutError):
                ker_run._settle_private_source_shutdown(controller, shutdown_receipt)
        controller._first_candidate_relay_anchor = old_channel
        with self.assertRaisesRegex(PermissionError, 'prepared relay'):
            ker_run._settle_private_source_shutdown(controller, shutdown_receipt)
        controller._first_candidate_relay_anchor = relay_anchor
        self.assertNotIn((1, 1), context._completed_retirements)
        settlement = ker_run._settle_private_source_shutdown(controller, shutdown_receipt)
        self.assertIs(controller._private_source_settlement, settlement)
        self.assertIs(context._completed_retirements[(1, 1)], settlement)
        self.assertEqual(settlement.c31_last_packet_id, 37)
        self.assertEqual(settlement.request_sha256, pending.request_sha256)
        self.assertNotIn(913, context._pending_preexits)
        self.assertNotIn(913, context._authorized_preexits)
        self.assertEqual(candidate.wait(timeout=2), 0)
        self.assertEqual(candidate.stdout.read(), 'settled\n')
        with self.assertRaisesRegex(PermissionError, 'unused shutdown collection'):
            ker_run._settle_private_source_shutdown(controller, shutdown_receipt)
        old_fd_number = retained_old_channel.fileno()
        def live_fds():
            result = set()
            for name in os.listdir('/proc/self/fd'):
                try:
                    os.fstat(int(name))
                except (OSError, ValueError):
                    continue
                result.add(int(name))
            return result
        fd_census_before = live_fds()
        backup_fd = fcntl.fcntl(old_fd_number, fcntl.F_DUPFD_CLOEXEC, 3)
        replacement, replacement_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        replacement.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        replacement_peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        os.close(old_fd_number)
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'closed retained channel fd must invalidate old-exit proof')
        os.dup2(replacement.fileno(), old_fd_number)
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'dup2 replacement on the same descriptor number must invalidate old-exit proof')
        os.dup2(backup_fd, old_fd_number, inheritable=False)
        os.close(backup_fd)
        replacement.close()
        replacement_peer.close()
        self.assertEqual(module._source_bootstrap_channel_identity(retained_old_channel),
            observation.channel_identity,
            'the original held socket identity must be restored exactly')
        self.assertFalse(controller._valid_private_initial_exit_observation(transport, context),
            'the completed broker STOP makes the private live-old-exit phase inactive')
        self.assertEqual(live_fds(), fd_census_before,
            'close/dup2 negative checks must leave the actual process descriptor census unchanged')

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
    def test_private_postcommit_eof_before_pidfd_exit_is_only_a_bounded_hint(self):
        module = ker_run._load_source_shell_controller()
        boot_spec = importlib.util.spec_from_file_location('private_old_eof_bootstrap_test',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        self.addCleanup(self.cleanup_app, child)
        child_fd = os.pidfd_open(child.pid, 0)
        self.addCleanup(os.close, child_fd)
        left0, peer0 = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        left1, peer1 = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        for endpoint in (left0, peer0, left1, peer1):
            self.addCleanup(endpoint.close)
        peer0.close()
        context = object.__new__(boot.SourceBootstrapSupervisor)
        context.control_only = True
        context.workers = {(0, 0): (child_fd, ()), (1, 1): (child_fd, ())}
        context.worker_channels = {(0, 0): left0, (1, 1): left1}
        context._completed_master_barriers = {(1, 5), (1, 6)}
        context._source_shell_committed_plans = {(1, 1): {'native_current_cookie': 1}}
        profile_module = module._c34_profile_module()
        profile = object.__new__(profile_module.PrivateNewC34InteropProfile)
        profile.origin_module = SimpleNamespace(bootstrap=boot, identity=boot.identity)
        controller = object.__new__(module.SourceShellController)
        controller.profile = profile
        controller.bootstrap_context = context
        controller.launch = SimpleNamespace(context=context)
        controller._initial_transport = SimpleNamespace()
        controller._first_candidate_worker_pending = True
        controller._first_candidate_observed_ready = None
        controller._check_first_candidate_phase = lambda _transport: True
        controller._private_initial_exit_observation = None
        controller._private_initial_exit_eof_hint_ns = None
        controller._first_candidate_revoke_attempted = False
        controller.unresolved = False
        self.assertTrue(boot.identity.process_alive(child_fd))
        self.assertIsNone(controller.poll_source_preexit())
        self.assertIsNotNone(controller._private_initial_exit_eof_hint_ns)
        self.assertIsNone(controller._private_initial_exit_observation,
            'channel EOF alone must not mint an old-worker death observation')
        self.assertFalse(controller.unresolved)

    def test_wait_after_consumed_preexit_uses_short_origin_term_retry_cadence(self):
        module = ker_run._load_source_shell_controller()
        controller = object.__new__(module.SourceShellController)
        context = SimpleNamespace(deadline_ns=time.monotonic_ns() + 2_000_000_000,
            worker_channels={}, workers={})
        controller.bootstrap_context = context
        controller.listener = None
        controller.broker_readiness = None
        controller._valid_private_initial_exit_observation = lambda *_: False
        controller._private_initial_exit_eof_hint_ns = None
        controller._private_candidate_preexit_pending = SimpleNamespace(
            deadline_ns=time.monotonic_ns() + 100_000_000)
        controller._private_candidate_preexit_evidence = None
        started = time.monotonic()
        self.assertFalse(controller.wait_source_worker(0.25, -1))
        self.assertLess(time.monotonic() - started, 0.08,
            'consumed PREEXIT must return to the SDK pump well before its 100ms deadline')
        controller._private_candidate_preexit_pending.deadline_ns = time.monotonic_ns() - 1
        with self.assertRaisesRegex(TimeoutError, 'PREEXIT deadline'):
            controller.wait_source_worker(0.25, -1)

    def test_private_stop_ack_wakes_worker_wait_within_preexit_budget(self):
        module = ker_run._load_source_shell_controller()
        controller = object.__new__(module.SourceShellController)
        controller.bootstrap_context = SimpleNamespace(
            deadline_ns=time.monotonic_ns() + 2_000_000_000, worker_channels={})
        controller.listener = None
        controller._valid_private_initial_exit_observation = lambda *_: False
        controller._private_initial_exit_eof_hint_ns = None
        controller._private_candidate_preexit_pending = SimpleNamespace(
            deadline_ns=time.monotonic_ns() + 80_000_000)
        controller._private_candidate_preexit_evidence = object()
        controller._private_stop_ack_receipt = None
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        with parent, child:
            controller.broker_readiness = SimpleNamespace(parent=parent,
                _stop={'private': True, 'sent': True})
            child.send(b'ACK')
            self.assertTrue(controller.wait_source_worker(0.25, -1))
            self.assertEqual(parent.recv(3), b'ACK', 'only the STOP reader consumes the receipt')
            controller._private_candidate_preexit_pending.deadline_ns = time.monotonic_ns() - 1
            with self.assertRaisesRegex(TimeoutError, 'PREEXIT deadline'):
                controller.wait_source_worker(0.25, -1)

    def test_runtime_path_parser_preserves_defaults_and_tracks_only_cli_options(self):
        base = ['--address', '198.18.0.2/24', '--port', 'host0',
            '--eal=--no-huge', '--', '/bin/true']
        defaults = ker_run.parse_arguments(base, defer_worker_limits=True)
        expected_library = Path(ker_run.__file__).resolve().parent / ker_run.LIB_FROM_BIN / 'libker-posix.so'
        expected_worker = Path(ker_run.__file__).resolve().parent / 'ker-io-worker'
        self.assertEqual(defaults.library, expected_library)
        self.assertEqual(defaults.io_worker, expected_worker)
        self.assertFalse(getattr(defaults, '_explicit_cli_overrides', frozenset()))
        merged = ker_run.parse_arguments(['--config', str(
            Path(ker_run.__file__).resolve().parents[1] / 'config/native-launcher.example.ini'),
            '--', '/bin/true'], defer_worker_limits=True)
        self.assertEqual(str(merged.address), '198.18.0.2/24')
        self.assertEqual(merged.port, 'net_tap0')
        self.assertEqual(merged.library, expected_library)
        self.assertEqual(merged.io_worker, expected_worker)
        self.assertFalse(getattr(merged, '_explicit_cli_overrides', frozenset()))
        explicit = ker_run.parse_arguments(base[:-2] + ['--library', str(expected_library),
            '--io-worker', str(expected_worker), '--', '/bin/true'],
            defer_worker_limits=True)
        self.assertEqual(explicit._explicit_cli_overrides,
            frozenset({'library', 'io_worker'}))
        after_separator = ker_run.parse_arguments(base[:-2] + ['--', '--library',
            '/tmp/user-path'], defer_worker_limits=True)
        self.assertFalse(getattr(after_separator, '_explicit_cli_overrides', frozenset()))
        self.assertEqual(after_separator.command, ['--library', '/tmp/user-path'])

    def test_failed_master_channels_close_only_after_validated_settlement(self):
        module = ker_run._load_source_shell_controller()
        controller = object.__new__(module.SourceShellController)
        left, right = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        left_fd, right_fd = left.fileno(), right.fileno()
        events = []
        settled = {'value': False}
        controller.launch = SimpleNamespace(
            observe_settlement=lambda: {'settled': settled['value']},
            close=lambda: events.append('origin-close'))
        controller.validate_settled_actors = lambda: events.append(
            ('validate', left.fileno(), right.fileno()))
        controller.c22_provider = None
        controller._initial_transport = None
        controller.profile = SimpleNamespace(close=lambda: events.append('profile-close'))
        controller.capsules = SimpleNamespace(close=lambda _launch: events.append(
            ('capsule-close', left.fileno(), right.fileno())))
        controller.control_slim_channel = None
        controller._accepted_candidate_worker_request = None
        controller._first_candidate_pending_ready = None
        controller._first_candidate_pending_watch = None
        controller._first_candidate_pending_error = None
        controller._first_candidate_worker_grant = None
        controller._first_candidate_observed_ready = None
        controller._first_candidate_worker_pending = False
        controller._first_candidate_relay_anchor = None
        controller._first_candidate_observed_pidfd = -1
        controller._private_source_master_channels = [left, right]
        controller.listener = None
        controller.started = True
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with self.assertRaisesRegex(RuntimeError, 'has not settled'):
            controller.close_settled()
        self.assertEqual([fd.fileno() for fd in
            controller._private_source_master_channels], [left.fileno(), right.fileno()])
        settled['value'] = True
        controller.close_settled()
        self.assertEqual(events[0], ('validate', left_fd, right_fd))
        self.assertEqual(events[2], ('capsule-close', left_fd, right_fd))
        self.assertEqual(controller._private_source_master_channels, [])
        self.assertEqual((left.fileno(), right.fileno()), (-1, -1))

    def test_private_runtime_trio_binds_held_capture_and_rejects_mismatch_before_actors(self):
        shell_module = ker_run._load_source_shell_controller()
        profile_module = shell_module._c34_profile_module()
        artifact_module = profile_module._provider()
        if not artifact_module._BUILD_MANIFEST.exists():
            self.skipTest('fixed C34 artifact build manifest is unavailable')
        capture = artifact_module.PrivateC34ArtifactCapture.capture(
            time.monotonic_ns() + 30_000_000_000)
        self.addCleanup(capture.close)
        profile = object.__new__(profile_module.PrivateNewC34InteropProfile)
        object.__setattr__(profile, '_sealed', False)
        profile.artifact_capture = capture
        profile.deadline_ns = time.monotonic_ns() + 20_000_000_000
        profile.network_expectation = object()
        object.__setattr__(profile, '_sealed', True)
        controller = object.__new__(shell_module.SourceShellController)
        controller.profile = profile
        defaults = SimpleNamespace(library=Path('/unused/default-lib'),
            io_worker=Path('/unused/default-worker'), _explicit_cli_overrides=frozenset())
        binding = ker_run._bind_private_c34_runtime_artifacts(defaults, controller)
        posix, io_worker, ker_app = (capture.artifact(name)
            for name in ('posix', 'io_worker', 'ker_app'))
        self.assertIs(binding[0], capture)
        self.assertIs(binding[1], posix)
        self.assertIs(binding[2], io_worker)
        self.assertIs(binding[3], ker_app)
        self.assertEqual(defaults.library, posix.path)
        self.assertEqual(defaults.io_worker, io_worker.path)
        matched = SimpleNamespace(library=posix.path, io_worker=io_worker.path,
            _explicit_cli_overrides=frozenset({'library', 'io_worker'}))
        self.assertEqual(ker_run._bind_private_c34_runtime_artifacts(matched,
            controller), binding)
        mismatch = SimpleNamespace(library=Path('/bin/true'), io_worker=io_worker.path,
            _explicit_cli_overrides=frozenset({'library'}))
        with self.assertRaisesRegex(PermissionError, 'explicit --library differs'):
            ker_run._bind_private_c34_runtime_artifacts(mismatch, controller)
        stale = SimpleNamespace(library=Path('/unused/lib'),
            io_worker=Path('/unused/worker'), _explicit_cli_overrides=frozenset())
        with mock.patch.object(artifact_module._HeldArtifact, 'verify',
                side_effect=PermissionError('injected stale held identity')):
            with self.assertRaisesRegex(PermissionError, 'stale held identity'):
                ker_run._bind_private_c34_runtime_artifacts(stale, controller)
        self.assertEqual(stale.library, Path('/unused/lib'))
        self.assertEqual(stale.io_worker, Path('/unused/worker'))

        # Drive the real programmatic main path through the pre-actor join.
        # It must reject before validate_main, bond-limit work, IPC or Popen.
        mismatch_args = SimpleNamespace(library=Path('/bin/true'),
            io_worker=io_worker.path, _explicit_cli_overrides=frozenset({'library'}),
            control_nginx_source_private_c34_profile=False)
        controller.validate_main = mock.Mock(side_effect=AssertionError('too late'))
        controller.start = mock.Mock(side_effect=AssertionError('actor launch must remain held'))
        expected = ker_run.source_network_startup.SourceNetworkExpectation(
            'template.ini', 'a' * 64, '198.18.0.2', '255.255.255.0',
            '198.18.0.255', '198.18.0.1', profile.deadline_ns, None)
        object.__setattr__(profile, 'network_expectation', expected)
        with mock.patch.object(ker_run, 'parse_arguments', return_value=mismatch_args), \
                mock.patch.object(ker_run.source_network_startup, 'prepare_from_launch',
                    return_value=expected), \
                mock.patch.object(ker_run.source_network_startup,
                    '_captured_expectation_key', return_value='same'), \
                mock.patch.object(ker_run.source_network_startup,
                    '_expected_key', return_value='same'), \
                mock.patch.object(ker_run, 'control_nginx_profile', return_value=None), \
                mock.patch.object(ker_run, '_select_source_shell_controller',
                    return_value=controller), \
                mock.patch.object(shell_module, 'create_source_c31_channels') as source_channels, \
                mock.patch.object(ker_run, '_close_private_c34_source_controller'), \
                mock.patch.object(ker_run, 'validate_selected_bond_limits') as bond_limits, \
                mock.patch.object(ker_run, 'primary_channels') as channels, \
                mock.patch.object(ker_run.subprocess, 'Popen') as popen:
            self.assertEqual(ker_run.main(source_shell_controller=controller), 125)
        controller.validate_main.assert_not_called()
        controller.start.assert_not_called()
        source_channels.assert_not_called()
        bond_limits.assert_not_called()
        channels.assert_not_called()
        popen.assert_not_called()

    def test_private_prepare_consumes_before_callback_and_after_activation_error(self):
        module = ker_run._load_source_shell_controller()
        profile_module = module._c34_profile_module()
        proof = object()

        def fixture(preparer, activation):
            controller = object.__new__(module.SourceShellController)
            controller.profile = object.__new__(profile_module.PrivateNewC34InteropProfile)
            left, right = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
            self.addCleanup(left.close)
            self.addCleanup(right.close)
            rec0, rec1 = [0] * 28, [0] * 28
            rec0[5:7], rec0[11] = (111, 112), 113
            rec1[5:7], rec1[11], rec1[24:28] = (121, 122), 123, (1, 2, 3, 4)
            initial, candidate = object(), object()
            context = SimpleNamespace(control_only=True, workers={(0, 0):(1, tuple(rec0)),
                (1, 1):(2, tuple(rec1))}, worker_proofs={(0, 0):initial,
                (1, 1):candidate}, initial_cycle_proof=initial,
                worker_channels={(1, 1):right}, master=object(), epoch=7,
                deadline_ns=time.monotonic_ns()+5_000_000_000)
            transport = SimpleNamespace(auth=left, worker_view=object(), app=object(),
                app_pidfd=10, supervisor_pidfd=11, nonce=b'n'*16, epoch=7)
            cap = module._FirstCandidateWorkerGrant(
                module._FIRST_CANDIDATE_GRANT_TOKEN, controller, context, None,
                transport, right, (), 1, b'request', (121, os.getuid(), os.getgid()),
                left, (), 2, context.deadline_ns, (1, 1), candidate, (1,2,3),
                initial, object())
            controller.bootstrap_context = context
            controller._first_candidate_worker_grant = cap
            controller._first_candidate_worker_grant_consumed = True
            controller._first_candidate_worker_pending = True
            controller._first_candidate_observed_ready = (121,122,0,1,0,0,123,1,2,4)
            controller._first_candidate_observed_pidfd = 12
            controller._first_candidate_relay_anchor = left
            controller._first_candidate_source_prepared = None
            controller._first_candidate_prepare_attempted = False
            controller._first_candidate_activation_delivered = False
            controller._first_candidate_pending_error = None
            controller.unresolved = False
            controller._check_first_candidate_phase = lambda *_: True
            controller._source_route_preparer = preparer
            context.activate_prepared_first_candidate = activation
            return controller, context, transport, cap

        calls = []
        def side_effect_then_raise(*_args, **_kwargs):
            calls.append('prepared-send-attempt')
            raise OSError('unknown C31 PREPARED result')
        ctl, context, transport, cap = fixture(side_effect_then_raise,
            lambda *_: self.fail('activation must not run after unknown PREPARE'))
        watch = {'role':1}
        with self.assertRaisesRegex(OSError, 'unknown C31'):
            ctl._prepare_and_activate_first_candidate(transport, cap, watch)
        with self.assertRaisesRegex(PermissionError, 'one-shot observed role-1 grant'):
            ctl._prepare_and_activate_first_candidate(transport, cap, watch)
        self.assertEqual(calls, ['prepared-send-attempt'])
        self.assertTrue(ctl._first_candidate_prepare_attempted)
        self.assertIsNone(ctl._first_candidate_source_prepared)

        prep_calls, activation_calls = [], []
        prepared = SimpleNamespace()
        ctl, context, transport, cap = fixture(
            lambda *_args, **_kwargs: (prep_calls.append('prepare') or prepared),
            lambda *_args: (activation_calls.append('activation') or
                (_ for _ in ()).throw(OSError('unknown ACTIVATE result'))))
        with self.assertRaisesRegex(OSError, 'unknown ACTIVATE'):
            ctl._prepare_and_activate_first_candidate(transport, cap, watch)
        with self.assertRaisesRegex(PermissionError, 'one-shot observed role-1 grant'):
            ctl._prepare_and_activate_first_candidate(transport, cap, watch)
        self.assertEqual((prep_calls, activation_calls), (['prepare'], ['activation']))
        self.assertIs(ctl._first_candidate_source_prepared, prepared)
        self.assertTrue(ctl._first_candidate_prepare_attempted)

    def invoke(self, controller):
        args = SimpleNamespace()
        expected = {'deadline_ns': 123, 'template_sha256': 'a' * 64,
            'address': '198.18.0.2', 'gateway': '198.18.0.1'}
        with mock.patch.object(ker_run, 'parse_arguments', return_value=args), \
                mock.patch.object(ker_run.source_network_startup,
                    'prepare_from_launch', return_value=expected), \
                mock.patch.object(ker_run, 'control_nginx_profile', return_value=None), \
                mock.patch.dict('os.environ', {'KER_NGINX_SOURCE_SHELL_ENABLE': '1'},
                    clear=False):
            return ker_run.main(source_shell_controller=controller)

    @staticmethod
    def cleanup_app(app):
        if app.poll() is None:
            app.terminate()
            try:
                app.wait(timeout=2)
            except subprocess.TimeoutExpired:
                app.kill(); app.wait(timeout=2)

    def test_source_c31_channels_are_credentialed_and_distinct(self):
        controller_module = ker_run._load_source_shell_controller()
        channels = controller_module.create_source_c31_channels()
        try:
            self.assertEqual(len(channels), 4)
            cookies = set()
            for endpoint in channels:
                self.assertEqual(endpoint.family, socket.AF_UNIX)
                self.assertEqual(endpoint.getsockopt(socket.SOL_SOCKET,
                    socket.SO_TYPE), socket.SOCK_SEQPACKET)
                self.assertEqual(endpoint.getsockopt(socket.SOL_SOCKET,
                    socket.SO_PASSCRED), 1)
                self.assertEqual(endpoint.getsockopt(socket.SOL_SOCKET,
                    socket.SO_PEERCRED, struct.calcsize('=3i')),
                    struct.pack('=3i', os.getpid(), os.getuid(), os.getgid()))
                self.assertTrue(endpoint.getblocking() is False)
                cookie = endpoint.getsockopt(socket.SOL_SOCKET,
                    getattr(socket, 'SO_COOKIE', 57), 8)
                self.assertNotIn(cookie, cookies)
                cookies.add(cookie)
        finally:
            for endpoint in channels:
                endpoint.close()

    def test_source_c31_pair_construction_closes_first_pair_on_second_failure(self):
        controller_module = ker_run._load_source_shell_controller()
        real_socketpair = socket.socketpair
        first_pair = real_socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        calls = 0

        def fail_second(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return first_pair
            raise OSError('injected second-pair failure')

        with mock.patch.object(controller_module.socket, 'socketpair', side_effect=fail_second):
            with self.assertRaisesRegex(OSError, 'second-pair failure'):
                controller_module.create_source_c31_channels()
        for endpoint in first_pair:
            self.assertEqual(endpoint.fileno(), -1)

    def test_profile_capture_owns_fixed_c22_build_fd_without_authorizing_worker(self):
        controller_module = ker_run._load_source_shell_controller()
        provider_module = controller_module._c22_provider_module()
        if not provider_module._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        startup = ker_run.source_network_startup
        deadline = time.monotonic_ns() + 5_000_000_000

        def require(condition, message):
            if not condition:
                raise PermissionError(message)

        origin = SimpleNamespace(__file__=str(ROOT / 'tools/nginx_source_origin.py'),
            require=require,
            identity=SimpleNamespace(_start_ticks=ker_run.process_start_ticks))
        before = set(os.listdir('/proc/self/fd'))
        with tempfile.TemporaryDirectory(prefix='ker-profile-c22-capture-') as directory:
            root = Path(directory)
            scope = root / 'scope'
            scope.mkdir(mode=0o700)
            template = root / 'fstack.conf'
            template.write_text('fixture\n')
            nginx = root / 'nginx'
            nginx.write_bytes(b'pinned test identity')
            output = root / 'fresh-output'
            expectation = startup.SourceNetworkExpectation(
                str(template), 'a' * 64, '198.18.0.2', '255.255.255.0',
                '198.18.0.255', '198.18.0.1', deadline, None)
            environment = {
                'KER_NGINX_SOURCE_SHELL_ENABLE': '1',
                'KER_NGINX_SOURCE_FIRST_HUP_ENABLE': '1',
                'KER_NGINX_SOURCE_BOOTSTRAP_NONCE': 'a' * 32,
                'KER_NGINX_SOURCE_BOOTSTRAP_EPOCH': '19',
                startup.BOOTSTRAP_DEADLINE_ENV: str(deadline),
                'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID': str(os.getpid()),
                'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START': str(
                    ker_run.process_start_ticks(os.getpid())),
            }
            arguments = ['--cases', 'precheck,rt01', '--workers', '1',
                '--graceful', '1', '--target-ip', expectation.address,
                '--out', str(output), '--fstack-conf', str(template)]
            with mock.patch.object(provider_module.subprocess, 'Popen',
                    side_effect=AssertionError('profile capture must not execute the helper')):
                profile = controller_module.SourceShellProfile.capture(origin, startup,
                    source_root=root, arguments=arguments, environment=environment,
                    nginx=nginx, nginx_hash=b'n' * 32,
                    network_expectation=expectation, scope_directory=scope,
                    stdout=None, stderr=None, port_name='eth0')
            capture = profile.c22_build_capture
            self.assertIs(type(capture), provider_module.C22HelperBuildCapture)
            self.assertEqual(capture.sha256.hex(), provider_module._HELPER_SHA256)
            self.assertGreater(os.fstat(capture._fd).st_size, 0)
            context = SimpleNamespace(control_only=True)
            controller = object.__new__(controller_module.SourceShellController)
            controller.profile = profile
            controller.bootstrap_context = context
            controller.launch = SimpleNamespace(context=context)
            controller.c22_provider = None
            sentinel_provider = object()
            readiness = SimpleNamespace(ready=True, stopped=False)
            with mock.patch.object(provider_module, 'SourceShellC22Provider',
                    return_value=sentinel_provider) as construct_provider:
                self.assertIs(controller.start_c22_provider(readiness), sentinel_provider)
            construct_provider.assert_called_once_with(context, readiness, capture)
            self.assertTrue(context.control_only)
            profile.close()
            with self.assertRaises(OSError):
                os.fstat(capture._fd)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_controller_retains_unsettled_provider_from_constructor_exception(self):
        controller_module = ker_run._load_source_shell_controller()
        provider_module = controller_module._c22_provider_module()
        if not provider_module._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        deadline = time.monotonic_ns() + 5_000_000_000
        capture = provider_module.C22HelperBuildCapture.capture(deadline)
        context = SimpleNamespace(control_only=True)
        controller = object.__new__(controller_module.SourceShellController)
        controller.profile = SimpleNamespace(c22_build_capture=capture)
        controller.bootstrap_context = context
        controller.launch = SimpleNamespace(context=context)
        controller.c22_provider = None
        controller.unresolved = False
        native_provider = SimpleNamespace(_helper_fd=-1)
        primary = RuntimeError('injected C22 startup failure')
        cleanup = TimeoutError('injected unsettled C22 helper')
        pending = provider_module.C22ProviderCleanupPending(
            native_provider, primary, cleanup)

        def fail_after_fd_transfer(_context, _readiness, source_capture):
            fd, _metadata, _digest = source_capture._take_helper_fd(deadline)
            native_provider._helper_fd = fd
            raise pending

        try:
            with mock.patch.object(provider_module, 'SourceShellC22Provider',
                    side_effect=fail_after_fd_transfer):
                with self.assertRaises(provider_module.C22ProviderCleanupPending) as caught:
                    controller.start_c22_provider(SimpleNamespace(ready=True, stopped=False))
            self.assertIs(caught.exception, pending)
            self.assertIs(controller.c22_provider, native_provider)
            self.assertTrue(controller.unresolved)
            self.assertEqual(capture._fd, -1)
            os.fstat(native_provider._helper_fd)
        finally:
            if native_provider._helper_fd >= 0:
                os.close(native_provider._helper_fd)
                native_provider._helper_fd = -1

    def test_bound_transport_survives_pre_ready_pump_then_constructs_provider_after_c34(self):
        controller_module = ker_run._load_source_shell_controller()
        provider_module = controller_module._c22_provider_module()
        if not provider_module._RECEIPT_PATH.exists():
            self.skipTest('fixed C22 helper build receipt is unavailable')
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        self.addCleanup(self.cleanup_app, app)
        app_pidfd = os.pidfd_open(app.pid, 0)
        self.addCleanup(os.close, app_pidfd)
        app.pidfd = app_pidfd
        controller, context, endpoint, slim_request = self.make_startup_mux(app)
        bootstrap_spec = importlib.util.spec_from_file_location(
            'pending_provider_bootstrap_test', ROOT / 'tools' /
            'nginx_source_bootstrap_supervisor.py')
        bootstrap = importlib.util.module_from_spec(bootstrap_spec)
        bootstrap_spec.loader.exec_module(bootstrap)
        deadline = time.monotonic_ns() + 4_000_000_000
        nonce = bytes(range(1, 17))
        context.deadline_ns = deadline
        context.epoch = 19
        context.nonce = nonce
        context.workers = {}
        context.worker_channels = {}
        context.worker_process_slots = {}
        context.worker_proofs = {}
        context.initial_cycle_proof = None
        context.live = lambda: None
        context._executable_live = lambda _pid: True
        context.slim_pidfd = -1
        context._initial_worker_grant_consumed = False
        context._activated_workers = set()
        context._completed_master_barriers = set()
        context._source_shell_committed_plans = {}
        profile = controller.profile
        profile.nonce, profile.epoch, profile.deadline_ns = nonce, 19, deadline
        profile.origin_module.identity = bootstrap.identity
        profile.origin_module.parent_pid = lambda _pid: os.getppid()
        profile.origin_module.namespace_identity = lambda _pid: ('pid', 1)
        profile.c22_build_capture = provider_module.C22HelperBuildCapture.capture(deadline)
        self.addCleanup(profile.c22_build_capture.close)
        supervisor_pidfd = os.pidfd_open(os.getpid(), 0)
        self.addCleanup(os.close, supervisor_pidfd)
        controller.launch.backend_runtime_actor = SimpleNamespace(pid=app.pid,
            pidfd=app_pidfd)
        controller.c22_provider = None
        controller.broker_readiness = None
        controller.launch.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
        controller.launch.pidfd = supervisor_pidfd
        controller.launch.start = bootstrap.identity._start_ticks(os.getpid())
        controller.launch.creator_pid = os.getppid()
        controller.launch.pid_namespace = ('pid', 1)
        controller.launch.master_pidfd = -1
        controller.launch.origin_pidfd = -1
        controller.launch.native_io_pidfd = -1
        controller.launch.backend_receipt = None
        controller.io_actor = None
        parent, child = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        self.addCleanup(parent.close)
        self.addCleanup(child.close)

        class Broker:
            ready = False
            stopped = False
            nonce = bytes(range(17, 33))
            epoch = 29
            def _check_app_identity(self):
                if not bootstrap.identity.process_alive(app_pidfd):
                    raise ProcessLookupError('runtime actor exited')
            def poll_ready(self):
                try:
                    value = self.parent.recv(1)
                except BlockingIOError:
                    return False
                if value != b'R':
                    raise PermissionError('unexpected C34 readiness record')
                self.ready = True
                return True

        broker = Broker()
        broker.parent = parent
        channels = controller_module.create_source_c31_channels()
        for c31_endpoint in channels:
            self.addCleanup(c31_endpoint.close)
        transport = controller.bind_initial_worker_transport(broker,
            channels[0], channels[1], channels[2], app, app_pidfd,
            supervisor_pidfd, nonce, 19, lambda *_: None, lambda: None)
        self.assertIs(controller._initial_transport, transport)
        client = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(client.close)
        client.connect(str(endpoint)); client.send(slim_request)
        self.assertFalse(controller.pump_source_requests(broker))
        self.assertIsNone(controller.c22_provider)
        self.assertFalse(context.workers or context.worker_channels or context.worker_proofs)
        self.assertEqual(context.replies, [])

        child.send(b'R')
        events = []
        ready_receiver, ready_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(ready_receiver.close)
        self.addCleanup(ready_peer.close)
        class Provider:
            _used_slots = set()
            slot_identities = ((123, 456), (789, 987))
            _closed = False
            def _check_actor(self, _deadline):
                if broker.stopped:
                    raise ProcessLookupError('C22/C34 actor stopped')
            def reply_initial_worker(self, channel, packet, credentials, relay, grant_deadline):
                events.append('WORKER_REQUEST')
                if (channel.gettimeout() != 0.0 or
                        credentials != (os.getpid(), os.getuid(), os.getgid()) or
                        time.monotonic_ns() >= grant_deadline or relay is not transport.relay):
                    raise AssertionError('initial worker request lost its bounded live channel')
                self._used_slots.add(0)
                return {'pid': os.getpid()}, ready_receiver
        provider = Provider()
        provider.context = context
        provider.broker_readiness = broker
        with mock.patch.object(provider_module, 'SourceShellC22Provider',
                return_value=provider) as construct_provider:
            self.assertTrue(controller.pump_source_requests(broker))
        construct_provider.assert_called_once_with(context, broker,
            profile.c22_build_capture)
        self.assertIs(controller.c22_provider, provider)
        self.assertTrue(broker.ready)
        self.assertEqual(len(context.replies), 1)
        self.assertTrue(context.replies[0][2])
        self.assertIsNotNone(controller.control_slim_channel)
        self.addCleanup(lambda: controller.control_slim_channel.close()
            if controller.control_slim_channel is not None else None)
        self.assertFalse(transport.grant_attempted or transport.auth_started or
            transport.authenticated or context.workers or context.worker_proofs)
        client.close()
        client = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(client.close)
        worker_fields = list(bootstrap.SHELL_RECORD.unpack(slim_request))
        worker_fields[4] = 1
        worker_fields[5], worker_fields[6] = os.getpid(), threading.get_native_id()
        worker_fields[8:10] = [0, 0]
        worker_fields[14:17] = [context.epoch, context.deadline_ns, context.nonce]
        client.connect(str(endpoint)); client.send(bootstrap.SHELL_RECORD.pack(*worker_fields))
        callback = []
        def mark_external_ready_auth(_transport, _provider, _watch, receiver):
            callback.append('READY_AUTH_CALLBACK')
            receiver.close()
        controller._initial_worker_ready_and_auth = mark_external_ready_auth
        self.assertTrue(controller.pump_source_requests(broker))
        self.assertEqual(callback, ['READY_AUTH_CALLBACK'])
        self.assertEqual(events, ['WORKER_REQUEST'])
        self.assertTrue(controller.unresolved)
        self.assertFalse(context.control_only is False or context.workers or
            context.worker_proofs)
        self.assertFalse(context.control_only is False)
        controller.control_slim_channel.close()
        controller.control_slim_channel = None

    def test_main_source_c31_factory_failure_closes_all_pre_runtime_fds(self):
        class NetworkExpectation:
            template_file = None
            deadline_ns = 60
            template_sha256 = 'a' * 64
            address = '198.18.0.2'
            netmask = '255.255.255.0'
            broadcast = '198.18.0.255'
            gateway = '198.18.0.1'
            def readback_setting(self):
                return 'v1|%s|%s|%s|%s|%s|%d' % (self.template_sha256,
                    self.address, self.netmask, self.broadcast, self.gateway,
                    self.deadline_ns)

        network = NetworkExpectation()

        class Controller:
            profile = SimpleNamespace(network_expectation=network)
            nonce = b'source-c31-test01'
            epoch = 19
            def validate_main(self, *_args):
                return None

        controller = Controller()
        source_module = SimpleNamespace(SourceShellController=Controller,
            create_source_c31_channels=mock.Mock(side_effect=OSError(
                'injected source C31 allocation failure')))
        opened_sockets = []
        opened_pidfds = []
        real_socketpair = socket.socketpair
        real_pidfd_open = os.pidfd_open

        def track_socketpair(*args, **kwargs):
            pair = real_socketpair(*args, **kwargs)
            opened_sockets.extend(pair)
            return pair

        def track_pidfd_open(*args, **kwargs):
            fd = real_pidfd_open(*args, **kwargs)
            opened_pidfds.append(fd)
            return fd

        before_fds = set(os.listdir('/proc/self/fd'))
        with tempfile.TemporaryDirectory(prefix='ker-source-c31-main-fail-') as directory:
            root = Path(directory)
            library = root / 'libker.so'
            worker = root / 'io-worker'
            guard = root / 'ker-app'
            for path in (library, worker, guard):
                path.write_bytes(b'fixture')
            worker.chmod(0o700)
            guard.chmod(0o700)
            args = SimpleNamespace(library=library, io_worker=worker,
                rx_decision=True, control_nginx_rx_relay=True)
            with mock.patch.object(ker_run, 'parse_arguments', return_value=args), \
                    mock.patch.object(ker_run.source_network_startup,
                        'SourceNetworkExpectation', NetworkExpectation), \
                    mock.patch.object(ker_run.source_network_startup,
                        'prepare_from_launch', return_value=network), \
                    mock.patch.object(ker_run.source_network_startup,
                        '_expected_key', return_value=('same-profile',)), \
                    mock.patch.object(ker_run.source_network_startup,
                        'pipe_identity', return_value=('pipe-proof',)), \
                    mock.patch.object(ker_run, '_load_source_shell_controller',
                        return_value=source_module), \
                    mock.patch.object(ker_run, 'control_nginx_profile', return_value=None), \
                    mock.patch.object(ker_run, 'validate_selected_bond_limits'), \
                    mock.patch.object(socket, 'socketpair', side_effect=track_socketpair), \
                    mock.patch.object(os, 'pidfd_open', side_effect=track_pidfd_open), \
                    mock.patch.dict(os.environ, {'KER_NGINX_SOURCE_SHELL_ENABLE': '1'},
                        clear=False):
                result = ker_run.main(source_shell_controller=controller)
        self.assertEqual(result, 125)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before_fds)
        self.assertTrue(opened_sockets)
        self.assertTrue(all(endpoint.fileno() == -1 for endpoint in opened_sockets))
        self.assertEqual(len(opened_pidfds), 1)
        with self.assertRaises(OSError):
            os.fstat(opened_pidfds[0])

    def make_startup_mux(self, app):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        boot_spec = importlib.util.spec_from_file_location('startup_mux_bootstrap_test',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)

        class Context:
            control_only = True
            record_struct = boot.SHELL_RECORD
            deadline_ns = time.monotonic_ns() + 3_000_000_000
            workers = {}
            worker_channels = {}
            def __init__(self):
                self.replies = []
            def reply_slim(self, channel, packet, credentials, *, control_only):
                self.replies.append((packet, credentials, control_only))

        directory = tempfile.TemporaryDirectory(prefix='ker-startup-mux-')
        self.addCleanup(directory.cleanup)
        endpoint = Path(directory.name) / 'origin.sock'
        listener = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(endpoint)); listener.listen(4)
        self.addCleanup(listener.close)
        context = Context()
        actor = SimpleNamespace(pid=app.pid, pidfd=app.pidfd)
        origin_module = SimpleNamespace(bootstrap=SimpleNamespace(
            SourceBootstrapSupervisor=Context, SHELL_RECORD=boot.SHELL_RECORD,
            SHELL_VERSION=boot.SHELL_VERSION, MAGIC=boot.MAGIC))
        controller = object.__new__(controller_type)
        controller.profile = SimpleNamespace(origin_module=origin_module)
        controller.bootstrap_context = context
        controller.launch = SimpleNamespace(context=context,
            backend_runtime_actor=actor)
        controller.listener = listener
        controller.control_slim_channel = None
        controller.io_actor = SimpleNamespace(pid=-1)
        controller.unresolved = False
        controller.check_live = lambda: None

        fields = [0] * len(boot.SHELL_RECORD.unpack(bytes(boot.SHELL_RECORD.size)))
        fields[16], fields[33], fields[34] = bytes(16), bytes(32), bytes(32)
        fields[:5] = [boot.MAGIC, boot.SHELL_VERSION, 1,
            boot.SHELL_RECORD.size, 0]
        return controller, context, endpoint, boot.SHELL_RECORD.pack(*fields)

    def test_source_shell_cannot_enter_generic_launcher_without_controller(self):
        self.assertEqual(self.invoke(None), 125)

    def test_arbitrary_object_cannot_claim_source_controller_type(self):
        self.assertEqual(self.invoke(object()), 125)

    def test_worker_pidfd_retention_does_not_open_duplicate(self):
        worker = SimpleNamespace(pid=456789)
        with mock.patch.object(ker_run.os, 'pidfd_open', return_value=99) as open_pidfd:
            self.assertEqual(ker_run._retain_worker_pidfd(worker, 55), 55)
            open_pidfd.assert_not_called()
            self.assertEqual(ker_run._retain_worker_pidfd(worker, -1), 99)
            open_pidfd.assert_called_once_with(worker.pid, 0)

    def test_canonical_controller_still_requires_captured_profile(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        with self.assertRaises(TypeError):
            controller_type(object())

    def test_source_runtime_profile_is_exact_and_mutually_exclusive(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        controller = object.__new__(controller_type)
        record = 'v1|' + 'b' * 64 + '|198.18.0.2|255.255.255.0|198.18.0.255|198.18.0.1|700'
        expectation = ker_run.source_network_startup.SourceNetworkExpectation(
            '/tmp/source.ini', 'b' * 64, '198.18.0.2', '255.255.255.0',
            '198.18.0.255', '198.18.0.1', 700, None)
        controller.profile = SimpleNamespace(network_expectation=expectation,
            port_name='net_tap0', deadline_ns=700,
            origin_module=SimpleNamespace(_SOURCE_NETWORK_STARTUP=ker_run.source_network_startup))
        controller.started = False
        values = dict(port='net_tap0', queues=1, rx_lcores='1', rx_decision=True,
            runtime_service=True, broker_readiness=True,
            address=ipaddress.ip_interface('198.18.0.2/24'),
            gateway=ipaddress.ip_address('198.18.0.1'), vlans=(), vlan_gateways=(),
            vlan_gateways6=(), interfaces=(), bonds=(), vdevs=(), address6=None,
            gateway6=None, vip_addresses=(), vip_addresses6=(), promiscuous=None,
            all_multicast=False, exception_iface=None, sysctls=(), tcp_ecn=None)
        expected = {'record':record,'deadline_ns': 700, 'template_sha256': 'b' * 64,
            'address': '198.18.0.2', 'netmask':'255.255.255.0',
            'broadcast':'198.18.0.255','gateway': '198.18.0.1'}
        controller.validate_main(expected, None, SimpleNamespace(**values))
        with self.assertRaises(PermissionError):
            controller.validate_main(expected, (object(),), SimpleNamespace(**values))
        values['gateway'] = ipaddress.ip_address('198.18.0.254')
        with self.assertRaises(PermissionError):
            controller.validate_main(expected, None, SimpleNamespace(**values))
        values['gateway'] = ipaddress.ip_address('198.18.0.1')
        values['interfaces'] = (object(),)
        with self.assertRaises(PermissionError):
            controller.validate_main(expected, None, SimpleNamespace(**values))

    def test_start_publishes_bootstrap_before_real_launch_constructor(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        events = []

        class Capsules:
            def __init__(self, origin):
                events.append(('capsules', origin))

            def publish_bootstrap(self, path):
                events.append(('bootstrap', Path(path).name))

            def close(self):
                events.append(('capsules-close',))

        class Launch:
            def __init__(self, source_root, arguments, environment, nginx, nginx_hash,
                    **kwargs):
                events.append(('launch-construct', environment.get(
                    'KER_NGINX_SOURCE_BOOTSTRAP_PATH')))
                self.process = object()

            def live_supervisor(self, deadline):
                events.append(('launch-live', deadline))

        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            controller_module = ker_run._load_source_shell_controller()
            origin = SimpleNamespace(OriginalShellLaunch=Launch)
            profile = object.__new__(controller_module.SourceShellProfile)
            profile.origin_module = origin
            profile.scope_directory = Path(directory)
            profile.environment = {}
            profile.arguments = ()
            profile.source_root = Path(directory)
            profile.nginx = Path(directory)
            profile.nginx_hash = b'x' * 32
            profile.network_expectation = object()
            profile.stdout = profile.stderr = profile.cwd = None
            profile.deadline_ns = 99
            profile.c22_build_capture = SimpleNamespace(close=lambda: None)
            controller = object.__new__(controller_type)
            controller.profile = profile
            controller.scope_api = SimpleNamespace(SourceScopeCapsules=Capsules)
            controller.capsules = None
            controller.launch = None
            controller.listener = None
            controller.socket_identity = None
            controller.io_actor = None
            controller.io_record = None
            controller.started = False
            controller.unresolved = False
            controller.start()
            try:
                self.assertEqual([item[0] for item in events],
                    ['capsules', 'bootstrap', 'launch-construct', 'launch-live'])
                self.assertIn(str(Path(directory) / 'origin.sock'), events[2][1])
            finally:
                controller._close_unstarted()

    def test_main_startup_dispatch_preserves_source_reader_without_controller(self):
        status = b'KER_NATIVE_READY\nKER_SOURCE_NETWORK_READBACK_V1 ...\n'
        with mock.patch.object(ker_run, '_read_legacy_backend_ready') as legacy:
            result = ker_run._finish_initial_backend_startup(
                object(), None, None, 99, status)
        self.assertEqual(result, status)
        legacy.assert_not_called()

    def test_main_startup_dispatch_attaches_controller_only_for_source_mode(self):
        controller = mock.Mock()
        actor = SimpleNamespace(pid=123)
        context = object()
        controller.accept_origin.return_value = context
        controller.bootstrap_context = context
        status = b'KER_NATIVE_READY\nKER_SOURCE_NETWORK_READBACK_V1 ...\n'
        with mock.patch.object(ker_run, '_read_legacy_backend_ready') as legacy:
            result = ker_run._finish_initial_backend_startup(
                object(), controller, actor, 99, status)
        self.assertEqual(result, status)
        controller.accept_origin.assert_called_once_with(actor)
        legacy.assert_not_called()

    def test_main_startup_rejects_an_origin_context_the_controller_did_not_retain(self):
        controller = mock.Mock()
        controller.accept_origin.return_value = object()
        controller.bootstrap_context = object()
        with self.assertRaisesRegex(RuntimeError, 'did not retain'):
            ker_run._finish_initial_backend_startup(
                object(), controller, SimpleNamespace(pid=123), 99, b'')

    def test_source_preexit_pump_uses_only_retained_context_and_fails_closed(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController

        class Context:
            def __init__(self, pending):
                self.worker_channels = {'existing': object()}
                self.pending = pending
                self.authorized = []

            def poll_worker_preexit(self):
                return self.pending

            def authorize_worker_preexit(self, operation_id):
                self.authorized.append(operation_id)

        context_type = Context
        origin = SimpleNamespace(bootstrap=SimpleNamespace(
            SourceBootstrapSupervisor=context_type))
        context = context_type(None)
        controller = object.__new__(controller_type)
        controller.profile = SimpleNamespace(origin_module=origin)
        controller.launch = SimpleNamespace(context=context)
        controller.bootstrap_context = context
        controller.unresolved = False
        self.assertIsNone(controller.poll_source_preexit())
        self.assertEqual(controller.source_worker_channels(), tuple(context.worker_channels.values()))

        pending = SimpleNamespace(operation_id=77)
        context.pending = pending
        with self.assertRaises(OSError) as raised:
            controller.poll_source_preexit()
        self.assertEqual(raised.exception.errno, __import__('errno').ENOTSUP)
        self.assertEqual(context.authorized, [77])
        self.assertTrue(controller.unresolved)

    def test_listener_dispatch_grants_only_slim_control_record(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        boot_spec = importlib.util.spec_from_file_location('test_control_dispatch_bootstrap',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)

        class Context:
            record_struct = boot.SHELL_RECORD
            deadline_ns = time.monotonic_ns() + 2_000_000_000
            def __init__(self):
                self.replies = []
            def reply_slim(self, channel, packet, credentials, *, control_only):
                self.replies.append((packet, credentials, control_only))

        class Listener:
            def __init__(self, accepted):
                self.accepted = accepted
            def accept(self):
                return self.accepted, None

        fake_module = SimpleNamespace(bootstrap=SimpleNamespace(
            SourceBootstrapSupervisor=Context, MAGIC=boot.MAGIC,
            SHELL_VERSION=boot.SHELL_VERSION))

        def make_request(flags):
            fields = [0] * len(boot.SHELL_RECORD.unpack(bytes(boot.SHELL_RECORD.size)))
            fields[16], fields[33], fields[34] = bytes(16), bytes(32), bytes(32)
            fields[:5] = [boot.MAGIC, boot.SHELL_VERSION, 1,
                boot.SHELL_RECORD.size, flags]
            return boot.SHELL_RECORD.pack(*fields)

        context = Context()
        controller = object.__new__(controller_type)
        controller.profile = SimpleNamespace(origin_module=fake_module)
        controller.bootstrap_context = context
        controller.launch = SimpleNamespace(context=context)
        controller.io_actor = SimpleNamespace(pid=999999)
        controller.control_slim_channel = None
        tx, accepted = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        accepted.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        controller.listener = Listener(accepted)
        try:
            tx.send(make_request(0))
            self.assertTrue(controller.pump_bootstrap_listener())
            self.assertTrue(context.replies[0][2])
            self.assertIs(controller.control_slim_channel, accepted)
            controller.control_slim_channel = None
            context2 = Context()
            controller.bootstrap_context = context2
            controller.launch.context = context2
            tx2, accepted2 = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            accepted2.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            controller.listener = Listener(accepted2)
            try:
                tx2.send(make_request(1))
                with self.assertRaises(OSError) as caught:
                    controller.pump_bootstrap_listener()
                self.assertEqual(caught.exception.errno, errno.ENOTSUP)
                self.assertIn('trusted C22 build receipt', str(caught.exception))
                self.assertEqual(context2.replies, [])
            finally:
                tx2.close()
            class UnknownFlagsSocket:
                def __init__(self, wrapped):
                    self.wrapped = wrapped
                def __getattr__(self, name):
                    return getattr(self.wrapped, name)
                def recvmsg(self, *args):
                    packet, ancillary, flags, address = self.wrapped.recvmsg(*args)
                    return packet, ancillary, flags | 0x4000, address
            context3 = Context()
            controller.bootstrap_context = context3
            controller.launch.context = context3
            tx3, accepted3 = socket.socketpair(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            accepted3.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            controller.listener = Listener(UnknownFlagsSocket(accepted3))
            try:
                tx3.send(make_request(0))
                with self.assertRaises(PermissionError):
                    controller.pump_bootstrap_listener()
                self.assertEqual(context3.replies, [])
                with self.assertRaises(OSError):
                    accepted3.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            finally:
                tx3.close()
        finally:
            tx.close()
            accepted.close()

    def test_candidate_post_receipt_failures_are_one_shot_and_revoke_once(self):
        module = ker_run._load_source_shell_controller()
        boot_spec = importlib.util.spec_from_file_location('candidate_failure_bootstrap',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)

        for failure_point in ('relay-create', 'mint'):
            with self.subTest(failure_point=failure_point):
                context = object.__new__(boot.SourceBootstrapSupervisor)
                context.record_struct = boot.SHELL_RECORD
                context.deadline_ns = time.monotonic_ns() + 3_000_000_000
                context.nonce = b'candidate-failure'
                context.epoch = 3
                broker = SimpleNamespace()
                revokes = []
                transport = SimpleNamespace(context=context, broker=broker,
                    attachment=None, request_revoke=lambda: revokes.append('revoke'))
                provider = SimpleNamespace(context=context, broker_readiness=broker,
                    _first_candidate_pending_error=None)
                controller = object.__new__(module.SourceShellController)
                controller.profile = SimpleNamespace(origin_module=
                    SimpleNamespace(bootstrap=boot))
                controller.bootstrap_context = context
                controller.launch = SimpleNamespace(context=context)
                controller.broker_readiness = broker
                controller._initial_transport = controller.initial_worker_binding = transport
                controller.c22_provider = provider
                controller._check_initial_worker_binding = lambda _transport: True
                controller._accepted_candidate_worker_request = None
                controller._first_candidate_worker_grant = None
                controller._first_candidate_worker_grant_consumed = False
                controller._first_candidate_worker_pending = False
                controller._first_candidate_pending_error = None
                controller._first_candidate_pending_watch = None
                controller._first_candidate_pending_ready = None
                controller._first_candidate_revoke_attempted = False
                controller._first_candidate_relay_anchor = None
                controller.unresolved = False
                listener = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                address = '\0candidate-failure-%d-%d' % (os.getpid(), time.monotonic_ns())
                listener.bind(address); listener.listen(1)
                controller.listener = listener
                client = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                accepted = None
                try:
                    client.connect(address)
                    fields = [0] * len(boot.SHELL_RECORD.unpack(
                        bytes(boot.SHELL_RECORD.size)))
                    fields[16], fields[33], fields[34] = bytes(16), bytes(32), bytes(32)
                    fields[:5] = [boot.MAGIC, boot.SHELL_VERSION, 1,
                        boot.SHELL_RECORD.size, 1]
                    fields[8:10] = [1, 1]
                    client.send(boot.SHELL_RECORD.pack(*fields))
                    if failure_point == 'relay-create':
                        failure = mock.patch.object(socket, 'socketpair',
                            side_effect=OSError(errno.EMFILE, 'injected relay creation failure'))
                    else:
                        failure = mock.patch.object(controller,
                            'mint_first_candidate_worker_grant',
                            side_effect=OSError(errno.EIO, 'injected mint failure'))
                    with failure, self.assertRaises(OSError):
                        controller.pump_bootstrap_listener()
                    accepted = controller._accepted_candidate_worker_request
                    self.assertIsNotNone(accepted)
                    self.assertTrue(controller.unresolved)
                    self.assertTrue(controller._first_candidate_worker_pending)
                    self.assertIs(controller._first_candidate_pending_error,
                        provider._first_candidate_pending_error)
                    self.assertEqual(revokes, ['revoke'])
                    controller._revoke_first_candidate_once(transport)
                    self.assertEqual(revokes, ['revoke'], 'candidate revoke repeated')
                    self.assertIsNotNone(controller.listener)
                    self.assertEqual(accepted.channel.getsockopt(socket.SOL_SOCKET,
                        socket.SO_TYPE), socket.SOCK_SEQPACKET)
                finally:
                    client.close()
                    if accepted is not None:
                        accepted.channel.close()
                    if controller._first_candidate_relay_anchor is not None:
                        controller._first_candidate_relay_anchor.close()
                    listener.close()

    def test_candidate_preexit_checks_both_retained_channels_and_eof(self):
        module = ker_run._load_source_shell_controller()
        boot_spec = importlib.util.spec_from_file_location('candidate_preexit_bootstrap',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)
        for key in ((0, 0), (1, 1)):
            for event in ('data', 'eof'):
                with self.subTest(key=key, event=event):
                    context = object.__new__(boot.SourceBootstrapSupervisor)
                    context.control_only = True
                    context.workers = {(0, 0): (1, ()), (1, 1): (2, ())}
                    left0, peer0 = socket.socketpair(socket.AF_UNIX,
                        socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
                    left1, peer1 = socket.socketpair(socket.AF_UNIX,
                        socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
                    context.worker_channels = {(0, 0): left0, (1, 1): left1}
                    calls = []
                    transport = SimpleNamespace(request_revoke=lambda: calls.append('revoke'))
                    controller = object.__new__(module.SourceShellController)
                    controller.profile = SimpleNamespace(origin_module=
                        SimpleNamespace(bootstrap=boot))
                    controller.bootstrap_context = context
                    controller.launch = SimpleNamespace(context=context)
                    controller._initial_transport = transport
                    controller._first_candidate_worker_pending = True
                    controller._first_candidate_observed_ready = None
                    controller._first_candidate_revoke_attempted = False
                    controller.unresolved = False
                    controller._check_first_candidate_phase = lambda _transport: True
                    target = left0 if key == (0, 0) else left1
                    peer = peer0 if key == (0, 0) else peer1
                    if event == 'data':
                        peer.send(b'PREEXIT')
                    else:
                        peer.close()
                    try:
                        with self.assertRaises(OSError):
                            controller.poll_source_preexit()
                        self.assertTrue(controller.unresolved)
                        self.assertEqual(calls, ['revoke'])
                    finally:
                        for endpoint in (left0, peer0, left1, peer1):
                            try: endpoint.close()
                            except OSError: pass

    def test_initial_listener_clears_positive_socket_timeout_before_one_shot_provider_send(self):
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        self.addCleanup(self.cleanup_app, app)
        app.pidfd = os.pidfd_open(app.pid, 0)
        self.addCleanup(os.close, app.pidfd)
        controller, context, endpoint, request = self.make_startup_mux(app)
        fields = list(controller.profile.origin_module.bootstrap.SHELL_RECORD.unpack(request))
        fields[4] = 1
        request = controller.profile.origin_module.bootstrap.SHELL_RECORD.pack(*fields)
        broker = SimpleNamespace(ready=True, stopped=False)
        transport = SimpleNamespace(context=context, broker=broker,
            relay=object(), authenticated=False)
        controller.broker_readiness = broker
        controller._initial_transport = controller.initial_worker_binding = transport
        observed = []
        ready_receiver, ready_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(ready_receiver.close)
        self.addCleanup(ready_peer.close)

        class Provider:
            def reply_initial_worker(self, channel, packet, credentials, relay, deadline):
                observed.append((channel.gettimeout(), packet, credentials, relay, deadline))
                return {'pid': os.getpid()}, ready_receiver

        controller.c22_provider = Provider()
        controller._initial_worker_ready_and_auth = lambda _transport, _provider, _watch, recv: recv.close()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        try:
            client.connect(str(endpoint))
            client.send(request)
            self.assertTrue(controller.pump_bootstrap_listener())
            self.assertEqual(len(observed), 1)
            timeout, packet, credentials, relay, deadline = observed[0]
            self.assertEqual(timeout, 0.0)
            self.assertEqual(packet, request)
            self.assertEqual(credentials, (os.getpid(), os.getuid(), os.getgid()))
            self.assertIs(relay, transport.relay)
            self.assertGreater(deadline, time.monotonic_ns())
        finally:
            client.close()

    def test_main_request_turn_keeps_control_ack_context_servicing_listener(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController

        class Context:
            control_only = True
            workers = {}
            worker_channels = {}
            deadline_ns = time.monotonic_ns() + 2_000_000_000

        class Listener:
            def __init__(self):
                self.calls = 0
            def accept(self):
                self.calls += 1
                raise BlockingIOError

        context = Context()
        listener = Listener()
        origin_module = SimpleNamespace(bootstrap=SimpleNamespace(
            SourceBootstrapSupervisor=Context))
        controller = object.__new__(controller_type)
        controller.profile = SimpleNamespace(origin_module=origin_module)
        controller.bootstrap_context = context
        controller.launch = SimpleNamespace(context=context)
        controller.listener = listener
        self.assertFalse(controller.pump_source_requests())
        self.assertEqual(listener.calls, 1)

    def test_startup_marker_wait_services_queued_control_request_before_marker(self):
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        self.addCleanup(self.cleanup_app, app)
        app_pidfd = os.pidfd_open(app.pid)
        self.addCleanup(os.close, app_pidfd)
        app.pidfd = app_pidfd
        controller, context, endpoint, request = self.make_startup_mux(app)
        startup_read, startup_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.addCleanup(os.close, startup_read)
        self.addCleanup(os.close, startup_write)
        marker = b'KER_RX_DECISION_READY\n'
        thread_errors = []

        def send_request():
            try:
                time.sleep(0.02)
                client = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                try:
                    client.connect(str(endpoint))
                    client.send(request)
                finally:
                    client.close()
            except BaseException as error:
                thread_errors.append(error)

        def delayed_marker():
            deadline = time.monotonic() + 1.0
            while not context.replies and time.monotonic() < deadline:
                time.sleep(0.001)
            if not context.replies:
                thread_errors.append(AssertionError('control request was not serviced before marker'))
                return
            time.sleep(0.03)
            try:
                os.write(startup_write, marker + b'KER_NATIVE_STATS tail\n')
            except BaseException as error:
                thread_errors.append(error)

        request_thread = threading.Thread(target=send_request)
        marker_thread = threading.Thread(target=delayed_marker)
        request_thread.start(); marker_thread.start()
        try:
            result = controller.wait_startup_marker(startup_read,
                b'KER_NATIVE_READY\n', marker, 2.0, 'RX decision consumer',
                app, app_pidfd)
            request_thread.join(timeout=1); marker_thread.join(timeout=1)
            self.assertFalse(request_thread.is_alive())
            self.assertFalse(marker_thread.is_alive())
            self.assertEqual(thread_errors, [])
            self.assertIn(marker, result)
            self.assertIn(b'KER_NATIVE_STATS tail\n', result)
            self.assertEqual(len(context.replies), 1)
            self.assertTrue(context.replies[0][2])
        finally:
            if controller.control_slim_channel is not None:
                controller.control_slim_channel.close()
            app.terminate(); app.wait(timeout=2)

    def test_startup_mux_polls_broker_fd_in_either_origin_request_order(self):
        for request_first in (False, True):
            with self.subTest(request_first=request_first):
                app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
                self.addCleanup(self.cleanup_app, app)
                app_pidfd = os.pidfd_open(app.pid)
                self.addCleanup(os.close, app_pidfd)
                app.pidfd = app_pidfd
                controller, context, endpoint, request = self.make_startup_mux(app)
                if request_first:
                    fields = list(controller.profile.origin_module.bootstrap.SHELL_RECORD.unpack(request))
                    fields[4] = 1
                    request = controller.profile.origin_module.bootstrap.SHELL_RECORD.pack(*fields)
                controller.c22_provider = None
                started = []
                def start_provider(_broker):
                    started.append(time.monotonic())
                    controller.c22_provider = object()
                controller.start_c22_provider = start_provider
                broker_parent, broker_child = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK)
                self.addCleanup(broker_parent.close)
                self.addCleanup(broker_child.close)
                class Broker:
                    ready = False
                    parent = broker_parent
                    def poll_ready(self):
                        try:
                            packet = self.parent.recv(1)
                        except BlockingIOError:
                            return False
                        if packet != b'R':
                            raise AssertionError('unexpected broker test record')
                        self.ready = True
                        return True
                broker = Broker()
                startup_read, startup_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
                self.addCleanup(os.close, startup_read)
                self.addCleanup(os.close, startup_write)
                marker = b'KER_RX_DECISION_READY\n'
                errors = []

                def send_origin_request():
                    try:
                        client = socket.socket(socket.AF_UNIX,
                            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                        try:
                            client.connect(str(endpoint))
                            client.send(request)
                        finally:
                            client.close()
                    except BaseException as error:
                        errors.append(error)

                def send_broker_ready():
                    try:
                        broker_child.send(b'R')
                    except BaseException as error:
                        errors.append(error)

                def release_marker():
                    deadline = time.monotonic() + 1.0
                    while (not started or (not request_first and not context.replies)) and time.monotonic() < deadline:
                        time.sleep(0.001)
                    if not started or (not request_first and not context.replies):
                        errors.append(AssertionError('broker or Origin event was not serviced'))
                        return
                    os.write(startup_write, marker)

                if request_first:
                    threads = [threading.Thread(target=send_origin_request),
                        threading.Thread(target=lambda: (time.sleep(0.03), send_broker_ready()))]
                else:
                    threads = [threading.Thread(target=lambda: (time.sleep(0.03), send_origin_request())),
                        threading.Thread(target=send_broker_ready)]
                marker_thread = threading.Thread(target=release_marker)
                for thread in threads + [marker_thread]:
                    thread.start()
                try:
                    if request_first:
                        module = ker_run._load_source_shell_controller()
                        with self.assertRaises(module.SourceStartupMarkerError) as rejected:
                            controller.wait_startup_marker(startup_read, b'', marker,
                                1.5, 'early initial worker request', app, app_pidfd, broker)
                        self.assertIsInstance(rejected.exception.cause, OSError)
                        self.assertEqual(rejected.exception.cause.errno, errno.ENOTSUP)
                        self.assertEqual(context.replies, [])
                    else:
                        result = controller.wait_startup_marker(startup_read, b'', marker,
                            1.5, 'broker/Origin startup multiplex', app, app_pidfd, broker)
                        self.assertIn(marker, result)
                    self.assertTrue(broker.ready)
                    self.assertEqual(len(started), 1)
                    self.assertEqual(len(context.replies), 0 if request_first else 1)
                    self.assertEqual(errors, [])
                finally:
                    for thread in threads + [marker_thread]:
                        thread.join(timeout=1)
                    if controller.control_slim_channel is not None:
                        controller.control_slim_channel.close()
                    app.terminate(); app.wait(timeout=2)

    def test_startup_marker_wait_preserves_eof_and_actor_exit_evidence(self):
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        self.addCleanup(self.cleanup_app, app)
        app_pidfd = os.pidfd_open(app.pid)
        self.addCleanup(os.close, app_pidfd)
        app.pidfd = app_pidfd
        controller, _, _, _ = self.make_startup_mux(app)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.addCleanup(os.close, read_fd)
        os.write(write_fd, b'partial startup tail')
        os.close(write_fd)
        controller_module = ker_run._load_source_shell_controller()
        with self.assertRaises(controller_module.SourceStartupMarkerError) as caught:
            controller.wait_startup_marker(read_fd, b'prefix', b'NEVER', 1,
                'controlled EOF', app, app_pidfd)
        self.assertTrue(caught.exception.eof)
        self.assertIn(b'partial startup tail', caught.exception.startup_bytes)

        dead = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(.05); raise SystemExit(7)'])
        dead_pidfd = os.pidfd_open(dead.pid)
        self.addCleanup(os.close, dead_pidfd)
        dead.wait(timeout=2)
        dead.pidfd = dead_pidfd
        dead_controller, _, _, _ = self.make_startup_mux(dead)
        read2, write2 = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.addCleanup(os.close, read2)
        self.addCleanup(os.close, write2)
        with self.assertRaises(controller_module.SourceStartupMarkerError) as dead_error:
            dead_controller.wait_startup_marker(read2, b'kept bytes', b'NEVER', 1,
                'controlled app exit', dead, dead_pidfd)
        self.assertEqual(dead_error.exception.actor_exit, 7)
        self.assertEqual(dead_error.exception.startup_bytes, b'kept bytes')

    def test_startup_marker_deadline_is_not_renewed_by_control_request(self):
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        self.addCleanup(self.cleanup_app, app)
        app_pidfd = os.pidfd_open(app.pid)
        self.addCleanup(os.close, app_pidfd)
        app.pidfd = app_pidfd
        controller, context, endpoint, request = self.make_startup_mux(app)
        startup_read, startup_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.addCleanup(os.close, startup_read)
        self.addCleanup(os.close, startup_write)

        def send_control():
            time.sleep(0.01)
            client = socket.socket(socket.AF_UNIX,
                socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            try:
                client.connect(str(endpoint)); client.send(request)
            finally:
                client.close()

        sender = threading.Thread(target=send_control)
        sender.start()
        started = time.monotonic()
        try:
            module = ker_run._load_source_shell_controller()
            with self.assertRaises(module.SourceStartupMarkerError) as caught:
                controller.wait_startup_marker(startup_read, b'preserved',
                    b'NEVER', 0.06, 'fixed-deadline startup', app, app_pidfd)
            sender.join(timeout=1)
            self.assertFalse(sender.is_alive())
            self.assertTrue(context.replies)
            self.assertTrue(caught.exception.timed_out)
            self.assertEqual(caught.exception.startup_bytes, b'preserved')
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            if controller.control_slim_channel is not None:
                controller.control_slim_channel.close()

    def test_startup_marker_rechecks_deadline_after_pump_select_read_and_buffered_marker(self):
        controller_module = ker_run._load_source_shell_controller()

        class LateSelector:
            def __init__(self, delay):
                self.delay = delay
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def register(self, *_args, **_kwargs):
                return None
            def select(self, _timeout):
                time.sleep(self.delay)
                return [(SimpleNamespace(data='startup'), 1)]

        def new_controller():
            app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
            self.addCleanup(self.cleanup_app, app)
            app_pidfd = os.pidfd_open(app.pid)
            self.addCleanup(os.close, app_pidfd)
            app.pidfd = app_pidfd
            controller, _, _, _ = self.make_startup_mux(app)
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            self.addCleanup(os.close, read_fd)
            self.addCleanup(os.close, write_fd)
            return controller, app, app_pidfd, read_fd

        # A marker already buffered is still rejected if the initial source
        # pump consumes the immutable budget before final liveness/deadline checks.
        controller, app, app_pidfd, read_fd = new_controller()
        controller.pump_source_requests = lambda: time.sleep(0.04)
        with self.assertRaises(controller_module.SourceStartupMarkerError) as pump_error:
            controller.wait_startup_marker(read_fd, b'prefixREADY', b'READY',
                0.02, 'late pump', app, app_pidfd)
        self.assertTrue(pump_error.exception.timed_out)
        self.assertEqual(pump_error.exception.startup_bytes, b'prefixREADY')

        # A selector that reports readiness after expiry cannot authorize the
        # later read or accept a marker.
        controller, app, app_pidfd, read_fd = new_controller()
        with mock.patch.object(controller_module.selectors, 'DefaultSelector',
                side_effect=lambda: LateSelector(0.04)):
            with self.assertRaises(controller_module.SourceStartupMarkerError) as select_error:
                controller.wait_startup_marker(read_fd, b'prefix', b'READY',
                    0.02, 'late select', app, app_pidfd)
        self.assertTrue(select_error.exception.timed_out)
        self.assertEqual(select_error.exception.startup_bytes, b'prefix')

        # A delayed read that returns the marker after expiry is rejected and
        # its bytes remain attached as evidence.
        controller, app, app_pidfd, read_fd = new_controller()
        original_read = os.read
        def delayed_read(fd, size):
            if fd == read_fd:
                time.sleep(0.04)
                return b'READY'
            return original_read(fd, size)
        with mock.patch.object(controller_module.selectors, 'DefaultSelector',
                side_effect=lambda: LateSelector(0)), \
                mock.patch.object(controller_module.os, 'read', side_effect=delayed_read):
            with self.assertRaises(controller_module.SourceStartupMarkerError) as read_error:
                controller.wait_startup_marker(read_fd, b'prefix', b'READY',
                    0.02, 'late read', app, app_pidfd)
        self.assertTrue(read_error.exception.timed_out)
        self.assertEqual(read_error.exception.startup_bytes, b'prefixREADY')

    def test_startup_marker_buffer_cap_keeps_bounded_prefix_and_tail(self):
        controller_module = ker_run._load_source_shell_controller()
        app = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        self.addCleanup(self.cleanup_app, app)
        app_pidfd = os.pidfd_open(app.pid)
        self.addCleanup(os.close, app_pidfd)
        app.pidfd = app_pidfd
        controller, _, _, _ = self.make_startup_mux(app)
        oversized = b'a' * controller_module.SOURCE_STARTUP_BUFFER_MAX + b'END-OVERFLOW'
        with self.assertRaises(controller_module.SourceStartupMarkerError) as caught:
            controller.wait_startup_marker(-1, oversized,
                b'NEVER', 1, 'oversized startup', app, app_pidfd)
        self.assertTrue(caught.exception.overflow)
        self.assertEqual(len(caught.exception.startup_bytes),
            controller_module.SOURCE_STARTUP_BUFFER_MAX)
        self.assertTrue(caught.exception.diagnostic_tail.endswith(b'END-OVERFLOW'))

    def test_main_startup_dispatch_keeps_legacy_reader_for_legacy_mode(self):
        with mock.patch.object(ker_run, '_read_legacy_backend_ready',
                return_value=b'KER_NATIVE_READY\n') as legacy:
            result = ker_run._finish_initial_backend_startup(
                None, None, None, 99, b'')
        self.assertEqual(result, b'KER_NATIVE_READY\n')
        legacy.assert_called_once_with(None, 99, b'')

    def test_source_supervisor_stop_requires_full_native_and_io_settlement(self):
        counters = {'buffer_allocations': 2, 'buffer_releases': 2,
            'buffer_shutdown_releases': 0, 'buffers_live': 0, 'buffer_bytes': 0,
            'buffer_option_guards_live': 0}
        wire = (b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_NATIVE_STATS ' +
            json.dumps(counters).encode() + b'\nKER_NATIVE_DONE\n')
        io = {'control_eof': True, 'rx_decision_enabled': True,
            'rx_decision_settled': True, 'outstanding': 0}
        self.assertTrue(ker_run.source_shutdown_evidence(wire, True, io))
        self.assertFalse(ker_run.source_shutdown_evidence(wire, False, io))
        self.assertFalse(ker_run.source_shutdown_evidence(wire, True,
            {**io, 'control_eof': False}))
        self.assertFalse(ker_run.source_shutdown_evidence(wire, True,
            {**io, 'rx_decision_enabled': False}))
        self.assertFalse(ker_run.source_shutdown_evidence(wire, True,
            {**io, 'rx_decision_settled': False}))
        self.assertFalse(ker_run.source_shutdown_evidence(
            b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_NATIVE_DONE\n', True, io))
        bad = dict(counters, buffers_live=1)
        bad_wire = (b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_NATIVE_STATS ' +
            json.dumps(bad).encode() + b'\nKER_NATIVE_DONE\n')
        self.assertFalse(ker_run.source_shutdown_evidence(bad_wire, True, io))
        for changed in (dict(counters, buffer_bytes=1),
                dict(counters, buffer_allocations=3),
                dict(counters, buffer_shutdown_releases=1),
                dict(counters, buffer_shutdown_releases=3),
                dict(counters, buffers_live=True)):
            bad_wire = (b'KER_NATIVE_READY\nKER_NATIVE_STOPPING\nKER_NATIVE_STATS ' +
                json.dumps(changed).encode() + b'\nKER_NATIVE_DONE\n')
            self.assertFalse(ker_run.source_shutdown_evidence(bad_wire, True, io))

    def test_source_eal_prefix_comes_from_authenticated_run_id(self):
        run_id = 'gr_20261113_123456_1_abcdef12'
        expected = '--file-prefix=container-' + run_id
        self.assertEqual(ker_run._source_shell_eal_args(['--in-memory'], run_id),
            ['--in-memory', expected])
        self.assertEqual(ker_run._source_shell_eal_args(
            ['--file-prefix', 'container-' + run_id], run_id), [expected])
        with self.assertRaises(ValueError):
            ker_run._source_shell_eal_args(['--file-prefix=caller'], run_id)
        with self.assertRaises(ValueError):
            ker_run._source_shell_eal_args([expected, expected], run_id)

    @staticmethod
    def make_process_controller(*, deadline_ns=None, wrong_start=False):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        child = subprocess.Popen([sys.executable, '-c',
            'import signal,time; signal.signal(signal.SIGTERM, lambda *_: exit(0)); time.sleep(30)'])
        pidfd = os.pidfd_open(child.pid)

        def start_ticks(pid):
            return ker_run.runtime_service.process_start_ticks(pid) + int(wrong_start)

        def pidfd_pid(fd):
            with open(f'/proc/self/fdinfo/{fd}', 'r', encoding='ascii') as stream:
                for line in stream:
                    if line.startswith('Pid:\t'):
                        return int(line.split()[1])
            raise ProcessLookupError('pidfd has no live PID')

        def alive(fd):
            poller = select.poll()
            poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
            return not bool(poller.poll(0))

        identity = SimpleNamespace(_start_ticks=start_ticks,
            _pidfd_pid=pidfd_pid, process_alive=alive)

        class Launch:
            def __init__(self):
                self.process = child
                self.pidfd = pidfd
                self.start = ker_run.runtime_service.process_start_ticks(child.pid)
                self.creator_pid = os.getpid()
                self.pid_namespace = ('pidns', 1)
                self.settlement = None

            def live_supervisor(self, deadline):
                if (time.monotonic_ns() >= deadline or child.poll() is not None or
                        child.pid != pidfd_pid(pidfd)):
                    raise ProcessLookupError('model supervisor identity is no longer live')

            python = SimpleNamespace(matches_process=lambda pid, deadline: None)

            def observe_settlement(self):
                if child.poll() is None:
                    raise RuntimeError('model settlement requested while child is live')
                self.settlement = {'settled': True, 'result': child.returncode}
                return dict(self.settlement)

        launch = Launch()
        controller = object.__new__(controller_type)
        controller.profile = SimpleNamespace(origin_module=SimpleNamespace(identity=identity,
            parent_pid=lambda pid: os.getpid(), namespace_identity=lambda pid: ('pidns', 1)),
            deadline_ns=deadline_ns or time.monotonic_ns() + 3_000_000_000)
        controller.launch = launch
        controller.shutdown_requested = False
        controller.stop_target_validated = False
        return controller, child, pidfd

    def test_original_supervisor_stop_uses_captured_pidfd_and_settlement(self):
        controller, child, pidfd = self.make_process_controller()
        try:
            receipt = controller.stop_original()
            self.assertTrue(receipt['settled'])
            self.assertIsNotNone(child.returncode)
            self.assertTrue(controller.shutdown_requested)
        finally:
            os.close(pidfd)
            if child.poll() is None:
                child.kill(); child.wait()

    def test_original_supervisor_identity_mismatch_is_not_signaled(self):
        controller, child, pidfd = self.make_process_controller(wrong_start=True)
        try:
            with self.assertRaises(ProcessLookupError):
                controller.stop_original()
            self.assertIsNone(child.poll())
        finally:
            child.kill(); child.wait(); os.close(pidfd)

    def test_expired_supervisor_deadline_does_not_send_term(self):
        controller, child, pidfd = self.make_process_controller(
            deadline_ns=time.monotonic_ns() - 1)
        try:
            with self.assertRaises(TimeoutError):
                controller.stop_original()
            self.assertIsNone(child.poll())
        finally:
            child.kill(); child.wait(); os.close(pidfd)

    def test_source_shutdown_order_revokes_then_stops_native_then_source_tree(self):
        events = []
        controller = SimpleNamespace(launch=object(), deadline_ns=time.monotonic_ns() + 2_000_000_000,
            io_actor=object(), validate_stop_target=lambda: events.append('target-validated'))
        runtime = SimpleNamespace(revoke=lambda reason: events.append('runtime-revoked'))

        class Broker:
            ready = True
            stopped = False
            def stop(self, timeout):
                events.append('broker-stop')
                self.stopped = True

        class App:
            returncode = None
            def poll(self):
                return self.returncode
            def wait(self, timeout):
                events.append('app-wait')
                self.returncode = 0

        ker_run._settle_source_shell_actors(controller, runtime, Broker(), App(), object())
        self.assertEqual(events, ['runtime-revoked', 'broker-stop', 'app-wait'])

    def test_missing_native_stop_channel_prevents_source_signal(self):
        events = []
        controller = SimpleNamespace(launch=object(), deadline_ns=time.monotonic_ns() + 2_000_000_000,
            io_actor=object(), validate_stop_target=lambda: events.append('target-validated'))
        runtime = SimpleNamespace(revoke=lambda reason: events.append('runtime-revoked'))
        broker = SimpleNamespace(ready=False, stopped=False)
        with self.assertRaises(RuntimeError):
            ker_run._settle_source_shell_actors(controller, runtime, broker, None, object())
        self.assertEqual(events, ['runtime-revoked'])

    def test_exited_app_skips_redundant_broker_stop_for_later_worker_validation(self):
        events = []
        controller = SimpleNamespace(launch=object(), deadline_ns=time.monotonic_ns() + 2_000_000_000,
            io_actor=object(), validate_stop_target=lambda: events.append('target-validated'))
        runtime = SimpleNamespace(revoke=lambda reason: events.append('runtime-revoked'))
        app = SimpleNamespace(poll=lambda: 0)
        result = ker_run._settle_source_shell_actors(controller, runtime,
            SimpleNamespace(ready=True, stopped=False), app, object())
        self.assertFalse(result)
        self.assertEqual(events, ['runtime-revoked'])

    def test_source_liveness_monitor_checks_supervisor_and_io_pidfds(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        live = {10, 11}
        identity = SimpleNamespace(_pidfd_pid=lambda fd: fd,
            process_alive=lambda fd: fd in live,
            _start_ticks=lambda pid: 100 + pid)
        process = SimpleNamespace(pid=10, poll=lambda: None)
        launch = SimpleNamespace(process=process, pidfd=10, start=110,
            creator_pid=os.getpid(), pid_namespace=('pid', 1), master_pidfd=-1,
            origin_pidfd=-1, native_io_pidfd=11, backend_receipt=None, context=None,
            live_supervisor=mock.Mock())
        profile = SimpleNamespace(origin_module=SimpleNamespace(identity=identity,
            parent_pid=lambda pid: os.getpid(), namespace_identity=lambda pid: ('pid', 1)),
            deadline_ns=time.monotonic_ns() + 2_000_000_000)
        controller = object.__new__(controller_type)
        controller.launch = launch
        controller.profile = profile
        controller.io_actor = SimpleNamespace(pid=11, start_ticks=111)
        self.assertTrue(controller.check_live())
        launch.live_supervisor.assert_called_once_with(profile.deadline_ns)
        live.remove(11)
        with self.assertRaises(ProcessLookupError):
            controller.check_live()

    def test_source_liveness_uses_actual_worker_record_shape_and_exact_receipt_method(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        bootstrap_spec = importlib.util.spec_from_file_location(
            'source_shell_controller_test_bootstrap',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        bootstrap = importlib.util.module_from_spec(bootstrap_spec)
        bootstrap_spec.loader.exec_module(bootstrap)
        source_startup = ker_run.source_network_startup
        receipt = object.__new__(source_startup.RetainedBackendReceipt)
        actor_pid = 12345
        actor_fd = 77
        actor_start = 98765
        record = list(bootstrap.SHELL_RECORD.unpack(bytes(bootstrap.SHELL_RECORD.size)))
        record[5], record[8], record[9], record[11] = actor_pid, 1, 2, actor_start
        observer = object.__new__(bootstrap.SourceBootstrapSupervisor)
        observer.workers = {(2, 1): (actor_fd, tuple(record))}
        observer.slim_pidfd = -1
        observer.live = mock.Mock()
        observer._executable_live = mock.Mock(return_value=True)
        actor_runtime = SimpleNamespace(pid=actor_pid, pidfd=actor_fd,
            start_ticks=actor_start, executable_hash=b'x' * 32)
        launch = SimpleNamespace(process=SimpleNamespace(pid=100, poll=lambda: None),
            pidfd=100, start=1000, creator_pid=os.getpid(), pid_namespace=('pid', 1),
            master_pidfd=-1, origin_pidfd=-1, native_io_pidfd=-1,
            backend_receipt=receipt, backend_runtime_actor=actor_runtime,
            context=observer, live_supervisor=mock.Mock(),
            _backend_expected=lambda: {'record': 'captured'})

        def pidfd_pid(fd):
            return {100: 100, actor_fd: actor_pid}.get(fd, -1)

        identity = SimpleNamespace(_pidfd_pid=pidfd_pid,
            process_alive=lambda fd: fd in (100, actor_fd),
            _start_ticks=lambda pid: {100: 1000, actor_pid: actor_start}[pid])
        origin_module = SimpleNamespace(identity=identity,
            parent_pid=lambda pid: os.getpid(), namespace_identity=lambda pid: ('pid', 1),
            _SOURCE_NETWORK_STARTUP=source_startup)
        controller = object.__new__(controller_type)
        controller.profile = SimpleNamespace(origin_module=origin_module,
            deadline_ns=time.monotonic_ns() + 2_000_000_000)
        controller.launch = launch
        controller.io_actor = None
        with mock.patch.object(source_startup.RetainedBackendReceipt, 'validate_live',
                autospec=True, return_value=True) as validate_receipt:
            self.assertTrue(controller.check_live())
        validate_receipt.assert_called_once_with(receipt,
            {'record': 'captured'}, actor_runtime, controller.deadline_ns)
        observer.live.assert_called_once_with()
        observer._executable_live.assert_called_once_with(actor_pid)

        live_deadline = controller.profile.deadline_ns
        controller.profile.deadline_ns = time.monotonic_ns() - 1
        with mock.patch.object(source_startup.RetainedBackendReceipt, 'validate_live',
                autospec=True, return_value=True):
            with self.assertRaises(TimeoutError):
                controller.check_live()
        controller.profile.deadline_ns = live_deadline

        observer.workers = {(3, 1): (actor_fd, tuple(record))}
        with mock.patch.object(source_startup.RetainedBackendReceipt, 'validate_live',
                autospec=True, return_value=True):
            with self.assertRaises(RuntimeError):
                controller.check_live()
        record[5] = actor_pid + 1
        observer.workers = {(2, 1): (actor_fd, tuple(record))}
        with mock.patch.object(source_startup.RetainedBackendReceipt, 'validate_live',
                autospec=True, return_value=True):
            with self.assertRaises(ProcessLookupError):
                controller.check_live()

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
    def test_initial_worker_binding_rechecks_provider_attachment_worker_and_frozen_view(self):
        module = ker_run._load_source_shell_controller()
        boot_spec = importlib.util.spec_from_file_location('initial_binding_bootstrap_test',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)
        child = subprocess.Popen(['sleep', '30'])
        self.addCleanup(self.cleanup_app, child)
        worker_fd = os.pidfd_open(child.pid, 0)
        context_fd = os.dup(worker_fd)
        self.addCleanup(os.close, worker_fd)
        self.addCleanup(os.close, context_fd)
        start = ker_run.process_start_ticks(child.pid)
        relay, relay_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(relay.close)
        self.addCleanup(relay_peer.close)
        auth, auth_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.addCleanup(auth.close)
        self.addCleanup(auth_peer.close)
        ready_cookie = 991
        slot_device, slot_inode = 101, 202
        nonce = bytes(range(16))
        deadline = time.monotonic_ns() + 2_000_000_000
        proof = boot.SourceCycleProof(1, 0, 1, 123, b'a' * 32, b'b' * 32)
        record = list(boot.SHELL_RECORD.unpack(bytes(boot.SHELL_RECORD.size)))
        record[5], record[6], record[8], record[9], record[11] = (
            child.pid, child.pid, 0, 0, start)
        record[14:17] = [19, deadline, nonce]
        record[20] = 2
        relay_cookie = struct.unpack('=Q', relay.getsockopt(socket.SOL_SOCKET,
            getattr(socket, 'SO_COOKIE', 57), 8))[0]
        record[24:28] = [slot_device, slot_inode, relay_cookie, ready_cookie]
        context = SimpleNamespace(epoch=19, deadline_ns=deadline, nonce=nonce,
            workers={(0, 0): (context_fd, tuple(record))},
            worker_channels={(0, 0): object()}, worker_proofs={(0, 0): proof},
            worker_process_slots={(0, 0): 7}, worker_ready_receivers={},
            initial_cycle_proof=proof,
            slim_pidfd=-1, live=lambda: None, _executable_live=lambda _pid: True)

        class Provider:
            slot_identities = ((slot_device, slot_inode), (303, 404))
            _used_slots = {0}
            _closed = False
            broker_readiness = None
            failure = None
            def _check_actor(self, _deadline):
                if self.failure:
                    raise self.failure
                if not child.poll() is None:
                    raise ProcessLookupError('provider actor exited')

        class Broker:
            ready = True
            stopped = False
            def _check_app_identity(self):
                if child.poll() is not None:
                    raise ProcessLookupError('broker app exited')

        broker = Broker()
        provider = Provider()
        provider.context = context
        provider.broker_readiness = broker
        class Attachment:
            failure = None
            ready = None
            def check(self):
                if self.failure:
                    raise self.failure
        attachment = Attachment()
        view = module._InitialOwnerAuthView(worker_fd, child.pid, child.pid, 0,
            start, slot_device, slot_inode, ready_cookie)
        transport = module._SourceInitialWorkerTransport(
            module._INITIAL_TRANSPORT_TOKEN, context, broker, relay, relay_peer,
            auth, child, worker_fd, worker_fd, nonce, 19, lambda *_: None,
            lambda: revoke_calls.append('revoke'))
        transport.grant_attempted = transport.auth_started = transport.authenticated = True
        transport.attachment = attachment
        transport.ready_identity = (child.pid, os.getuid(), os.getgid(), 0,
            child.pid, 0, start, slot_device, slot_inode, ready_cookie)
        attachment.ready = (transport.ready_identity, worker_fd)
        transport.watch = {'pid': child.pid, 'tid': child.pid, 'role': 0,
            'start': start, 'slot_device': slot_device, 'slot_inode': slot_inode,
            'cookie': ready_cookie, 'source_epoch': 0, 'generation': 0,
            'process_slot': 7}
        transport.worker_pidfd = worker_fd
        transport.worker_view = view
        controller = object.__new__(module.SourceShellController)
        controller.bootstrap_context = context
        controller.initial_worker_binding = transport
        controller._initial_transport = transport
        controller.broker_readiness = broker
        controller.c22_provider = provider
        controller.unresolved = False
        controller.profile = SimpleNamespace(deadline_ns=deadline,
            origin_module=SimpleNamespace(identity=boot.identity,
                parent_pid=lambda _pid: os.getppid(),
                namespace_identity=lambda _pid: ('pid', 1)))
        controller.io_actor = None
        supervisor_pidfd = os.pidfd_open(os.getpid(), 0)
        self.addCleanup(os.close, supervisor_pidfd)
        controller.launch = SimpleNamespace(process=SimpleNamespace(pid=os.getpid(),
                poll=lambda: None), pidfd=supervisor_pidfd,
            start=boot.identity._start_ticks(os.getpid()), creator_pid=os.getppid(),
            pid_namespace=('pid', 1), master_pidfd=-1, origin_pidfd=-1,
            native_io_pidfd=-1, context=context, backend_receipt=None)
        revoke_calls = []
        self.assertTrue(controller.check_live())

        context.worker_ready_receivers[(0, 0)] = object()
        with self.assertRaises(PermissionError):
            controller._check_initial_worker_binding(transport)
        context.worker_ready_receivers.clear()

        original_attachment_ready = attachment.ready
        attachment.ready = (tuple(transport.ready_identity[:7]) +
            (slot_device + 1, slot_inode, ready_cookie), worker_fd)
        with self.assertRaises(PermissionError):
            controller._check_initial_worker_binding(transport)
        attachment.ready = original_attachment_ready

        broker.stopped = True
        with self.assertRaises(ProcessLookupError):
            controller._check_authenticated_initial_worker_core(transport, provider)
        broker.stopped = False

        with self.assertRaises(AttributeError):
            view.owner_pid = child.pid + 1
        transport.worker_view = view._replace(owner_pid=child.pid + 1)
        with self.assertRaises(PermissionError):
            controller.check_live()
        self.assertTrue(controller.unresolved)
        self.assertEqual(revoke_calls, ['revoke'])
        transport.worker_view = view
        transport.worker_pidfd = supervisor_pidfd
        transport.worker_view = view._replace(owner_pidfd=supervisor_pidfd)
        with self.assertRaises(ProcessLookupError):
            controller._check_initial_worker_binding(transport)
        transport.worker_pidfd = worker_fd
        transport.worker_view = view
        provider.failure = ProcessLookupError('helper exited')
        with self.assertRaises(ProcessLookupError):
            controller._check_initial_worker_binding(transport)
        provider.failure = None
        transport.watch['cookie'] += 1
        with self.assertRaises(PermissionError):
            controller._check_initial_worker_binding(transport)
        transport.watch['cookie'] = ready_cookie
        context.worker_proofs[(0, 0)] = boot.SourceCycleProof(
            1, 0, 2, 456, b'c' * 32, b'd' * 32)
        with self.assertRaises(PermissionError):
            controller._check_initial_worker_binding(transport)
        context.worker_proofs[(0, 0)] = proof
        attachment.failure = ProcessLookupError('observer exited')
        with self.assertRaises(ProcessLookupError):
            controller._check_initial_worker_binding(transport)
        attachment.failure = None
        child.terminate()
        child.wait(timeout=2)
        with self.assertRaises(ProcessLookupError):
            controller._check_initial_worker_binding(transport)

    @unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfds required')
    def test_first_candidate_grant_is_controller_bound_and_transfers_real_fds(self):
        """Host-only composition through the real listener, grant, and observer."""
        module = ker_run._load_source_shell_controller()
        provider_module = module._c22_provider_module()
        boot_spec = importlib.util.spec_from_file_location('first_candidate_boot_test',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)
        attach_module = module._attach_module()
        origin_spec = importlib.util.spec_from_file_location(
            '_first_candidate_origin_test', ROOT / 'tools' / 'nginx_source_origin.py')
        origin = importlib.util.module_from_spec(origin_spec)
        sys.modules[origin_spec.name] = origin
        origin_spec.loader.exec_module(origin)
        wire = attach_module.wire
        helper_spec = importlib.util.spec_from_file_location(
            '_first_candidate_attach_helper_test', ROOT / 'tools' / 'ker-nginx-companion.py')
        helper = importlib.util.module_from_spec(helper_spec)
        helper_spec.loader.exec_module(helper)
        def fd_links():
            result = {}
            for fd in os.listdir('/proc/self/fd'):
                if fd.isdigit():
                    try: result[int(fd)] = os.readlink(f'/proc/self/fd/{fd}')
                    except OSError: pass
            return result
        baseline_fd_links = fd_links()
        def direct_children():
            path = Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children')
            return {int(value) for value in path.read_text().split()}
        baseline_children = direct_children()
        ready_receiver = ready_sender = None
        attachment = None
        launch = None
        initial_ready_receiver, initial_ready_sender = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        initial_ready_receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        initial_ready_cookie = struct.unpack('=Q', initial_ready_sender.getsockopt(
            socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
        owner_ready_command_r, owner_ready_command_w = os.pipe()
        parent_pid = os.getpid()
        master_pidfd = os.pidfd_open(parent_pid, 0)
        master_start = boot.identity._start_ticks(parent_pid)
        binary_hash = module._c22_provider_module().hashlib.sha256(
            Path(f'/proc/{parent_pid}/exe').read_bytes()).digest()
        nonce = b'first-candidate1'
        deadline = time.monotonic_ns() + 15_000_000_000
        epoch = 37
        config_hash, ini_hash = b'c' * 32, b'i' * 32
        initial_proof = boot.SourceCycleProof(1, 0, 1, 123,
            config_hash, ini_hash)
        candidate_proof = boot.SourceCycleProof(1, 0, 2, 456,
            config_hash, ini_hash)

        def child_waiter():
            release_r, release_w = os.pipe()
            ready_r, ready_w = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(release_w); os.close(ready_r)
                os.close(owner_ready_command_w)
                start = boot.identity._start_ticks(os.getpid())
                os.write(ready_w, struct.pack('=Q', start)); os.close(ready_w)
                record = b''
                while len(record) < helper.OWNER_READY_RECORD.size:
                    part = os.read(owner_ready_command_r,
                        helper.OWNER_READY_RECORD.size - len(record))
                    if not part: os._exit(94)
                    record += part
                initial_ready_sender.send(record)
                initial_ready_sender.close()
                os.close(owner_ready_command_r)
                os.read(release_r, 1)
                os._exit(0)
            os.close(release_r); os.close(ready_w)
            start, = struct.unpack('=Q', os.read(ready_r, 8))
            os.close(ready_r)
            os.close(owner_ready_command_r)
            initial_ready_sender.close()
            return pid, start, release_w

        initial_pid, initial_start, initial_release = child_waiter()
        listener = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        address = '\0ker-candidate-%d-%d' % (parent_pid, time.monotonic_ns())
        listener.bind(address); listener.listen(1)
        candidate_started_r, candidate_started_w = os.pipe()
        candidate_report_r, candidate_report_w = os.pipe()
        candidate_release_r, candidate_release_w = os.pipe()
        candidate_pid = os.fork()
        if candidate_pid == 0:
            try:
                listener.close()
                os.close(candidate_started_r); os.close(candidate_report_r)
                os.close(candidate_release_w)
                client = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                client.settimeout(3.0)
                client.connect(address)
                start = boot.identity._start_ticks(os.getpid())
                request_fields = list(boot.SHELL_RECORD.unpack(
                    bytes(boot.SHELL_RECORD.size)))
                request_fields[:5] = [boot.MAGIC, boot.SHELL_VERSION, 1,
                    boot.SHELL_RECORD.size, 1]
                request_fields[5:17] = [os.getpid(), os.getpid(), os.getppid(),
                    1, 1, 0, start, master_start, 0x100000, epoch,
                    deadline, nonce]
                request_fields[29:35] = list(candidate_proof)
                client.send(boot.SHELL_RECORD.pack(*request_fields))
                os.write(candidate_started_w, struct.pack('=Q', start))
                os.close(candidate_started_w)
                packet, ancillary, flags, _ = client.recvmsg(4096,
                    socket.CMSG_SPACE(5 * 4), getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
                fds = []
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        usable = len(payload) - len(payload) % 4
                        fds.extend(array.array('i', payload[:usable]))
                flags_ok = 0
                if len(fds) == 5:
                    fifo = os.fstat(fds[2])
                    if (stat.S_ISFIFO(fifo.st_mode) and
                            fcntl.fcntl(fds[2], fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
                            fcntl.fcntl(fds[2], fcntl.F_GETFL) & os.O_NONBLOCK and
                            fcntl.fcntl(fds[2], fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
                        flags_ok |= 1
                    relay_copy = socket.socket(fileno=os.dup(fds[3]))
                    ready_copy = socket.socket(fileno=os.dup(fds[4]))
                    try:
                        relay_cookie = struct.unpack('=Q', relay_copy.getsockopt(
                            socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
                        ready_cookie = struct.unpack('=Q', ready_copy.getsockopt(
                            socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
                        ready_record = helper.OWNER_READY_RECORD.pack(
                            helper.OWNER_READY_MAGIC, helper.OWNER_READY_VERSION,
                            helper.OWNER_READY_RECORD.size, 1, 0, fifo.st_dev,
                            fifo.st_ino, start, os.getpid(), os.getpid(),
                            ready_cookie, 0)
                        ready_copy.send(ready_record)
                        relay_peer = struct.unpack('=3i', relay_copy.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        ready_peer = struct.unpack('=3i', ready_copy.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if (relay_copy.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) ==
                                socket.SOCK_SEQPACKET and
                                relay_copy.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1 and
                                relay_peer[0] == os.getppid() and relay_cookie and
                                fcntl.fcntl(fds[3], fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
                            flags_ok |= 2
                        if (ready_copy.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) ==
                                socket.SOCK_SEQPACKET and ready_peer[0] == os.getppid() and
                                ready_cookie and fcntl.fcntl(fds[4], fcntl.F_GETFD) &
                                    fcntl.FD_CLOEXEC):
                            flags_ok |= 4
                        if all(boot.identity._pidfd_pid(fd) == os.getppid()
                                for fd in fds[:2]):
                            flags_ok |= 8
                        if all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                                for fd in fds):
                            flags_ok |= 16
                    finally:
                        relay_copy.close(); ready_copy.close()
                else:
                    fifo = os.fstat(0)
                os.write(candidate_report_w, struct.pack('=IQQQQI', len(fds),
                    fifo.st_dev, fifo.st_ino,
                    relay_cookie if len(fds) == 5 else 0,
                    ready_cookie if len(fds) == 5 else 0, flags_ok))
                os.close(candidate_report_w)
                for fd in fds: os.close(fd)
                client.close()
                os.read(candidate_release_r, 1)
                os._exit(0 if packet else 91)
            except BaseException:
                os._exit(92)
        os.close(candidate_started_w); os.close(candidate_report_w)
        os.close(candidate_release_r)
        candidate_start, = struct.unpack('=Q', os.read(candidate_started_r, 8))
        os.close(candidate_started_r)
        readable, _, _ = select.select([listener], [], [], 2.0)
        self.assertTrue(readable, 'modeled candidate did not connect its distinct channel')
        channel = None

        slot0_r, slot0_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        slot1_r, slot1_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        relay, relay_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        relay.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        relay_peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        initial_relay, initial_relay_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        initial_relay_auth, initial_relay_auth_peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        initial_auth, initial_auth_peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        for endpoint in (initial_relay, initial_relay_peer, initial_relay_auth,
                initial_relay_auth_peer, initial_auth, initial_auth_peer):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        app_pidfd = os.pidfd_open(parent_pid, 0)
        initial_pidfd = os.pidfd_open(initial_pid, 0)
        context_initial_pidfd = os.dup(initial_pidfd)
        try:
            slot0 = os.fstat(slot0_w); slot1 = os.fstat(slot1_w)
            initial_relay_cookie = struct.unpack('=Q', initial_relay.getsockopt(
                socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
            initial_slot_cookie = initial_ready_cookie
            record = list(boot.SHELL_RECORD.unpack(bytes(boot.SHELL_RECORD.size)))
            record[5], record[6], record[8], record[9], record[11] = (
                initial_pid, initial_pid, 0, 0, initial_start)
            record[14:17] = [epoch, deadline, nonce]
            record[20] = 2
            record[24:28] = [slot0.st_dev, slot0.st_ino,
                initial_relay_cookie, initial_slot_cookie]
            context = object.__new__(boot.SourceBootstrapSupervisor)
            context.control_only = True
            context.shell_mode = True
            context.epoch, context.deadline_ns, context.nonce = epoch, deadline, nonce
            context.binary_hash = binary_hash
            context.master = SimpleNamespace(pid=parent_pid, pidfd=master_pidfd,
                start_ticks=master_start, executable_hash=binary_hash)
            context.runtime = SimpleNamespace(pid=parent_pid, pidfd=master_pidfd,
                start_ticks=master_start)
            context.io = SimpleNamespace(pid=parent_pid, pidfd=master_pidfd,
                start_ticks=master_start)
            context.workers = {(0, 0): (context_initial_pidfd, tuple(record))}
            context.worker_channels = {(0, 0): initial_relay_peer}
            context.worker_ready_receivers = {}
            context.worker_process_slots = {(0, 0): 7}
            context.worker_proofs = {(0, 0): initial_proof}
            context.initial_cycle_proof = initial_proof
            context.expected_config_sha256, context.expected_ini_sha256 = config_hash, ini_hash
            context._used_cycle_proofs = set()
            context._cycle_serial_highwater = 1
            context.allow_abort_retry = False
            context.allow_successor = False
            context._activated_workers = set()
            context._completed_master_barriers = set()
            context._source_shell_committed_plans = {}
            context._source_route_preparations = {}
            context._source_route_park_joins = {}
            context._source_route_commit_receipts = {}
            context._source_route_commit_consumed = set()
            context._source_route_sequences = {}
            context.record_struct = boot.SHELL_RECORD
            context._unpack_request = boot.SourceBootstrapSupervisor._unpack_request.__get__(context)
            context._fresh_candidate_cycle_proof = lambda fields: candidate_proof
            context._cycle_token_live = lambda *_: None
            context.live = lambda *_: None
            block_address = 0x100000
            reload_prefix = struct.pack('=8I', 0x46524c4d, 1, 32, 1, 0, 1, 1, 0)
            context.slim_pidfd = master_pidfd
            slim_reply = [0] * 21
            slim_reply[20] = 1
            context.slim_reply = slim_reply
            context.supervisor_start = master_start
            context._scalar = lambda pid, name, fmt: ({
                'ngx_ff_reload_shm': block_address,
                'ngx_process': 3, 'ngx_worker': 0, 'ngx_ff_process': 2,
                'ngx_ff_graceful_reload': 1, 'ngx_process_slot': 9,
            }[name])
            context.shared_mapping = lambda _pid, address: (address, address + 4096)

            class Broker:
                ready = True
                stopped = False
                def _check_app_identity(self): pass
            broker = Broker()
            provider_actor = provider_module.SourceShellC22Provider.__new__(
                provider_module.SourceShellC22Provider)
            provider_actor.context = context
            provider_actor.broker_readiness = broker
            provider_actor._closed = False
            provider_actor._used_slots = {0}
            provider_actor._first_candidate_pending_watch = None
            provider_actor._first_candidate_pending_ready = None
            provider_actor._first_candidate_pending_error = None
            provider_actor.slots = [slot0_w, slot1_w]
            provider_actor.slot_identities = ((slot0.st_dev, slot0.st_ino),
                (slot1.st_dev, slot1.st_ino))
            provider_actor._check_actor = lambda *_: None

            controller = object.__new__(module.SourceShellController)
            controller.bootstrap_context = context
            controller.listener = listener
            controller.initial_worker_binding = None
            controller._initial_transport = None
            controller._first_candidate_worker_grant = None
            controller._accepted_candidate_worker_request = None
            controller._first_candidate_worker_grant_consumed = False
            controller._first_candidate_worker_pending = False
            controller._first_candidate_pending_watch = None
            controller._first_candidate_pending_ready = None
            controller._first_candidate_pending_error = None
            controller._first_candidate_source_prepared = None
            controller._first_candidate_prepare_attempted = False
            controller._first_candidate_activation_delivered = False
            controller._first_candidate_revoke_attempted = False
            controller.broker_readiness = broker
            controller.c22_provider = provider_actor
            profile_module = module._c34_profile_module()
            controller.profile = object.__new__(profile_module.PrivateNewC34InteropProfile)
            controller.profile.deadline_ns = deadline
            controller.profile.origin_module = SimpleNamespace(bootstrap=boot,
                identity=boot.identity,
                parent_pid=lambda pid: int(Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[1]))
            launch = object.__new__(origin.OriginalShellLaunch)
            launch.consumed = True
            launch.context = context
            launch.master_pidfd = master_pidfd
            launch.origin_pidfd = os.dup(master_pidfd)
            launch.pidfd = os.dup(master_pidfd)
            launch.process = SimpleNamespace(poll=lambda: None)
            launch.python = SimpleNamespace(path=sys.executable)
            launch.creator_pid = parent_pid
            launch.creator_start = master_start
            launch.nonce, launch.epoch, launch.deadline_ns = nonce, epoch, deadline
            launch.output = '/private/first-candidate-host-model'
            launch.artifact_binding = SimpleNamespace(config_sha256=config_hash.hex(),
                ini_sha256=ini_hash.hex())
            launch.origin_proof = object()
            launch.live_supervisor = lambda _deadline: None
            controller.launch = launch
            controller.unresolved = False

            attachment = attach_module.SourceAttachment(launch,
                revoke_native_auth=lambda: None)
            attachment.attach(timeout=5.0)
            initial_ready_record = helper.OWNER_READY_RECORD.pack(
                helper.OWNER_READY_MAGIC, helper.OWNER_READY_VERSION,
                helper.OWNER_READY_RECORD.size, 0, 0, slot0.st_dev,
                slot0.st_ino, initial_start, initial_pid, initial_pid,
                initial_slot_cookie, 0)
            os.write(owner_ready_command_w, initial_ready_record)
            os.close(owner_ready_command_w)
            owner_watch = {'pid': initial_pid, 'tid': initial_pid, 'role': 0,
                'start': initial_start, 'slot_device': slot0.st_dev,
                'slot_inode': slot0.st_ino, 'cookie': initial_slot_cookie,
                'pidfd': initial_pidfd}
            initial_ready_identity, _ = attachment.receive_owner_ready(
                owner_watch, initial_ready_receiver, timeout=5.0)

            transport = module._SourceInitialWorkerTransport(
                module._INITIAL_TRANSPORT_TOKEN, context, broker, initial_relay,
                initial_relay_auth, initial_auth, SimpleNamespace(pid=parent_pid),
                app_pidfd, app_pidfd, nonce, epoch, lambda *_: None, lambda: None)
            transport.grant_attempted = transport.auth_started = transport.authenticated = True
            transport.attachment = attachment
            transport.ready_identity = tuple(initial_ready_identity)
            transport.watch = {'pid': initial_pid, 'tid': initial_pid, 'role': 0,
                'start': initial_start, 'slot_device': slot0.st_dev,
                'slot_inode': slot0.st_ino, 'cookie': initial_slot_cookie,
                'source_epoch': 0, 'generation': 0, 'process_slot': 7}
            transport.worker_pidfd = initial_pidfd
            transport.worker_view = module._InitialOwnerAuthView(initial_pidfd,
                initial_pid, initial_pid, 0, initial_start, slot0.st_dev,
                slot0.st_ino, initial_slot_cookie)
            transport.broker = broker
            controller.initial_worker_binding = transport
            controller._initial_transport = transport
            initial_record = list(record)
            context.workers[(0, 0)] = (context_initial_pidfd, tuple(initial_record))
            context_route = []
            prepared_sentinel = SimpleNamespace()
            controller._check_first_candidate_phase = lambda _transport: True
            def capture_prepare(*args, **kwargs):
                context_route.append(('prepare', args, kwargs))
                return prepared_sentinel
            controller._source_route_preparer = capture_prepare
            def capture_activate(prepared, channel, watch, source_controller, grant):
                context_route.append(('activate', prepared, channel, watch,
                    source_controller, grant))
            context.activate_prepared_first_candidate = capture_activate

            candidate_fields = list(boot.SHELL_RECORD.unpack(bytes(boot.SHELL_RECORD.size)))
            candidate_fields[:5] = [boot.MAGIC, boot.SHELL_VERSION, 1,
                boot.SHELL_RECORD.size, 1]
            candidate_fields[5:17] = [candidate_pid, candidate_pid, parent_pid,
                1, 1, 0, candidate_start, master_start, block_address,
                epoch, deadline, nonce]
            candidate_fields[29:35] = list(candidate_proof)
            packet = boot.SHELL_RECORD.pack(*candidate_fields)
            with mock.patch.object(boot, 'memory', return_value=reload_prefix), \
                    mock.patch.object(boot, 'shared_mapping',
                        return_value=(block_address, block_address + 4096)):
                self.assertTrue(controller.pump_bootstrap_listener())
            self.assertEqual([entry[0] for entry in context_route],
                ['prepare', 'activate'], 'private C31 PREPARE must precede ACTIVATE')
            prepare_call = context_route[0]
            self.assertIs(prepare_call[1][0], transport.auth)
            self.assertIs(prepare_call[1][1], controller._first_candidate_relay_anchor)
            self.assertIs(prepare_call[1][2], transport.app)
            self.assertIs(prepare_call[1][3], transport.app_pidfd)
            self.assertIs(prepare_call[1][4], transport.supervisor_pidfd)
            self.assertIs(prepare_call[1][5], transport.worker_view)
            self.assertIs(prepare_call[1][7], context.master)
            self.assertIs(prepare_call[1][10], context.deadline_ns)
            self.assertIs(prepare_call[2]['source_context'], context)
            self.assertIs(prepare_call[2]['source_cycle_proof'], candidate_proof)
            self.assertEqual(prepare_call[2]['source_epoch'], 1)
            self.assertTrue(controller._first_candidate_activation_delivered)
            self.assertIs(controller._first_candidate_source_prepared, prepared_sentinel)
            receipt = controller._accepted_candidate_worker_request
            self.assertIsNotNone(receipt,
                'the real listener pump did not retain its accepted request provenance')
            self.assertEqual(receipt.packet, packet)
            self.assertEqual(receipt.credentials, (candidate_pid, os.getuid(), os.getgid()))
            self.assertIs(receipt.listener, listener)
            self.assertEqual(receipt.worker_key, (1, 1))
            channel = receipt.channel
            cap = controller._first_candidate_worker_grant
            self.assertEqual(provider_actor._used_slots, {0, 1})
            self.assertTrue(controller._first_candidate_worker_grant_consumed)
            self.assertTrue(controller._first_candidate_worker_pending)
            self.assertFalse(controller.unresolved)
            self.assertIs(controller._first_candidate_worker_grant, cap)
            self.assertIsNone(controller._first_candidate_pending_error)
            self.assertIsNone(provider_actor._first_candidate_pending_ready)
            self.assertIsNone(provider_actor._first_candidate_pending_error)
            self.assertEqual(controller._first_candidate_observed_ready[3], 1)
            self.assertEqual(attachment.candidate_ready[0],
                controller._first_candidate_observed_ready)
            self.assertEqual(set(context.workers), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_channels), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_process_slots), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_proofs), {(0, 0), (1, 1)})
            self.assertEqual(context.worker_ready_receivers, {})
            report_ready, _, _ = select.select([candidate_report_r], [], [], 3.0)
            self.assertTrue(report_ready, 'candidate did not receive the real SCM_RIGHTS grant')
            report = b''
            while len(report) < struct.calcsize('=IQQQQI'):
                report += os.read(candidate_report_r,
                    struct.calcsize('=IQQQQI') - len(report))
            fd_count, transferred_dev, transferred_ino, relay_cookie, ready_cookie, rights_flags = struct.unpack('=IQQQQI', report)
            self.assertEqual(fd_count, 5)
            self.assertEqual(rights_flags, 31,
                'candidate did not receive exact FIFO, relay, READY and PIDFD capabilities')
            self.assertEqual((transferred_dev, transferred_ino),
                (slot1.st_dev, slot1.st_ino))
            self.assertEqual(relay_cookie, cap.relay_cookie)
            self.assertNotEqual(relay_cookie, ready_cookie)
            self.assertEqual(set(context.workers), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_channels), {(0, 0), (1, 1)})
        finally:
            if attachment is not None:
                try: attachment.close()
                except BaseException: pass
            if launch is not None:
                for fd in (launch.origin_pidfd, launch.pidfd):
                    try: os.close(fd)
                    except OSError: pass
            if 'controller' in locals():
                anchor = getattr(controller, '_first_candidate_relay_anchor', None)
                if anchor is not None:
                    try: anchor.close()
                    except OSError: pass
                observed_pidfd = getattr(controller, '_first_candidate_observed_pidfd', -1)
                if observed_pidfd >= 0:
                    try: os.close(observed_pidfd)
                    except OSError: pass
            for fd, value in ((initial_release, b'x'),
                    (candidate_release_w, b'x')):
                try: os.write(fd, value)
                except OSError: pass
            for fd in (initial_release, candidate_release_w, candidate_report_r,
                    master_pidfd, app_pidfd, initial_pidfd, context_initial_pidfd,
                    slot0_r, slot0_w, slot1_r, slot1_w, candidate_report_w,
                    owner_ready_command_w):
                try: os.close(fd)
                except OSError: pass
            for sock in (listener, channel, initial_ready_receiver, initial_ready_sender,
                    relay, relay_peer, initial_relay,
                    initial_relay_peer, initial_relay_auth, initial_relay_auth_peer,
                    initial_auth, initial_auth_peer,
                    ready_receiver, ready_sender):
                if sock is not None:
                    try: sock.close()
                    except OSError: pass
            if 'context' in locals():
                candidate_entry = context.workers.get((1, 1))
                if candidate_entry is not None:
                    try: os.close(candidate_entry[0])
                    except OSError: pass
                candidate_channel = context.worker_channels.get((1, 1))
                if candidate_channel is not None:
                    try: candidate_channel.close()
                    except OSError: pass
            for pid in (initial_pid, candidate_pid):
                try: os.waitpid(pid, 0)
                except (ChildProcessError, UnboundLocalError): pass
        current_fd_links = fd_links()
        self.assertEqual(current_fd_links, baseline_fd_links,
            f'first-candidate model changed its descriptor census: {current_fd_links}, baseline {baseline_fd_links}')
        self.assertEqual(direct_children(), baseline_children,
            'first-candidate model leaked a forked worker child')


    def test_first_candidate_grant_rejects_forgery_and_retains_unknown_send(self):
        module = ker_run._load_source_shell_controller()
        provider_module = module._c22_provider_module()
        boot_spec = importlib.util.spec_from_file_location('first_candidate_boot_test',
            ROOT / 'tools' / 'nginx_source_bootstrap_supervisor.py')
        boot = importlib.util.module_from_spec(boot_spec)
        boot_spec.loader.exec_module(boot)
        baseline_fds = len(os.listdir('/proc/self/fd'))
        def direct_children():
            path = Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children')
            return {int(value) for value in path.read_text().split()}
        baseline_children = direct_children()
        ready_receiver = ready_sender = None
        parent_pid = os.getpid()
        master_pidfd = os.pidfd_open(parent_pid, 0)
        master_start = boot.identity._start_ticks(parent_pid)
        binary_hash = module._c22_provider_module().hashlib.sha256(
            Path(f'/proc/{parent_pid}/exe').read_bytes()).digest()
        nonce = b'first-candidate1'
        deadline = time.monotonic_ns() + 5_000_000_000
        epoch = 37
        config_hash, ini_hash = b'c' * 32, b'i' * 32
        initial_proof = boot.SourceCycleProof(1, 0, 1, 123,
            config_hash, ini_hash)
        candidate_proof = boot.SourceCycleProof(1, 0, 2, 456,
            config_hash, ini_hash)

        def child_waiter():
            release_r, release_w = os.pipe()
            ready_r, ready_w = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(release_w); os.close(ready_r)
                start = boot.identity._start_ticks(os.getpid())
                os.write(ready_w, struct.pack('=Q', start)); os.close(ready_w)
                os.read(release_r, 1)
                os._exit(0)
            os.close(release_r); os.close(ready_w)
            start, = struct.unpack('=Q', os.read(ready_r, 8))
            os.close(ready_r)
            return pid, start, release_w

        initial_pid, initial_start, initial_release = child_waiter()
        listener = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        address = '\0ker-candidate-%d-%d' % (parent_pid, time.monotonic_ns())
        listener.bind(address); listener.listen(1)
        candidate_started_r, candidate_started_w = os.pipe()
        candidate_report_r, candidate_report_w = os.pipe()
        candidate_release_r, candidate_release_w = os.pipe()
        candidate_pid = os.fork()
        if candidate_pid == 0:
            try:
                listener.close()
                os.close(candidate_started_r); os.close(candidate_report_r)
                os.close(candidate_release_w)
                client = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                client.settimeout(3.0)
                client.connect(address)
                start = boot.identity._start_ticks(os.getpid())
                request_fields = list(boot.SHELL_RECORD.unpack(
                    bytes(boot.SHELL_RECORD.size)))
                request_fields[:5] = [boot.MAGIC, boot.SHELL_VERSION, 1,
                    boot.SHELL_RECORD.size, 1]
                request_fields[5:17] = [os.getpid(), os.getpid(), os.getppid(),
                    1, 1, 0, start, master_start, 0x100000, epoch,
                    deadline, nonce]
                request_fields[29:35] = list(candidate_proof)
                client.send(boot.SHELL_RECORD.pack(*request_fields))
                os.write(candidate_started_w, struct.pack('=Q', start))
                os.close(candidate_started_w)
                packet, ancillary, flags, _ = client.recvmsg(4096,
                    socket.CMSG_SPACE(5 * 4), getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
                fds = []
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        usable = len(payload) - len(payload) % 4
                        fds.extend(array.array('i', payload[:usable]))
                flags_ok = 0
                if len(fds) == 5:
                    fifo = os.fstat(fds[2])
                    if (stat.S_ISFIFO(fifo.st_mode) and
                            fcntl.fcntl(fds[2], fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY and
                            fcntl.fcntl(fds[2], fcntl.F_GETFL) & os.O_NONBLOCK and
                            fcntl.fcntl(fds[2], fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
                        flags_ok |= 1
                    relay_copy = socket.socket(fileno=os.dup(fds[3]))
                    ready_copy = socket.socket(fileno=os.dup(fds[4]))
                    try:
                        relay_cookie = struct.unpack('=Q', relay_copy.getsockopt(
                            socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
                        ready_cookie = struct.unpack('=Q', ready_copy.getsockopt(
                            socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
                        relay_peer = struct.unpack('=3i', relay_copy.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        ready_peer = struct.unpack('=3i', ready_copy.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if (relay_copy.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) ==
                                socket.SOCK_SEQPACKET and
                                relay_copy.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1 and
                                relay_peer[0] == os.getppid() and relay_cookie and
                                fcntl.fcntl(fds[3], fcntl.F_GETFD) & fcntl.FD_CLOEXEC):
                            flags_ok |= 2
                        if (ready_copy.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) ==
                                socket.SOCK_SEQPACKET and ready_peer[0] == os.getppid() and
                                ready_cookie and fcntl.fcntl(fds[4], fcntl.F_GETFD) &
                                    fcntl.FD_CLOEXEC):
                            flags_ok |= 4
                        if all(boot.identity._pidfd_pid(fd) == os.getppid()
                                for fd in fds[:2]):
                            flags_ok |= 8
                        if all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
                                for fd in fds):
                            flags_ok |= 16
                    finally:
                        relay_copy.close(); ready_copy.close()
                else:
                    fifo = os.fstat(0)
                os.write(candidate_report_w, struct.pack('=IQQQQI', len(fds),
                    fifo.st_dev, fifo.st_ino,
                    relay_cookie if len(fds) == 5 else 0,
                    ready_cookie if len(fds) == 5 else 0, flags_ok))
                os.close(candidate_report_w)
                for fd in fds: os.close(fd)
                client.close()
                os.read(candidate_release_r, 1)
                os._exit(0 if packet else 91)
            except BaseException:
                os._exit(92)
        os.close(candidate_started_w); os.close(candidate_report_w)
        os.close(candidate_release_r)
        candidate_start, = struct.unpack('=Q', os.read(candidate_started_r, 8))
        os.close(candidate_started_r)
        readable, _, _ = select.select([listener], [], [], 2.0)
        self.assertTrue(readable, 'modeled candidate did not connect its distinct channel')
        channel, _ = listener.accept()
        channel.setblocking(False)
        channel.set_inheritable(False)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

        slot0_r, slot0_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        slot1_r, slot1_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        relay, relay_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        relay.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        relay_peer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        initial_relay, initial_relay_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        initial_relay_auth, initial_relay_auth_peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        initial_auth, initial_auth_peer = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        for endpoint in (initial_relay, initial_relay_peer, initial_relay_auth,
                initial_relay_auth_peer, initial_auth, initial_auth_peer):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        ready_channel, ready_peer = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        app_pidfd = os.pidfd_open(parent_pid, 0)
        initial_pidfd = os.pidfd_open(initial_pid, 0)
        context_initial_pidfd = os.dup(initial_pidfd)
        try:
            slot0 = os.fstat(slot0_w); slot1 = os.fstat(slot1_w)
            initial_relay_cookie = struct.unpack('=Q', initial_relay.getsockopt(
                socket.SOL_SOCKET, getattr(socket, 'SO_COOKIE', 57), 8))[0]
            initial_slot_cookie = 19191
            record = list(boot.SHELL_RECORD.unpack(bytes(boot.SHELL_RECORD.size)))
            record[5], record[6], record[8], record[9], record[11] = (
                initial_pid, initial_pid, 0, 0, initial_start)
            record[14:17] = [epoch, deadline, nonce]
            record[20] = 2
            record[24:28] = [slot0.st_dev, slot0.st_ino,
                initial_relay_cookie, initial_slot_cookie]
            context = object.__new__(boot.SourceBootstrapSupervisor)
            context.control_only = True
            context.shell_mode = True
            context.epoch, context.deadline_ns, context.nonce = epoch, deadline, nonce
            context.binary_hash = binary_hash
            context.master = SimpleNamespace(pid=parent_pid, pidfd=master_pidfd,
                start_ticks=master_start)
            context.runtime = SimpleNamespace(pid=parent_pid, pidfd=master_pidfd,
                start_ticks=master_start)
            context.io = SimpleNamespace(pid=parent_pid, pidfd=master_pidfd,
                start_ticks=master_start)
            context.workers = {(0, 0): (context_initial_pidfd, tuple(record))}
            context.worker_channels = {(0, 0): initial_relay_peer}
            context.worker_ready_receivers = {}
            context.worker_process_slots = {(0, 0): 7}
            context.worker_proofs = {(0, 0): initial_proof}
            context.initial_cycle_proof = initial_proof
            context.expected_config_sha256, context.expected_ini_sha256 = config_hash, ini_hash
            context._used_cycle_proofs = set()
            context._cycle_serial_highwater = 1
            context.allow_abort_retry = False
            context.allow_successor = False
            context._activated_workers = set()
            context._completed_master_barriers = set()
            context._source_shell_committed_plans = {}
            context._source_route_preparations = {}
            context._source_route_park_joins = {}
            context._source_route_commit_receipts = {}
            context._source_route_commit_consumed = set()
            context._source_route_sequences = {}
            context.record_struct = boot.SHELL_RECORD
            context._unpack_request = boot.SourceBootstrapSupervisor._unpack_request.__get__(context)
            context._fresh_candidate_cycle_proof = lambda fields: candidate_proof
            context._cycle_token_live = lambda *_: None
            context.live = lambda *_: None
            block_address = 0x100000
            reload_prefix = struct.pack('=8I', 0x46524c4d, 1, 32, 1, 0, 1, 1, 0)
            context.slim_pidfd = master_pidfd
            slim_reply = [0] * 21
            slim_reply[20] = 1
            context.slim_reply = slim_reply
            context.supervisor_start = master_start
            context._scalar = lambda pid, name, fmt: ({
                'ngx_ff_reload_shm': block_address,
                'ngx_process': 3, 'ngx_worker': 0, 'ngx_ff_process': 2,
                'ngx_ff_graceful_reload': 1, 'ngx_process_slot': 9,
            }[name])
            context.shared_mapping = lambda _pid, address: (address, address + 4096)

            class Broker:
                ready = True
                stopped = False
                def _check_app_identity(self): pass
            broker = Broker()
            provider_actor = provider_module.SourceShellC22Provider.__new__(
                provider_module.SourceShellC22Provider)
            provider_actor.context = context
            provider_actor.broker_readiness = broker
            provider_actor._closed = False
            provider_actor._used_slots = {0}
            provider_actor._first_candidate_pending_watch = None
            provider_actor._first_candidate_pending_ready = None
            provider_actor._first_candidate_pending_error = None
            provider_actor.slots = [slot0_w, slot1_w]
            provider_actor.slot_identities = ((slot0.st_dev, slot0.st_ino),
                (slot1.st_dev, slot1.st_ino))
            provider_actor._check_actor = lambda *_: None

            controller = object.__new__(module.SourceShellController)
            controller.bootstrap_context = context
            controller.listener = listener
            controller.initial_worker_binding = None
            controller._initial_transport = None
            controller._first_candidate_worker_grant = None
            controller._accepted_candidate_worker_request = None
            controller._first_candidate_worker_grant_consumed = False
            controller._first_candidate_worker_pending = False
            controller._first_candidate_pending_watch = None
            controller._first_candidate_pending_ready = None
            controller._first_candidate_pending_error = None
            controller.broker_readiness = broker
            controller.c22_provider = provider_actor
            controller.profile = SimpleNamespace(deadline_ns=deadline,
                origin_module=SimpleNamespace(identity=boot.identity,
                    parent_pid=lambda pid: int(Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[1])))
            controller.launch = SimpleNamespace(context=context,
                live_supervisor=lambda _deadline: None)
            controller.unresolved = False

            transport = module._SourceInitialWorkerTransport(
                module._INITIAL_TRANSPORT_TOKEN, context, broker, initial_relay,
                initial_relay_auth, initial_auth, SimpleNamespace(pid=parent_pid),
                app_pidfd, app_pidfd, nonce, epoch, lambda *_: None, lambda: None)
            transport.grant_attempted = transport.auth_started = transport.authenticated = True
            transport.attachment = SimpleNamespace(check=lambda: None)
            transport.ready_identity = (initial_pid, os.getuid(), os.getgid(), 0,
                initial_pid, 0, initial_start, slot0.st_dev, slot0.st_ino,
                initial_slot_cookie)
            transport.attachment.ready = (transport.ready_identity, initial_pidfd)
            transport.watch = {'pid': initial_pid, 'tid': initial_pid, 'role': 0,
                'start': initial_start, 'slot_device': slot0.st_dev,
                'slot_inode': slot0.st_ino, 'cookie': initial_slot_cookie,
                'source_epoch': 0, 'generation': 0, 'process_slot': 7}
            transport.worker_pidfd = initial_pidfd
            transport.worker_view = module._InitialOwnerAuthView(initial_pidfd,
                initial_pid, initial_pid, 0, initial_start, slot0.st_dev,
                slot0.st_ino, initial_slot_cookie)
            transport.broker = broker
            controller.initial_worker_binding = transport
            controller._initial_transport = transport
            initial_record = list(record)
            context.workers[(0, 0)] = (context_initial_pidfd, tuple(initial_record))

            candidate_fields = list(boot.SHELL_RECORD.unpack(bytes(boot.SHELL_RECORD.size)))
            candidate_fields[:5] = [boot.MAGIC, boot.SHELL_VERSION, 1,
                boot.SHELL_RECORD.size, 1]
            candidate_fields[5:17] = [candidate_pid, candidate_pid, parent_pid,
                1, 1, 0, candidate_start, master_start, block_address,
                epoch, deadline, nonce]
            candidate_fields[29:35] = list(candidate_proof)
            packet = boot.SHELL_RECORD.pack(*candidate_fields)
            received_packet, request_ancillary, request_flags, _ = channel.recvmsg(
                boot.SHELL_RECORD.size + 1, socket.CMSG_SPACE(12),
                getattr(socket, 'MSG_CMSG_CLOEXEC', 0) |
                    getattr(socket, 'MSG_DONTWAIT', 0))
            request_credentials = [struct.unpack('=3i', value)
                for level, kind, value in request_ancillary
                if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and
                    len(value) == 12]
            self.assertEqual(received_packet, packet)
            self.assertEqual(len(request_credentials), 1)
            self.assertFalse(request_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
            credentials = request_credentials[0]
            with self.assertRaises(PermissionError):
                controller.mint_first_candidate_worker_grant(transport,
                    provider_actor, channel, packet, credentials, relay, deadline)
            # This private record only models the pump's listener receipt for
            # downstream grant-layer coverage; it is not pipeline provenance.
            controller._accepted_candidate_worker_request = (
                module._AcceptedCandidateWorkerRequest(
                    module._ACCEPTED_CANDIDATE_REQUEST_TOKEN, controller,
                    listener, module.SourceShellController._first_candidate_endpoint_identity(listener),
                    module.SourceShellController._first_candidate_socket_cookie(listener),
                    channel, module.SourceShellController._first_candidate_endpoint_identity(channel),
                    module.SourceShellController._first_candidate_socket_cookie(channel),
                    received_packet, credentials, deadline, (1, 1)))
            binding_calls = []
            initial_check = controller._check_initial_worker_binding
            controller._check_initial_worker_binding = lambda *_: binding_calls.append('checked')
            with self.assertRaises(TimeoutError):
                controller.mint_first_candidate_worker_grant(transport,
                    provider_actor, channel, packet, credentials, relay,
                    time.monotonic_ns() - 1)
            with self.assertRaises(TimeoutError):
                controller.mint_first_candidate_worker_grant(transport,
                    provider_actor, channel, packet, credentials, relay,
                    deadline + 1)
            with self.assertRaises(TimeoutError):
                controller.mint_first_candidate_worker_grant(transport,
                    provider_actor, channel, packet, credentials, relay, True)
            self.assertEqual(binding_calls, [],
                'expired grant reached provider/initial-binding checks before deadline rejection')
            controller._check_initial_worker_binding = initial_check
            cap = controller.mint_first_candidate_worker_grant(transport,
                provider_actor, channel, packet, credentials, relay, deadline)
            copied_cap_receipt = cap._replace(
                accepted_request=cap.accepted_request._replace())
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(
                    copied_cap_receipt, provider_actor, channel, packet,
                    credentials, relay, deadline)
            held_receipt = controller._accepted_candidate_worker_request
            controller._accepted_candidate_worker_request = held_receipt._replace()
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(
                    cap, provider_actor, channel, packet, credentials, relay, deadline)
            controller._accepted_candidate_worker_request = held_receipt
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(
                    cap, provider_actor, relay, packet, credentials, relay, deadline)
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(
                    cap._replace(packet=b'x' * len(packet)), provider_actor,
                    channel, packet, credentials, relay, deadline)
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(cap,
                    object(), channel, packet, credentials, relay, deadline)
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(cap,
                    provider_actor, channel, packet, credentials, relay, deadline + 1)
            original_context = controller.bootstrap_context
            controller.bootstrap_context = SimpleNamespace()
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(cap,
                    provider_actor, channel, packet, credentials, relay, deadline)
            controller.bootstrap_context = original_context
            original_transport = controller.initial_worker_binding
            controller.initial_worker_binding = object()
            with self.assertRaises(PermissionError):
                controller._validate_first_candidate_worker_grant(cap,
                    provider_actor, channel, packet, credentials, relay, deadline)
            controller.initial_worker_binding = original_transport
            altered_fields = list(candidate_fields)
            altered_fields[9] = 2
            wrong_epoch_packet = boot.SHELL_RECORD.pack(*altered_fields)
            with self.assertRaises(PermissionError):
                provider_actor.reply_first_candidate_worker(controller, cap,
                    channel, wrong_epoch_packet, credentials, relay, deadline)
            self.assertEqual(provider_actor._used_slots, {0},
                'wrong key/epoch burned the candidate FIFO')
            with self.assertRaises(OSError) as generic_closed:
                provider_actor.reply_worker(channel, packet, credentials, relay)
            self.assertEqual(generic_closed.exception.errno, errno.ENOTSUP)
            self.assertEqual(provider_actor._used_slots, {0},
                'generic control-only reply mutated the slot state')

            actual_send = boot.send_initial_worker_grant
            send_attempts = []
            def send_then_report_unknown(ch, data, rights, send_deadline):
                actual_send(ch, data, rights, send_deadline)
                send_attempts.append('real-send-then-unknown')
                raise OSError(errno.EIO, 'injected lost result after real common-path send')
            with mock.patch.object(boot, 'memory', return_value=reload_prefix), \
                    mock.patch.object(boot, 'shared_mapping',
                        return_value=(block_address, block_address + 4096)), \
                    mock.patch.object(boot, 'send_initial_worker_grant',
                        side_effect=send_then_report_unknown):
                with self.assertRaises(OSError) as unknown:
                    provider_actor.reply_first_candidate_worker(controller, cap,
                        channel, packet, credentials, relay, deadline)
            self.assertEqual(unknown.exception.errno, errno.EIO)
            self.assertEqual(send_attempts, ['real-send-then-unknown'])
            self.assertEqual(provider_actor._used_slots, {0, 1})
            self.assertTrue(controller._first_candidate_worker_grant_consumed)
            self.assertTrue(controller._first_candidate_worker_pending)
            self.assertTrue(controller.unresolved)
            self.assertIs(controller._first_candidate_worker_grant, cap)
            self.assertIsNone(controller._first_candidate_pending_ready)
            self.assertIsNotNone(controller._first_candidate_pending_error)
            self.assertIsNone(provider_actor._first_candidate_pending_ready)
            self.assertIsNotNone(provider_actor._first_candidate_pending_error)
            self.assertEqual(set(context.workers), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_channels), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_process_slots), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_proofs), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_ready_receivers), {(1, 1)},
                'uncertain send dropped the exact READY receiver anchor')
            ready_receiver = context.worker_ready_receivers[(1, 1)]
            with self.assertRaises((PermissionError, OSError)):
                provider_actor.reply_first_candidate_worker(controller, cap,
                    channel, packet, credentials, relay, deadline)
            report_ready, _, _ = select.select([candidate_report_r], [], [], 3.0)
            self.assertTrue(report_ready, 'candidate did not receive the modeled SCM_RIGHTS grant')
            report = b''
            while len(report) < struct.calcsize('=IQQQQI'):
                report += os.read(candidate_report_r,
                    struct.calcsize('=IQQQQI') - len(report))
            fd_count, transferred_dev, transferred_ino, relay_cookie, ready_cookie, rights_flags = struct.unpack('=IQQQQI', report)
            self.assertEqual(fd_count, 5)
            self.assertEqual(rights_flags, 31,
                'candidate did not receive exact FIFO, relay, READY and PIDFD capabilities')
            self.assertEqual((transferred_dev, transferred_ino),
                (slot1.st_dev, slot1.st_ino))
            self.assertEqual(relay_cookie, cap.relay_cookie)
            self.assertNotEqual(relay_cookie, ready_cookie)
            self.assertEqual(set(context.workers), {(0, 0), (1, 1)})
            self.assertEqual(set(context.worker_channels), {(0, 0), (1, 1)})
        finally:
            for fd, value in ((initial_release, b'x'),
                    (candidate_release_w, b'x')):
                try: os.write(fd, value)
                except OSError: pass
            for fd in (initial_release, candidate_release_w, candidate_report_r,
                    master_pidfd, app_pidfd, initial_pidfd, context_initial_pidfd,
                    slot0_r, slot0_w, slot1_r, slot1_w, candidate_report_w):
                try: os.close(fd)
                except OSError: pass
            for sock in (listener, channel, relay, relay_peer, initial_relay,
                    initial_relay_peer, initial_relay_auth, initial_relay_auth_peer,
                    initial_auth, initial_auth_peer, ready_channel, ready_peer,
                    ready_receiver, ready_sender):
                if sock is not None:
                    try: sock.close()
                    except OSError: pass
            if 'context' in locals():
                candidate_entry = context.workers.get((1, 1))
                if candidate_entry is not None:
                    try: os.close(candidate_entry[0])
                    except OSError: pass
                candidate_channel = context.worker_channels.get((1, 1))
                if candidate_channel is not None:
                    try: candidate_channel.close()
                    except OSError: pass
            for pid in (initial_pid, candidate_pid):
                try: os.waitpid(pid, 0)
                except (ChildProcessError, UnboundLocalError): pass
        self.assertEqual(len(os.listdir('/proc/self/fd')), baseline_fds,
            'first-candidate modeled grant leaked descriptors')
        self.assertEqual(direct_children(), baseline_children,
            'first-candidate model leaked a forked worker child')


    def test_capsules_are_not_released_while_native_io_actor_is_live(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        events = []

        class Launch:
            process = SimpleNamespace(returncode=0, poll=lambda: 0)
            settlement = {'settled': True}

            def observe_settlement(self):
                return dict(self.settlement)

            pidfd = -1
            master_pidfd = origin_pidfd = native_io_pidfd = -1
            context = None

            def close(self):
                events.append('origin-close')

        class Capsules:
            def close(self, launch):
                events.append('capsules-close')

        controller = object.__new__(controller_type)
        controller.launch = Launch()
        controller.capsules = Capsules()
        controller.profile = SimpleNamespace(origin_module=SimpleNamespace(identity=
            SimpleNamespace(process_alive=lambda fd: fd == 44)))
        controller.launch.native_io_pidfd = 44
        controller.listener = None
        controller.started = True
        with self.assertRaises(RuntimeError):
            controller.close_settled()
        self.assertEqual(events, [])

    def test_capsules_read_settlement_before_origin_closes_output_fd(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        events = []

        class Launch:
            process = SimpleNamespace(returncode=0, poll=lambda: 0)
            settlement = {'settled': True}
            pidfd = master_pidfd = origin_pidfd = native_io_pidfd = -1
            context = None
            output_open = True

            def observe_settlement(self):
                events.append('observe')
                if not self.output_open:
                    raise RuntimeError('output receipt descriptor already closed')
                return dict(self.settlement)

            def close(self):
                events.append('origin-close')
                self.output_open = False

        class Capsules:
            def close(self, launch):
                self.launch = launch
                launch.observe_settlement()
                events.append('capsules-close')

        identity = SimpleNamespace(process_alive=lambda fd: False)
        controller = object.__new__(controller_type)
        controller.launch = Launch()
        controller.capsules = Capsules()
        controller.profile = SimpleNamespace(origin_module=SimpleNamespace(identity=identity))
        controller.io_actor = None
        controller.listener = None
        controller.started = True
        controller.close_settled()
        self.assertEqual(events, ['observe', 'observe', 'capsules-close', 'origin-close'])

    def test_close_settled_releases_candidate_anchors_after_all_outcome_states(self):
        module = ker_run._load_source_shell_controller()
        for state in ('pre-mint-failure', 'uncertain-send', 'observer-failure'):
            with self.subTest(state=state):
                baseline_fds = len(os.listdir('/proc/self/fd'))
                accepted, accepted_peer = socket.socketpair(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                relay_anchor, relay_peer = socket.socketpair(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                context_channels = {}
                ready_receivers = {}
                pending_ready = None
                context_ready = None
                ready_sender = None
                candidate_dup = None
                observed_pidfd = -1
                if state != 'pre-mint-failure':
                    candidate_dup = accepted.dup()
                    context_channels[(1, 1)] = candidate_dup
                if state == 'uncertain-send':
                    context_ready, ready_sender = socket.socketpair(socket.AF_UNIX,
                        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                    ready_receivers[(1, 1)] = context_ready
                if state == 'observer-failure':
                    pending_ready, ready_sender = socket.socketpair(socket.AF_UNIX,
                        socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                    observed_pidfd = os.pidfd_open(os.getpid(), 0)

                class Context:
                    slim_pidfd = -1
                    workers = {}
                    def __init__(self):
                        self.worker_channels = context_channels
                        self.worker_ready_receivers = ready_receivers
                    def close(self):
                        for sock in self.worker_channels.values(): sock.close()
                        for sock in self.worker_ready_receivers.values(): sock.close()
                        self.worker_channels.clear(); self.worker_ready_receivers.clear()

                context = Context()
                class Launch:
                    process = SimpleNamespace(poll=lambda: 0)
                    pidfd = master_pidfd = origin_pidfd = native_io_pidfd = -1
                    backend_receipt = None
                    def __init__(self): self.context = context
                    def observe_settlement(self): return {'settled': True}
                    def close(self): context.close()

                provider = SimpleNamespace(_first_candidate_pending_ready=pending_ready,
                    _first_candidate_pending_watch={'watch': state},
                    _first_candidate_pending_error=OSError(errno.EIO, state),
                    close=lambda: None)
                controller = object.__new__(module.SourceShellController)
                controller.launch = Launch()
                controller.profile = SimpleNamespace(origin_module=SimpleNamespace(
                    identity=SimpleNamespace(process_alive=lambda _fd: False)))
                controller.capsules = SimpleNamespace(close=lambda _launch: None)
                controller.c22_provider = provider
                controller._initial_transport = None
                controller._accepted_candidate_worker_request = SimpleNamespace(
                    channel=accepted)
                controller._first_candidate_worker_grant = (
                    None if state == 'pre-mint-failure' else object())
                controller._first_candidate_worker_grant_consumed = state != 'pre-mint-failure'
                controller._first_candidate_worker_pending = True
                controller._first_candidate_pending_watch = {'watch': state}
                controller._first_candidate_pending_ready = pending_ready
                controller._first_candidate_pending_error = OSError(errno.EIO, state)
                controller._first_candidate_relay_anchor = relay_anchor
                controller._first_candidate_observed_pidfd = observed_pidfd
                controller._first_candidate_observed_ready = None
                controller.listener = None
                controller.io_actor = None
                controller.control_slim_channel = None
                controller.started = True
                try:
                    controller.close_settled()
                    self.assertIsNone(controller._accepted_candidate_worker_request)
                    self.assertIsNone(controller._first_candidate_worker_grant)
                    self.assertIsNone(controller._first_candidate_pending_ready)
                    self.assertIsNone(provider._first_candidate_pending_ready)
                    self.assertIsNone(controller._first_candidate_relay_anchor)
                    self.assertEqual(controller._first_candidate_observed_pidfd, -1)
                    self.assertEqual(accepted.fileno(), -1)
                    self.assertEqual(relay_anchor.fileno(), -1)
                    if candidate_dup is not None:
                        self.assertEqual(candidate_dup.fileno(), -1)
                    if pending_ready is not None:
                        self.assertEqual(pending_ready.fileno(), -1)
                    if context_ready is not None:
                        self.assertEqual(context_ready.fileno(), -1)
                    if observed_pidfd >= 0:
                        with self.assertRaises(OSError):
                            fcntl.fcntl(observed_pidfd, fcntl.F_GETFD)
                finally:
                    for sock in (accepted, accepted_peer, relay_anchor, relay_peer,
                            candidate_dup, pending_ready, context_ready, ready_sender):
                        if sock is not None:
                            try: sock.close()
                            except OSError: pass
                    if observed_pidfd >= 0:
                        try: os.close(observed_pidfd)
                        except OSError: pass
                self.assertEqual(len(os.listdir('/proc/self/fd')), baseline_fds,
                    f'{state} settlement leaked candidate descriptors')

    def test_control_slim_socket_closes_only_after_verified_settlement(self):
        controller_type = ker_run._load_source_shell_controller().SourceShellController
        accepted, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(accepted.close)
        self.addCleanup(peer.close)
        context = SimpleNamespace(slim_channel=accepted, slim_pidfd=-1, workers={})
        events = []

        class Launch:
            process = SimpleNamespace(returncode=0, poll=lambda: 0)
            settlement = {'settled': True}
            pidfd = master_pidfd = origin_pidfd = native_io_pidfd = -1
            backend_receipt = None
            def __init__(self):
                self.context = context
            def observe_settlement(self):
                return dict(self.settlement)
            def close(self):
                events.append('origin-close')

        class Capsules:
            def __init__(self, fail=False):
                self.fail = fail
            def close(self, launch):
                events.append('capsules-close')
                if self.fail:
                    raise RuntimeError('receipt revalidation failed')

        controller = object.__new__(controller_type)
        controller.launch = Launch()
        controller.capsules = Capsules(fail=True)
        controller.profile = SimpleNamespace(origin_module=SimpleNamespace(
            identity=SimpleNamespace(process_alive=lambda fd: False)))
        controller.listener = None
        controller.control_slim_channel = accepted
        with self.assertRaisesRegex(RuntimeError, 'receipt revalidation'):
            controller.close_settled()
        self.assertGreaterEqual(accepted.fileno(), 0)
        self.assertIs(controller.control_slim_channel, accepted)
        self.assertIs(context.slim_channel, accepted)

        controller.capsules = Capsules()
        controller.close_settled()
        self.assertEqual(events, ['capsules-close', 'capsules-close', 'origin-close'])
        self.assertIsNone(controller.control_slim_channel)
        self.assertIsNone(context.slim_channel)
        self.assertEqual(accepted.fileno(), -1)
if __name__ == '__main__':
    unittest.main()
