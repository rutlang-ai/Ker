"""Wire/lifetime controls for the source-origin observer.

These tests exercise the observer with controlled forked Python actors. They
are not evidence about the original shell, original supervisor, Nginx, or a
native handoff.
"""
import array
import errno
import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from types import MethodType, SimpleNamespace
from unittest import mock


MODULE = Path(__file__).resolve().parents[2] / 'tools/nginx_source_origin.py'
SPEC = importlib.util.spec_from_file_location('test_nginx_source_origin_impl', MODULE)
origin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(origin)


def fd_count():
    return len(os.listdir('/proc/self/fd'))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


class SourceOriginControls(unittest.TestCase):
    CONFIG_DIGEST = 'ab' * 32
    INI_DIGEST = 'cd' * 32

    def setUp(self):
        if not hasattr(os, 'pidfd_open'):
            self.skipTest('pidfds are unavailable')
        self.rx, self.tx = socket.socketpair(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.rx.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.child = self.origin_pid = self.sibling_pid = None
        self.actor_fds = []
        self.launch = self._launch()

    def tearDown(self):
        for pid in (self.child, self.origin_pid, self.sibling_pid):
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for pid in (self.child, self.origin_pid, self.sibling_pid):
            if pid:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
        for fd in self.actor_fds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.rx.close()
        self.tx.close()

    def _launch(self):
        value = origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
        value.creator_pid = os.getppid()
        value.creator_start = origin.identity._start_ticks(value.creator_pid)
        value.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
        value.pidfd = -1
        value.master_pidfd = value.origin_pidfd = value.output_fd = -1
        value.context = value.origin_channel = value.settlement = None
        value.files = []
        value.artifact_binding = None
        value.consumed = False
        value.epoch = 7
        value.deadline_ns = time.monotonic_ns() + 10_000_000_000
        value.nonce = bytes.fromhex('01' * 16)
        value.pid_namespace = origin.namespace_identity(os.getpid())
        value.nginx = SimpleNamespace(sha256=b'controlled-test-build',
            path=Path('/controlled/test-nginx'), matches_process=lambda pid, deadline: None)
        value.live_supervisor = lambda deadline=None: None
        return value

    def test_retained_backend_attach_matches_creator_expectation_runtime_and_lifetime(self):
        startup = origin._SOURCE_NETWORK_STARTUP
        now = time.monotonic_ns()
        deadline = self.launch.deadline_ns
        digest = 'ef' * 32
        record = (f'v1|{digest}|192.168.1.2|255.255.255.0|'
            f'192.168.1.255|192.168.1.1|{deadline}')
        expected = startup.prepare_expected('1', record, str(deadline),
            '192.168.1.2/24', '192.168.1.1', now_ns=now)
        expectation = startup.SourceNetworkExpectation('/captured/template', digest,
            '192.168.1.2', '255.255.255.0', '192.168.1.255', '192.168.1.1',
            deadline, None)
        proof = (f'KER_SOURCE_NETWORK_READBACK_V1 template_sha256={digest} '
            'ifindex=2 address=192.168.1.2 netmask=255.255.255.0 '
            'broadcast=192.168.1.255 gateway=192.168.1.1 route_oif=2 '
            f'route_table=254 deadline_ns={deadline}\n').encode()
        prefix = startup.READY + proof
        parsed = startup.parse_startup_prefix(prefix, expected, now)
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        pin = startup.PinnedExecutable(sys.executable, deadline)
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
            close_fds=True)
        pidfd = os.pidfd_open(process.pid, 0)
        receipt = None
        try:
            os.write(write_fd, prefix)
            pipe_identity = startup.pipe_identity(read_fd, write_fd)
            receipt = startup._capture_retained_backend_receipt(process, pidfd,
                startup._proc_start_ticks(process.pid), pin, read_fd, pipe_identity,
                expected, parsed, time.monotonic_ns(), object())
            runtime = receipt.actor_identity
            self.launch.creator_pid = os.getpid()
            self.launch.creator_start = origin.identity._start_ticks(os.getpid())
            self.launch.network_expectation = expectation
            self.launch.backend_receipt = None
            self.launch.backend_handoff = startup.RetainedBackendHandoff.for_network_expectation(
                expectation, self.launch.creator_pid, self.launch.creator_start)
            with self.assertRaises(PermissionError):
                self.launch.attach_retained_backend_receipt({})
            self.launch.attach_retained_backend_receipt(receipt)
            self.assertTrue(self.launch._require_retained_backend(runtime, deadline))
            with self.assertRaises(RuntimeError):
                self.launch._require_retained_backend(object(), deadline)
            with self.assertRaises(AttributeError):
                receipt.expected = ()
            process.terminate()
            process.wait(timeout=3)
            with self.assertRaises(RuntimeError):
                self.launch._require_retained_backend(runtime, deadline)
            receipt.close()
        finally:
            if process.poll() is None:
                process.kill(); process.wait()
            if receipt is not None and not receipt.closed:
                receipt.close()
            os.close(pidfd)
            pin.close()
            os.close(read_fd)
            os.close(write_fd)

    def test_separate_ker_run_import_reuses_path_checked_receipt_types(self):
        launcher_path = Path(origin.launcher.__file__).resolve(strict=True)
        spec = importlib.util.spec_from_file_location('independent_ker_run_import',
            launcher_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIs(module.source_network_startup, origin._SOURCE_NETWORK_STARTUP)
        self.assertIs(module.source_network_startup.RetainedBackendReceipt,
            origin._SOURCE_NETWORK_STARTUP.RetainedBackendReceipt)
        wrong_path = SimpleNamespace(__file__='/tmp/other-source-network-startup.py')
        with mock.patch.dict(sys.modules,
                {module._SOURCE_NETWORK_STARTUP_NAME: wrong_path}):
            with self.assertRaises(ImportError):
                module._load_source_network_startup(
                    launcher_path.with_name('source_network_startup.py'))

    def _send_actor_request(self, mutation=None, rights_mode='valid', legacy=False):
        """Fork origin->child; child sends a kernel-credentialed test record."""
        parent = os.getpid()
        report_r, report_w = os.pipe2(os.O_CLOEXEC)
        sibling_pid = None
        if rights_mode == 'wrong_lineage':
            sibling_pid = os.fork()
            if sibling_pid == 0:
                os.close(report_r)
                os.close(report_w)
                while True:
                    time.sleep(1)
            self.sibling_pid = sibling_pid
        origin_pid = os.fork()
        if origin_pid == 0:
            os.close(report_r)
            try:
                child_pid = os.fork()
                if child_pid == 0:
                    try:
                        nsdev, nsino = origin.namespace_identity(os.getpid())
                        now = time.monotonic_ns()
                        fields = [origin.ORIGIN_MAGIC, origin.ORIGIN_VERSION,
                            origin.ORIGIN_REQUEST, origin.ORIGIN.size, 0,
                            (sibling_pid if rights_mode == 'wrong_lineage' else os.getppid()),
                            os.getpid(), os.getpid(), self.launch.creator_pid,
                            origin.identity._start_ticks(sibling_pid if rights_mode == 'wrong_lineage'
                                else os.getppid()),
                            origin.identity._start_ticks(os.getpid()),
                            self.launch.creator_start, self.launch.epoch,
                            self.launch.deadline_ns, min(self.launch.deadline_ns,
                                now + 2_000_000_000), 19, self.launch.nonce, nsdev, nsino,
                            origin.ORIGIN_PROOF_VERSION, 0, 11, 0x12345678,
                            bytes.fromhex(self.CONFIG_DIGEST), bytes.fromhex(self.INI_DIGEST)]
                        if mutation:
                            mutation(fields)
                        wire_fields = fields
                        wire_struct = origin.ORIGIN
                        if legacy:
                            fields[1] = 1
                            fields[3] = origin.ORIGIN_PREFIX.size
                            wire_fields = fields[:19]
                            wire_struct = origin.ORIGIN_PREFIX
                        os.write(report_w, struct.pack('=i', os.getpid()))
                        os.close(report_w)
                        rights = [os.pidfd_open(sibling_pid if rights_mode == 'wrong_lineage'
                            else os.getppid()), os.pidfd_open(os.getpid())]
                        if rights_mode == 'duplicate':
                            os.close(rights[1])
                            rights[1] = os.dup(rights[0])
                        elif rights_mode == 'extra':
                            rights.append(os.pidfd_open(os.getpid()))
                        self.tx.sendmsg([wire_struct.pack(*wire_fields)],
                            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
                        for fd in rights:
                            os.close(fd)
                        while True:
                            time.sleep(1)
                    except BaseException:
                        os._exit(92)
                while True:
                    time.sleep(1)
            except BaseException:
                os._exit(93)
        self.origin_pid = origin_pid
        os.close(report_w)
        self.child = struct.unpack('=i', os.read(report_r, 4))[0]
        os.close(report_r)
        self.rx.settimeout(2)

    def _accept_origin_wire_only(self, channel, runtime=None, io=None):
        """Mock only artifact gates, so these tests exercise origin wire/lifetime."""
        with mock.patch.object(self.launch, '_native_io_ready_live'), \
                mock.patch.object(self.launch, '_require_retained_backend',
                    return_value=object()) as backend_receipt, \
                mock.patch.object(self.launch, '_bind_original_artifacts',
                    return_value=self._wire_binding()), \
                mock.patch.object(self.launch,
                    '_require_control_origin_attestation', return_value=None), \
                mock.patch.object(self.launch, 'capture_source_supervisor_identity',
                    return_value={}):
            return self.launch.accept_origin(channel, runtime, io)

    def _wire_binding(self):
        return SimpleNamespace(config_sha256=self.CONFIG_DIGEST,
            ini_sha256=self.INI_DIGEST, config_file_sha256='12' * 32,
            ini_file_sha256='34' * 32)

    def test_claimed_pid_mismatch_rejects_and_closes_received_rights(self):
        before = fd_count()
        self._send_actor_request(lambda fields: fields.__setitem__(6,
            fields[6] + 1))
        with self.assertRaises(PermissionError):
            self._accept_origin_wire_only(self.rx, object(), object())
        self.assertFalse(self.launch.consumed)
        self.assertEqual(self.launch.master_pidfd, -1)
        self.assertEqual(fd_count(), before)

    def test_legacy_120_byte_origin_record_is_rejected(self):
        before = fd_count()
        self._send_actor_request(legacy=True)
        with self.assertRaises(PermissionError):
            self._accept_origin_wire_only(self.rx, object(), object())
        self.assertFalse(self.launch.consumed)
        self.assertEqual(fd_count(), before)

    def test_constructor_failure_retains_consumed_actor_pidfds(self):
        self._send_actor_request()
        with mock.patch.object(origin.bootstrap, 'SourceBootstrapSupervisor',
                side_effect=RuntimeError('controlled constructor failure')):
            with self.assertRaisesRegex(RuntimeError, 'controlled constructor'):
                self._accept_origin_wire_only(self.rx, object(), object())
        self.assertTrue(self.launch.consumed)
        self.assertIsNone(self.launch.context)
        self.assertEqual(origin.identity._pidfd_pid(self.launch.origin_pidfd),
            self.origin_pid)
        self.assertEqual(origin.identity._pidfd_pid(self.launch.master_pidfd),
            self.child)
        self.assertTrue(origin.identity.process_alive(self.launch.origin_pidfd))
        self.assertTrue(origin.identity.process_alive(self.launch.master_pidfd))
        self.actor_fds.extend((self.launch.origin_pidfd, self.launch.master_pidfd))
        self.launch.origin_pidfd = self.launch.master_pidfd = -1

    def test_wire_negative_controls_close_all_transferred_descriptors(self):
        cases = (
            ('bad magic', lambda f: f.__setitem__(0, 0), 'valid'),
            ('old version and record size', lambda f: (f.__setitem__(1, 1),
                f.__setitem__(3, origin.ORIGIN_PREFIX.size)), 'valid'),
            ('stale operation', lambda f: f.__setitem__(15, 0), 'valid'),
            ('expired startup', lambda f: f.__setitem__(14, 1), 'valid'),
            ('wrong namespace', lambda f: f.__setitem__(18, f[18] + 1), 'valid'),
            ('wrong actor pidfd', None, 'duplicate'),
            ('wrong parent lineage', None, 'wrong_lineage'),
            ('extra descriptor', None, 'extra'),
        )
        for label, mutation, rights_mode in cases:
            with self.subTest(case=label):
                before = fd_count()
                self._send_actor_request(mutation, rights_mode)
                with self.assertRaises(PermissionError):
                    self._accept_origin_wire_only(self.rx, object(), object())
                self.assertFalse(self.launch.consumed)
                self.assertEqual(self.launch.master_pidfd, -1)
                self.assertEqual(fd_count(), before)
                # Recreate a fresh one-shot observer/socket pair for the next
                # independent malformed-record case.
                self.tearDown()
                self.setUp()

    def test_v2_proof_rejects_malformed_zero_and_replayed_transcripts(self):
        valid = [origin.ORIGIN_MAGIC, origin.ORIGIN_VERSION, origin.ORIGIN_REQUEST,
            origin.ORIGIN.size, 0, 1, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            self.launch.nonce, 11, 12, origin.ORIGIN_PROOF_VERSION, 0, 13, 14,
            bytes.fromhex(self.CONFIG_DIGEST), bytes.fromhex(self.INI_DIGEST)]
        binding = self._wire_binding()
        self.assertEqual(origin.validate_origin_proof(valid, binding).adapter_cycle_serial, 13)
        cases = (
            ('unsupported proof version', 19, 2),
            ('nonzero proof flags', 20, 1),
            ('zero adapter cycle serial', 21, 0),
            ('zero opaque cycle token', 22, 0),
            ('corrupt config digest', 23, b'\0' * 32),
            ('replayed config digest', 23, bytes.fromhex('ef' * 32)),
            ('replayed INI digest', 24, bytes.fromhex('ef' * 32)),
            ('truncated record', None, None),
        )
        for label, index, replacement in cases:
            with self.subTest(case=label):
                fields = list(valid)
                if index is None:
                    fields.pop()
                else:
                    fields[index] = replacement
                with self.assertRaises(PermissionError):
                    origin.validate_origin_proof(fields, binding)
        with self.assertRaises(PermissionError):
            origin.validate_origin_proof(valid, None)

    def test_ack_echoes_v2_proof_but_constructs_control_only_context(self):
        self._send_actor_request()
        context = SimpleNamespace(close=lambda: None)
        with mock.patch.object(self.launch, '_native_io_ready_live'), \
                mock.patch.object(self.launch, '_require_retained_backend',
                    return_value=object()) as backend_receipt, \
                mock.patch.object(self.launch, '_bind_original_artifacts',
                    return_value=self._wire_binding()), \
                mock.patch.object(self.launch,
                    '_require_preparse_artifact_attestation', return_value=None), \
                mock.patch.object(self.launch, 'capture_source_supervisor_identity',
                    return_value={}), \
                mock.patch.object(origin.bootstrap, 'SourceBootstrapSupervisor',
                    return_value=context) as construct:
            self.assertIs(self.launch.accept_origin(self.rx, object(), object()), context)
        args, kwargs = construct.call_args
        self.assertEqual(len(args), 8)
        self.assertIs(kwargs['control_only'], True)
        proof = kwargs['initial_cycle_proof']
        self.assertIs(type(proof), origin.bootstrap.SourceCycleProof)
        self.assertEqual(proof, origin.bootstrap.SourceCycleProof(
            origin.ORIGIN_PROOF_VERSION, 0, 11, 0x12345678,
            bytes.fromhex(self.CONFIG_DIGEST), bytes.fromhex(self.INI_DIGEST)))
        self.assertEqual(kwargs['expected_config_sha256'], bytes.fromhex(self.CONFIG_DIGEST))
        self.assertEqual(kwargs['expected_ini_sha256'], bytes.fromhex(self.INI_DIGEST))
        self.assertEqual(backend_receipt.call_count, 3)
        packet, ancillary, flags, _ = self.tx.recvmsg(origin.ORIGIN.size + 1,
            socket.CMSG_SPACE(4 * 4), getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        self.assertEqual(len(packet), origin.ORIGIN.size)
        ack = list(origin.ORIGIN.unpack(packet))
        self.assertEqual(ack[2], origin.ORIGIN_ACK)
        self.assertEqual(ack[19:], [origin.ORIGIN_PROOF_VERSION, 0, 11,
            0x12345678, bytes.fromhex(self.CONFIG_DIGEST), bytes.fromhex(self.INI_DIGEST)])
        self.assertEqual(len([item for item in ancillary
            if item[0] == socket.SOL_SOCKET and item[1] == socket.SCM_RIGHTS]), 1)
        self.assertEqual(self.launch.origin_proof.opaque_cycle_token, 0x12345678)
        self.actor_fds.extend((self.launch.origin_pidfd, self.launch.master_pidfd))
        self.launch.origin_pidfd = self.launch.master_pidfd = -1

    def test_ack_send_timeout_keeps_context_channel_and_actor_proofs(self):
        self._send_actor_request()
        context = SimpleNamespace(close=lambda: None)
        class AckTimeoutChannel:
            def __init__(self, wrapped):
                self.wrapped = wrapped
            def getsockopt(self, *args):
                return self.wrapped.getsockopt(*args)
            def settimeout(self, *args):
                return self.wrapped.settimeout(*args)
            def recvmsg(self, *args):
                return self.wrapped.recvmsg(*args)
            def sendmsg(self, *args):
                raise socket.timeout('controlled indeterminate ACK')
            def close(self):
                return self.wrapped.close()
        channel = AckTimeoutChannel(self.rx)
        with mock.patch.object(self.launch, '_require_retained_backend',
                return_value=object()), \
                mock.patch.object(origin.bootstrap, 'SourceBootstrapSupervisor',
                return_value=context):
            with self.assertRaises(socket.timeout):
                self._accept_origin_wire_only(channel, object(), object())
        self.assertTrue(self.launch.consumed)
        self.assertIs(self.launch.context, context)
        self.assertIs(self.launch.origin_channel, channel)
        self.assertTrue(origin.identity.process_alive(self.launch.origin_pidfd))
        self.assertTrue(origin.identity.process_alive(self.launch.master_pidfd))
        self.actor_fds.extend((self.launch.origin_pidfd, self.launch.master_pidfd))
        self.launch.origin_pidfd = self.launch.master_pidfd = -1

    def test_artifact_failure_precedes_bootstrap_context_construction(self):
        self._send_actor_request()
        with mock.patch.object(self.launch, '_native_io_ready_live'), \
                mock.patch.object(self.launch, '_bind_original_artifacts',
                    side_effect=PermissionError('controlled artifact mismatch')) as bind, \
                mock.patch.object(origin.bootstrap, 'SourceBootstrapSupervisor') as construct:
            with self.assertRaisesRegex(PermissionError, 'artifact mismatch'):
                self.launch.accept_origin(self.rx, object(), object())
        bind.assert_called_once()
        construct.assert_not_called()
        self.assertTrue(self.launch.consumed)
        self.assertIsNone(self.launch.context)
        self.assertEqual(origin.identity._pidfd_pid(self.launch.origin_pidfd),
            self.origin_pid)
        self.assertEqual(origin.identity._pidfd_pid(self.launch.master_pidfd), self.child)
        self.actor_fds.extend((self.launch.origin_pidfd, self.launch.master_pidfd))
        self.launch.origin_pidfd = self.launch.master_pidfd = -1

    def test_postparse_artifact_observation_allows_only_control_origin_ack(self):
        self._send_actor_request()
        observation = self._wire_binding()
        context = SimpleNamespace(close=lambda: None)
        with mock.patch.object(self.launch, '_native_io_ready_live'), \
                mock.patch.object(self.launch, '_bind_original_artifacts',
                    return_value=observation) as bind, \
                mock.patch.object(self.launch, '_require_retained_backend',
                    return_value=object()) as backend_receipt, \
                mock.patch.object(origin.bootstrap, 'SourceBootstrapSupervisor',
                    return_value=context) as construct, \
                mock.patch.object(self.launch, 'capture_source_supervisor_identity',
                    return_value={}):
            self.assertIs(self.launch.accept_origin(self.rx, object(), object()), context)
        bind.assert_called_once()
        self.assertEqual(backend_receipt.call_count, 3)
        construct.assert_called_once()
        self.assertTrue(construct.call_args.kwargs['control_only'])
        self.assertTrue(self.launch.consumed)
        self.assertIs(self.launch.context, context)
        self.assertIs(self.launch.artifact_binding, observation)
        self.assertEqual(self.launch.origin_proof.config_sha256, self.CONFIG_DIGEST)
        self.assertEqual(self.launch.origin_proof.ini_sha256, self.INI_DIGEST)
        packet, ancillary, _, _ = self.tx.recvmsg(origin.ORIGIN.size + 1,
            socket.CMSG_SPACE(4 * 4), getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        self.assertEqual(len(packet), origin.ORIGIN.size)
        self.assertEqual(origin.ORIGIN.unpack(packet)[2], origin.ORIGIN_ACK)
        self.assertEqual(len([item for item in ancillary if item[1] == socket.SCM_RIGHTS]), 1)
        self.actor_fds.extend((self.launch.origin_pidfd, self.launch.master_pidfd))
        self.launch.origin_pidfd = self.launch.master_pidfd = -1

    def test_full_preparse_authority_guard_remains_explicitly_unsupported(self):
        with self.assertRaises(OSError) as caught:
            self.launch._require_preparse_artifact_attestation(self._wire_binding())
        self.assertEqual(caught.exception.errno, errno.ENOTSUP)

    def test_accept_origin_requires_stored_native_io_receipt_before_wire_receive(self):
        self._send_actor_request()
        before = fd_count()
        with self.assertRaisesRegex(PermissionError,
                'origin requires its captured native I/O READY observation'):
            self.launch.accept_origin(self.rx, object(), object())
        self.assertFalse(self.launch.consumed)
        self.assertIsNone(self.launch.context)
        self.assertEqual(self.launch.master_pidfd, -1)
        self.assertEqual(fd_count(), before)

    def test_close_refuses_live_original_and_unverified_settlement(self):
        child = __import__('subprocess').Popen([sys.executable, '-c',
            'import time; time.sleep(30)'])
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        self.addCleanup(child.wait)
        value = self._launch()
        value.process = child
        value.pidfd = os.pidfd_open(child.pid)
        self.addCleanup(lambda: os.close(value.pidfd) if value.pidfd >= 0 else None)
        with self.assertRaises(PermissionError):
            value.close()
        child.terminate()
        child.wait(timeout=2)
        with self.assertRaisesRegex(PermissionError, 'settlement remains unverified'):
            value.close()

    def test_close_refuses_live_daemon_actor_after_supervisor_exit(self):
        child = __import__('subprocess').Popen([sys.executable, '-c',
            'import time; time.sleep(30)'])
        value = self._launch()
        value.process = SimpleNamespace(poll=lambda: 0)
        value.settlement = {'settled': True}
        value.master_pidfd = os.pidfd_open(child.pid)
        with self.assertRaisesRegex(PermissionError, 'daemon actors remain live'):
            value.close()
        self.assertGreaterEqual(fcntl.fcntl(value.master_pidfd, fcntl.F_GETFD), 0)
        child.kill()
        child.wait(timeout=2)
        os.close(value.master_pidfd)
        value.master_pidfd = -1

    def test_missing_passcred_is_rejected_before_consuming_request(self):
        self._send_actor_request()
        self.rx.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
        with self.assertRaisesRegex(PermissionError, 'enable credentials'):
            self._accept_origin_wire_only(self.rx, object(), object())
        self.assertFalse(self.launch.consumed)

    def test_loader_environment_rejection_does_not_start_or_adopt_a_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            template = Path(temporary) / 'network.ini'
            template.write_bytes(self._valid_template_ini())
            deadline = time.monotonic_ns() + 60_000_000_000
            captured = origin.capture_source_network_expectation(template, deadline)
            before = fd_count()
            with mock.patch.object(origin.subprocess, 'Popen') as popen:
                with self.assertRaisesRegex(PermissionError, 'alternate loader'):
                    origin.OriginalShellLaunch('/unread/source', [],
                        {'LD_PRELOAD': '/tmp/untrusted.so'}, '/unread/nginx',
                        bytes.fromhex(origin.NGINX_SHA256),
                        network_expectation=captured, stdout=-1, stderr=-1)
                popen.assert_not_called()
            self.assertEqual(fd_count(), before - 1)

    def test_pinned_hash_and_executable_mismatch_fail_without_adoption(self):
        with tempfile.NamedTemporaryFile() as value:
            value.write(b'controlled immutable input')
            value.flush()
            before = fd_count()
            with self.assertRaisesRegex(PermissionError, 'hash mismatch'):
                origin.PinnedFile(value.name, '0' * 64)
            self.assertEqual(fd_count(), before)
        pinned = origin.PinnedFile('/bin/sleep')
        self.addCleanup(pinned.close)
        with self.assertRaisesRegex(PermissionError, 'executable inode mismatch'):
            pinned.matches_process(os.getpid())

    def test_cleanup_timeout_preserves_launch_proof_when_fixture_is_supplied(self):
        source_root = os.environ.get('KER_FSTACK_SOURCE_ROOT')
        nginx = os.environ.get('KER_FSTACK_NGINX_BINARY')
        if not source_root and not nginx:
            self.skipTest('set KER_FSTACK_SOURCE_ROOT and KER_FSTACK_NGINX_BINARY for pinned fixture')
        self.assertTrue(source_root and nginx, 'explicit fixture requires both source and Nginx paths')
        for relative, expected in (
                ('tests/integration/test_graceful_reload.sh', origin.SHELL_SHA256),
                ('tests/integration/common/reload_supervisor.py', origin.SUPERVISOR_SHA256),
                ('tests/integration/common/reload_checks.py', origin.CHECKS_SHA256),
                ('tests/integration/common/reload_runtime.sh', origin.RUNTIME_SHA256)):
            path = Path(source_root) / relative
            self.assertTrue(path.is_file(), 'explicit source fixture input is missing: ' + relative)
            self.assertEqual(sha256_file(path), expected,
                'explicit source fixture differs from pinned original input: ' + relative)
        self.assertEqual(sha256_file(nginx), origin.NGINX_SHA256,
            'explicit Nginx fixture differs from pinned observed build')
        self.assertFalse((Path(source_root) / 'tests/integration/common/__pycache__').exists(),
            'explicit source fixture has an import cache')

        class StuckChild:
            pid = os.getpid()
            returncode = None
            def poll(self):
                return None
            def terminate(self):
                raise subprocess.TimeoutExpired('controlled-no-exec', 15)

        with tempfile.TemporaryDirectory() as temporary:
            environment = {
                'PATH': os.environ.get('PATH', os.defpath),
                'KER_NGINX_SOURCE_SHELL_ENABLE': '1',
                'KER_NGINX_SOURCE_FIRST_HUP_ENABLE': '1',
                'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_PID': str(os.getpid()),
                'KER_NGINX_SOURCE_BOOTSTRAP_SUPERVISOR_START':
                    str(origin.identity._start_ticks(os.getpid())),
                'KER_NGINX_SOURCE_BOOTSTRAP_NONCE': '12' * 16,
                'KER_NGINX_SOURCE_BOOTSTRAP_EPOCH': '9',
                'KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS':
                    str(time.monotonic_ns() + 120_000_000_000),
            }
            output = str(Path(temporary) / 'out')
            template_path = Path(temporary) / 'source-network.ini'
            template_path.write_bytes(self._valid_template_ini())
            deadline = int(environment['KER_NGINX_SOURCE_BOOTSTRAP_DEADLINE_NS'])
            captured = origin.capture_source_network_expectation(template_path, deadline)
            environment['KER_FSTACK_NGINX_INI'] = output + '/fstack_rt01.ini'
            arguments = ['--out', output, '--target-ip', '192.0.2.1',
                '--cases', 'precheck,rt01', '--workers', '1', '--graceful', '1',
                '--fstack-conf', str(template_path)]
            with mock.patch.object(origin.subprocess, 'Popen', return_value=StuckChild()) as popen:
                with self.assertRaises(origin.OriginalLaunchUnsettled) as caught:
                    origin.OriginalShellLaunch(source_root, arguments,
                        environment, nginx, bytes.fromhex(origin.NGINX_SHA256),
                        network_expectation=captured,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            popen.assert_called_once()
            launch = caught.exception.launch
            self.assertGreaterEqual(launch.pidfd, 0)
            self.assertTrue(launch.files)
            self.assertGreaterEqual(captured.template_file.fd, 0,
                'unsettled original launch must retain its pinned source template')
            os.close(launch.pidfd)
            launch.pidfd = -1
            for pinned in launch.files:
                pinned.close()
            self.assertEqual(captured.template_file.fd, -1)

    @staticmethod
    def _valid_template_ini():
        return (b'[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n'
            b'[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n'
            b'file_prefix=template\nfstack_log_file_prefix=/tmp/fstack-\n'
            b'fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.0.2.1\n'
            b'netmask=255.255.255.0\nbroadcast=192.0.2.255\n'
            b'gateway=192.0.2.254\n')


class GeneratedArtifactBindingControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'out'
        self.output.mkdir(mode=0o700)
        self.template_path = Path(self.temporary.name) / 'source-network.ini'
        self.template_bytes = (b'[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n'
            b'[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n'
            b'file_prefix=template\nfstack_log_file_prefix=/tmp/fstack-\n'
            b'fstack_log_level=0\n[port0]\nlcore_list=1\naddr=192.168.1.2\n'
            b'netmask=255.255.255.0\nbroadcast=192.168.1.255\n'
            b'gateway=192.168.1.1\n')
        self.template_path.write_bytes(self.template_bytes)
        self.launch = self._launch()
        self.io = SimpleNamespace(pid=os.getpid())
        self.argv = os.fsencode(self.launch.nginx_argument) + b'\0-c\0' + \
            os.fsencode(self.launch.expected_config) + b'\0'

    def _launch(self):
        value = origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
        value.creator_pid = os.getpid()
        value.creator_start = origin.identity._start_ticks(value.creator_pid)
        value.arguments = ['--out', str(self.output), '--target-ip', '192.168.1.2',
            '--cases', 'precheck,rt01', '--workers', '1', '--graceful', '1',
            '--nginx', '/opt/fstack/nginx', '--fstack-conf', str(self.template_path)]
        value.nginx_argument = '/opt/fstack/nginx'
        value.output_argument = str(self.output)
        value.output = str(self.output)
        value.expected_ini = value.output + '/fstack_rt01.ini'
        value.expected_config = value.output + '/ngx_rt01.conf'
        value.run_id = 'gr_20261113_101200_' + str(os.getpid()) + '_0123abcd'
        value.nonce = bytes.fromhex('12' * 16)
        value.epoch = 9
        value.deadline_ns = time.monotonic_ns() + 4_000_000_000
        value.output_fd = os.open(self.output,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        self.addCleanup(lambda: os.close(value.output_fd) if value.output_fd >= 0 else None)
        directory = os.fstat(value.output_fd)
        value.output_identity = directory.st_dev, directory.st_ino
        value.environment = {
            'KER_FSTACK_NGINX_INI': value.expected_ini,
            'KER_SOCKET_BROKER_PATH': '/run/ker/broker.sock',
        }
        value.files = []
        value.context = None
        value.origin_channel = None
        value.network_expectation = origin.capture_source_network_expectation(
            self.template_path, value.deadline_ns)
        value.network_template = value.network_expectation.template_file
        value.files.append(value.network_template)
        value.environment[origin.SOURCE_NETWORK_READBACK_ENV] = \
            value.network_expectation.readback_setting()
        value.artifact_binding = None
        value.native_io_ready = None
        value.source_root = None
        self.shell_bytes = (MODULE.parents[1] /
            'tests/upstream/fstack/tests/integration/test_graceful_reload.sh').read_bytes()
        self.mime_bytes = b'types { text/plain txt; }\n'
        shell_path = Path(self.temporary.name) / 'pinned-shell.sh'
        mime_path = Path(self.temporary.name) / 'pinned-mime.types'
        shell_path.write_bytes(self.shell_bytes)
        mime_path.write_bytes(self.mime_bytes)
        value.shell = origin.PinnedFile(shell_path, origin.SHELL_SHA256)
        value.mime_source = origin.PinnedFile(mime_path)
        self.addCleanup(value.shell.close)
        self.addCleanup(value.mime_source.close)
        value.live_supervisor = lambda deadline=None: None
        value._native_io_ready_live = lambda io, deadline: None
        value.nginx = SimpleNamespace(path=Path(value.nginx_argument))
        queue_proof = {
            'version': 1, 'worker_pid': os.getpid(),
            'session_nonce': value.nonce.hex(), 'session_epoch': value.epoch,
            'role': 'native-io-owner', 'source_proc_id': 1, 'port_id': 0,
            'queues': [{'queue_id': 0, 'owner_eal_lcore': 1,
                'observed_eal_lcore': 1, 'allowed_cpus': [0], 'actual_cpu': 0}],
        }
        record = {'process_type': 'primary', 'main_lcore': 0, 'lcore_count': 2,
            'port_id': 0, 'port_count': 1, 'queues': 1,
            'queue_owner_proof': queue_proof}
        record_bytes = json.dumps(record, sort_keys=True,
            separators=(',', ':')).encode()
        value.native_io_ready = SimpleNamespace(actor=None, nonce=value.nonce,
            epoch=value.epoch, run_id=value.run_id, grant_deadline=value.deadline_ns,
            record_bytes=record_bytes,
            record_sha256=hashlib.sha256(record_bytes).hexdigest(),
            argv=b'/native/ker-io-worker\0--\0--file-prefix=container-' +
                value.run_id.encode() + b'\0')
        return value

    def tearDown(self):
        for item in getattr(self.launch, 'files', []):
            item.close()

    def _ini(self, **overrides):
        values = {
            'broker': '/run/ker/broker.sock', 'graceful': '1', 'mask': '3',
            'primary': '1', 'prefix': self.launch.run_id,
            'log_prefix': str(self.output) + '/fstack-', 'log_level': '0',
            'port_lcores': '1', 'address': '192.168.1.2',
            'netmask': '255.255.255.0', 'broadcast': '192.168.1.255',
            'gateway': '192.168.1.1',
        }
        values.update(overrides)
        return (b'[ker_socket_broker]\nversion=1\npath=' + values['broker'].encode() +
            b'\n[dpdk]\ngraceful_reload=' + values['graceful'].encode() +
            b'\nlcore_mask=' + values['mask'].encode() +
            b'\nprimary_slim=' + values['primary'].encode() +
            b'\nfile_prefix=' + values['prefix'].encode() +
            b'\nfstack_log_file_prefix=' + values['log_prefix'].encode() +
            b'\nfstack_log_level=' + values['log_level'].encode() +
            b'\n[port0]\nlcore_list=' + values['port_lcores'].encode() +
            b'\naddr=' + values['address'].encode() +
            b'\nnetmask=' + values['netmask'].encode() +
            b'\nbroadcast=' + values['broadcast'].encode() +
            b'\ngateway=' + values['gateway'].encode() + b'\n')

    def _config(self, **overrides):
        rendered = origin.render_rt01_config(self.shell_bytes, str(self.output))
        if 'worker_processes' in overrides:
            rendered = rendered.replace(b'worker_processes  1;',
                ('worker_processes  ' + overrides['worker_processes'] + ';').encode())
        if 'pid' in overrides:
            rendered = rendered.replace(b'pid        ' + str(self.output).encode() +
                b'/nginx.pid;', b'pid        ' + overrides['pid'].encode() + b';')
        if 'error_log' in overrides:
            rendered = rendered.replace(b'error_log  ' + str(self.output).encode() +
                b'/err_rt01.log  notice;', b'error_log  ' + overrides['error_log'].encode() + b';')
        if 'fstack_conf' in overrides:
            rendered = rendered.replace(b'fstack_conf ' + str(self.output).encode() +
                b'/fstack_rt01.ini;', b'fstack_conf ' + overrides['fstack_conf'].encode() + b';')
        return rendered

    def _write_files(self, config=None, ini=None):
        (self.output / 'ngx_rt01.conf').write_bytes(
            self._config() if config is None else config)
        (self.output / 'fstack_rt01.ini').write_bytes(
            self._ini() if ini is None else ini)
        os.chmod(self.output / 'ngx_rt01.conf', 0o644)
        os.chmod(self.output / 'fstack_rt01.ini', 0o644)

    def _bind(self, *, argv=None, config=None, ini=None, deadline=None):
        self._write_files(config, ini)
        with mock.patch.object(origin, 'MIME_SHA256', hashlib.sha256(self.mime_bytes).hexdigest()), \
                mock.patch.object(origin, '_read_pinned', side_effect=lambda pinned, *args, **kwargs:
                    self.shell_bytes if pinned is self.launch.shell else self.mime_bytes), \
                mock.patch.object(origin, 'bounded_cmdline',
                return_value=self.argv if argv is None else argv):
            return self.launch._bind_original_artifacts(os.getpid(), os.getpid(),
                deadline or self.launch.deadline_ns, self.io)

    def test_valid_rt01_artifacts_bind_to_run_and_actual_io_proof(self):
        self.launch.native_io_ready.actor = self.io
        binding = self._bind()
        self.launch.artifact_binding = binding
        self.assertEqual(binding.run_id, self.launch.run_id)
        self.assertEqual(binding.sections['dpdk']['file_prefix'], self.launch.run_id)
        self.assertEqual(binding.sections['dpdk']['lcore_mask'], '3')
        self.assertEqual(binding.sections['port0']['lcore_list'], '1')
        self.assertEqual(binding.sections['port0']['addr'], '192.168.1.2')
        self.assertEqual(binding.sections['port0']['netmask'], '255.255.255.0')
        self.assertEqual(binding.sections['port0']['broadcast'], '192.168.1.255')
        self.assertEqual(binding.sections['port0']['gateway'], '192.168.1.1')
        self.assertEqual(self.launch.environment[origin.SOURCE_NETWORK_READBACK_ENV],
            'v1|' + hashlib.sha256(self.template_bytes).hexdigest() +
            '|192.168.1.2|255.255.255.0|192.168.1.255|192.168.1.1|' +
            str(self.launch.deadline_ns))
        self.assertEqual(binding.broker_path, '/run/ker/broker.sock')
        self.assertEqual(len(binding.config.sha256), 32)
        self.assertEqual(len(binding.ini.sha256), 32)
        expected_main = origin.render_rt01_config(self.shell_bytes, str(self.output))
        self.assertEqual(binding.config.data, expected_main)
        self.assertEqual(binding.config_sha256, origin.config_dump_transcript_sha256(
            self.launch.expected_config, expected_main, self.mime_bytes).hex())
        self.assertEqual(binding.ini_sha256, origin.ini_transcript_sha256(
            binding.ini.data).hex())
        self.assertNotEqual(binding.config_sha256, binding.config_file_sha256)
        self.assertGreaterEqual(fcntl.fcntl(binding.config.fd, fcntl.F_GETFD), 0)
        self.assertGreaterEqual(fcntl.fcntl(binding.ini.fd, fcntl.F_GETFD), 0)
        self.assertFalse((self.output / 'nginx.pid').exists(),
            'origin ACK must not wait for Nginx to create its PID file')
        self.launch._original_artifacts_live(self.launch.deadline_ns)
        (self.output / 'fstack_rt01.ini').write_bytes(self._ini(mask='7'))
        with self.assertRaises(PermissionError):
            self.launch._original_artifacts_live(self.launch.deadline_ns)

    def test_generated_network_must_match_pinned_template_and_environment(self):
        self.launch.native_io_ready.actor = self.io
        for label, mutation in (
                ('address', {'address': '192.168.1.3'}),
                ('netmask', {'netmask': '255.255.255.128',
                    'broadcast': '192.168.1.127'}),
                ('broadcast', {'broadcast': '192.168.1.127'}),
                ('gateway', {'gateway': '192.168.1.3'})):
            with self.subTest(network=label):
                with self.assertRaises(PermissionError):
                    self._bind(ini=self._ini(**mutation))
                for item in self.launch.files[1:]:
                    item.close()
                del self.launch.files[1:]
        expected = self.launch.network_expectation.readback_setting()
        self.launch.environment[origin.SOURCE_NETWORK_READBACK_ENV] = 'x' + expected[1:]
        with self.assertRaisesRegex(PermissionError, 'readback setting changed'):
            self._bind()
        for item in self.launch.files[1:]:
            item.close()
        del self.launch.files[1:]

    def test_template_replacement_is_rejected_before_binding(self):
        self.launch.native_io_ready.actor = self.io
        replacement = self.template_path.with_suffix('.replacement')
        replacement.write_bytes(self.template_bytes)
        os.replace(replacement, self.template_path)
        with self.assertRaisesRegex(PermissionError, 'pinned input changed'):
            self._bind()
        self.assertIsNone(self.launch.context)
        self.assertIsNone(self.launch.origin_channel)
        for item in self.launch.files[1:]:
            item.close()
        del self.launch.files[1:]

    def test_pinned_template_is_closed_one_pass_and_output_is_inert(self):
        rendered = origin.render_rt01_config(self.shell_bytes, str(self.output))
        self.assertIn(b'worker_processes  1;\n', rendered)
        self.assertIn(b'listen       80;\n', rendered)
        self.assertIn(os.fsencode(str(self.output)) + b'/err_rt01.log', rendered)
        self.assertNotIn(b'$OUT', rendered)
        self.assertNotIn(b'$tag', rendered)
        for bad_output in (str(self.output) + '\ninclude /tmp/evil;',
                str(self.output) + '$(touch', '/tmp/../escape', '/tmp/a b',
                '/tmp/`id`'):
            with self.subTest(output=bad_output):
                with self.assertRaises(PermissionError):
                    origin.render_rt01_config(self.shell_bytes, bad_output)

    def test_template_rejects_unknown_expansion_duplicate_or_extra_include(self):
        marker = b'worker_processes  $WORKERS;'
        for changed in (
                self.shell_bytes.replace(marker, b'worker_processes  $UNKNOWN;', 1),
                self.shell_bytes.replace(b'<<CONF', b'<<OTHER', 1),
                self.shell_bytes.replace(b'include       /usr/local/nginx_fstack/conf/mime.types;',
                    b'include       /usr/local/nginx_fstack/conf/mime.types;\n'
                    b'    include /tmp/extra.conf;', 1),
                self.shell_bytes.replace(b'gen_nginx_conf() {',
                    b'gen_nginx_conf() {', 1) + b'\ngen_nginx_conf() {\n}\n'):
            with self.subTest(changed=hashlib.sha256(changed).hexdigest()):
                with self.assertRaises(PermissionError):
                    origin.render_rt01_config(changed, str(self.output))

    def test_transcript_hash_matches_ordered_nul_terminated_c_encoding(self):
        main_name = '/tmp/rt01.conf'
        main = b'main\0bytes'
        mime = b'mime\0bytes'
        encoded = (b'ker-nginx-config-dump-v1\0' + struct.pack('>Q', 2) +
            struct.pack('>Q', len(main_name)) + main_name.encode() +
            struct.pack('>Q', len(main)) + main +
            struct.pack('>Q', len(origin.MIME_CONFIG_PATH)) +
            origin.MIME_CONFIG_PATH.encode() + struct.pack('>Q', len(mime)) + mime)
        self.assertEqual(origin.config_dump_transcript_sha256(main_name, main, mime),
            hashlib.sha256(encoded).digest())
        self.assertNotEqual(origin.config_dump_transcript_sha256(main_name, main, mime),
            origin.config_dump_transcript_sha256(main_name, mime, main))
        ini = b'[a]\nx=1\0tail'
        self.assertEqual(origin.ini_transcript_sha256(ini), hashlib.sha256(
            b'ker-source-native-ini-v1\0' + struct.pack('>Q', len(ini)) + ini).digest())
        c_main = b'worker_processes 1;\ninclude /usr/local/nginx_fstack/conf/mime.types;\n'
        c_mime = b'types { text/plain txt; }\n'
        self.assertEqual(origin.config_dump_transcript_sha256(
            '/tmp/ngx_rt01.conf', c_main, c_mime).hex(),
            'ea21de9a87569f24e05f5fe6a57bcd34565f7a01de4f7db2ece30573bdeec183')
        c_ini = (b'[ker_socket_broker]\nversion=1\npath=/run/ker/broker.sock\n'
            b'[dpdk]\ngraceful_reload=1\nlcore_mask=3\nprimary_slim=1\n'
            b'file_prefix=run_7f3a\nfstack_log_file_prefix=/tmp/native/fstack-\n'
            b'fstack_log_level=0\n[port0]\nlcore_list=1\n')
        self.assertEqual(origin.ini_transcript_sha256(c_ini).hex(),
            '1e9ff4868312b1366cbc29a4446020e47116f94c4600054c9216db2dc9605cbf')

    def test_original_argv_must_still_be_pre_title_exact_c_path(self):
        self._write_files()
        wrong = os.fsencode(self.launch.nginx_argument) + b'\0-c\0' + \
            os.fsencode(str(self.output / 'other.conf')) + b'\0'
        before = fd_count()
        with mock.patch.object(origin, 'bounded_cmdline', return_value=wrong):
            with self.assertRaisesRegex(PermissionError, 'exact rt01 -c launch'):
                self.launch._bind_original_artifacts(os.getpid(), os.getpid(),
                    self.launch.deadline_ns, self.io)
        self.assertEqual(self.launch.files, [self.launch.network_template])
        self.assertEqual(fd_count(), before)

    def test_ini_rejects_wrong_run_broker_log_and_topology_values(self):
        cases = (
            ('file_prefix', {'prefix': 'gr_20261113_101200_1_wrong0000'}),
            ('broker', {'broker': '/run/other.sock'}),
            ('log_prefix', {'log_prefix': str(self.output) + '/elsewhere/fstack-'}),
            ('mask', {'mask': '7'}),
            ('port_lcores', {'port_lcores': '0'}),
            ('invalid_address', {'address': '192.168.1.999'}),
            ('noncontiguous_mask', {'netmask': '255.0.255.0'}),
            ('hostmask_not_netmask', {'netmask': '0.0.0.255'}),
            ('address_first_octet_zero', {'address': '0.1.2.3',
                'netmask': '255.255.255.0', 'broadcast': '0.1.2.255',
                'gateway': '0.1.2.1'}),
            ('address_first_octet_class_e', {'address': '240.1.2.3',
                'netmask': '255.255.255.0', 'broadcast': '240.1.2.255',
                'gateway': '240.1.2.1'}),
            ('gateway_first_octet_zero', {'address': '10.1.2.4',
                'netmask': '128.0.0.0', 'broadcast': '127.255.255.255',
                'gateway': '0.1.2.3'}),
            ('gateway_first_octet_class_e', {'address': '240.1.2.4',
                'netmask': '255.255.255.0', 'broadcast': '240.1.2.255',
                'gateway': '240.1.2.3'}),
            ('custom_broadcast', {'broadcast': '192.168.1.254'}),
            ('offlink_gateway', {'gateway': '192.168.2.1'}),
            ('gateway_is_local', {'gateway': '192.168.1.2'}),
            ('unsupported_31_prefix', {'netmask': '255.255.255.254',
                'address': '192.168.1.2', 'broadcast': '192.168.1.3'}),
            ('unsupported_32_prefix', {'netmask': '255.255.255.255',
                'address': '192.168.1.2', 'broadcast': '192.168.1.2'}),
            ('graceful', {'graceful': '0'}),
        )
        self.launch.native_io_ready.actor = self.io
        for label, mutation in cases:
            with self.subTest(case=label):
                self.launch.files.clear()
                with self.assertRaises(PermissionError):
                    self._bind(ini=self._ini(**mutation))
                for item in self.launch.files:
                    item.close()
                self.launch.files.clear()

    def test_ini_rejects_unknown_duplicate_and_missing_schema_records(self):
        self.launch.native_io_ready.actor = self.io
        valid = self._ini()
        for invalid in (valid + b'[extra]\nx=1\n',
                valid.replace(b'[port0]', b'[dpdk]\n[port0]', 1),
                valid.replace(b'lcore_list=1', b'lcore_list=1\nextra=1'),
                valid.replace(b'addr=192.168.1.2\n', b''),
                valid.replace(b'path=/run/ker/broker.sock\n', b'')):
            with self.subTest(invalid=invalid[-32:]):
                with self.assertRaises(PermissionError):
                    self._bind(ini=invalid)
                for item in self.launch.files:
                    item.close()
                self.launch.files.clear()

    def test_config_paths_worker_count_and_mutable_receipts_are_bound_correctly(self):
        self.launch.native_io_ready.actor = self.io
        for override in ({'worker_processes': '2'},
                {'pid': str(self.output) + '/other.pid'},
                {'error_log': str(self.output) + '/other.log notice'},
                {'fstack_conf': str(self.output) + '/other.ini'}):
            with self.subTest(override=override):
                with self.assertRaises(PermissionError):
                    self._bind(config=self._config(**override))
                for item in self.launch.files:
                    item.close()
                self.launch.files.clear()

    def test_fifo_symlink_and_nonregular_artifacts_reject_without_blocking(self):
        self.launch.native_io_ready.actor = self.io
        for artifact in ('ngx_rt01.conf', 'fstack_rt01.ini'):
            for kind in ('symlink', 'fifo'):
                with self.subTest(artifact=artifact, kind=kind):
                    self._write_files()
                    path = self.output / artifact
                    path.unlink()
                    outside = Path(self.temporary.name) / ('outside-' + artifact)
                    outside.write_bytes(self._config() if artifact == 'ngx_rt01.conf'
                        else self._ini())
                    if kind == 'symlink':
                        path.symlink_to(outside)
                    else:
                        os.mkfifo(path, 0o600)
                    started = time.monotonic()
                    with mock.patch.object(origin, 'bounded_cmdline',
                            return_value=self.argv):
                        with self.assertRaises(OSError):
                            self.launch._bind_original_artifacts(os.getpid(),
                                os.getpid(), self.launch.deadline_ns, self.io)
                    self.assertLess(time.monotonic() - started, 1.0)
                    for item in self.launch.files:
                        item.close()
                    self.launch.files.clear()
                    path.unlink()

    def test_native_io_session_and_queue_proof_must_match_ini_topology(self):
        self.launch.native_io_ready.actor = self.io
        original = json.loads(self.launch.native_io_ready.record_bytes)
        for mutate in (
                lambda record: record['queue_owner_proof'].__setitem__('source_proc_id', 0),
                lambda record: record['queue_owner_proof']['queues'][0].__setitem__(
                    'owner_eal_lcore', 2),
                lambda record: record['queue_owner_proof'].__setitem__(
                    'session_nonce', '34' * 16),
                lambda record: record['queue_owner_proof']['queues'][0].__setitem__(
                    'actual_cpu', 1)):
            with self.subTest(proof=mutate):
                record = json.loads(json.dumps(original))
                mutate(record)
                encoded = json.dumps(record, sort_keys=True,
                    separators=(',', ':')).encode()
                self.launch.native_io_ready.record_bytes = encoded
                self.launch.native_io_ready.record_sha256 = hashlib.sha256(
                    encoded).hexdigest()
                with self.assertRaises(PermissionError):
                    self._bind()
                for item in self.launch.files:
                    item.close()
                self.launch.files.clear()
        self.launch.native_io_ready.record_bytes = json.dumps(original,
            sort_keys=True, separators=(',', ':')).encode()
        self.launch.native_io_ready.record_sha256 = hashlib.sha256(
            self.launch.native_io_ready.record_bytes).hexdigest()

    def test_ini_environment_and_each_fork_side_argv_are_bound(self):
        self.launch.native_io_ready.actor = self.io
        self._write_files()
        self.launch.environment['KER_FSTACK_NGINX_INI'] = str(
            self.output / 'other.ini')
        with self.assertRaisesRegex(PermissionError, 'INI path'):
            self.launch._bind_original_artifacts(os.getpid(), os.getpid(),
                self.launch.deadline_ns, self.io)
        self.launch.environment['KER_FSTACK_NGINX_INI'] = self.launch.expected_ini
        wrong = os.fsencode(self.launch.nginx_argument) + b'\0-c\0' + \
            os.fsencode(str(self.output / 'other.conf')) + b'\0'
        responses = iter((self.argv, wrong))
        with mock.patch.object(origin, 'bounded_cmdline',
                side_effect=lambda *args: next(responses)):
            with self.assertRaisesRegex(PermissionError, 'exact rt01 -c launch'):
                self.launch._bind_original_artifacts(os.getpid(), os.getpid(),
                    self.launch.deadline_ns, self.io)
        self.assertEqual(self.launch.files, [self.launch.network_template])

    def test_expired_origin_budget_fails_before_opening_artifacts(self):
        self.launch.native_io_ready.actor = self.io
        self._write_files()
        before = fd_count()
        with self.assertRaises(PermissionError):
            self._bind(deadline=time.monotonic_ns() - 1)
        self.assertEqual(self.launch.files, [self.launch.network_template])
        self.assertEqual(fd_count(), before)

    def test_launch_scope_rejects_widening_and_duplicate_case_options(self):
        for args in (
                ['--out', str(self.output), '--target-ip', '192.0.2.1',
                    '--cases', 'precheck,rt01,rt02', '--workers', '1', '--graceful', '1',
                    '--fstack-conf', str(self.template_path)],
                ['--out', str(self.output), '--target-ip', '192.0.2.1',
                    '--cases', 'precheck,rt01', '--cases', 'precheck,rt01',
                    '--workers', '1', '--graceful', '1', '--fstack-conf', str(self.template_path)],
                ['--out', str(self.output), '--target-ip', '192.0.2.1',
                    '--cases', 'precheck,rt01', '--workers', '2', '--graceful', '1',
                    '--fstack-conf', str(self.template_path)],
                ['--out', str(self.output), '--target-ip', '192.0.2.1',
                    '--cases', 'precheck,rt01', '--workers', '1', '--graceful', '0',
                    '--baseline', '--fstack-conf', str(self.template_path)],
                ['--out', str(self.output), '--target-ip', '192.0.2.1',
                    '--cases', 'precheck,rt01', '--workers', '1', '--graceful', '1',
                    '--fault', 'ready_delay', '--fstack-conf', str(self.template_path)],
                ['--out', str(self.output), '--target-ip', '192.0.2.1',
                    '--cases', 'precheck,rt01', '--workers', '1', '--graceful', '1'],
                ['--out', str(self.output), '--target-ip', '192.0.2.1',
                    '--cases', 'precheck,rt01', '--workers', '1', '--graceful', '1',
                    '--fstack-conf', str(self.template_path), '--fstack-conf',
                    str(self.template_path)]):
            self.launch.arguments = args
            with self.assertRaises(PermissionError):
                self.launch._validate_rt01_launch_scope()

    def test_launch_scope_requires_one_canonical_pinned_template_and_matching_target(self):
        base = ['--out', str(self.output), '--target-ip', '192.168.1.2',
            '--cases', 'precheck,rt01', '--workers', '1', '--graceful', '1',
            '--fstack-conf', str(self.template_path)]
        self.launch.arguments = list(base)
        self.launch._validate_rt01_launch_scope()
        for args in (
                base[:-2],
                base + ['--fstack-conf', str(self.template_path)],
                base[:-1] + ['relative-template.ini'],
                base[:2] + ['--target-ip', '192.168.1.3'] + base[3:]):
            with self.subTest(arguments=args):
                self.launch.arguments = args
                with self.assertRaises(PermissionError):
                    self.launch._validate_rt01_launch_scope()


class SourceNetworkTemplateCaptureControls(unittest.TestCase):
    def test_template_capture_is_owned_immutable_and_nonblocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            regular = Path(temporary) / 'source.ini'
            regular.write_bytes(SourceOriginControls._valid_template_ini())
            before = fd_count()
            deadline = time.monotonic_ns() + 5_000_000_000
            captured = origin.capture_source_network_expectation(regular, deadline)
            self.assertEqual(fd_count(), before + 1)
            self.assertTrue(captured.template_file.nonblocking)
            self.assertEqual(captured.address, '192.0.2.1')
            self.assertEqual(captured.template_sha256, sha256_file(regular))
            with self.assertRaises(AttributeError):
                captured.address = '192.0.2.2'
            captured.template_file.close()
            self.assertEqual(fd_count(), before)

            fifo = Path(temporary) / 'no-writer.fifo'
            os.mkfifo(fifo, 0o600)
            symlink = Path(temporary) / 'source-link.ini'
            symlink.symlink_to(regular)
            for path in (fifo, symlink):
                with self.subTest(path=path.name):
                    count = fd_count()
                    started = time.monotonic()
                    with self.assertRaises(PermissionError):
                        origin.capture_source_network_expectation(
                            path, time.monotonic_ns() + 5_000_000_000)
                    self.assertLess(time.monotonic() - started, 0.5)
                    self.assertEqual(fd_count(), count)

            other = Path(temporary) / 'replacement.ini'
            other.write_bytes(SourceOriginControls._valid_template_ini())
            real_resolve = Path.resolve
            calls = {'template': 0}
            def swap_on_second_resolve(path, strict=False):
                if path == regular:
                    calls['template'] += 1
                    if calls['template'] == 2:
                        return other
                return real_resolve(path, strict=strict)
            count = fd_count()
            with mock.patch.object(origin.Path, 'resolve', swap_on_second_resolve):
                with self.assertRaisesRegex(PermissionError,
                        'owned bounded regular file'):
                    origin.capture_source_network_expectation(
                        regular, time.monotonic_ns() + 5_000_000_000)
            self.assertEqual(calls['template'], 2)
            self.assertEqual(fd_count(), count)


class NativeIoReadyObserverControls(unittest.TestCase):
    PORT_NAME = 'net_tap0'
    NONCE = bytes.fromhex('12' * 16)
    EPOCH = 9

    def setUp(self):
        if not hasattr(os, 'pidfd_open'):
            self.skipTest('pidfds are unavailable')
        self.initial_fd_count = fd_count()
        self.processes = []
        self.actor_pidfds = []
        self.launch = origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
        self.launch.creator_pid = os.getpid()
        self.launch.creator_start = origin.identity._start_ticks(os.getpid())
        self.launch.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None,
            returncode=None)
        self.launch.pidfd = self.launch.master_pidfd = self.launch.origin_pidfd = -1
        self.launch.native_io_pidfd = self.launch.native_io_stdout_fd = -1
        self.launch.files = []
        self.launch.context = self.launch.origin_channel = self.launch.settlement = None
        self.launch.consumed = False
        self.launch.native_io_observation_started = False
        self.launch.native_io_ready = None
        self.launch.epoch = self.EPOCH
        self.launch.deadline_ns = time.monotonic_ns() + 8_000_000_000
        self.launch.nonce = self.NONCE
        self.launch.run_id = time.strftime('gr_%Y%m%d_%H%M%S_') + \
            str(os.getpid()) + '_01234567'
        self.launch.live_supervisor = lambda deadline=None: None
        self.addCleanup(self._cleanup)

    @staticmethod
    def _ready_record(pid, nonce, epoch):
        return {
            'mac': '02:00:00:00:00:01',
            'tx_offload_features': 0,
            'process_type': 'primary',
            'port_id': 0,
            'port_count': 1,
            'queues': 1,
            'main_lcore': 0,
            'lcore_count': 2,
            'queue_owner_proof': {
                'version': 1,
                'worker_pid': pid,
                'session_nonce': nonce.hex(),
                'session_epoch': epoch,
                'role': 'native-io-owner',
                'source_proc_id': 1,
                'port_id': 0,
                'queues': [{
                    'queue_id': 0,
                    'owner_eal_lcore': 1,
                    'observed_eal_lcore': 1,
                    'allowed_cpus': [0],
                    'actual_cpu': 0,
                }],
            },
        }

    def _spawn_io(self, *, ready_mutator=None, argv_mutator=None, mode='ready'):
        decision_read, decision_write = os.pipe2(os.O_CLOEXEC)
        sync_read, sync_write = os.pipe2(os.O_CLOEXEC)
        script = '\n'.join((
            'import os,sys,time',
            'mode=sys.argv[1]; sync=int(sys.argv[2])',
            'if mode == "pipe":',
            '    fd=os.open("/dev/null",os.O_WRONLY); os.dup2(fd,1); os.write(sync,b"x"); time.sleep(30)',
            'elif mode == "partial":',
            '    os.write(1,b"KER_IO_READY {\\\"partial\\\":"); time.sleep(30)',
            'else:',
            '    data=sys.stdin.buffer.readline(); os.write(1,data); os.write(sync,b"x"); time.sleep(30)',
        ))
        record = self._ready_record(0, self.launch.nonce, self.launch.epoch)
        args = [sys.executable, '-c', script, mode, str(sync_write),
            '--packet-fd', '4', '--queues', '1', '--rx-lcores', '1',
            '--port', self.PORT_NAME,
            '--queue-proof-session', self.launch.nonce.hex(),
            '--queue-proof-epoch', str(self.launch.epoch),
            '--queue-proof-source-proc-id', '1',
            '--rx-decision-fd', str(decision_read), '--', '--no-pci',
            '--vdev=net_tap0,iface=fixture0',
            '--file-prefix=container-' + self.launch.run_id]
        if argv_mutator:
            argv_mutator(args)
        process = subprocess.Popen(args, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            pass_fds=(decision_read, sync_write), bufsize=0)
        self.processes.append(process)
        os.close(decision_read)
        os.close(decision_write)
        os.close(sync_write)
        if mode == 'pipe':
            self.assertEqual(os.read(sync_read, 1), b'x')
        os.close(sync_read)
        pidfd = os.pidfd_open(process.pid)
        self.actor_pidfds.append(pidfd)
        actor = SimpleNamespace(pid=process.pid, pidfd=pidfd,
            start_ticks=origin.identity._start_ticks(process.pid),
            executable_hash=bytes.fromhex(sha256_file(f'/proc/{process.pid}/exe')))
        if mode == 'ready':
            record['queue_owner_proof']['worker_pid'] = process.pid
            if ready_mutator:
                # The caller mutation is applied again with the actual actor
                # PID so the wire-model record remains otherwise realistic.
                ready_mutator(record)
            line = b'KER_IO_READY ' + json.dumps(record,
                separators=(',', ':')).encode() + b'\n'
            process.stdin.write(line)
            process.stdin.close()
        return process, actor

    def _observe(self, process, actor, *, expected_port_name=None):
        return self.launch.observe_native_io_ready(process, actor,
            expected_port_name=expected_port_name or self.PORT_NAME)

    def _cleanup(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            for stream_name in ('stdin', 'stdout', 'stderr'):
                stream = getattr(process, stream_name, None)
                if stream is not None:
                    stream.close()
        for fd in self.actor_pidfds:
            try:
                os.close(fd)
            except OSError:
                pass
        self.launch.process = SimpleNamespace(pid=os.getpid(), poll=lambda: 0,
            returncode=0)
        self.launch.settlement = {'settled': True, 'result': 0}
        self.launch.close()
        self.assertEqual(fd_count(), self.initial_fd_count)

    def test_valid_actual_child_pipe_receipt_is_bound_once_to_actor_and_launch(self):
        process, actor = self._spawn_io()
        result = self._observe(process, actor)
        self.assertEqual(result['queue_owner_proof']['session_nonce'],
            self.launch.nonce.hex())
        self.assertEqual(result['queue_owner_proof']['session_epoch'],
            self.launch.epoch)
        proof = self.launch.native_io_ready
        self.assertIs(proof.actor, actor)
        self.assertIs(proof.process, process)
        self.assertEqual(proof.pid, actor.pid)
        self.assertEqual(proof.run_id, self.launch.run_id)
        self.assertEqual(proof.pipe_identity,
            (os.fstat(process.stdout.fileno()).st_dev,
                os.fstat(process.stdout.fileno()).st_ino))
        self.launch._native_io_ready_live(actor, self.launch.deadline_ns)
        with self.assertRaises(PermissionError):
            self._observe(process, actor)

    def test_wrong_session_in_ready_record_rejects(self):
        process, actor = self._spawn_io(ready_mutator=lambda record:
            record['queue_owner_proof'].__setitem__('session_nonce', '34' * 16))
        with self.assertRaisesRegex(RuntimeError, 'process/session mismatch'):
            self._observe(process, actor)
        self.assertIsNone(self.launch.native_io_ready)

    def test_wrong_epoch_in_ready_record_rejects(self):
        process, actor = self._spawn_io(ready_mutator=lambda record:
            record['queue_owner_proof'].__setitem__('session_epoch', self.EPOCH + 1))
        with self.assertRaisesRegex(RuntimeError, 'process/session mismatch'):
            self._observe(process, actor)
        self.assertIsNone(self.launch.native_io_ready)

    def test_wrong_ready_pid_rejects(self):
        process, actor = self._spawn_io(ready_mutator=lambda record:
            record['queue_owner_proof'].__setitem__('worker_pid',
                record['queue_owner_proof']['worker_pid'] + 1))
        with self.assertRaisesRegex(RuntimeError, 'process/session mismatch'):
            self._observe(process, actor)
        self.assertIsNone(self.launch.native_io_ready)

    def test_wrong_start_ticks_reject(self):
        process, actor = self._spawn_io()
        actor.start_ticks += 1
        with self.assertRaisesRegex(PermissionError, 'exact live captured child'):
            self._observe(process, actor)

    def test_wrong_executable_hash_rejects(self):
        process, actor = self._spawn_io()
        actor.executable_hash = bytes.fromhex('00' * 32)
        with self.assertRaisesRegex(PermissionError, 'pinned original input hash mismatch'):
            self._observe(process, actor)

    def test_wrong_pipe_identity_rejects(self):
        process, actor = self._spawn_io(mode='pipe')
        with self.assertRaisesRegex(PermissionError, 'stdout is not the captured child pipe'):
            self._observe(process, actor)

    def test_wrong_port_name_rejects(self):
        process, actor = self._spawn_io()
        with self.assertRaises((RuntimeError, PermissionError)):
            self._observe(process, actor, expected_port_name='net_tap1')

    def test_missing_matching_vdev_rejects(self):
        process, actor = self._spawn_io(argv_mutator=lambda args: args.__setitem__(
            slice(None), [item for item in args if not item.startswith('--vdev=')]))
        with self.assertRaisesRegex(PermissionError, 'exact configured single virtual ethdev'):
            self._observe(process, actor)

    def test_wrong_vdev_name_rejects(self):
        process, actor = self._spawn_io(argv_mutator=lambda args: args.__setitem__(
            args.index('--vdev=net_tap0,iface=fixture0'),
            '--vdev=net_tap1,iface=fixture1'))
        with self.assertRaisesRegex(PermissionError, 'exact configured single virtual ethdev'):
            self._observe(process, actor)

    def test_duplicate_vdev_rejects(self):
        process, actor = self._spawn_io(argv_mutator=lambda args: args.insert(
            args.index('--file-prefix=container-' + self.launch.run_id),
            '--vdev=net_tap0,iface=fixture0'))
        with self.assertRaisesRegex(PermissionError, 'exact configured single virtual ethdev'):
            self._observe(process, actor)

    def test_partial_ready_line_uses_one_short_absolute_grant_and_cannot_retry(self):
        process, actor = self._spawn_io(mode='partial')
        self.launch.deadline_ns = time.monotonic_ns() + 180_000_000
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'startup timed out'):
            self._observe(process, actor)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.12)
        self.assertLess(elapsed, 0.8)
        self.assertTrue(self.launch.native_io_observation_started)
        retry_started = time.monotonic()
        with self.assertRaises(PermissionError):
            self._observe(process, actor)
        self.assertLess(time.monotonic() - retry_started, 0.1)

    def test_expired_pinned_file_deadline_opens_no_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'controlled file')
            before = fd_count()
            with self.assertRaisesRegex(PermissionError,
                    'origin observation deadline expired'):
                origin.PinnedFile(path, deadline_ns=time.monotonic_ns() - 1)
            self.assertEqual(fd_count(), before)


class OriginalOwnerLifetimeControls(unittest.TestCase):
    def test_initial_owner_observation_receives_the_original_deadline(self):
        observer = origin.bootstrap.SourceBootstrapSupervisor.__new__(
            origin.bootstrap.SourceBootstrapSupervisor)
        deadline = time.monotonic_ns() + 1_000_000_000
        calls = []

        def owner_expired(observed_deadline):
            calls.append(observed_deadline)
            raise PermissionError('initial owner observation expired')

        observer.owner_live = owner_expired
        with self.assertRaisesRegex(PermissionError, 'initial owner observation expired'):
            observer.live(deadline)
        self.assertEqual(calls, [deadline])

    def test_source_authority_rechecks_original_owner_before_other_observations(self):
        observer = origin.bootstrap.SourceBootstrapSupervisor.__new__(
            origin.bootstrap.SourceBootstrapSupervisor)
        calls = []

        def owner_dead():
            calls.append('original-owner')
            raise PermissionError('captured original supervisor exited')

        observer.owner_live = owner_dead
        with self.assertRaisesRegex(PermissionError, 'captured original supervisor exited'):
            observer.live()
        self.assertEqual(calls, ['original-owner'])


class OriginalWorkerTermControls(unittest.TestCase):
    """Controlled receipt files and real pidfds; not the original producer."""
    RUN_ID = 'gr_test_9876_abcdef01'
    CONTROLLER = 1234
    STACK = 'rt01'

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ker-term-proof-')
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'out'
        self.output.mkdir(mode=0o700)
        self.output_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.output_fd)
        self.output_stat = os.fstat(self.output_fd)
        self.worker = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        self.addCleanup(self._stop_worker)
        self.worker_pidfd = os.pidfd_open(self.worker.pid)
        self.addCleanup(os.close, self.worker_pidfd)
        worker_start = origin.identity._start_ticks(self.worker.pid)
        self.supervisor_pid = os.getpid()
        self.supervisor_start = origin.identity._start_ticks(self.supervisor_pid)
        self.python_stat = os.stat('/proc/self/exe')
        self.launch = origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
        self.launch.process = SimpleNamespace(pid=self.supervisor_pid, poll=lambda: None)
        self.launch.pidfd = os.pidfd_open(self.supervisor_pid)
        self.addCleanup(os.close, self.launch.pidfd)
        self.launch.start = self.supervisor_start
        self.launch.deadline_ns = time.monotonic_ns() + 3_000_000_000
        self.launch.run_id = self.RUN_ID
        self.launch.output = str(self.output)
        self.launch.output_fd = self.output_fd
        self.launch.output_identity = (self.output_stat.st_dev, self.output_stat.st_ino)
        self.launch.python = SimpleNamespace(
            frozen=(self.python_stat.st_dev, self.python_stat.st_ino,
                self.python_stat.st_size, self.python_stat.st_mtime_ns,
                self.python_stat.st_ctime_ns),
            sha256=hashlib.sha256(Path('/proc/self/exe').read_bytes()).digest())
        self.live_checks = []
        def live(launch, deadline):
            self.live_checks.append(deadline)
            if time.monotonic_ns() >= deadline:
                raise PermissionError('original supervisor deadline expired')
        self.launch.live_supervisor = MethodType(live, self.launch)
        self.context = origin.bootstrap.SourceBootstrapSupervisor.__new__(
            origin.bootstrap.SourceBootstrapSupervisor)
        self.context.owner_live = self.launch.live_supervisor
        self.context.shell_mode = True
        self.context.deadline_ns = self.launch.deadline_ns
        self.context.original_supervisor_identity = None
        self.context._original_supervisor_pidfd = -1
        self.context._original_supervisor_output_fd = -1
        self.context._authorized_preexits = {}
        self.context._pending_preexits = {}
        self.context.workers = {}
        self.context._completed_retirements = {}
        self.context.runtime = SimpleNamespace(pidfd=-1)
        self.context.io = SimpleNamespace(pidfd=-1)
        self.key = (1, 1)
        grant = [0] * 35
        grant[5], grant[11] = self.worker.pid, worker_start
        self.context.workers[self.key] = (self.worker_pidfd, tuple(grant))
        self.operation_id = 41
        self.request_sha256 = bytes.fromhex('11' * 32)
        self.pending = origin.bootstrap.PendingSourceRetirement(self.key,
            self.operation_id, self.worker.pid, worker_start, 3,
            self.request_sha256, self.launch.deadline_ns)
        self.context._pending_preexits[self.operation_id] = (
            self.pending, b'request', None)
        self._write_snapshot('running')
        self.launch.capture_source_supervisor_identity(
            self.context, self.launch.deadline_ns)
        self._write_stopping_receipts()

    def _stop_worker(self):
        if self.worker.poll() is None:
            self.worker.kill()
        self.worker.wait(timeout=3)

    def _snapshot(self, phase, **changes):
        snapshot = {
            'version': 1,
            'run_id': self.RUN_ID,
            'supervisor': {'pid': self.supervisor_pid,
                'start_time': self.supervisor_start,
                'device': self.python_stat.st_dev,
                'inode': self.python_stat.st_ino},
            'controller': self.CONTROLLER,
            'stack': self.STACK,
            'phase': phase,
            'members': [{'pid': self.worker.pid,
                'start_time': self.pending.worker_start_ticks,
                'role': 'target', 'relation': 'spawned', 'parent': self.supervisor_pid,
                'initial': {}, 'current': {}}],
        }
        snapshot.update(changes)
        return snapshot

    def _atomic_bytes(self, name, value):
        temporary = self.output / (name + '.next')
        temporary.write_bytes(value)
        temporary.chmod(0o600)
        os.replace(temporary, self.output / name)

    def _write_snapshot(self, phase, **changes):
        data = json.dumps(self._snapshot(phase, **changes), separators=(',', ':')).encode() + b'\n'
        self._atomic_bytes('supervisor.json', data)
        return data

    def _write_stopping_receipts(self, *, events=None, **snapshot_changes):
        self._write_snapshot('stopping', **snapshot_changes)
        if events is None:
            events = [{'run_id': self.RUN_ID, 'event': 'signal_requested',
                'monotonic': time.monotonic(), 'pid': self.worker.pid,
                'start_time': self.pending.worker_start_ticks,
                'signal': 'TERM', 'helper': 999}]
        data = b''.join(json.dumps(event, separators=(',', ':')).encode() + b'\n'
            for event in events)
        self._atomic_bytes('ownership-events.jsonl', data)

    def test_original_term_receipt_binds_exact_process_run_and_control_snapshot(self):
        authorized = self.context.authorize_worker_preexit(self.operation_id)
        evidence = self.context._authorized_preexits[self.operation_id]
        self.assertIs(authorized, self.pending)
        self.assertIs(type(evidence), origin.bootstrap.SupervisorTermEvidence)
        self.assertEqual((evidence.run_id, evidence.controller, evidence.stack,
            evidence.worker_pid, evidence.worker_start_ticks, evidence.signal),
            (self.RUN_ID, self.CONTROLLER, self.STACK, self.worker.pid,
             self.pending.worker_start_ticks, 'TERM'))
        self.assertEqual(evidence.receipt_device, os.fstat(self.output_fd).st_dev)
        self.assertEqual(evidence.receipt_inode, os.fstat(self.output_fd).st_ino)
        self.assertEqual(self.context._authorized_preexits[self.operation_id], evidence)
        self.assertGreaterEqual(len(self.live_checks), 2)

    def test_private_candidate_term_gate_retries_same_pending_through_real_origin_parser(self):
        controller = SimpleNamespace(_private_candidate_preexit_pending=self.pending,
            _private_candidate_preexit_evidence=None)
        # This fixture isolates the exact Origin parser/registration seam; the
        # production controller's exact profile/provider authority predicate
        # is exercised separately by fail-closed controller tests.
        self.context._private_candidate_preexit_authority = lambda value: value is controller
        self._write_snapshot('running')
        with self.assertRaises(BlockingIOError) as raised:
            self.context.authorize_private_candidate_preexit(controller, self.pending)
        self.assertEqual(raised.exception.errno, errno.EAGAIN)
        self.assertIsNone(controller._private_candidate_preexit_evidence)
        self.assertNotIn(self.operation_id, self.context._authorized_preexits)
        self._write_stopping_receipts()
        self.assertIs(self.context.authorize_private_candidate_preexit(
            controller, self.pending), self.pending)
        evidence = self.context._authorized_preexits[self.operation_id]
        self.assertIs(type(evidence), origin.bootstrap.SupervisorTermEvidence)
        self.assertIs(controller._private_candidate_preexit_evidence, evidence)
        self.assertIs(self.context._pending_preexits[self.operation_id][0], self.pending)
        checks = len(self.live_checks)
        self.assertIs(self.context.authorize_private_candidate_preexit(
            controller, self.pending), self.pending)
        self.assertIs(controller._private_candidate_preexit_evidence, evidence)
        self.assertEqual(len(self.live_checks), checks,
            'duplicate authorization must not reread receipts or replace evidence')
        controller._private_candidate_preexit_evidence = object()
        with self.assertRaisesRegex(PermissionError, 'already consumed'):
            self.context.authorize_private_candidate_preexit(controller, self.pending)

    def test_pinned_supervisor_process_tree_emits_receipt_for_dummy_target(self):
        """Run the pinned receipt producer against dummy Python actors only."""
        source = (Path(__file__).resolve().parents[2] /
            'tests/upstream/fstack/tests/integration/common/reload_supervisor.py')
        if not source.exists():
            self.skipTest('pinned original supervisor source is unavailable')
        self.assertEqual(sha256_file(source), origin.SUPERVISOR_SHA256)
        producer_spec = importlib.util.spec_from_file_location(
            'pinned_dummy_original_supervisor', source)
        producer = importlib.util.module_from_spec(producer_spec)
        sys.path.insert(0, str(source.parent))
        try:
            producer_spec.loader.exec_module(producer)
        finally:
            sys.path.pop(0)
        output = Path(self.temporary.name) / 'producer-out'
        output.mkdir(mode=0o700)
        output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        supervisor = None
        context = origin.bootstrap.SourceBootstrapSupervisor.__new__(
            origin.bootstrap.SourceBootstrapSupervisor)
        previous_umask = os.umask(0o077)
        try:
            supervisor = producer.Supervisor(output, self.RUN_ID, 30)
            controller = supervisor.tree.spawn(['/bin/sleep', '30'], 'controller')
            supervisor.controller = controller
            supervisor.stack = self.STACK
            supervisor.tree.default_stack = self.STACK
            python_path = str(Path(sys.executable).resolve(strict=True))
            supervisor.approve_image(python_path, producer.digest(python_path))
            target = supervisor.tree.spawn([python_path, '-c',
                'import signal,time; signal.signal(signal.SIGTERM, lambda *_: None); '
                'exec("while True: time.sleep(0.02)")'], 'target', self.STACK)
            for _ in range(10):
                supervisor.tree.tick()
                time.sleep(.002)
            self.assertIsNone(supervisor.tree.failure)
            supervisor.phase = 'running'
            supervisor.snapshot()

            real_stat = os.stat('/proc/self/exe')
            launch = origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
            launch.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
            launch.pidfd = os.pidfd_open(os.getpid())
            launch.start = origin.identity._start_ticks(os.getpid())
            launch.deadline_ns = time.monotonic_ns() + 2_000_000_000
            launch.run_id = self.RUN_ID
            launch.output = str(output)
            launch.output_fd = output_fd
            output_stat = os.fstat(output_fd)
            launch.output_identity = (output_stat.st_dev, output_stat.st_ino)
            launch.python = SimpleNamespace(
                frozen=(real_stat.st_dev, real_stat.st_ino, real_stat.st_size,
                    real_stat.st_mtime_ns, real_stat.st_ctime_ns),
                sha256=hashlib.sha256(Path('/proc/self/exe').read_bytes()).digest())
            checks = []
            def live(_launch, deadline):
                checks.append(deadline)
                if time.monotonic_ns() >= deadline:
                    raise PermissionError('dummy supervisor observation expired')
            launch.live_supervisor = MethodType(live, launch)
            context.owner_live = launch.live_supervisor
            context.shell_mode = True
            context.deadline_ns = launch.deadline_ns
            context.original_supervisor_identity = None
            context._original_supervisor_pidfd = -1
            context._original_supervisor_output_fd = -1
            context._pending_preexits = {}
            context._authorized_preexits = {}
            context.workers = {}
            context.capture = None
            launch.capture_source_supervisor_identity(context, launch.deadline_ns)

            key = (1, 1)
            worker_record = [0] * 35
            target_start = supervisor.tree.members[target]['start_time']
            worker_record[5], worker_record[11] = target, target_start
            target_pidfd = os.dup(supervisor.tree.members[target]['pidfd'])
            context.workers[key] = (target_pidfd, tuple(worker_record))
            operation_id = 72
            pending = origin.bootstrap.PendingSourceRetirement(key, operation_id,
                target, target_start, 3, bytes.fromhex('aa' * 32),
                launch.deadline_ns)
            context._pending_preexits[operation_id] = (pending, b'request', None)

            supervisor.phase = 'stopping'
            supervisor.snapshot()
            item = supervisor.tree.members[target]
            supervisor.tree.send(item, 'TERM')
            evidence_pending = context.authorize_worker_preexit(operation_id)
            evidence = context._authorized_preexits[operation_id]
            self.assertIs(evidence_pending, pending)
            self.assertEqual((evidence.phase, evidence.signal, evidence.run_id,
                evidence.controller, evidence.stack, evidence.worker_pid,
                evidence.worker_start_ticks),
                ('stopping', 'TERM', self.RUN_ID, controller, self.STACK,
                 target, target_start))
            self.assertEqual(len(evidence.receipt_sha256), 32)
            self.assertGreaterEqual(len(checks), 2)
        finally:
            os.umask(previous_umask)
            if context._original_supervisor_pidfd >= 0:
                os.close(context._original_supervisor_pidfd)
            if context._original_supervisor_output_fd >= 0:
                os.close(context._original_supervisor_output_fd)
            if 'target_pidfd' in locals():
                os.close(target_pidfd)
            if 'launch' in locals() and launch.pidfd >= 0:
                os.close(launch.pidfd)
            if supervisor is not None:
                for member in list(supervisor.tree.members.values()):
                    try:
                        os.kill(member['pid'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for _ in range(50):
                    try:
                        supervisor.tree.tick()
                    except (OSError, RuntimeError, ValueError):
                        pass
                    if supervisor.tree.no_children:
                        break
                    time.sleep(.005)
                supervisor.tree.close()
                supervisor.server.close()
                supervisor.client.close()
                os.close(supervisor.caller_fd)
                supervisor.events.close()
            os.close(output_fd)

    def test_pinned_supervisor_starting_snapshot_binds_parked_origin_lineage_only(self):
        source = (Path(__file__).resolve().parents[2] /
            'tests/upstream/fstack/tests/integration/common/reload_supervisor.py')
        if not source.exists():
            self.skipTest('pinned original supervisor source is unavailable')
        self.assertEqual(sha256_file(source), origin.SUPERVISOR_SHA256)
        producer_spec = importlib.util.spec_from_file_location(
            'pinned_parked_dummy_supervisor', source)
        producer = importlib.util.module_from_spec(producer_spec)
        sys.path.insert(0, str(source.parent))
        try:
            producer_spec.loader.exec_module(producer)
        finally:
            sys.path.pop(0)
        output = Path(self.temporary.name) / 'parked-out'
        output.mkdir(mode=0o700)
        output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        report_r, report_w = os.pipe2(os.O_CLOEXEC)
        release_r, release_w = os.pipe2(os.O_CLOEXEC)
        supervisor = None
        context = None
        launch = None
        parent_pidfd = child_pidfd = -1
        previous_umask = os.umask(0o077)
        try:
            supervisor = producer.Supervisor(output, self.RUN_ID, 30)
            controller = supervisor.tree.spawn(['/bin/sleep', '30'], 'controller')
            supervisor.controller = controller
            supervisor.stack = self.STACK
            supervisor.tree.default_stack = self.STACK
            python_path = str(Path(sys.executable).resolve(strict=True))
            supervisor.approve_image(python_path, producer.digest(python_path))
            code = ('import os,signal,sys,time\n'
                'report=int(sys.argv[1]); gate=int(sys.argv[2]); child=os.fork()\n'
                'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                'if child == 0:\n'
                ' os.close(report)\n'
                ' while True: time.sleep(0.02)\n'
                'else:\n'
                ' os.write(report, (str(child)+"\\n").encode()); os.close(report)\n'
                ' os.read(gate,1); os._exit(0)\n')
            parent = supervisor.tree.spawn([python_path, '-c', code,
                str(report_w), str(release_r)], 'target', self.STACK,
                pass_fds=(report_w, release_r))
            os.close(report_w); report_w = -1
            os.close(release_r); release_r = -1
            child_bytes = os.read(report_r, 64)
            child = int(child_bytes.strip())
            os.close(report_r); report_r = -1
            for _ in range(10):
                supervisor.tree.tick()
                time.sleep(.002)
            self.assertIsNone(supervisor.tree.failure)
            self.assertIn(child, supervisor.tree.members)
            supervisor.phase = 'starting'
            supervisor.snapshot()
            launch = origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
            launch.process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
            launch.pidfd = os.pidfd_open(os.getpid())
            launch.start = origin.identity._start_ticks(os.getpid())
            launch.deadline_ns = time.monotonic_ns() + 3_000_000_000
            launch.run_id = self.RUN_ID
            launch.output = str(output)
            launch.output_fd = output_fd
            held_dir = os.fstat(output_fd)
            launch.output_identity = (held_dir.st_dev, held_dir.st_ino)
            python_stat = os.stat('/proc/self/exe')
            launch.python = SimpleNamespace(
                frozen=(python_stat.st_dev, python_stat.st_ino, python_stat.st_size,
                    python_stat.st_mtime_ns, python_stat.st_ctime_ns),
                sha256=hashlib.sha256(Path('/proc/self/exe').read_bytes()).digest())
            launch.live_supervisor = MethodType(
                lambda _launch, deadline: None if time.monotonic_ns() < deadline else
                    (_ for _ in ()).throw(PermissionError('expired')), launch)
            launch.origin_pidfd = os.dup(supervisor.tree.members[parent]['pidfd'])
            parent_pidfd = launch.origin_pidfd
            launch.master_pidfd = os.dup(supervisor.tree.members[child]['pidfd'])
            child_pidfd = launch.master_pidfd
            context = origin.bootstrap.SourceBootstrapSupervisor.__new__(
                origin.bootstrap.SourceBootstrapSupervisor)
            context.owner_live = launch.live_supervisor
            context.shell_mode = True
            context.deadline_ns = launch.deadline_ns
            context.original_supervisor_identity = None
            context._original_supervisor_pidfd = -1
            context._original_supervisor_output_fd = -1
            context._pending_preexits = {}
            context._authorized_preexits = {}
            context.workers = {}
            parent_start = supervisor.tree.members[parent]['start_time']
            child_start = supervisor.tree.members[child]['start_time']
            launch.capture_source_supervisor_identity(context, launch.deadline_ns,
                origin_pid=parent, origin_start=parent_start,
                child_pid=child, child_start=child_start)
            self.assertTrue(origin.identity.process_alive(parent_pidfd))
            self.assertTrue(origin.identity.process_alive(child_pidfd))
            key, operation_id = (1, 1), 73
            record = [0] * 35
            record[5], record[11] = child, child_start
            context.workers[key] = (child_pidfd, tuple(record))
            pending = origin.bootstrap.PendingSourceRetirement(key, operation_id,
                child, child_start, 3, bytes.fromhex('bb' * 32), launch.deadline_ns)
            context._pending_preexits[operation_id] = (pending, b'request', None)
            with self.assertRaises(BlockingIOError):
                context.authorize_worker_preexit(operation_id)
            self.assertNotIn(operation_id, context._authorized_preexits)

            # The daemon launcher stays parked until the modeled Origin ACK.
            os.write(release_w, b'A')
            release_w = -1
            for _ in range(50):
                supervisor.tree.tick()
                if parent in supervisor.tree.history:
                    break
                time.sleep(.002)
            self.assertIn(parent, supervisor.tree.history)
            supervisor.phase = 'running'
            supervisor.snapshot()
            supervisor.phase = 'stopping'
            supervisor.snapshot()
            supervisor.tree.send(supervisor.tree.members[child], 'TERM')
            self.assertEqual(context.authorize_worker_preexit(operation_id), pending)
            evidence = context._authorized_preexits[operation_id]
            self.assertEqual((evidence.phase, evidence.signal, evidence.worker_pid,
                evidence.worker_start_ticks), ('stopping', 'TERM', child, child_start))
        finally:
            os.umask(previous_umask)
            for fd in (report_r, report_w, release_r, release_w):
                if fd >= 0:
                    os.close(fd)
            if context is not None:
                for fd in (context._original_supervisor_pidfd,
                        context._original_supervisor_output_fd):
                    if fd >= 0:
                        os.close(fd)
            for fd in (parent_pidfd, child_pidfd):
                if fd >= 0:
                    os.close(fd)
            if launch is not None and launch.pidfd >= 0:
                os.close(launch.pidfd)
            if supervisor is not None:
                for member in list(supervisor.tree.members.values()):
                    try:
                        os.kill(member['pid'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for _ in range(50):
                    try:
                        supervisor.tree.tick()
                    except (OSError, RuntimeError, ValueError):
                        pass
                    if supervisor.tree.no_children:
                        break
                    time.sleep(.005)
                supervisor.tree.close()
                supervisor.server.close()
                supervisor.client.close()
                os.close(supervisor.caller_fd)
                supervisor.events.close()
            os.close(output_fd)

    def test_wrong_run_supervisor_and_captured_control_identity_reject(self):
        cases = (
            ('run', {'run_id': 'other'}),
            ('supervisor pid', {'supervisor': {'pid': 1,
                'start_time': self.supervisor_start,
                'device': self.python_stat.st_dev, 'inode': self.python_stat.st_ino}}),
            ('supervisor start', {'supervisor': {'pid': self.supervisor_pid,
                'start_time': self.supervisor_start + 1,
                'device': self.python_stat.st_dev, 'inode': self.python_stat.st_ino}}),
            ('supervisor interpreter inode', {'supervisor': {'pid': self.supervisor_pid,
                'start_time': self.supervisor_start,
                'device': self.python_stat.st_dev, 'inode': self.python_stat.st_ino + 1}}),
            ('controller', {'controller': self.CONTROLLER + 1}),
            ('stack', {'stack': 'other-stack'}),
        )
        for label, mutation in cases:
            with self.subTest(case=label):
                self._write_stopping_receipts(**mutation)
                with self.assertRaises(PermissionError):
                    self.context.authorize_worker_preexit(self.operation_id)

    def test_second_identity_dup_failure_closes_first_duplicate(self):
        fresh = origin.bootstrap.SourceBootstrapSupervisor.__new__(
            origin.bootstrap.SourceBootstrapSupervisor)
        fresh.owner_live = self.launch.live_supervisor
        fresh.shell_mode = True
        fresh.deadline_ns = self.launch.deadline_ns
        fresh.original_supervisor_identity = None
        fresh._original_supervisor_pidfd = -1
        fresh._original_supervisor_output_fd = -1
        real_dup = os.dup
        calls = 0
        def fail_second(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_dup(fd)
            raise OSError(errno.EMFILE, 'controlled second dup failure')
        before = fd_count()
        with mock.patch.object(origin.bootstrap.os, 'dup', side_effect=fail_second):
            with self.assertRaises(OSError):
                fresh.bind_original_supervisor_identity(self.launch,
                    self.CONTROLLER, self.STACK)
        self.assertEqual(fd_count(), before)
        self.assertEqual(fresh._original_supervisor_pidfd, -1)
        self.assertEqual(fresh._original_supervisor_output_fd, -1)

    def test_term_membership_kill_symlink_size_and_deadline_are_fail_closed(self):
        with self.subTest(case='term absent'):
            self._write_stopping_receipts(events=[])
            with self.assertRaises(BlockingIOError):
                self.context.authorize_worker_preexit(self.operation_id)
        with self.subTest(case='wrong worker start'):
            self._write_stopping_receipts(events=[{'run_id': self.RUN_ID,
                'event': 'signal_requested', 'monotonic': time.monotonic(),
                'pid': self.worker.pid, 'start_time': self.pending.worker_start_ticks + 1,
                'signal': 'TERM', 'helper': 999}])
            with self.assertRaises((BlockingIOError, PermissionError)):
                self.context.authorize_worker_preexit(self.operation_id)
        with self.subTest(case='wrong worker pid'):
            self._write_stopping_receipts(events=[{'run_id': self.RUN_ID,
                'event': 'signal_requested', 'monotonic': time.monotonic(),
                'pid': self.worker.pid + 1, 'start_time': self.pending.worker_start_ticks,
                'signal': 'TERM', 'helper': 999}])
            with self.assertRaises(BlockingIOError):
                self.context.authorize_worker_preexit(self.operation_id)
        with self.subTest(case='wrong run event'):
            self._write_stopping_receipts(events=[{'run_id': 'other',
                'event': 'signal_requested', 'monotonic': time.monotonic(),
                'pid': self.worker.pid, 'start_time': self.pending.worker_start_ticks,
                'signal': 'TERM', 'helper': 999}])
            with self.assertRaisesRegex(PermissionError, 'another run'):
                self.context.authorize_worker_preexit(self.operation_id)
        with self.subTest(case='KILL escalation'):
            events = [
                {'run_id': self.RUN_ID, 'event': 'signal_requested',
                    'monotonic': time.monotonic(), 'pid': self.worker.pid,
                    'start_time': self.pending.worker_start_ticks, 'signal': 'TERM', 'helper': 999},
                {'run_id': self.RUN_ID, 'event': 'signal_requested',
                    'monotonic': time.monotonic(), 'pid': self.worker.pid,
                    'start_time': self.pending.worker_start_ticks, 'signal': 'KILL', 'helper': 1000},
            ]
            self._write_stopping_receipts(events=events)
            with self.assertRaisesRegex(PermissionError, 'escalated'):
                self.context.authorize_worker_preexit(self.operation_id)
        with self.subTest(case='symlink'):
            path = self.output / 'ownership-events.jsonl'
            path.unlink()
            outside = Path(self.temporary.name) / 'outside'
            outside.write_text('{}\n')
            path.symlink_to(outside)
            with self.assertRaises(OSError):
                self.context.authorize_worker_preexit(self.operation_id)
        with self.subTest(case='hardlink'):
            self._write_stopping_receipts()
            path = self.output / 'ownership-events.jsonl'
            os.link(path, Path(self.temporary.name) / 'extra-events-link')
            with self.assertRaisesRegex(PermissionError, 'invalid original supervisor receipt'):
                self.context.authorize_worker_preexit(self.operation_id)
            (Path(self.temporary.name) / 'extra-events-link').unlink()
        with self.subTest(case='oversized snapshot'):
            self._write_snapshot('stopping')
            (self.output / 'supervisor.json').write_bytes(b'X' * 65537)
            before_fds = fd_count()
            with self.assertRaisesRegex(PermissionError, 'invalid original supervisor receipt'):
                self.context.authorize_worker_preexit(self.operation_id)
            self.assertEqual(fd_count(), before_fds)
        with self.subTest(case='oversized events'):
            self._write_stopping_receipts()
            (self.output / 'ownership-events.jsonl').write_bytes(
                b'X' * (8 * 1024 * 1024 + 1))
            before_fds = fd_count()
            with self.assertRaisesRegex(PermissionError, 'invalid original supervisor receipt'):
                self.context.authorize_worker_preexit(self.operation_id)
            self.assertEqual(fd_count(), before_fds)
        with self.subTest(case='receipt replacement while reading'):
            self._write_stopping_receipts()
            real_read = os.read
            changed = False
            def replace_snapshot(fd, size):
                nonlocal changed
                data = real_read(fd, size)
                if not changed:
                    changed = True
                    self._write_snapshot('stopping')
                return data
            with mock.patch.object(origin.os, 'read', side_effect=replace_snapshot):
                with self.assertRaises(BlockingIOError):
                    self.context.authorize_worker_preexit(self.operation_id)
        with self.subTest(case='expired'):
            self.pending = self.pending._replace(deadline_ns=time.monotonic_ns() - 1)
            self.context._pending_preexits[self.operation_id] = (self.pending, b'request', None)
            with self.assertRaises(PermissionError):
                self.context.authorize_worker_preexit(self.operation_id)


class SettlementReceiptControls(unittest.TestCase):
    """Modeled receipt controls, not original-shell settlement evidence."""
    RUN_ID = 'gr_test_4242_abcdef01'
    SUPERVISOR_PID = 4242
    SUPERVISOR_START = 123456

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'out'
        self.output.mkdir(mode=0o700)
        self.output_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(lambda: os.close(self.output_fd) if self.output_fd >= 0 else None)
        self.observer = self._observer()

    def _observer(self, result=0, phase=None):
        value = origin.OriginalShellLaunch.__new__(origin.OriginalShellLaunch)
        directory = os.stat(self.output)
        value.process = SimpleNamespace(pid=self.SUPERVISOR_PID, poll=lambda: 0,
            returncode=result)
        value.run_id = self.RUN_ID
        value.output = str(self.output)
        value.output_fd = os.dup(self.output_fd)
        self.addCleanup(self._close_fd, value.output_fd)
        value.output_identity = directory.st_dev, directory.st_ino
        value.pidfd = value.master_pidfd = value.origin_pidfd = -1
        value.context = None
        value.start = self.SUPERVISOR_START
        value.python = SimpleNamespace(frozen=(directory.st_dev, 777, 0, 0, 0))
        value.files = []
        value.origin_channel = None
        value.settlement = None
        self._write_receipts(value, result=result, phase=phase)
        return value

    @staticmethod
    def _close_fd(fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def _write_receipts(self, observer, *, result=0, phase=None, snapshot=None,
            events=None, snapshot_bytes=None, events_bytes=None):
        phase = phase or ('finished' if result == 0 else 'failed')
        snapshot = snapshot if snapshot is not None else {
            'version': 1, 'run_id': self.RUN_ID, 'phase': phase, 'members': [],
            'failure': None if result == 0 else 'controlled modeled failure',
            'supervisor': {'pid': self.SUPERVISOR_PID, 'start_time': self.SUPERVISOR_START,
                'device': self.observer.python.frozen[0] if hasattr(self, 'observer') else
                    os.stat(self.output).st_dev,
                'inode': 777},
        }
        events = events if events is not None else [{
            'event': 'run_finished', 'run_id': self.RUN_ID, 'echild': True, 'result': result}]
        snapshot_data = snapshot_bytes if snapshot_bytes is not None else (
            json.dumps(snapshot, separators=(',', ':')).encode() + b'\n')
        events_data = events_bytes if events_bytes is not None else b''.join(
            json.dumps(event, separators=(',', ':')).encode() + b'\n' for event in events)
        for name, data in (('supervisor.json', snapshot_data),
                ('ownership-events.jsonl', events_data)):
            path = self.output / name
            if path.exists() or path.is_symlink():
                if path.is_dir() and not path.is_symlink():
                    path.rmdir()
                else:
                    path.unlink()
            path.write_bytes(data)
            path.chmod(0o600)

    def test_valid_finished_and_failed_receipts_are_observed_as_their_actual_results(self):
        finished = self.observer.observe_settlement()
        self.assertEqual((finished['result'], finished['phase'], finished['settled']),
            (0, 'finished', True))
        failed = self._observer(result=125)
        observed = failed.observe_settlement()
        self.assertEqual((observed['result'], observed['phase'], observed['settled']),
            (125, 'failed', True))
        self.assertNotEqual(observed['result'], 0,
            'a settled nonzero supervisor result must remain a failure')

    def test_wrong_run_and_supervisor_identity_or_exit_result_reject(self):
        mutations = (
            ('run id', lambda s, e: s.update(run_id='another')),
            ('supervisor pid', lambda s, e: s['supervisor'].update(pid=99)),
            ('supervisor start', lambda s, e: s['supervisor'].update(start_time=99)),
            ('supervisor device', lambda s, e: s['supervisor'].update(device=99)),
            ('supervisor inode', lambda s, e: s['supervisor'].update(inode=99)),
        )
        for label, mutate in mutations:
            with self.subTest(case=label):
                observer = self._observer()
                snapshot = json.loads((self.output / 'supervisor.json').read_bytes())
                events = [json.loads((self.output / 'ownership-events.jsonl').read_text())]
                mutate(snapshot, events)
                self._write_receipts(observer, snapshot=snapshot, events=events)
                with self.assertRaises(PermissionError):
                    observer.observe_settlement()
        for label, event_result, phase in (
                ('wrong result', 1, 'finished'), ('wrong phase', 0, 'failed')):
            with self.subTest(case=label):
                observer = self._observer(result=0)
                snapshot = json.loads((self.output / 'supervisor.json').read_bytes())
                events = [json.loads((self.output / 'ownership-events.jsonl').read_text())]
                events[0]['result'] = event_result
                snapshot['phase'] = phase
                self._write_receipts(observer, snapshot=snapshot, events=events)
                with self.assertRaises(PermissionError):
                    observer.observe_settlement()

    def test_members_and_run_finished_event_order_echild_are_required(self):
        cases = (
            ('members remain', {'members': [{'pid': 5} ]},
                [{'event': 'run_finished', 'run_id': self.RUN_ID, 'echild': True, 'result': 0}]),
            ('missing ending', {}, [{'event': 'worker_exit'}]),
            ('duplicate ending', {}, [
                {'event': 'run_finished', 'run_id': self.RUN_ID, 'echild': True, 'result': 0},
                {'event': 'run_finished', 'run_id': self.RUN_ID, 'echild': True, 'result': 0}]),
            ('ending not final', {}, [
                {'event': 'run_finished', 'run_id': self.RUN_ID, 'echild': True, 'result': 0},
                {'event': 'later_event'}]),
            ('echild false', {}, [
                {'event': 'run_finished', 'run_id': self.RUN_ID, 'echild': False, 'result': 0}]),
        )
        for label, snapshot_change, events in cases:
            with self.subTest(case=label):
                observer = self._observer()
                snapshot = json.loads((self.output / 'supervisor.json').read_bytes())
                snapshot.update(snapshot_change)
                self._write_receipts(observer, snapshot=snapshot, events=events)
                with self.assertRaises(PermissionError):
                    observer.observe_settlement()

    def test_nonobject_receipt_json_is_rejected(self):
        for label, snapshot_bytes, events_bytes in (
                ('snapshot array', b'[]\n', None),
                ('event array', None, b'[]\n')):
            with self.subTest(case=label):
                observer = self._observer()
                self._write_receipts(observer, snapshot_bytes=snapshot_bytes,
                    events_bytes=events_bytes)
                with self.assertRaises(PermissionError):
                    observer.observe_settlement()

    def test_live_known_actor_rejects_before_trusting_receipt(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            self.observer.master_pidfd = os.pidfd_open(child.pid)
            with self.assertRaisesRegex(PermissionError, 'actors still live'):
                self.observer.observe_settlement()
        finally:
            child.kill()
            child.wait(timeout=2)
            os.close(self.observer.master_pidfd)
            self.observer.master_pidfd = -1

    def test_receipt_symlink_hardlink_type_and_size_are_rejected_without_fd_leak(self):
        cases = ('symlink', 'hardlink', 'directory', 'oversized-snapshot',
            'oversized-events')
        for case in cases:
            with self.subTest(case=case):
                observer = self._observer()
                path = self.output / ('ownership-events.jsonl' if case == 'oversized-events'
                    else 'supervisor.json')
                original = path.read_bytes()
                path.unlink()
                if case == 'symlink':
                    target = Path(self.temporary.name) / 'outside.json'
                    target.write_bytes(original)
                    path.symlink_to(target)
                elif case == 'hardlink':
                    path.write_bytes(original)
                    os.link(path, Path(self.temporary.name) / 'extra-link')
                elif case == 'directory':
                    path.mkdir()
                elif case == 'oversized-snapshot':
                    path.write_bytes(b'X' * 65537)
                else:
                    path.write_bytes(b'X' * (8 * 1024 * 1024 + 1))
                before = fd_count()
                with self.assertRaises((PermissionError, OSError)):
                    observer.observe_settlement()
                self.assertEqual(fd_count(), before)
                if path.is_dir() and not path.is_symlink():
                    path.rmdir()
                else:
                    path.unlink()
                extra = Path(self.temporary.name) / 'extra-link'
                if extra.exists():
                    extra.unlink()
                # Restore a valid state for the next subcase.
                self._write_receipts(observer)

    def test_output_path_or_held_directory_replacement_rejects(self):
        observer = self._observer()
        moved = Path(self.temporary.name) / 'moved'
        self.output.rename(moved)
        self.output.mkdir(mode=0o700)
        with self.assertRaisesRegex(PermissionError, 'output directory changed'):
            observer.observe_settlement()
        self.output = moved
        observer = self._observer()
        replacement = Path(self.temporary.name) / 'replacement'
        replacement.mkdir(mode=0o700)
        replacement_fd = os.open(replacement, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.close(observer.output_fd)
            observer.output_fd = replacement_fd
            replacement_fd = -1
            self.addCleanup(self._close_fd, observer.output_fd)
            with self.assertRaisesRegex(PermissionError, 'output directory changed'):
                observer.observe_settlement()
        finally:
            if replacement_fd >= 0:
                os.close(replacement_fd)

    def test_close_requires_observed_receipt_then_closes_owned_descriptors(self):
        observer = self._observer()
        with self.assertRaisesRegex(PermissionError, 'settlement remains unverified'):
            observer.close()
        observer.observe_settlement()
        observer.close()
        observer.output_fd = -1
        self.assertEqual(observer.output_fd, -1)


if __name__ == '__main__':
    unittest.main()
