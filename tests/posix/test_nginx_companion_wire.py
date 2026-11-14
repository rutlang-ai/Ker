"""Validation for the private ker-run companion helper wire codec."""
import unittest
import array
import fcntl
import io
from unittest import mock
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace

from nginx_companion_wire import *
from nginx_companion_supervisor import NginxCompanion

_COMPANION_SPEC = importlib.util.spec_from_file_location(
    '_test_ker_nginx_companion', Path(__file__).parents[2] / 'tools' /
    'ker-nginx-companion.py')
_COMPANION = importlib.util.module_from_spec(_COMPANION_SPEC)
_COMPANION_SPEC.loader.exec_module(_COMPANION)
broker_ini_matches = _COMPANION.broker_ini_matches

_ALIAS_CAPABILITY_SPEC = importlib.util.spec_from_file_location(
    '_test_nginx_companion_alias_capability', Path(__file__).with_name(
        'nginx_companion_test_alias.py'))
_ALIAS_CAPABILITY = importlib.util.module_from_spec(_ALIAS_CAPABILITY_SPEC)
_ALIAS_CAPABILITY_SPEC.loader.exec_module(_ALIAS_CAPABILITY)

_TAP_SPEC = importlib.util.spec_from_file_location(
    '_test_native_nginx_companion_tap', Path(__file__).with_name(
        'native-nginx-companion-tap.py'))
_TAP = importlib.util.module_from_spec(_TAP_SPEC)
_TAP_SPEC.loader.exec_module(_TAP)


class CompanionWireTest(unittest.TestCase):
    def setUp(self):
        self.nonce = bytes.fromhex('0123456789abcdef0123456789abcdef')
        self.epoch = 17
        self.sequence = 0

    def test_record_sizes_are_exact(self):
        self.assertEqual((HELLO_BYTES, START_BYTES, STARTED_BYTES,
            RELOAD_BYTES, RELOAD_RESULT_BYTES, STOP_BYTES, SETTLED_BYTES,
            ERROR_BYTES, OWNER_READY_BYTES), (48, 168, 136, 48, 96, 48, 104, 104, 104))

    def test_owner_ready_wrapper_requires_identity_and_slot(self):
        valid = (123, 1000, 1000, 0, 456, 0, 789, 11, 12, 13)
        validate_owner_ready(valid, expected_uid=1000, expected_gid=1000,
            expected_role=0)
        for index, value in ((0, 0), (1, 1001), (3, 1), (4, 0),
                (5, 1), (6, 0), (7, 0), (8, 0), (9, 0)):
            invalid = list(valid)
            invalid[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                validate_owner_ready(tuple(invalid), expected_uid=1000,
                    expected_gid=1000, expected_role=0)
        with self.assertRaises(ValueError):
            validate_owner_ready(valid, expected_uid=1000, expected_gid=1000,
                expected_role=0, expected_cookie=14)

    def test_owner_ready_mode_refuses_reload_without_poisoning_session(self):
        companion = object.__new__(NginxCompanion)
        companion.owner_ready_required = True
        companion.unresolved = False
        with self.assertRaises(NotImplementedError):
            companion.reload()
        self.assertFalse(companion.unresolved)

    def test_prepared_retention_requires_supervisor_to_outlive_timeout(self):
        for code in (0, 7):
            with self.subTest(exit_code=code):
                process = subprocess.Popen([sys.executable, '-c',
                    f'import sys; sys.exit({code})'])
                with self.assertRaisesRegex(RuntimeError,
                        rf'exited before the retention timeout \(rc={code}\)'):
                    _TAP.require_wait_timeout(process, 2, 'test retention')
                self.assertEqual(process.wait(timeout=2), code)

        process = subprocess.Popen([sys.executable, '-c',
            'import os, signal; os.kill(os.getpid(), signal.SIGKILL)'])
        with self.assertRaisesRegex(RuntimeError,
                r'exited before the retention timeout \(rc=-9\)'):
            _TAP.require_wait_timeout(process, 2, 'test retention')
        self.assertEqual(process.wait(timeout=2), -signal.SIGKILL)

        process = subprocess.Popen([sys.executable, '-c',
            'import time; time.sleep(5)'])
        try:
            self.assertTrue(_TAP.require_wait_timeout(process, 0.05,
                'test retention'))
        finally:
            process.terminate()
            self.assertEqual(process.wait(timeout=2), -signal.SIGTERM)

    def _helper_owner_ready_rejects(self, *, change=None, with_rights=False,
                                    truncate=False, exit_before_receive=False,
                                    expected_role=0, expected_slot=None):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        gate_read, gate_write = os.pipe()
        release_read, release_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                receiver.close()
                os.close(gate_write)
                os.close(release_write)
                os.read(gate_read, 1)
                worker_pid = os.getpid()
                fields = [_COMPANION.OWNER_READY_MAGIC,
                    _COMPANION.OWNER_READY_VERSION,
                    _COMPANION.OWNER_READY_RECORD.size, 0, 0,
                    11, 12, _COMPANION.start_ticks(worker_pid),
                    worker_pid, worker_pid, 13, 0]
                if change is not None:
                    index, value = change
                    fields[index] = value
                data = _COMPANION.OWNER_READY_RECORD.pack(*fields)
                if truncate:
                    data = data[:-1]
                ancillary = []
                if with_rights:
                    fd = os.open('/dev/null', os.O_RDONLY)
                    ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                        struct.pack('i', fd))]
                sender.sendmsg([data], ancillary)
                if exit_before_receive:
                    os._exit(0)
                os.read(release_read, 1)
                os._exit(0)
            except BaseException:
                os._exit(99)
        os.close(gate_read)
        os.close(release_read)
        child_pidfd = os.pidfd_open(pid, 0)
        master_pidfd = os.pidfd_open(os.getpid(), 0)
        supervisor_pidfd = os.pidfd_open(os.getpid(), 0)
        reaped = False
        try:
            binary_hash = _COMPANION.sha256_file(f'/proc/{pid}/exe')
            os.write(gate_write, b'g')
            poller = select.poll()
            poller.register(receiver.fileno(), select.POLLIN)
            self.assertTrue(poller.poll(2000), 'child did not send READY test record')
            if exit_before_receive:
                os.waitpid(pid, 0)
                reaped = True
            class Master:
                def poll(self):
                    return None
            master = Master()
            master.pid = os.getpid()
            kwargs = dict(expected_cookie=13, binary_hash=binary_hash,
                master=master, master_pidfd=master_pidfd,
                master_start=_COMPANION.start_ticks(os.getpid()),
                supervisor_pidfd=supervisor_pidfd,
                supervisor_pid=os.getpid(),
                supervisor_start=_COMPANION.start_ticks(os.getpid()),
                expected_role=expected_role, expected_slot=expected_slot,
                timeout=1.0)
            before_fds = len(os.listdir('/proc/self/fd'))
            with self.assertRaises((ValueError, PermissionError,
                                    ProcessLookupError, FileNotFoundError,
                                    ConnectionError)):
                _COMPANION.receive_owner_ready(receiver, **kwargs)
            if with_rights:
                self.assertEqual(len(os.listdir('/proc/self/fd')), before_fds,
                    'rejected READY leaked an SCM_RIGHTS descriptor')
        finally:
            if not reaped:
                try:
                    os.write(release_write, b'x')
                except OSError:
                    pass
                try:
                    signal.pidfd_send_signal(child_pidfd, signal.SIGKILL)
                except OSError:
                    pass
                os.waitpid(pid, 0)
            for fd in (gate_write, release_write, child_pidfd,
                       master_pidfd, supervisor_pidfd):
                try:
                    os.close(fd)
                except OSError:
                    pass
            receiver.close()
            sender.close()

    def test_helper_ready_rejects_wrong_cookie_claimed_pid_and_stale_worker(self):
        self._helper_owner_ready_rejects(change=(10, 14))
        self._helper_owner_ready_rejects(change=(8, os.getpid() + 100000))
        self._helper_owner_ready_rejects(change=(7, 1))

    def test_helper_ready_rejects_dead_worker_truncated_record_and_rights(self):
        self._helper_owner_ready_rejects(exit_before_receive=True)
        self._helper_owner_ready_rejects(truncate=True)
        self._helper_owner_ready_rejects(with_rights=True)

    def test_source_candidate_ready_rejects_wrong_role_and_exact_slot(self):
        self._helper_owner_ready_rejects(expected_role=1,
            expected_slot=(11, 12), change=(3, 0))
        self._helper_owner_ready_rejects(expected_role=1,
            expected_slot=(11, 12), change=(5, 14))
        self._helper_owner_ready_rejects(expected_role=1,
            expected_slot=(11, 12), change=(6, 15))

    def _candidate_slot_transfer_case(self, mode, initial=False):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        report_read, report_write = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                sender.close()
                os.close(report_read)
                transfer_fd = receiver.fileno()
                companion = object.__new__(NginxCompanion)
                companion.candidate_slot_transfer_fd = transfer_fd
                companion.candidate_slot_stat = None
                companion.initial_slot_mode = initial
                before = len(os.listdir('/proc/self/fd'))
                try:
                    companion._receive_candidate_slot(1.0)
                    status = 0
                    stat = companion.candidate_slot_stat
                    inheritable = os.get_inheritable(transfer_fd)
                except BaseException as error:
                    status = 1
                    stat = None
                    inheritable = False
                    error_text = f'{type(error).__name__}: {error}'
                after = len(os.listdir('/proc/self/fd'))
                result = {'status': status, 'before': before, 'after': after,
                    'device': stat.st_dev if stat else None,
                    'inode': stat.st_ino if stat else None,
                    'inheritable': inheritable,
                    'error': error_text if status else None}
                if status == 0:
                    os.close(transfer_fd)
                os.write(report_write, json.dumps(result).encode())
                os._exit(0)
            except BaseException:
                os._exit(99)
        receiver.close()
        os.close(report_write)
        file_fd = os.open('/dev/null', os.O_RDONLY)
        try:
            tag = b'KER_INITIAL_SLOT_V1' if initial else b'KER_CANDIDATE_SLOT_V1'
            if mode == 'zero-rights':
                sender.sendmsg([tag])
            else:
                packet = (b'WRONG_CANDIDATE_SLOT' if mode == 'wrong-packet'
                    else tag)
                count = 2 if mode == 'two-rights' else 1
                sender.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                    struct.pack('i' * count, *([file_fd] * count)))])
        finally:
            os.close(file_fd)
            sender.close()
        with os.fdopen(report_read, 'rb') as report_file:
            result = json.loads(report_file.read())
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
            f'candidate transfer child failed: {status}, {result!r}')
        return result

    def test_candidate_slot_transfer_authenticates_one_fd_and_closes_rejections(self):
        self._assert_slot_transfer(False)

    def test_initial_slot_transfer_authenticates_one_fd_and_closes_rejections(self):
        self._assert_slot_transfer(True)

    def _assert_slot_transfer(self, initial):
        expected = os.stat('/dev/null')
        valid = self._candidate_slot_transfer_case('valid', initial)
        self.assertEqual(valid['status'], 0, valid)
        self.assertEqual((valid['device'], valid['inode']),
            (expected.st_dev, expected.st_ino))
        self.assertTrue(valid['inheritable'])
        self.assertEqual(valid['after'], valid['before'])
        for mode in ('zero-rights', 'two-rights', 'wrong-packet'):
            with self.subTest(mode=mode):
                rejected = self._candidate_slot_transfer_case(mode, initial)
                self.assertEqual(rejected['status'], 1, rejected)
                self.assertEqual(rejected['after'], rejected['before'] - 1,
                    f'rejected capability or transfer socket leaked: {rejected!r}')

    def test_valid_header_round_trip(self):
        packet = pack_record(HELLO, b'', self.nonce, self.epoch, self.sequence)
        self.assertEqual(unpack_header(packet),
            (HELLO, self.nonce, self.epoch, self.sequence))

    def test_zero_nonce_epoch_and_sequence_are_rejected(self):
        for values in ((HELLO, 48, bytes(16), 1, 1),
                       (HELLO, 48, self.nonce, 0, 1),
                       (START, 48, self.nonce, 1, 0)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                pack_header(*values)

    def test_hello_uses_reserved_zero_sequence_only(self):
        packet = pack_record(HELLO, b'', self.nonce, self.epoch, 0)
        self.assertEqual(unpack_header(packet)[-1], 0)
        with self.assertRaises(ValueError):
            pack_header(START, 48, self.nonce, self.epoch, 0)

    def test_request_sequence_exhaustion_does_not_wrap(self):
        sequence = RequestSequence()
        self.assertEqual(sequence.take(), 1)
        sequence._next = MAX_SEQUENCE
        self.assertEqual(sequence.take(), MAX_SEQUENCE)
        with self.assertRaises(OverflowError):
            sequence.take()

    def test_record_type_size_correlation_and_trailing_bytes_fail_closed(self):
        packet = pack_record(HELLO, b'', self.nonce, self.epoch, self.sequence)
        with self.assertRaises(ValueError):
            unpack_record(packet, START, self.nonce, self.epoch,
                self.sequence, START_BODY)
        with self.assertRaises(ValueError):
            unpack_record(packet, HELLO, self.nonce, self.epoch + 1,
                self.sequence, struct.Struct(''))
        with self.assertRaises(ValueError):
            unpack_header(packet + b'x')

    def test_start_and_settlement_layouts(self):
        body = START_BODY.pack(1, 1000, 1000, 0, 42, b'p' * 32,
            b'n' * 32, b'c' * 32)
        request_sequence = self.sequence + 1
        packet = pack_record(START, body, self.nonce, self.epoch, request_sequence)
        self.assertEqual(len(packet), START_BYTES)
        self.assertEqual(unpack_record(packet, START, self.nonce, self.epoch,
            request_sequence, START_BODY), START_BODY.unpack(body))
        settled = SETTLED_BODY.pack(0, CLEANUP_SETTLED, 55, 0, 42,
            b'n' * 32)
        packet = pack_record(SETTLED, settled, self.nonce, self.epoch, 2)
        self.assertEqual(len(packet), SETTLED_BYTES)
        fields = unpack_record(packet, SETTLED, self.nonce, self.epoch,
            2, SETTLED_BODY)
        self.assertEqual(fields[3], 0)
        validate_settled(fields, 55, 42, b'n' * 32)

    def test_settlement_requires_exact_master_and_clean_state(self):
        fields = (0, CLEANUP_SETTLED, 55, 0, 42, b'n' * 32)
        validate_settled(fields, 55, 42, b'n' * 32)
        for bad in (
                (0, CLEANUP_UNRESOLVED, 55, 1, 42, b'n' * 32),
                (0, CLEANUP_SETTLED, 55, 1, 42, b'n' * 32),
                (0, CLEANUP_SETTLED, 55, 0, 42, b'x' * 32),
                (0, 8, 55, 0, 42, b'n' * 32),
                (-1, CLEANUP_SETTLED, 55, 0, 42, b'n' * 32),
                (1, CLEANUP_SETTLED, 55, 0, 42, b'n' * 32)):
            with self.subTest(fields=bad), self.assertRaises(ValueError):
                validate_settled(bad, 55, 42, b'n' * 32)

    def test_error_requires_positive_errno_and_phase(self):
        validate_error((5, 2, 55, 1, 42, b'n' * 32))
        for bad in ((0, 2, 55, 1, 42, b'n' * 32),
                    (-5, 2, 55, 1, 42, b'n' * 32),
                    (5, 0, 55, 0, 42, b'\0' * 32)):
            with self.subTest(fields=bad), self.assertRaises(ValueError):
                validate_error(bad)

    def test_profile_binds_binary_config_ini_prefix_and_environment(self):
        binary = b'b' * 32
        config = b'c' * 32
        ini = b'i' * 32
        env = {'KER_SOCKET_BROKER_PATH': '/run/ker.sock'}
        baseline = profile_hash(binary, config, ini, '/opt/nginx', env)
        self.assertEqual(len(baseline), 32)
        for replacement in (
                (b'x' * 32, config, ini, '/opt/nginx', env),
                (binary, b'x' * 32, ini, '/opt/nginx', env),
                (binary, config, b'x' * 32, '/opt/nginx', env),
                (binary, config, ini, '/srv/nginx', env),
                (binary, config, ini, '/opt/nginx',
                    {'KER_SOCKET_BROKER_PATH': '/run/other.sock'})):
            with self.subTest(replacement=replacement):
                self.assertNotEqual(profile_hash(*replacement), baseline)

    def test_graceful_reload_profile_is_exact_and_unambiguous(self):
        profiles = (
            ('[ker_socket_broker]\nversion=1\npath=/run/ker.sock\n'
             '[dpdk]\ngraceful_reload=0\n', True),
            ('[ker_socket_broker]\nversion=1\npath=/run/other.sock\n'
             '[dpdk]\ngraceful_reload=0\n', False),
            ('[ker_socket_broker]\nversion=1\npath=/run/ker.sock\n'
             '[dpdk]\ngraceful_reload=1\n', False),
            ('[ker_socket_broker]\nversion=1\npath=/run/ker.sock\n'
             '[dpdk]\ngraceful_reload=0\ngraceful_reload=1\n', False),
            ('[ker_socket_broker]\nversion=1\npath=/run/ker.sock\n'
             '[dpdk]\ngraceful_reload=0\n[dpdk]\ngraceful_reload=0\n', False),
            ('[ker_socket_broker]\nversion=1\npath=/run/ker.sock\n'
             '[dpdk]\n# graceful_reload=0\ngraceful_reload=1\n', False))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fstack.ini'
            for content, expected in profiles:
                with self.subTest(content=content):
                    path.write_text(content, encoding='utf-8')
                    self.assertEqual(broker_ini_matches(path, '/run/ker.sock'),
                        expected)

    def _alias_profile_fixture(self, directory):
        directory = Path(directory)
        prefix = directory / 'nginx'
        prefix.mkdir(mode=0o700)
        module_source = directory / 'module.c'
        alias_module = directory / 'alias-test.so'
        normal_module = directory / 'normal.so'
        module_source.write_text(
            '#include <stddef.h>\n'
            '#if defined(TEST_ALIAS)\n'
            '__attribute__((visibility("default"),used))\n'
            'const char ker_nginx_owner_activation_alias_test_marker[] = '
            '"KER_NGINX_OWNER_ALIAS_TEST_V1";\n'
            'void keep_marker(void) { (void)ker_nginx_owner_activation_alias_test_marker[0]; }\n'
            '#else\n'
            'int normal_owner_module(void) { return 1; }\n'
            '#endif\n', encoding='ascii')
        compiler = shutil.which('cc')
        if compiler is None:
            self.skipTest('C compiler required for ELF marker fixture')
        for output, defines in ((alias_module, ['-DTEST_ALIAS=1']),
                (normal_module, [])):
            result = subprocess.run([compiler, '-shared', '-fPIC',
                '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
                *defines, str(module_source), '-o', str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        alias_path = directory / 'initial-alias.sock'
        listener.bind(str(alias_path))
        os.chmod(alias_path, 0o600)
        listener.listen(4)
        path_stat = os.stat(alias_path, follow_symlinks=False)
        parent_stat = os.stat(directory, follow_symlinks=False)
        path_identity = (path_stat.st_dev, path_stat.st_ino, path_stat.st_mode,
            path_stat.st_uid, path_stat.st_gid)
        parent_identity = (parent_stat.st_dev, parent_stat.st_ino, parent_stat.st_mode,
            parent_stat.st_uid, parent_stat.st_gid)
        args = SimpleNamespace(owner_ready_required=True,
            source_bootstrap_required=True, cycle_control_fd=None,
            rx_owner_relay_fd=None, initial_slot_fd=None, candidate_slot_fd=None,
            prefix=prefix, test_initial_alias_listener_fd=listener.fileno(),
            test_initial_alias_path_identity=path_identity,
            test_initial_alias_parent_identity=parent_identity)
        values = {'KER_NGINX_SOURCE_FIRST_HUP_ENABLE': '1',
            'KER_NGINX_TEST_INITIAL_ALIAS_SOCKET': str(alias_path),
            'KER_NGINX_OWNER_MODULE_PATH': str(alias_module),
            'KER_NGINX_OWNER_MODULE_SHA256':
                hashlib.sha256(alias_module.read_bytes()).hexdigest()}
        return (args, values, listener, alias_path, alias_module, normal_module,
            path_identity, parent_identity)

    def test_alias_profile_accepts_explicit_pinned_test_module_and_listener(self):
        with tempfile.TemporaryDirectory(prefix='ker-companion-alias-profile-') as directory:
            args, values, listener, _path, _alias, _normal, _pathid, _parentid =                 self._alias_profile_fixture(directory)
            try:
                identity = _COMPANION._validate_test_alias_profile(args, values)
                self.assertIsNotNone(identity)
                self.assertEqual(_COMPANION._validate_test_alias_profile(
                    args, values, previous_identity=identity), identity)
            finally:
                listener.close()

    def test_alias_profile_rejects_missing_source_flags_and_normal_profile(self):
        with tempfile.TemporaryDirectory(prefix='ker-companion-alias-flags-') as directory:
            args, values, listener, *_ = self._alias_profile_fixture(directory)
            try:
                for field in ('owner_ready_required', 'source_bootstrap_required'):
                    original = getattr(args, field)
                    setattr(args, field, False)
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        _COMPANION._validate_test_alias_profile(args, values)
                    setattr(args, field, original)
                normal = dict(values)
                normal['KER_NGINX_SOURCE_FIRST_HUP_ENABLE'] = '0'
                with self.assertRaises(ValueError):
                    _COMPANION._validate_test_alias_profile(args, normal)
                faulted = dict(values, FF_FAULT='flip_fail_once')
                with self.assertRaises(ValueError):
                    _COMPANION._validate_test_alias_profile(args, faulted)
            finally:
                listener.close()

    def test_alias_profile_rejects_normal_module_and_wrong_hash(self):
        with tempfile.TemporaryDirectory(prefix='ker-companion-alias-module-') as directory:
            args, values, listener, _path, _alias, normal, *_ = self._alias_profile_fixture(directory)
            try:
                wrong_module = dict(values,
                    KER_NGINX_OWNER_MODULE_PATH=str(normal),
                    KER_NGINX_OWNER_MODULE_SHA256=hashlib.sha256(normal.read_bytes()).hexdigest())
                with self.assertRaisesRegex(PermissionError, 'alias-test variant'):
                    _COMPANION._validate_test_alias_profile(args, wrong_module)
                wrong_hash = dict(values, KER_NGINX_OWNER_MODULE_SHA256='0' * 64)
                with self.assertRaisesRegex(PermissionError, 'hash mismatch'):
                    _COMPANION._validate_test_alias_profile(args, wrong_hash)
            finally:
                listener.close()

    def test_alias_profile_rejects_wrong_path_symlink_and_replaced_socket(self):
        with tempfile.TemporaryDirectory(prefix='ker-companion-alias-path-') as directory:
            args, values, listener, path, _alias, _normal, original_pathid, parentid =                 self._alias_profile_fixture(directory)
            try:
                wrong = dict(values, KER_NGINX_TEST_INITIAL_ALIAS_SOCKET=str(path.parent/'sibling.sock'))
                with self.assertRaises(ValueError):
                    _COMPANION._validate_test_alias_profile(args, wrong)
                saved = path.with_name('saved.sock')
                path.rename(saved)
                path.symlink_to(saved.name)
                with self.assertRaises(PermissionError):
                    _COMPANION._validate_test_alias_profile(args, values)
                path.unlink()
                saved.rename(path)
                replaced = path.with_name('replacement.sock')
                path.unlink()
                replacement_listener = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                replacement_listener.bind(str(path))
                os.chmod(path, 0o600)
                replacement_listener.listen(1)
                replacement_stat=os.stat(path,follow_symlinks=False)
                replacement_identity=(replacement_stat.st_dev,replacement_stat.st_ino)
                try:
                    with self.assertRaisesRegex(PermissionError, 'captured'):
                        _COMPANION._validate_test_alias_profile(args, values)
                finally:
                    replacement_listener.close()
                    path.unlink()
                # The caller's prelaunch identity detects same-path replacement.
                self.assertNotEqual(original_pathid[:2], replacement_identity)
                self.assertEqual(parentid[:2],
                    (os.stat(path.parent, follow_symlinks=False).st_dev,
                     os.stat(path.parent, follow_symlinks=False).st_ino))
            finally:
                listener.close()

    def test_alias_profile_rejects_parent_mode_socket_mode_fd_and_listener_type(self):
        with tempfile.TemporaryDirectory(prefix='ker-companion-alias-mode-') as directory:
            args, values, listener, path, _alias, _normal, _pathid, _parentid =                 self._alias_profile_fixture(directory)
            try:
                os.chmod(path.parent, 0o755)
                with self.assertRaisesRegex(PermissionError, 'parent'):
                    _COMPANION._validate_test_alias_profile(args, values)
                os.chmod(path.parent, 0o700)
                os.chmod(path, 0o644)
                with self.assertRaisesRegex(PermissionError, 'mode-0600'):
                    _COMPANION._validate_test_alias_profile(args, values)
                os.chmod(path, 0o600)
                os.set_inheritable(listener.fileno(), True)
                with self.assertRaisesRegex(PermissionError, 'close-on-exec'):
                    _COMPANION._validate_test_alias_profile(args, values)
                os.set_inheritable(listener.fileno(), False)
                not_listener = socket.socket(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                args.test_initial_alias_listener_fd = not_listener.fileno()
                with self.assertRaisesRegex(PermissionError, 'exact listening'):
                    _COMPANION._validate_test_alias_profile(args, values)
                not_listener.close()
            finally:
                listener.close()

    def test_alias_profile_rejects_wrong_owner_and_nonseqpacket_listener(self):
        with tempfile.TemporaryDirectory(prefix='ker-companion-alias-owner-') as directory:
            args, values, listener, path, _alias, _normal, _pathid, _parentid = \
                self._alias_profile_fixture(directory)
            try:
                uid=os.geteuid()
                with mock.patch.object(_COMPANION.os, 'geteuid',
                        side_effect=(uid,uid + 1)):
                    with self.assertRaisesRegex(PermissionError, 'owned private directory'):
                        _COMPANION._validate_test_alias_profile(args, values)
                stream_path=path.parent/'stream.sock'
                listener.close()
                path.unlink()
                stream=socket.socket(socket.AF_UNIX,
                    socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
                stream.bind(str(path))
                os.chmod(path,0o600)
                stream.listen(1)
                path_stat=os.stat(path,follow_symlinks=False)
                args.test_initial_alias_path_identity=(path_stat.st_dev,path_stat.st_ino,
                    path_stat.st_mode,path_stat.st_uid,path_stat.st_gid)
                args.test_initial_alias_listener_fd=stream.fileno()
                with self.assertRaisesRegex(PermissionError, 'SOCK_SEQPACKET'):
                    _COMPANION._validate_test_alias_profile(args, values)
                stream.close()
            finally:
                try: listener.close()
                except OSError: pass

    def test_member_alias_capability_requires_nonblocking_write_fifo(self):
        read_fd, capability_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            identity = _ALIAS_CAPABILITY.validate_member_alias_fd(capability_fd)
            self.assertEqual(identity['access'], 'write-only')
            self.assertTrue(identity['nonblocking'] and identity['cloexec'])
            with self.assertRaisesRegex(PermissionError, 'write-only'):
                _ALIAS_CAPABILITY.validate_member_alias_fd(read_fd)
        finally:
            os.close(capability_fd); os.close(read_fd)
        blocking_read, blocking_write = os.pipe2(os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(PermissionError, 'nonblocking'):
                _ALIAS_CAPABILITY.validate_member_alias_fd(blocking_write)
        finally:
            os.close(blocking_read); os.close(blocking_write)
        socket_left, socket_right = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        try:
            with self.assertRaisesRegex(PermissionError, 'capability FIFO'):
                _ALIAS_CAPABILITY.validate_member_alias_fd(socket_left.fileno())
        finally:
            socket_left.close(); socket_right.close()
        plain_read, plain_write = os.pipe2(os.O_NONBLOCK)
        try:
            with self.assertRaisesRegex(PermissionError, 'close-on-exec'):
                _ALIAS_CAPABILITY.validate_member_alias_fd(plain_write)
        finally:
            os.close(plain_read); os.close(plain_write)

    @staticmethod
    def _send_member_alias_packet(sender, descriptors):
        rights = array.array('i', descriptors)
        sender.sendmsg([b'A'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            rights.tobytes())])

    @staticmethod
    def _open_fd_count():
        return len(list(Path('/proc/self/fd').iterdir()))

    def _member_alias_pair(self):
        listener = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        directory = Path(tempfile.mkdtemp(prefix='ker-alias-rx-'))
        path = directory / 'alias.sock'
        listener.bind(str(path))
        listener.listen(1)
        client = socket.socket(socket.AF_UNIX,
            socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        client.connect(str(path))
        server, _ = listener.accept()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        return path, listener, client, server

    @staticmethod
    def _close_member_alias_pair(path, listener, sender, receiver):
        listener.close()
        sender.close()
        receiver.close()
        path.unlink(missing_ok=True)
        path.parent.rmdir()

    def test_member_alias_recv_accepts_kernel_cloexec_output_flag(self):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        path, listener, sender, receiver = self._member_alias_pair()
        received = -1
        try:
            self._send_member_alias_packet(sender, [write_fd])
            diagnostic_stream = io.StringIO()
            with mock.patch('sys.stderr', diagnostic_stream):
                received, capability, diagnostic = _ALIAS_CAPABILITY.receive_member_alias(
                    receiver, os.getpid(), 'valid-cloexec')
            self.assertIn('MEMBER_ALIAS_DIAGNOSTIC ', diagnostic_stream.getvalue())
            self.assertEqual(capability['inode'], os.fstat(write_fd).st_ino)
            self.assertEqual(diagnostic['flags'], socket.MSG_CMSG_CLOEXEC)
            self.assertTrue(fcntl.fcntl(received, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        finally:
            if received >= 0:
                os.close(received)
            self._close_member_alias_pair(path, listener, sender, receiver); os.close(write_fd); os.close(read_fd)

    def test_member_alias_recv_rejects_wrong_pid_and_extra_fds_without_leaks(self):
        read_fd, write_fd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        extra_read, extra_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        for expected, sent in ((os.getpid() + 1, [write_fd]),
                (os.getpid(), [write_fd, extra_write])):
            path, listener, sender, receiver = self._member_alias_pair()
            try:
                self._send_member_alias_packet(sender, sent)
                before = self._open_fd_count()
                diagnostic_stream = io.StringIO()
                with mock.patch('sys.stderr', diagnostic_stream):
                    with self.assertRaisesRegex(RuntimeError, 'SCM credentials/FD/flags'):
                        _ALIAS_CAPABILITY.receive_member_alias(receiver, expected, 'reject')
                self.assertIn('MEMBER_ALIAS_DIAGNOSTIC ', diagnostic_stream.getvalue())
                self.assertEqual(self._open_fd_count(), before)
            finally:
                self._close_member_alias_pair(path, listener, sender, receiver)
        os.close(extra_write); os.close(extra_read); os.close(write_fd); os.close(read_fd)

    def test_member_alias_recv_rejects_truncated_ancillary_and_closes_delivered_fds(self):
        source = [os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC) for _ in range(3)]
        read_fds = [pair[0] for pair in source]
        write_fds = [pair[1] for pair in source]
        path, listener, sender, receiver = self._member_alias_pair()
        try:
            self._send_member_alias_packet(sender, write_fds)
            before = self._open_fd_count()
            small_control = socket.CMSG_SPACE(array.array('i').itemsize) + socket.CMSG_SPACE(12)
            diagnostic_stream = io.StringIO()
            with mock.patch('sys.stderr', diagnostic_stream):
                with self.assertRaisesRegex(RuntimeError, 'SCM credentials/FD/flags'):
                    _ALIAS_CAPABILITY.receive_member_alias(receiver, os.getpid(),
                        'truncated', control_size=small_control)
            diagnostic = json.loads(diagnostic_stream.getvalue().split(
                'MEMBER_ALIAS_DIAGNOSTIC ', 1)[1])
            self.assertTrue(diagnostic['flags'] & socket.MSG_CTRUNC)
            self.assertGreaterEqual(len(diagnostic['fds']), 1)
            self.assertEqual(self._open_fd_count(), before)
        finally:
            self._close_member_alias_pair(path, listener, sender, receiver)
            for descriptor in read_fds + write_fds:
                os.close(descriptor)

    def test_alias_env_cli_is_not_accepted_without_source_profile(self):
        argv = ['--control-fd', '3', '--nonce', '01' * 16,
            '--epoch', '1', '--binary', '/unused/nginx',
            '--config', '/unused/nginx.conf', '--prefix', '/unused',
            '--helper-sha256', '02' * 32, '--nginx-env',
            'KER_NGINX_TEST_INITIAL_ALIAS_SOCKET=/unused/initial-alias.sock']
        with mock.patch('sys.stderr'):
            with self.assertRaises(SystemExit) as raised:
                _COMPANION.main(argv)
        self.assertEqual(raised.exception.code, 2)

    def test_unsettled_companion_retains_channel_and_pidfds(self):
        class LiveHelper:
            def poll(self):
                return None

        parent, child = socket.socketpair()
        companion = object.__new__(NginxCompanion)
        companion.helper = LiveHelper()
        companion.channel = parent
        companion.master_pidfd = 101
        companion.supervisor_pidfd = 102
        companion.settled = False
        companion.unresolved = False
        companion.close()
        self.assertTrue(companion.unresolved)
        self.assertGreaterEqual(parent.fileno(), 0)
        self.assertEqual((companion.master_pidfd, companion.supervisor_pidfd),
            (101, 102))
        parent.close()
        child.close()


if __name__ == '__main__':
    import struct
    unittest.main()
