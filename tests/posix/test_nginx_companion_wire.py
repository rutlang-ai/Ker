"""Validation for the private ker-run companion helper wire codec."""
import unittest
import importlib.util
import os
from pathlib import Path
import select
import signal
import socket
import struct
import tempfile

from nginx_companion_wire import *
from nginx_companion_supervisor import NginxCompanion

_COMPANION_SPEC = importlib.util.spec_from_file_location(
    '_test_ker_nginx_companion', Path(__file__).parents[2] / 'tools' /
    'ker-nginx-companion.py')
_COMPANION = importlib.util.module_from_spec(_COMPANION_SPEC)
_COMPANION_SPEC.loader.exec_module(_COMPANION)
broker_ini_matches = _COMPANION.broker_ini_matches


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

    def _helper_owner_ready_rejects(self, *, change=None, with_rights=False,
                                    truncate=False, exit_before_receive=False):
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
