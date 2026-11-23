import importlib.util
from pathlib import Path
import os
import socket
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'broker_readiness_supervisor_test',
    ROOT / 'tools' / 'broker_readiness_supervisor.py')
supervisor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supervisor)


class BrokerReadinessVerifyDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.manager = supervisor.BrokerReadiness.__new__(
            supervisor.BrokerReadiness)
        self.sender, self.manager.parent = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.manager.parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.manager.parent.setblocking(False)
        self.manager.app = supervisor._identity(os.getpid())
        self.manager.app_pidfd = os.pidfd_open(os.getpid(), 0)
        self.manager.expected_executable_hash = b'e' * 32
        self.manager.nonce = b'n' * 16
        self.manager.epoch = 7
        self.manager.profile = b'p' * 32
        self.manager._verify_sequence = 1
        packet = supervisor.wire.pack_verify_result(self.manager.nonce,
            self.manager.epoch, 1, 0, 81, 99, 101, 103, 105, 107,
            self.manager.profile, 1)
        self.sender.send(packet)
        self.manager._verify = {'fd': -1, 'sequence': 1,
            'deadline': time.monotonic() + 2.0, 'sent': True}

    def tearDown(self):
        if self.manager.app_pidfd >= 0:
            os.close(self.manager.app_pidfd)
        self.manager.parent.close()
        self.sender.close()

    def test_slow_identity_hash_within_absolute_deadline_keeps_queued_reply(self):
        expected = self.manager.expected_executable_hash

        def slow_hash(_path):
            time.sleep(0.03)
            return expected

        with mock.patch.object(supervisor, '_sha256', side_effect=slow_hash):
            result = self.manager.poll_verify()
        self.assertIsNotNone(result)
        self.assertIsNone(self.manager._verify)

    def test_absolute_deadline_expiry_is_still_terminal(self):
        self.manager._verify['deadline'] = time.monotonic() - 0.001
        with self.assertRaises(TimeoutError):
            self.manager.poll_verify()
        self.assertTrue(self.manager._verify['unresolved'])

    def test_hash_finishing_after_absolute_deadline_is_terminal(self):
        self.manager._verify['deadline'] = time.monotonic() + 0.1

        def late_hash(_path):
            time.sleep(0.15)
            return self.manager.expected_executable_hash

        with mock.patch.object(supervisor, '_sha256', side_effect=late_hash):
            with self.assertRaises(TimeoutError):
                self.manager.poll_verify()
        self.assertTrue(self.manager._verify['unresolved'])

    def test_invalid_verify_record_is_retained_before_strict_decode(self):
        # The readiness session must reject a response from an unrelated RX
        # decision session while preserving the exact bounded record.
        self.manager.parent.recv(256)
        raw = supervisor.wire.pack_verify_result(b'r' * 16, 19, 1, 16,
            0, 0, 0, 0, 0, 0, self.manager.profile, 0)
        self.sender.send(raw)
        with mock.patch.object(supervisor, '_sha256',
                return_value=self.manager.expected_executable_hash):
            with self.assertRaisesRegex(ValueError, 'invalid VERIFY result fields'):
                self.manager.poll_verify()
        self.assertEqual(self.manager.last_verify_packet, raw)
        self.assertLessEqual(len(self.manager.last_verify_packet),
            supervisor.wire.VERIFY_RESULT.size)
        self.assertTrue(self.manager._verify['unresolved'])

    def test_ready_identity_hash_uses_absolute_not_poll_slice_deadline(self):
        self.manager.parent.recv(256)
        self.manager.ready = False
        self.manager.nonce = b'r' * 16
        self.manager.epoch = 8
        self.manager.profile = b'q' * 32
        self.manager.ready_deadline = time.monotonic() + 2.0
        packet = supervisor.wire.pack_ready(self.manager.nonce,
            self.manager.epoch, self.manager.profile, self.manager.app[3])
        self.sender.send(packet)

        def slow_hash(_path):
            time.sleep(0.12)
            return self.manager.expected_executable_hash

        with mock.patch.object(supervisor, '_sha256', side_effect=slow_hash):
            self.assertTrue(self.manager.poll_ready())
        self.assertTrue(self.manager.ready)


if __name__ == '__main__':
    unittest.main()
