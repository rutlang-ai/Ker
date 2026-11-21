import ipaddress
import hashlib
import os
from pathlib import Path
import tempfile
import sys
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest import mock

TOOLS = Path(__file__).resolve().parents[2] / 'tools'
sys.path.insert(0, str(TOOLS))
import source_network_startup as startup


class SourceNetworkExpectedTests(unittest.TestCase):
    def setUp(self):
        self.now = time.monotonic_ns()
        self.deadline = self.now + 30_000_000_000
        self.digest = 'a' * 64
        self.record = (f'v1|{self.digest}|192.168.1.2|255.255.255.0|'
            f'192.168.1.255|192.168.1.1|{self.deadline}')

    def parse(self, record=None, flag='1', deadline=None, address='192.168.1.2/24',
              gateway='192.168.1.1', forbidden=()):
        return startup.prepare_expected(flag, self.record if record is None else record,
            str(self.deadline) if deadline is None else deadline,
            ipaddress.IPv4Interface(address), ipaddress.IPv4Address(gateway),
            forbidden_network_settings=forbidden, now_ns=self.now)

    def test_exact_source_profile_matches_cli_tuple_and_deadline(self):
        expected = self.parse()
        self.assertEqual(expected['record'], self.record)
        self.assertEqual(expected['deadline_ns'], self.deadline)
        self.assertIsNone(startup.prepare_expected(None, None, None,
            ipaddress.IPv4Interface('192.168.1.2/24'), None, now_ns=self.now))

    def test_source_network_configuration_rejects_mismatch_and_extras(self):
        for kwargs in (
            {'flag': '0'}, {'record': ''}, {'deadline': ''},
            {'address': '192.168.1.3/24'}, {'address': '192.168.1.2/25'},
            {'gateway': '192.168.1.254'}, {'forbidden': ('VIP addresses',)},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.parse(**kwargs)
        with self.assertRaises(ValueError):
            startup.prepare_expected(None, self.record, str(self.deadline),
                ipaddress.IPv4Interface('192.168.1.2/24'), ipaddress.IPv4Address('192.168.1.1'),
                now_ns=self.now)

    def test_large_prefix_validation_is_constant_time_and_unicast_bounded(self):
        record = (f'v1|{self.digest}|223.255.255.2|128.0.0.0|'
            f'255.255.255.255|223.255.255.1|{self.deadline}')
        expected = startup.prepare_expected('1', record, str(self.deadline),
            ipaddress.IPv4Interface('223.255.255.2/1'),
            ipaddress.IPv4Address('223.255.255.1'), now_ns=self.now)
        self.assertEqual(expected['address'], '223.255.255.2')

        invalid = (
            ('0.1.0.2/24', '0.1.0.1', '0.1.0.255', '255.255.255.0'),
            ('240.1.0.2/24', '240.1.0.1', '240.1.0.255', '255.255.255.0'),
            ('127.1.0.2/24', '127.1.0.1', '127.1.0.255', '255.255.255.0'),
            ('192.168.1.2/31', '192.168.1.1', '192.168.1.3', '255.255.255.254'),
            ('192.168.1.2/32', '192.168.1.1', '192.168.1.2', '255.255.255.255'),
        )
        for address, gateway, broadcast, mask in invalid:
            ip = address.split('/')[0]
            record = (f'v1|{self.digest}|{ip}|{mask}|{broadcast}|'
                f'{gateway}|{self.deadline}')
            with self.subTest(address=address), self.assertRaises(ValueError):
                startup.prepare_expected('1', record, str(self.deadline),
                    ipaddress.IPv4Interface(address), ipaddress.IPv4Address(gateway),
                    now_ns=self.now)

    def test_network_record_grammar_and_time_are_strict(self):
        bad_records = (
            self.record + '|extra', self.record.replace('v1|', 'v2|'),
            self.record.replace('|192.168.1.2|', '|192.168.001.2|'),
            self.record.replace('|255.255.255.0|', '|255.0.255.0|'),
            self.record.replace('|192.168.1.255|', '|192.168.1.254|'),
            self.record.replace('|192.168.1.1|', '|192.168.2.1|'),
            self.record.replace(self.digest, 'A' * 64),
            self.record.replace(str(self.deadline), '0' + str(self.deadline)),
        )
        for record in bad_records:
            with self.subTest(record=record), self.assertRaises(ValueError):
                self.parse(record=record)
        with self.assertRaises(ValueError):
            self.parse(deadline=str(self.deadline + 1))
        with self.assertRaises(ValueError):
            startup.prepare_expected('1', self.record, str(self.deadline),
                ipaddress.IPv4Interface('192.168.1.2/24'), ipaddress.IPv4Address('192.168.1.1'),
                now_ns=self.deadline)
        too_far = self.now + startup.MAX_DEADLINE_AHEAD_NS + 1
        record = self.record.rsplit('|', 1)[0] + '|' + str(too_far)
        with self.assertRaises(ValueError):
            startup.prepare_expected('1', record, str(too_far),
                ipaddress.IPv4Interface('192.168.1.2/24'), ipaddress.IPv4Address('192.168.1.1'),
                now_ns=self.now)

    def test_ker_run_profile_requires_explicit_source_inputs_and_runtime_identity(self):
        args = SimpleNamespace(address=ipaddress.IPv4Interface('192.168.1.2/24'),
            gateway=ipaddress.IPv4Address('192.168.1.1'), runtime_service=True)
        env = {startup.PROFILE_ENV: '1', startup.READBACK_ENV: self.record,
            startup.BOOTSTRAP_DEADLINE_ENV: str(self.deadline)}
        expected = startup.prepare_from_launch(args, env, now_ns=self.now)
        self.assertEqual(expected['record'], self.record)
        with self.assertRaises(ValueError):
            startup.prepare_from_launch(args, {startup.READBACK_ENV: self.record}, now_ns=self.now)
        args.runtime_service = False
        with self.assertRaises(ValueError):
            startup.prepare_from_launch(args, env, now_ns=self.now)
        args.runtime_service = True
        args.interfaces = ({'name': 'extra'},)
        with self.assertRaises(ValueError):
            startup.prepare_from_launch(args, env, now_ns=self.now)


class SourceNetworkStartupPrefixTests(unittest.TestCase):
    def setUp(self):
        self.now = time.monotonic_ns()
        self.deadline = self.now + 30_000_000_000
        self.digest = 'a' * 64
        self.setting = (f'v1|{self.digest}|192.168.1.2|255.255.255.0|'
            f'192.168.1.255|192.168.1.1|{self.deadline}')
        self.expected = startup.prepare_expected('1', self.setting, str(self.deadline),
            ipaddress.IPv4Interface('192.168.1.2/24'), ipaddress.IPv4Address('192.168.1.1'),
            now_ns=self.now)
        self.proof = (f'KER_SOURCE_NETWORK_READBACK_V1 template_sha256={self.digest} '
            'ifindex=2 address=192.168.1.2 netmask=255.255.255.0 '
            'broadcast=192.168.1.255 gateway=192.168.1.1 route_oif=2 '
            f'route_table=254 deadline_ns={self.deadline}\n').encode()
        self.valid = startup.READY + self.proof

    def test_complete_prefix_and_phase_tail_are_preserved(self):
        tail = b'KER_NATIVE_STOPPING\nKER_NATIVE_STATS {}\nKER_NATIVE_DONE\n'
        result = startup.parse_startup_prefix(self.valid + tail, self.expected, self.now)
        self.assertEqual(result['prefix'], self.valid)
        self.assertEqual(result['tail'], tail)

    def test_rejects_malformed_or_mismatched_proof_fields(self):
        bad = (
            self.proof.replace(b'ifindex=2', b'ifindex=0'),
            self.proof.replace(b'route_oif=2', b'route_oif=3'),
            self.proof.replace(b'route_table=254', b'route_table=255'),
            self.proof.replace(b'template_sha256=' + self.digest.encode(),
                b'template_sha256=' + b'b' * 64),
            self.proof.replace(b'gateway=192.168.1.1', b'gateway=192.168.1.254'),
            self.proof.replace(b' deadline_ns=', b' unknown=x deadline_ns='),
            self.proof.replace(b' route_oif=2 ', b' route_oif=2 route_oif=2 '),
            self.proof.replace(b'deadline_ns=', b'deadline_ns=0'),
            self.proof[:-1],
        )
        for proof in bad:
            with self.subTest(proof=proof), self.assertRaises(ValueError):
                startup.parse_startup_prefix(startup.READY + proof, self.expected, self.now)
        with self.assertRaises(ValueError):
            startup.parse_startup_prefix(self.valid.replace(startup.READY,
                b'KER_NATIVE_STARTED\n', 1), self.expected, self.now)
        with self.assertRaises(ValueError):
            startup.parse_startup_prefix(self.valid + self.proof, self.expected, self.now)
        with self.assertRaises(ValueError):
            startup.parse_startup_prefix(self.valid + b'KER_NATIVE_SURPRISE\n', self.expected, self.now)

    def test_deadline_is_checked_at_read_and_parse(self):
        with self.assertRaises(ValueError):
            startup.parse_startup_prefix(self.valid, self.expected, self.deadline)
        with self.assertRaises(ValueError):
            startup.parse_startup_prefix(self.valid, self.expected,
                self.deadline - startup.MAX_DEADLINE_AHEAD_NS - 1)

    def test_reads_whole_proof_and_retains_tail_from_nonblocking_pipe(self):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            identity = startup.pipe_identity(read_fd, write_fd)
            payload = self.valid + b'KER_NATIVE_STOPPING\n'
            self.assertEqual(os.write(write_fd, payload), len(payload))
            captured = startup.read_startup_prefix(read_fd, identity, self.deadline)
            parsed = startup.parse_startup_prefix(captured, self.expected, self.now)
            self.assertGreater(len(parsed['prefix']), 128)
            self.assertEqual(parsed['prefix'], self.valid)
            self.assertEqual(parsed['tail'], b'KER_NATIVE_STOPPING\n')
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_rejects_nonpipe_or_wrong_pipe_pair(self):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        other_read, other_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            with self.assertRaises(ValueError):
                startup.pipe_identity(read_fd, other_write)
            identity = startup.pipe_identity(read_fd, write_fd)
            with self.assertRaises(ValueError):
                startup.read_startup_prefix(other_read, identity, self.deadline)
        finally:
            for fd in (read_fd, write_fd, other_read, other_write):
                os.close(fd)

    def test_prelaunch_executable_metadata_hash_and_actor_are_pinned(self):
        deadline = time.monotonic_ns() + 5_000_000_000
        pin = startup.PinnedExecutable('/proc/self/exe', deadline)
        try:
            self.assertTrue(startup.process_executable_matches(os.getpid(), pin, deadline))
            self.assertEqual(len(pin.sha256), hashlib.sha256().digest_size)
            self.assertEqual(len(pin.metadata), 6)
            with self.assertRaises(TimeoutError):
                startup.process_executable_matches(os.getpid(), pin,
                    time.monotonic_ns() - 1)
        finally:
            pin.close()


    def test_held_executable_detects_same_inode_metadata_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app'
            path.write_bytes(b'#!/bin/sh\nexit 0\n')
            path.chmod(0o700)
            pin = startup.PinnedExecutable(path, time.monotonic_ns() + 5_000_000_000)
            try:
                path.write_bytes(b'#!/bin/sh\nexit 1\n')
                with self.assertRaises(RuntimeError):
                    pin.verify(time.monotonic_ns() + 5_000_000_000)
            finally:
                pin.close()

    def test_executable_hash_deadline_and_descriptor_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app'
            path.write_bytes(b'#!/bin/sh\n' + b'x' * (1024 * 1024))
            path.chmod(0o700)
            clock = [100]
            opened = []
            original_open = os.open
            original_close = os.close
            original_pread = os.pread
            def tracked_open(*args, **kwargs):
                fd = original_open(*args, **kwargs)
                opened.append(fd)
                return fd
            def delayed_pread(fd, size, offset):
                result = original_pread(fd, size, offset)
                clock[0] = 200
                return result
            with mock.patch.object(startup.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
                    mock.patch.object(startup.os, 'open', side_effect=tracked_open), \
                    mock.patch.object(startup.os, 'pread', side_effect=delayed_pread):
                with self.assertRaises(TimeoutError):
                    startup.PinnedExecutable(path, 200)
            self.assertEqual(len(opened), 1)
            with self.assertRaises(OSError):
                original_close(opened[0])

    def test_executable_metadata_and_hash_are_checked_under_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app'
            path.write_bytes(b'#!/bin/sh\nexit 0\n')
            path.chmod(0o700)
            pin = startup.PinnedExecutable(path, time.monotonic_ns() + 5_000_000_000)
            try:
                clock = [100]
                original_pread = os.pread
                def delayed_pread(fd, size, offset):
                    result = original_pread(fd, size, offset)
                    clock[0] = 200
                    return result
                with mock.patch.object(startup.time, 'monotonic_ns', side_effect=lambda: clock[0]), \
                        mock.patch.object(startup.os, 'pread', side_effect=delayed_pread):
                    with self.assertRaises(TimeoutError):
                        pin.verify(200)
            finally:
                pin.close()

    def test_source_startup_audit_contains_only_validated_proof_and_actor_identity(self):
        deadline = time.monotonic_ns() + 5_000_000_000
        pin = startup.PinnedExecutable('/proc/self/exe', deadline)
        try:
            parsed = startup.parse_startup_prefix(self.valid, self.expected)
            validated = time.monotonic_ns()
            audit = startup.startup_audit_record(parsed, (7, 11, 0o010000),
                os.getpid(), 19, pin, validated, deadline)
            self.assertEqual(bytes.fromhex(audit['startup_prefix_hex']), self.valid)
            self.assertEqual(audit['observed'], parsed['proof'])
            self.assertEqual(audit['startup_pipe'],
                {'device': 7, 'inode': 11, 'type': 0o010000})
            self.assertEqual(audit['application']['pid'], os.getpid())
            self.assertEqual(audit['application']['start_ticks'], 19)
            self.assertEqual(audit['application']['executable']['sha256'], pin.sha256.hex())
            self.assertEqual(audit['validated_monotonic_ns'], validated)
        finally:
            pin.close()

    def test_source_startup_audit_is_not_emitted_for_invalid_or_expired_state(self):
        deadline = time.monotonic_ns() + 5_000_000_000
        pin = startup.PinnedExecutable('/proc/self/exe', deadline)
        try:
            parsed = startup.parse_startup_prefix(self.valid, self.expected)
            with self.assertRaises(ValueError):
                startup.startup_audit_record(parsed, (7, 11, 0o010000),
                    os.getpid(), 19, pin, deadline, deadline)
            with self.assertRaises(ValueError):
                startup.startup_audit_record(None, (7, 11, 0o010000),
                    os.getpid(), 19, pin, time.monotonic_ns(), deadline)
            pin.close()
            with self.assertRaises(ValueError):
                startup.startup_audit_record(parsed, (7, 11, 0o010000),
                    os.getpid(), 19, pin, time.monotonic_ns(), deadline)
        finally:
            pin.close()


class RetainedBackendReceiptTests(unittest.TestCase):
    def setUp(self):
        self.now = time.monotonic_ns()
        self.deadline = self.now + 5_000_000_000
        digest = 'ab' * 32
        record = (f'v1|{digest}|192.168.1.2|255.255.255.0|'
            f'192.168.1.255|192.168.1.1|{self.deadline}')
        self.expected = startup.prepare_expected('1', record, str(self.deadline),
            ipaddress.IPv4Interface('192.168.1.2/24'),
            ipaddress.IPv4Address('192.168.1.1'), now_ns=self.now)
        self.network_expectation = startup.SourceNetworkExpectation('/captured/template',
            self.expected['template_sha256'], self.expected['address'],
            self.expected['netmask'], self.expected['broadcast'],
            self.expected['gateway'], self.expected['deadline_ns'], None)
        self.proof = (f'KER_SOURCE_NETWORK_READBACK_V1 template_sha256={digest} '
            'ifindex=2 address=192.168.1.2 netmask=255.255.255.0 '
            'broadcast=192.168.1.255 gateway=192.168.1.1 route_oif=2 '
            f'route_table=254 deadline_ns={self.deadline}\n').encode()
        self.prefix = startup.READY + self.proof
        self.read_fd, self.write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        self.pipe_identity = startup.pipe_identity(self.read_fd, self.write_fd)
        os.write(self.write_fd, self.prefix)
        self.parsed = startup.parse_startup_prefix(self.prefix, self.expected, self.now)
        self.pin = startup.PinnedExecutable(sys.executable, self.deadline)
        self.process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
            close_fds=True)
        self.pidfd = os.pidfd_open(self.process.pid, 0)
        self.runtime = SimpleNamespace(pid=self.process.pid, pidfd=self.pidfd,
            start_ticks=startup._proc_start_ticks(self.process.pid),
            executable_hash=self.pin.sha256)
        self.fd_count_before_receipt = len(os.listdir('/proc/self/fd'))
        self.receipt = startup._capture_retained_backend_receipt(self.process, self.pidfd,
            startup._proc_start_ticks(self.process.pid), self.pin, self.read_fd,
            self.pipe_identity, self.expected, self.parsed, time.monotonic_ns(),
            self.runtime)
        self.assertEqual(len(os.listdir('/proc/self/fd')),
            self.fd_count_before_receipt + 3)
        self.handoff = startup.RetainedBackendHandoff.for_network_expectation(
            self.network_expectation)

    def tearDown(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait()
        for value in (self.receipt,):
            if not value.closed:
                value.close()
        for fd in (self.pidfd, self.read_fd, self.write_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        self.pin.close()

    def test_explicit_handoff_retains_same_live_actor_and_one_shot_receipt(self):
        self.handoff.publish(self.receipt)
        taken = self.handoff.take(self.deadline)
        self.assertIs(taken, self.receipt)
        self.assertTrue(taken.validate_live(self.expected, self.runtime, self.deadline))
        with self.assertRaises(RuntimeError):
            self.handoff.take(self.deadline)
        with self.assertRaises(RuntimeError):
            taken.close()
        self.process.terminate()
        self.process.wait(timeout=3)
        with self.assertRaises(RuntimeError):
            taken.validate_live(self.expected, self.runtime, self.deadline)
        taken.close()
        self.assertTrue(taken.closed)
        self.assertEqual(len(os.listdir('/proc/self/fd')),
            self.fd_count_before_receipt)

    def test_unsettled_handoff_close_keeps_receipt_and_descriptors(self):
        self.handoff.publish(self.receipt)
        with self.assertRaises(RuntimeError):
            self.handoff.close()
        self.assertFalse(self.handoff._closed)
        self.assertIs(self.handoff._receipt, self.receipt)
        self.process.terminate()
        self.process.wait(timeout=3)
        self.handoff.close()
        self.assertTrue(self.receipt.closed)

    def test_receipt_constructor_rejects_unvalidated_generic_payload(self):
        with self.assertRaises(TypeError):
            startup.RetainedBackendReceipt({}, self.process, self.pidfd,
                startup._proc_start_ticks(self.process.pid), self.pin, self.read_fd,
                self.pipe_identity, self.expected, {}, time.monotonic_ns(), self.runtime)

    def test_handoff_rejects_foreign_expectation_and_runtime(self):
        wrong = dict(self.expected)
        wrong['address'] = '192.168.1.9'
        with self.assertRaises(RuntimeError):
            self.receipt.validate_live(wrong, self.runtime, self.deadline)
        with self.assertRaises(RuntimeError):
            self.receipt.validate_live(self.expected, object(), self.deadline)
        other_expectation = self.network_expectation._replace(gateway='192.168.1.3')
        other_handoff = startup.RetainedBackendHandoff.for_network_expectation(
            other_expectation)
        with self.assertRaises(RuntimeError):
            other_handoff.publish(self.receipt)
        other_handoff.close()

    def test_retained_pipe_replacement_and_expired_deadline_fail_closed(self):
        other_read, other_write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            os.dup2(other_read, self.receipt.startup_fd, inheritable=False)
            with self.assertRaises(RuntimeError):
                self.receipt.validate_live(self.expected, self.runtime, self.deadline)
        finally:
            os.close(other_read)
            os.close(other_write)
        with self.assertRaises(TimeoutError):
            self.receipt.validate_live(self.expected, self.runtime,
                time.monotonic_ns() - 1)

    def test_failed_backend_startup_wakes_handoff_without_receipt(self):
        handoff = startup.RetainedBackendHandoff.for_network_expectation(
            self.network_expectation)
        handoff.fail(RuntimeError('controlled startup failure'))
        with self.assertRaises(OSError) as caught:
            handoff.take(self.deadline)
        self.assertEqual(caught.exception.errno, startup.errno.ENOTSUP)
        handoff.close()


if __name__ == '__main__':
    unittest.main()
