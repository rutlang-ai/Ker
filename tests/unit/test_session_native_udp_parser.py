#!/usr/bin/env python3
"""Unit checks for the exact native handoff UDP frame filter."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests' / 'posix'))
SOURCE = ROOT / 'tests' / 'posix' / 'session-native-packets.py'
SPEC = importlib.util.spec_from_file_location('session_native_packets_parser', SOURCE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class NativeHandoffUdpParserTests(unittest.TestCase):
    def test_exact_valid_frame_is_accepted(self):
        payload = b'KER-A09-HANDOFF-UDP seq=1\n'
        frame = FIXTURE.handoff_udp_test_frame(payload)
        self.assertEqual(len(frame), 14 + 20 + 8 + len(payload))
        self.assertEqual(FIXTURE.handoff_udp_payload(frame), payload)

    def test_truncated_frame_is_rejected(self):
        frame = FIXTURE.handoff_udp_test_frame()
        self.assertIsNone(FIXTURE.handoff_udp_payload(frame[:-1]))

    def test_trailing_ethernet_bytes_are_rejected(self):
        frame = FIXTURE.handoff_udp_test_frame()
        self.assertIsNone(FIXTURE.handoff_udp_payload(frame + b'\0'))

    def test_ipv4_fragment_is_rejected(self):
        frame = bytearray(FIXTURE.handoff_udp_test_frame())
        frame[14 + 6:14 + 8] = struct.pack('!H', 0x2000)
        self.assertIsNone(FIXTURE.handoff_udp_payload(bytes(frame)))

    def test_wrong_udp_ports_are_rejected(self):
        frame = bytearray(FIXTURE.handoff_udp_test_frame())
        frame[14 + 20:14 + 24] = struct.pack('!HH', 45000, 45002)
        self.assertIsNone(FIXTURE.handoff_udp_payload(bytes(frame)))

    def test_wire_wait_timeout_uses_fixture_capture_and_child_diagnostics(self):
        class Runner:
            pid = 4321
            returncode = None

            @staticmethod
            def poll():
                return None

        with tempfile.TemporaryDirectory() as directory:
            stats = Path(directory) / 'stats.json'
            stats.write_text('{"stage":"application-started"}')
            stderr = Path(directory) / 'runner.stderr'
            stderr.write_text('runner diagnostic')
            with self.assertRaisesRegex(RuntimeError, 'captured_frame_count') as error:
                FIXTURE.wait_for_handoff_wire_payload(2, [], [], threading.Lock(),
                    Runner(), stats, stderr, timeout=0)
        self.assertIn('runner_pid', str(error.exception))
        self.assertIn('application-started', str(error.exception))
        self.assertIn('runner diagnostic', str(error.exception))

    def test_wire_wait_returns_exact_captured_udp_frame(self):
        frame = FIXTURE.handoff_udp_test_frame(b'KER-A09-HANDOFF-UDP seq=2\n')
        observed = FIXTURE.wait_for_handoff_wire_payload(2, [frame], [], threading.Lock(),
            None, Path('/missing/stats.json'), Path('/missing/stderr'), timeout=0.01)
        self.assertEqual(observed, frame)


if __name__ == '__main__':
    unittest.main()
