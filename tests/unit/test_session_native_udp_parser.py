#!/usr/bin/env python3
"""Unit checks for the exact native handoff UDP frame filter."""
import importlib.util
from pathlib import Path
import struct
import sys
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


if __name__ == '__main__':
    unittest.main()
