#!/usr/bin/env python3
"""Check that raw packet capture setup verifies the requested receive capacity."""
import importlib.util
from pathlib import Path
import socket
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / 'posix' / 'tx-offloads.py'
SPEC = importlib.util.spec_from_file_location('tx_offloads_capture_test', FIXTURE)
OFFLOADS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OFFLOADS)


class FakeSocket:
    def __init__(self, actual):
        self.actual = actual
        self.options = []

    def setsockopt(self, level, option, value):
        self.options.append((level, option, value))

    def getsockopt(self, level, option):
        if (level, option) != (socket.SOL_SOCKET, socket.SO_RCVBUF):
            raise AssertionError('unexpected socket option read')
        return self.actual


class WireCaptureBufferTests(unittest.TestCase):
    def test_requests_and_verifies_doubled_linux_receive_buffer(self):
        wire = FakeSocket(2 * OFFLOADS.CAPTURE_RCVBUF_BYTES)
        self.assertEqual(OFFLOADS.configure_capture_socket(wire), wire.actual)
        self.assertEqual(wire.options, [(socket.SOL_SOCKET, socket.SO_RCVBUF,
            OFFLOADS.CAPTURE_RCVBUF_BYTES)])

    def test_rejects_receive_buffer_capped_below_request(self):
        wire = FakeSocket(2 * OFFLOADS.CAPTURE_RCVBUF_BYTES - 1)
        with self.assertRaisesRegex(RuntimeError, 'wire capture receive buffer is capped'):
            OFFLOADS.configure_capture_socket(wire)


if __name__ == '__main__':
    unittest.main()
