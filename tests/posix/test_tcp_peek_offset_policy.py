"""Capability-policy checks for the native TCP SO_PEEK_OFF integration."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name('tcp-interop.py')
spec = importlib.util.spec_from_file_location('ker_tcp_interop', SOURCE)
interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interop)


class PeekOffsetPolicyTests(unittest.TestCase):
    def test_unsupported_host_skips_only_reference_and_keeps_native_modes(self):
        self.assertEqual(interop.tcp_peek_offset_plan(77), [
            ('client', False, True),
            ('server', True, False),
        ])

    def test_supported_host_keeps_reference_and_native_modes(self):
        self.assertEqual(interop.tcp_peek_offset_plan(0), [
            ('host-reference', True, True),
            ('client', False, True),
            ('server', True, False),
        ])

    def test_unexpected_probe_failure_is_not_skipped(self):
        for status in (1, 2, 255):
            with self.subTest(status=status), self.assertRaisesRegex(RuntimeError,
                    'failed unexpectedly'):
                interop.tcp_peek_offset_plan(status)


if __name__ == '__main__':
    unittest.main()
