"""Regression coverage for captured IPv4 ICMP fragmentation flags."""
import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name('icmp-mtu.py')
spec = importlib.util.spec_from_file_location('ker_icmp_mtu', SOURCE)
icmp_mtu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(icmp_mtu)


class IcmpMtuFlagsTests(unittest.TestCase):
    def test_ipv4_echo_request_requires_df(self):
        with self.assertRaisesRegex(RuntimeError, 'missing DF'):
            icmp_mtu.validate_ipv4_flags(0, echo_request=True)

    def test_ipv4_echo_request_with_df_is_accepted(self):
        icmp_mtu.validate_ipv4_flags(0x4000, echo_request=True)

    def test_df_does_not_allow_more_fragments_or_an_offset(self):
        for flags in (0x4000 | 0x2000, 0x4001):
            with self.subTest(flags=hex(flags)), self.assertRaisesRegex(
                    RuntimeError, 'fragmented IPv4 echo'):
                icmp_mtu.validate_ipv4_flags(flags, echo_request=True)


if __name__ == '__main__':
    unittest.main()
