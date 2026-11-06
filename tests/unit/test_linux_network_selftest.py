import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'posix/linux-network-selftest.py'
spec = importlib.util.spec_from_file_location('network_selftest', path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class OriginalNetworkCompletionTests(unittest.TestCase):
    def test_peek_offset_exit_zero_cannot_hide_missing_families_or_protocols(self):
        lines = ['TCP/IPv4 with MSG_PEEK_OFF works correctly',
                 'TCP/IPv6 with MSG_PEEK_OFF works correctly',
                 'UDP/IPv4 with MSG_PEEK_OFF works correctly',
                 'UDP/IPv6 with MSG_PEEK_OFF works correctly']
        for output in ('', '\n'.join(lines[:2]), '\n'.join(lines[:-1]),
                       '\n'.join([*lines[:3], lines[2]]),
                       '\n'.join([*lines, 'UDP/IPv6 does not support SO_PEEK_OFF'])):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                runner.validate_original('sk_so_peek_off', dict(stdout=output, stderr=''))

    def test_reuseport_success_marker_cannot_replace_the_original_groups(self):
        with self.assertRaises(RuntimeError):
            runner.validate_original('reuseport_dualstack', dict(stdout='', stderr='SUCCESS\n'))

    def test_address_preference_rejects_skipped_dccp_and_missing_families(self):
        groups = [f'{protocol} {family} ... pass' for protocol in ('UDP', 'TCP', 'DCCP')
                  for family in ('IPv4', 'IPv6', 'IPv4 mapped to IPv6')]
        for lines in (['SUCCESS'], [*groups[:6], 'DCCP ... SKIP', 'SUCCESS'],
                      [*groups[:-1], 'SUCCESS'], [*groups, groups[-1], 'SUCCESS']):
            with self.subTest(lines=lines), self.assertRaises(RuntimeError):
                runner.validate_original('reuseport_addr_any.sh', dict(stdout='', stderr='\n'.join(lines)))


if __name__ == '__main__':
    unittest.main()
