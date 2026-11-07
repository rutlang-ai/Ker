import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'posix/linux-network-selftest.py'
spec = importlib.util.spec_from_file_location('network_selftest', path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class OriginalNetworkCompletionTests(unittest.TestCase):
    def test_netlink_dump_success_cannot_hide_ignored_mq_notify_failure(self):
        complete = dict(generic_netlinks=3, mq_opens=1, mq_notifications=1, mq_closes=1,
                        notified_netlink_closes=1, writes=3, sent=84, reads=2)
        runner.validate_netlink_dumps(complete)
        for key in complete:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_netlink_dumps(dict(complete, **{key: 0}))

    def test_macvtap_requires_both_real_writes_and_the_real_invalid_packet_error(self):
        complete = dict(macvtap_opens=3, tun_if_sets=3, macvtap_writes=2, macvtap_bytes=2149,
                        macvtap_write_einval=1, netlinks=12)
        for key, value in (('macvtap_opens', 0), ('tun_if_sets', 2), ('macvtap_writes', 1),
                           ('macvtap_bytes', 2148), ('macvtap_write_einval', 0), ('netlinks', 8)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_macvtap(dict(complete, **{key: value}))

    def test_socket_shell_pass_marker_cannot_hide_missing_native_protocols(self):
        with self.assertRaises(RuntimeError):
            runner.validate_missing_backend('run_netsocktests', dict(returncode=0, stdout='', stderr=''))
        with self.assertRaises(RuntimeError):
            runner.validate_original('run_netsocktests', dict(stdout='[PASS]\n', stderr=''))
        complete = dict(creation_attempts=5, creation_eafnosupport=1, creation_eprotonosupport=2,
                        creation_tcp=1, creation_udp=1)
        for key, value in (('creation_attempts', 4), ('creation_eafnosupport', 3),
                           ('creation_eprotonosupport', 0), ('creation_tcp', 0), ('creation_udp', 0)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.validate_socket_creation(dict(complete, **{key: value}))

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
