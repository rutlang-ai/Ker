"""F-Stack configuration scenarios through Ker's production loader.

These are parser/lifecycle checks, not NIC or original-kernel traffic evidence.
F-Stack's permissive unknown sections and global struct ABI are not emulated.
"""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[2] / 'tools/ker-run.py'
spec = importlib.util.spec_from_file_location('ker_config_lifecycle', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
BASE = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
MINIMAL = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\neal=--no-huge\nlcore_mask=01\n'


class ConfigLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'ker.ini'

    def parse(self, text, options=()):
        self.path.write_text(text)
        return launcher.parse_arguments(['--config', str(self.path), *options, '--', '/bin/true'])

    def reject_before_setup(self, text, diagnostic):
        self.path.write_text(text)
        result = subprocess.run([sys.executable, str(SOURCE), '--config', str(self.path),
            *BASE, '--library', '/missing-ker-library', '--io-worker', '/missing-worker',
            '--', '/bin/true'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn('missing-ker-library', result.stderr.splitlines()[-1])

    def test_minimal_populates_typed_settings_and_defaults(self):
        args = self.parse(MINIMAL)
        self.assertEqual(str(args.address), '198.18.0.2/24')
        self.assertEqual((args.port, args.lcore_mask), ('net_tap0', '1'))
        self.assertEqual(args.eal_args, ['--no-huge', '-c', '1'])
        self.assertEqual((args.mtu, args.max_mtu, args.mbuf_mode), (1500, 9000, 'large'))
        self.assertFalse(args.all_multicast)
        self.assertEqual(args.command, ['/bin/true'])

    def test_empty_and_no_dpdk_sections_keep_defaults(self):
        for text in ('', '[network]\naddress=198.18.0.2/24\n'):
            with self.subTest(text=text):
                args = self.parse(text, BASE)
                self.assertIsNone(args.lcore_mask)
                self.assertEqual(args.eal_args, ['--no-huge'])
                self.assertEqual(args.port, 'net_tap0')
                self.assertEqual(args.vlans, ())
                self.assertEqual(args.sysctls, {})
                self.assertEqual(args.vip_addresses, [])
                # The loader itself never invents DPDK fields for an empty file.
                self.assertNotIn('port', launcher.load_configuration(self.path))

    def test_cli_overrides_file_and_keeps_quoted_eal_token(self):
        args = self.parse(MINIMAL, ['--address', '198.19.0.2/25', '--port', 'net_tap9',
            '--lcore-mask', '0x2', '--mtu', '2000', '--eal=--no-huge --file-prefix="a b"'])
        self.assertEqual(str(args.address), '198.19.0.2/25')
        self.assertEqual((args.port, args.mtu, args.lcore_mask), ('net_tap9', 2000, '2'))
        self.assertEqual(args.eal_args, ['--no-huge', '--file-prefix=a b', '-c', '2'])

    def test_missing_file_rejected_before_library_resolution(self):
        result = subprocess.run([sys.executable, str(SOURCE), '--config', str(self.path),
            *BASE, '--library', '/missing-ker-library', '--', '/bin/true'],
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(str(self.path), result.stderr.splitlines()[-1])
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn('missing-ker-library', result.stderr.splitlines()[-1])

    def test_unknown_sections_reject_without_partial_result_and_recover(self):
        for text in ('[unknown]\nkey=value\n' + MINIMAL,
                     MINIMAL + '[unknown]\nkey=value\n'):
            with self.subTest(text=text):
                self.reject_before_setup(text, 'unknown section [unknown]')
                self.assertEqual(self.parse(MINIMAL).port, 'net_tap0')

    def test_supported_sections_loaded_together(self):
        args = self.parse(MINIMAL + '''
[logging]
directory=logs
level=6
[capture]
directory=captures
snaplen=2048
max_bytes=8192
nsec=yes
[runtime]
shutdown_timeout_ms=1234
stats=stats.json
[sysctl]
net.ipv4.ip_default_ttl=65
[vlan.100]
addresses=198.19.100.2/24,198.19.100.3/24
''')
        self.assertEqual((args.log_dir, args.pcap_dir, args.stats),
            tuple(Path(self.directory.name) / name for name in ('logs', 'captures', 'stats.json')))
        self.assertEqual((args.log_level, args.pcap_snaplen, args.pcap_max_bytes,
                          args.pcap_nsec, args.shutdown_timeout_ms), (6, 2048, 8192, True, 1234))
        self.assertEqual(args.sysctls, {'net.ipv4.ip_default_ttl': '65'})
        self.assertEqual([(tag, list(map(str, entries))) for tag, entries in args.vlans],
                         [(100, ['198.19.100.2/24', '198.19.100.3/24'])])

    def test_repeated_load_and_failure_do_not_leak_configuration_state(self):
        first = self.parse(MINIMAL + '[sysctl]\nnet.ipv4.ip_default_ttl=66\n'
                           '[vlan.100]\naddresses=198.19.100.2/24\n')
        for _ in range(20):
            self.path.write_text('[dpdk]\ne al=bad\n')
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                launcher.parse_arguments(['--config', str(self.path), *BASE, '--', '/bin/true'])
            self.assertEqual(error.exception.code, 2)
            fresh = self.parse('', BASE)
            self.assertEqual(fresh.sysctls, {})
            self.assertEqual(fresh.vlans, ())
            self.assertIsNone(fresh.lcore_mask)
        first.sysctls['net.ipv4.ip_default_ttl'] = '99'
        self.assertEqual(self.parse(MINIMAL).sysctls, {})
        self.assertEqual(launcher.CONFIG_DEFAULTS['sysctls'], ())
        self.assertEqual(launcher.CONFIG_DEFAULTS['vlans'], ())

    def test_repeated_keys_last_value_wins_without_state_leak(self):
        repeated = ('[network]\naddress=198.18.0.10/24\naddress=198.18.0.30/16\n'
                    'gateway=198.18.0.1\ngateway=198.18.0.254\n'
                    '[dpdk]\nport=net_tap1\nport=net_tap0\neal=--no-huge\n'
                    '[sysctl]\nnet.ipv4.ip_default_ttl=42\nnet.ipv4.ip_default_ttl=65\n'
                    '[vlan.100]\naddresses=198.19.100.2/24\naddresses=198.19.100.3/24\n')
        for _ in range(20):
            args = self.parse(repeated)
            self.assertEqual(str(args.address), '198.18.0.30/16')
            self.assertEqual(str(args.gateway), '198.18.0.254')
            self.assertEqual(args.port, 'net_tap0')
            self.assertEqual(args.sysctls, {'net.ipv4.ip_default_ttl': '65'})
            self.assertEqual(str(args.vlans[0][1][0]), '198.19.100.3/24')
            args.sysctls['net.ipv4.ip_default_ttl'] = '99'
            fresh = self.parse('', BASE)
            self.assertEqual(fresh.sysctls, {})
            self.assertEqual(fresh.vlans, ())
            self.assertIsNone(fresh.gateway)
        args = self.parse(repeated, ['--address', '198.20.0.2/24', '--port', 'net_tap9'])
        self.assertEqual(str(args.address), '198.20.0.2/24')
        self.assertEqual(args.port, 'net_tap9')
        self.assertEqual(launcher.CONFIG_DEFAULTS['sysctls'], ())
        self.assertEqual(launcher.CONFIG_DEFAULTS['vlans'], ())

    def test_repeated_sections_merge_but_invalid_final_values_still_fail(self):
        args = self.parse(MINIMAL + '[network]\nmtu=2000\naddress=198.19.0.2/25\n')
        self.assertEqual((str(args.address), args.mtu), ('198.19.0.2/25', 2000))
        self.assertEqual(args.port, 'net_tap0')
        self.reject_before_setup(MINIMAL + '[network]\naddress=bad-final\n', 'bad-final')
        self.reject_before_setup(MINIMAL + '[dpdk]\nunknown=one\nunknown=two\n', 'unknown option')
        self.reject_before_setup(MINIMAL + '[unknown]\nk=one\n[unknown]\nk=two\n', 'unknown section')
        self.assertEqual(self.parse(MINIMAL).port, 'net_tap0')


if __name__ == '__main__':
    unittest.main()
