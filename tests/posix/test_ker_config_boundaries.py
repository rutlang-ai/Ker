"""Pinned F-Stack malformed-section and disabled-jumbo scenarios.

Exercise Ker's production loader with its native schema. These checks do not
claim NIC traffic or implementation equivalence with the F-Stack loader.
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
spec = importlib.util.spec_from_file_location('ker_config_boundaries', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
MINIMAL = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\neal=--no-huge\n'


class BoundaryCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='ker-config-boundary-')
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / 'ker.ini'

    def parse(self, text=MINIMAL, options=()):
        self.path.write_text(text)
        return launcher.parse_arguments(['--config', str(self.path), *options, '--', '/bin/true'])

    def reject(self, text, diagnostic, options=()):
        self.path.write_text(text)
        missing_library = self.directory / 'missing-library.so'
        missing_worker = self.directory / 'missing-worker'
        result = subprocess.run([sys.executable, str(SOURCE), '--config', str(self.path),
            '--library', str(missing_library), '--io-worker', str(missing_worker),
            *options, '--', '/bin/true'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(diagnostic, result.stderr.splitlines()[-1])
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn(str(missing_library), result.stderr)
        self.assertNotIn(str(missing_worker), result.stderr)
        self.assertEqual(result.stdout, '')
        # Exercise the failure in this interpreter too: a later parse must not
        # inherit partial settings left by an earlier configuration failure.
        diagnostics = io.StringIO()
        with contextlib.redirect_stderr(diagnostics), self.assertRaises(SystemExit) as error:
            launcher.parse_arguments(['--config', str(self.path), *options, '--', '/bin/true'])
        self.assertEqual(error.exception.code, 2)
        self.assertIn(diagnostic, diagnostics.getvalue().splitlines()[-1])


class PortSectionTests(BoundaryCase):
    def test_malformed_port_section_rejects_before_setup_in_either_order(self):
        # F-Stack's source fixture names [portXX]. Ker's supported port selector
        # lives in [dpdk]; neither the source spelling nor a dotted variant is
        # silently accepted as a new interface.
        for section in ('portXX', 'port.XX', 'dpdk.XX'):
            bad = f'[{section}]\nport=net_tap9\n'
            for text in (bad + MINIMAL, MINIMAL + bad):
                with self.subTest(section=section, bad_first=text.startswith(bad)):
                    self.reject(text, f'unknown section [{section}]')
                    args = self.parse()
                    self.assertEqual(args.port, 'net_tap0')
                    self.assertEqual(str(args.address), '198.18.0.2/24')

    def test_cli_port_override_does_not_hide_bad_file_section(self):
        self.reject(MINIMAL + '[portXX]\nport=net_tap9\n',
                    'unknown section [portXX]', ['--port', 'net_tap1'])
        self.assertEqual(self.parse(options=['--port', 'net_tap1']).port, 'net_tap1')


class VLANSectionTests(BoundaryCase):
    def test_malformed_vlan_id_rejects_without_discarding_diagnostic(self):
        valid = '[vlan.100]\naddresses=198.19.100.2/24\n'
        for tag in ('XX', '', '-1', '0', '4095'):
            bad = f'[vlan.{tag}]\naddresses=198.19.200.2/24\n'
            for suffix in (bad + valid, valid + bad):
                with self.subTest(tag=tag, bad_first=suffix.startswith(bad)):
                    self.reject(MINIMAL + suffix, 'VLAN requires ID=IPv4/PREFIX')
                    args = self.parse(MINIMAL + valid)
                    self.assertEqual([(tag, list(map(str, entries))) for tag, entries in args.vlans],
                                     [(100, ['198.19.100.2/24'])])

    def test_source_style_malformed_section_is_not_ignored_by_cli_override(self):
        self.reject(MINIMAL + '[vlanXX]\naddresses=198.19.200.2/24\n',
                    'unknown section [vlanXX]', ['--vlan', '200=198.19.200.2/24'])
        self.assertEqual([tag for tag, _ in self.parse(options=['--vlan', '200=198.19.200.2/24']).vlans], [200])


class MTUGateTests(BoundaryCase):
    @staticmethod
    def configuration(mtu, mode='large', ceiling=1500):
        return (f'[network]\naddress=198.18.0.2/24\nmtu={mtu}\nmax_mtu={ceiling}\n'
                f'[dpdk]\nport=net_tap0\neal=--no-huge\nmbuf_mode={mode}\n')

    def test_disabled_jumbo_ceiling_rejects_first_excess_and_jumbo(self):
        # Ker's deployment ceiling is the native counterpart of disallowing
        # jumbo MTUs; this does not add or pretend to parse mtu_enable.
        for mode in ('large', 'scatter'):
            for mtu in (1501, 9000):
                with self.subTest(mode=mode, mtu=mtu):
                    self.reject(self.configuration(mtu, mode), '--mtu must not exceed --max-mtu')
                    self.reject(self.configuration(1500, mode), '--mtu must not exceed --max-mtu',
                                ['--mtu', str(mtu)])

    def test_exact_ceiling_and_explicit_jumbo_enable_parse_in_both_modes(self):
        for mode in ('large', 'scatter'):
            with self.subTest(mode=mode):
                args = self.parse(self.configuration(1500, mode))
                self.assertEqual((args.mtu, args.max_mtu, args.mbuf_mode), (1500, 1500, mode))
                args = self.parse(self.configuration(9000, mode), ['--max-mtu', '9000'])
                self.assertEqual((args.mtu, args.max_mtu, args.mbuf_mode), (9000, 9000, mode))
                args = self.parse(self.configuration(9000, mode), ['--mtu', '1500'])
                self.assertEqual((args.mtu, args.max_mtu), (1500, 1500))

    def test_cli_disable_wins_and_failure_does_not_relax_future_ceiling(self):
        for mode in ('large', 'scatter'):
            with self.subTest(mode=mode):
                self.reject(self.configuration(9000, mode, ceiling=9000),
                            '--mtu must not exceed --max-mtu', ['--max-mtu', '1500'])
                args = self.parse(self.configuration(1500, mode))
                self.assertEqual((args.mtu, args.max_mtu), (1500, 1500))
                self.assertEqual(launcher.CONFIG_DEFAULTS['max_mtu'], 9000)


if __name__ == '__main__':
    unittest.main()
