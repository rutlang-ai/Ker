"""Real launcher INI parsing and pre-launch rejection; no worker mocks."""
import configparser
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[2] / 'tools/ker-run.py'
spec = importlib.util.spec_from_file_location('ker_run_config', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class ConfigTests(unittest.TestCase):
    def read(self, text):
        return launcher.read_configuration(io.StringIO(text), Path('/configuration'), 'fixture.ini')

    def test_lcore_mask_syntax_precedence_and_actual_eal_tokens(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).lcore_mask)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cores.ini'
            for value, expected in [('0X5', '5'), ('  0x5  ', '5'), ('A0', 'a0'), ('0001', '1')]:
                path.write_text('[dpdk]\nlcore_mask=' + value + '\n')
                args = launcher.parse_arguments(base + ['--config', str(path), '--', '/bin/true'])
                self.assertEqual(args.lcore_mask, expected)
                self.assertEqual(args.eal_args, ['--no-huge', '-c', expected])
                self.assertEqual(int(args.lcore_mask, 16).bit_count(), int(value, 16).bit_count())
                self.assertEqual(str(args.address), '192.0.2.2/24')
                self.assertEqual(args.port, 'net_tap0')
                override = launcher.parse_arguments(base + ['--config', str(path), '--lcore-mask', '2', '--', '/bin/true'])
                self.assertEqual(override.eal_args, ['--no-huge', '-c', '2'])
            for value in ('ZZZ_NOT_HEX', '0x1Z', '', '   ', '0', '0x0000', '-1', '+1', '1 2', '0x'):
                path.write_text('[dpdk]\nlcore_mask=' + value + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(path),
                    '--library', str(Path(directory) / 'missing'), '--io-worker', str(Path(directory) / 'missing-worker'),
                    '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('nonzero hexadecimal', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
            # Validate only the winning value after CLI precedence.
            path.write_text('[dpdk]\nlcore_mask=invalid\n')
            self.assertEqual(launcher.parse_arguments(base + ['--config', str(path), '--lcore-mask', '2',
                '--', '/bin/true']).eal_args[-2:], ['-c', '2'])

    def test_lcore_mask_rejects_competing_eal_cpu_selection(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--lcore-mask', '1']
        for selection in ('-c 2', '-c2', '-l 1', '-l1', '--lcores=0@1', '--lcores 0@1'):
            with self.subTest(selection=selection), self.assertRaises(SystemExit) as caught:
                launcher.parse_arguments(base + ['--eal=' + selection, '--', '/bin/true'])
            self.assertEqual(caught.exception.code, 2)
        args = launcher.parse_arguments(base + ['--eal=--log-level=7 --main-lcore=0', '--', '/bin/true'])
        self.assertEqual(args.eal_args, ['--log-level=7', '--main-lcore=0', '-c', '1'])

    def test_mtu_defaults_ranges_and_cli_precedence(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments(base + ['--', '/bin/true']).mtu, 1500)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'mtu.ini'
            config.write_text('[network]\nmtu=9000\n')
            self.assertEqual(launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true']).mtu, 9000)
            self.assertEqual(launcher.parse_arguments(base + ['--config', str(config), '--mtu', '1280', '--', '/bin/true']).mtu, 1280)
            for text in ('not-a-number', '1279', '9001', '65535'):
                config.write_text('[network]\nmtu=' + text + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', str(Path(directory) / 'missing'), '--', '/bin/true'], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertIn('mtu', result.stderr)
            for text in ('0', '9001', '65535'):
                with self.assertRaises(SystemExit) as caught:
                    launcher.parse_arguments(base + ['--mtu', text, '--', '/bin/true'])
                self.assertEqual(caught.exception.code, 2)

    def test_tcp_ecn_policy_and_cli_override(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).tcp_ecn)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ecn.ini'
            for mode, value in [('off', 0), ('passive', 2), ('on', 1)]:
                path.write_text('[network]\ntcp_ecn=' + mode + '\n')
                parsed = launcher.parse_arguments(base + ['--config', str(path), '--', '/bin/true'])
                self.assertEqual(str(parsed.address), '192.0.2.2/24')
                self.assertEqual(parsed.port, 'net_tap0')
                self.assertEqual(parsed.eal_args, ['--no-huge'])
                self.assertEqual(parsed.tcp_ecn, mode)
                self.assertEqual(launcher.TCP_ECN[parsed.tcp_ecn], value)
                self.assertEqual(launcher.parse_arguments(base + ['--config', str(path),
                    '--tcp-ecn', 'off', '--', '/bin/true']).tcp_ecn, 'off')
            for mode in ('1', 'garbage', ''):
                path.write_text('[network]\ntcp_ecn=' + mode + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(path),
                    '--library', str(Path(directory) / 'missing'), '--', '/bin/true'],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('tcp-ecn', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_basic_and_multiple_sections(self):
        values = self.read('[network]\naddress=192.0.2.2/24\ngateway=192.0.2.1\n'
                           '[dpdk]\nport=net_tap0\neal=--no-huge\n'
                           '[logging]\ndirectory=logs\nlevel=7\n'
                           '[capture]\ndirectory=pcap\nsnaplen=96\nmax_bytes=4096\nnsec=yes\n'
                           '[runtime]\nshutdown_timeout_ms=1000\nstats=stats.json\n')
        self.assertEqual(str(values['address']), '192.0.2.2/24')
        self.assertEqual(str(values['gateway']), '192.0.2.1')
        self.assertEqual(values['port'], 'net_tap0')
        self.assertEqual(values['eal'], '--no-huge')
        self.assertEqual(values['log_dir'], Path('/configuration/logs'))
        self.assertEqual(values['stats'], Path('/configuration/stats.json'))
        self.assertEqual((values['pcap_snaplen'], values['pcap_max_bytes'], values['pcap_nsec']), (96, 4096, True))
        self.assertEqual(values['shutdown_timeout_ms'], 1000)

    def test_comments_whitespace_and_literal_interpolation(self):
        values = self.read('; comment\n# comment\n [dpdk] \n port = net_tap0 ; inline\n'
                           'eal = --file-prefix=100%literal#value\n')
        self.assertEqual(values, dict(port='net_tap0', eal='--file-prefix=100%literal#value'))

    def test_empty_value_empty_input_and_missing_final_newline(self):
        self.assertEqual(self.read('[dpdk]\neal=\n'), {'eal': ''})
        self.assertEqual(self.read(''), {})
        self.assertEqual(self.read('\n'), {})
        self.assertEqual(self.read('[dpdk]\nport=net_tap0'), {'port': 'net_tap0'})

    def test_colon_and_multiline(self):
        values = self.read('[dpdk]\nport:net_tap0\neal=--no-huge\n  --no-pci\n  --no-shconf\n')
        self.assertEqual(values['port'], 'net_tap0')
        self.assertEqual(values['eal'].split(), ['--no-huge', '--no-pci', '--no-shconf'])

    def test_bom_and_open_file(self):
        self.assertEqual(self.read('\ufeff[dpdk]\nport=net_tap0\n'), {'port': 'net_tap0'})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            path.write_bytes(b'\xef\xbb\xbf[dpdk]\nport=net_tap0\n')
            self.assertEqual(launcher.load_configuration(path), {'port': 'net_tap0'})
            with path.open(encoding='utf-8') as stream:
                self.assertEqual(launcher.read_configuration(stream, path.parent, path), {'port': 'net_tap0'})
            with self.assertRaises(FileNotFoundError):
                launcher.load_configuration(Path(directory) / 'missing')
            for prefix in (b'\xefA', b'\xef\xbbX'):
                path.write_bytes(prefix + b'\n[dpdk]\nport=net_tap0\n')
                with self.assertRaises(UnicodeError):
                    launcher.load_configuration(path)

    def test_syntax_errors_include_line(self):
        for text, line in (('[dpdk\nport=x\n', 1), ('[dpdk]\ninvalid_no_eq\n', 2),
                           ('[dpdk]\nbare_line_no_eq\n', 2)):
            with self.subTest(text=text), self.assertRaises(configparser.Error) as caught:
                self.read(text)
            self.assertIn(str(line), str(caught.exception))

    def test_explicit_boundaries(self):
        for text in ('port=x\n', '[unknown]\nport=x\n', '[dpdk]\nunknown=x\n',
                     '[DEFAULT]\nport=x\n', '[dpdk]\nport=a\nport=b\n',
                     '[dpdk]\nall_multicast=perhaps\n', '[network]\naddress=invalid\n'):
            with self.subTest(text=text), self.assertRaises((configparser.Error, ValueError)):
                self.read(text)

    def test_cli_overrides_file_and_keeps_application_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            path.write_text('[network]\naddress=192.0.2.2/24\n[dpdk]\nport=file-port\neal=\nall_multicast=yes\n'
                            '[capture]\nnsec=yes\n[runtime]\nstats=file.json\n')
            args = launcher.parse_arguments(['--config', str(path), '--port', 'cli-port',
                '--no-all-multicast', '--no-pcap-nsec', '--stats', 'cli.json', '--',
                '/bin/program', '--config', 'application.ini'])
            self.assertEqual(args.port, 'cli-port')
            self.assertEqual(args.stats, Path('cli.json'))
            self.assertFalse(args.all_multicast or args.pcap_nsec)
            self.assertEqual(args.command, ['/bin/program', '--config', 'application.ini'])

    def test_eal_is_validated_after_cli_overrides_and_tokens_are_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            path.write_text('[network]\naddress=192.0.2.2/24\n[dpdk]\nport=file-port\n'
                            'eal=--file-prefix="unterminated\n')
            with self.assertRaises(SystemExit) as caught:
                launcher.parse_arguments(['--config', str(path), '--', '/bin/true'])
            self.assertEqual(caught.exception.code, 2)

            args = launcher.parse_arguments(['--config', str(path),
                '--eal=--file-prefix="prefix with spaces" --no-huge', '--', '/bin/true'])
            self.assertEqual(args.eal_args, ['--file-prefix=prefix with spaces', '--no-huge'])

            args = launcher.parse_arguments(['--address', '192.0.2.2/24', '--port', 'cli-port',
                '--eal=--file-prefix="prefix with spaces"', '--', '/bin/true'])
            self.assertEqual(args.eal_args, ['--file-prefix=prefix with spaces'])

    def test_bad_configuration_is_rejected_before_resolving_or_starting_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.ini'
            for text in ('[dpdk]\nunknown=x\n', '[runtime]\nshutdown_timeout_ms=60001\n',
                         '[logging]\nlevel=9\n', '[capture]\nsnaplen=0\n', '[network]\naddress=bad\n'):
                path.write_text(text)
                result = subprocess.run([sys.executable, str(SOURCE), '--config', str(path),
                    '--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge',
                    '--library', str(Path(directory) / 'nonexistent-library'),
                    '--io-worker', str(Path(directory) / 'nonexistent-worker'), '--', '/bin/true'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)

            path.write_text('[network]\naddress=192.0.2.2/24\n[dpdk]\nport=net_tap0\n'
                            'eal=--file-prefix="unterminated\n')
            result = subprocess.run([sys.executable, str(SOURCE), '--config', str(path),
                '--library', str(Path(directory) / 'nonexistent-library'), '--io-worker',
                str(Path(directory) / 'nonexistent-worker'), '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('--eal:', result.stderr)
            self.assertNotIn('nonexistent-library', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

            result = subprocess.run([sys.executable, str(SOURCE), '--address', '192.0.2.2/24',
                '--port', 'net_tap0', '--eal=--file-prefix="unterminated', '--library',
                str(Path(directory) / 'nonexistent-library'), '--io-worker',
                str(Path(directory) / 'nonexistent-worker'), '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('--eal:', result.stderr)
            self.assertNotIn('nonexistent-library', result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
