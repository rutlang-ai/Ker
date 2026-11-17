"""Pinned F-Stack missing-deployment, malformed-section and MTU boundaries.

Exercise Ker's production loader with its native schema. These checks do not
claim NIC traffic or implementation equivalence with the F-Stack loader.
"""
import contextlib
import builtins
import copy
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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


class MissingDeploymentTests(BoundaryCase):
    settings = (('--address', '198.18.0.2/24'), ('--port', 'net_tap0'), ('--eal=--no-huge',))

    def reject_missing(self, options, missing, config=False):
        # An actual empty INI is an additional Ker boundary. The pinned
        # F-Stack test itself passes no filename, despite its "empty_ini" name.
        self.path.write_text('')
        marker = self.directory / 'application-ran'
        application = self.directory / 'application.py'
        application.write_text('from pathlib import Path\nimport sys\nPath(sys.argv[1]).touch()\n')
        library = self.directory / 'missing-library.so'
        worker = self.directory / 'missing-worker'
        prefix = ['--config', str(self.path)] if config else []
        command = [*prefix, *options, '--library', str(library), '--io-worker', str(worker),
                   '--', sys.executable, str(application), str(marker)]
        result = subprocess.run([sys.executable, str(SOURCE), *command],
                                capture_output=True, text=True, timeout=5)
        diagnostic = 'required via CLI or --config: ' + ', '.join('--' + name for name in missing)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(diagnostic, result.stderr.splitlines()[-1])
        self.assertEqual(result.stdout, '')
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn(str(library), result.stderr)
        self.assertNotIn(str(worker), result.stderr)
        self.assertFalse(marker.exists())
        # The same failure in a long-lived interpreter must not poison a
        # subsequent parse with complete, explicit deployment settings.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            launcher.parse_arguments(command)
        self.assertEqual(error.exception.code, 2)
        complete = [value for setting in self.settings for value in setting]
        args = launcher.parse_arguments([*complete, '--', '/bin/true'])
        self.assertIsNone(args.config)
        self.assertEqual((str(args.address), args.port, args.eal_args),
                         ('198.18.0.2/24', 'net_tap0', ['--no-huge']))

    def test_no_arguments_report_all_missing_settings(self):
        diagnostic = io.StringIO()
        with contextlib.redirect_stderr(diagnostic), self.assertRaises(SystemExit) as error:
            launcher.parse_arguments([])
        self.assertEqual(error.exception.code, 2)
        self.assertIn('required via CLI or --config: --address, --port, --eal',
                      diagnostic.getvalue().splitlines()[-1])
        self.reject_missing([], ['address', 'port', 'eal'])

    def test_empty_file_and_incomplete_cli_reject_before_any_setup(self):
        names = ('address', 'port', 'eal')
        for config in (False, True):
            with self.subTest(config=config, missing='all'):
                self.reject_missing([], names, config)
            for missing in range(len(names)):
                options = [value for index, setting in enumerate(self.settings)
                           if index != missing for value in setting]
                with self.subTest(config=config, missing=names[missing]):
                    self.reject_missing(options, [names[missing]], config)


class LcoreAllocationFailureTests(BoundaryCase):
    def allocation_failure(self, provider, config):
        text = MINIMAL + 'lcore_mask=01\n' if config else MINIMAL
        self.path.write_text(text)
        options = ['--config', str(self.path)]
        if not config:
            options += ['--lcore-mask', '0xA']
        options += ['--library', str(self.directory / 'missing-library.so'),
                    '--io-worker', str(self.directory / 'missing-worker'), '--', '/bin/true']
        calls = []
        real = getattr(builtins, provider)

        def fail_mask_allocation(*args, **kwargs):
            # Only the mask's integer conversion or normalized string is
            # failed. Other provider calls retain actual Python behavior.
            selected = len(args) == 2 and args[1] == (16 if provider == 'int' else 'x')
            if selected:
                calls.append(args)
                raise MemoryError('injected lcore allocation failure')
            return real(*args, **kwargs)

        defaults = copy.deepcopy(launcher.CONFIG_DEFAULTS)
        diagnostic = io.StringIO()
        with mock.patch.object(launcher, provider, fail_mask_allocation, create=True), \
                mock.patch.object(sys, 'argv', [str(SOURCE), *options]), \
                mock.patch.object(launcher.subprocess, 'Popen',
                                  side_effect=AssertionError('process started before validation')) as start, \
                contextlib.redirect_stderr(diagnostic), self.assertRaises(SystemExit) as error:
            launcher.main()
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(len(calls), 1)
        self.assertIn('not enough memory while processing --lcore-mask', diagnostic.getvalue())
        self.assertNotIn('Traceback', diagnostic.getvalue())
        self.assertNotIn('missing-library', diagnostic.getvalue())
        start.assert_not_called()
        self.assertEqual(launcher.CONFIG_DEFAULTS, defaults)
        recovered = launcher.parse_arguments(options)
        mask = '1' if config else 'a'
        self.assertEqual(recovered.lcore_mask, mask)
        self.assertEqual(recovered.eal_args, ['--no-huge', '-c', mask])
        self.assertEqual((str(recovered.address), recovered.port), ('198.18.0.2/24', 'net_tap0'))

    def test_cli_mask_allocation_failures_reject_then_recover(self):
        for provider in ('int', 'format'):
            with self.subTest(provider=provider):
                self.allocation_failure(provider, False)

    def test_ini_mask_allocation_failures_reject_then_recover(self):
        for provider in ('int', 'format'):
            with self.subTest(provider=provider):
                self.allocation_failure(provider, True)


class VLANAllocationFailureTests(BoundaryCase):
    vlan_text = ('[vlan.10]\naddresses=198.19.10.2/24,198.19.10.3/24\n'
                 '[vlan.20]\naddresses=198.19.20.2/24\n')
    addresses = ['198.19.10.2/24,198.19.10.3/24', '198.19.20.2/24']

    def options(self, config):
        self.path.write_text(MINIMAL + (self.vlan_text if config else ''))
        options = ['--config', str(self.path)]
        if not config:
            options += ['--vlan', '10=' + self.addresses[0], '--vlan', '20=' + self.addresses[1]]
        return [*options, '--library', str(self.directory / 'missing-library.so'),
                '--io-worker', str(self.directory / 'missing-worker'), '--', '/bin/true']

    def rejected_main(self, options, diagnostic):
        defaults = copy.deepcopy(launcher.CONFIG_DEFAULTS)
        stderr = io.StringIO()
        with mock.patch.object(sys, 'argv', [str(SOURCE), *options]), \
                mock.patch.object(launcher.subprocess, 'Popen',
                                  side_effect=AssertionError('process started before validation')) as start, \
                contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            launcher.main()
        self.assertEqual(error.exception.code, 2)
        self.assertIn(diagnostic, stderr.getvalue())
        self.assertNotIn('Traceback', stderr.getvalue())
        self.assertNotIn('missing-library', stderr.getvalue())
        start.assert_not_called()
        self.assertEqual(launcher.CONFIG_DEFAULTS, defaults)

    def recovered(self, options):
        args = launcher.parse_arguments(options)
        self.assertEqual([(tag, list(map(str, addresses))) for tag, addresses in args.vlans],
                         [(10, ['198.19.10.2/24', '198.19.10.3/24']), (20, ['198.19.20.2/24'])])
        self.assertEqual((str(args.address), args.port, args.eal_args),
                         ('198.18.0.2/24', 'net_tap0', ['--no-huge']))

    def fail_address_list(self, config, ordinal):
        options = self.options(config)
        real = launcher.vip_addresses
        calls = []

        def allocate_addresses(text):
            calls.append(text)
            if len(calls) == ordinal:
                raise MemoryError('injected VLAN address-list allocation failure')
            return real(text)

        # Failing the second VLAN leaves a real first result in the private
        # parser state; neither that result nor the failed load may leak into
        # a later invocation. Successful provider calls are never replaced.
        with mock.patch.object(launcher, 'vip_addresses', allocate_addresses):
            self.rejected_main(options, 'not enough memory while processing VLAN')
        self.assertEqual(calls, self.addresses[:ordinal])
        self.recovered(options)

    def test_cli_address_list_allocation_failure_and_recovery(self):
        for ordinal in (1, 2):
            with self.subTest(ordinal=ordinal):
                self.fail_address_list(False, ordinal)

    def test_ini_address_list_allocation_failure_and_recovery(self):
        for ordinal in (1, 2):
            with self.subTest(ordinal=ordinal):
                self.fail_address_list(True, ordinal)

    def test_ini_storage_allocation_failure_and_recovery(self):
        options = self.options(True)
        # Exercise the config-loading boundary outside the VLAN converter,
        # where stream/parser/result-storage allocation may also fail.
        with mock.patch.object(launcher, 'read_configuration', side_effect=MemoryError):
            self.rejected_main(options, 'not enough memory while loading configuration')
        self.recovered(options)


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
