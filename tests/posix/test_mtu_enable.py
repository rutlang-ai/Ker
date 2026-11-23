"""Adapt the disabled-jumbo configuration boundary through the real launcher."""
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
SPEC = importlib.util.spec_from_file_location('mtu_enable_launcher', SOURCE)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)
BASE = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-pci']
AUX = ('[interface.aux]\naddress=198.19.0.2/24\n'
       'port=net_tap1\neal=--no-pci\n')


class MtuEnableTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = self.root / 'ker.ini'

    def parse(self, text='', extra=()):
        self.config.write_text(text)
        return launcher.parse_arguments([
            *BASE, '--config', str(self.config), *extra, '--', '/bin/true'])

    def test_disabled_policy_accepts_standard_mtu_and_preserves_lower_ceiling(self):
        for mtu, ceiling in ((1280, 1280), (1280, 1400), (1500, 1500), (1500, 9000)):
            with self.subTest(mtu=mtu, ceiling=ceiling):
                args = self.parse(f'[network]\nmtu={mtu}\nmax_mtu={ceiling}\n'
                                  '[dpdk]\nmtu_enable=0\n')
                self.assertFalse(args.mtu_enable)
                self.assertEqual((args.mtu, args.max_mtu), (mtu, min(ceiling, 1500)))
        # Omission preserves Ker's existing jumbo-enabled policy.
        args = self.parse('[network]\nmtu=9000\n')
        self.assertTrue(args.mtu_enable)
        self.assertEqual((args.mtu, args.max_mtu), (9000, 9000))

    def test_disabled_jumbo_rejects_before_worker_or_application_and_recovers(self):
        marker = self.root / 'executed'
        worker = self.root / 'worker'
        worker.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 99\n')
        worker.chmod(0o700)
        for mtu in (1501, 2000, 9000):
            with self.subTest(mtu=mtu):
                self.config.write_text(f'[network]\nmtu={mtu}\n[dpdk]\nmtu_enable=0\n')
                result = subprocess.run([
                    sys.executable, str(SOURCE), *BASE, '--config', str(self.config),
                    '--io-worker', str(worker), '--library', str(self.root / 'missing'),
                    '--', str(worker)], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('--mtu must not exceed --max-mtu', result.stderr.splitlines()[-1])
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse(marker.exists())
                self.assertEqual(self.parse('[network]\nmtu=9000\n').max_mtu, 9000)

    def test_cli_precedence_and_repeated_policy_do_not_leak_state(self):
        disabled = '[network]\nmtu=9000\n[dpdk]\nmtu_enable=0\n'
        args = self.parse(disabled, ['--mtu-enable'])
        self.assertEqual((args.mtu_enable, args.mtu, args.max_mtu), (True, 9000, 9000))
        args = self.parse(disabled, ['--mtu', '1500', '--max-mtu', '9000'])
        self.assertEqual((args.mtu_enable, args.max_mtu), (False, 1500))
        args = self.parse('[dpdk]\nmtu_enable=1\n', ['--no-mtu-enable'])
        self.assertEqual((args.mtu_enable, args.max_mtu), (False, 1500))
        args = self.parse(disabled + 'mtu_enable=1\n')
        self.assertEqual((args.mtu_enable, args.max_mtu), (True, 9000))
        self.assertTrue(self.parse().mtu_enable)

    def test_disabled_policy_caps_each_additional_interface(self):
        disabled = '[dpdk]\nmtu_enable=0\n'
        for ceiling in ('', 'max_mtu=9000\n', 'max_mtu=1400\nmtu=1280\n'):
            with self.subTest(ceiling=ceiling):
                args = self.parse(disabled + AUX + ceiling)
                self.assertEqual(args.interfaces[0]['max_mtu'], 1400 if '1400' in ceiling else 1500)
        for extra in ('mtu=1501\n', 'mtu=9000\nmax_mtu=9000\n'):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                self.parse(disabled + AUX + extra)
            self.assertEqual(error.exception.code, 2)
        args = self.parse(disabled + AUX + 'mtu=9000\n', ['--mtu-enable'])
        self.assertEqual(args.interfaces[0]['max_mtu'], 9000)

    def test_disabled_policy_still_rejects_invalid_configured_limits(self):
        for text in ('[dpdk]\nmtu_enable=garbage\n',
                     '[dpdk]\nmtu_enable=0\n[network]\nmax_mtu=65535\n',
                     '[dpdk]\nmtu_enable=0\n' + AUX + 'max_mtu=65535\n',
                     '[dpdk]\nmtu_enable=0\n' + AUX + 'max_mtu=1279\n'):
            with self.subTest(text=text), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                self.parse(text)
            self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
