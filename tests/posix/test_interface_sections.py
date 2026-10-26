"""Malformed interface names through the actual typed reader and CLI.

Configuration evidence only: no F-Stack numeric port ABI or traffic claim.
"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tools/ker-run.py'
spec = importlib.util.spec_from_file_location('interface_sections', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
BASE = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\neal=--no-huge --no-pci\n'


def interface(name, network=19):
    return (f'[interface.{name}]\naddress=198.{network}.0.2/24\n'
            f'port=net_tap{network}\neal=--no-huge --no-pci\n')


class InterfaceSectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config = self.root / 'native.ini'
        self.marker = self.root / 'executed'
        self.worker = self.root / 'worker'
        self.worker.write_text('#!/bin/sh\ntouch "' + str(self.marker) + '"\nexit 99\n')
        self.worker.chmod(0o700)

    def parse(self, text):
        self.config.write_text(text)
        return launcher.parse_arguments(['--config', str(self.config), '--', '/bin/true'])

    def reject_cli(self, text, diagnostic):
        self.config.write_text(text)
        result = subprocess.run([sys.executable, str(SOURCE), '--config', str(self.config),
            '--library', '/missing-native-library', '--io-worker', str(self.worker),
            '--', str(self.worker)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(diagnostic, result.stderr.splitlines()[-1])
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(self.marker.exists(), result.stderr)

    def test_malformed_names_reject_before_worker_or_application(self):
        # Upstream rejects a nondecimal suffix in [portXX]. Ker's real
        # grammar names interfaces, so XX is legal; exercise invalid names
        # in that grammar rather than inventing a numeric-port restriction.
        for name in ('', 'bad/name', 'bad.name', 'bad name', 'é', 'a'*33):
            bad = interface(name, 20)
            good = interface('aux')
            for sections in (bad+good, good+bad):
                with self.subTest(name=name, bad_first=sections.startswith(bad)):
                    self.config.write_text(BASE+sections)
                    with self.assertRaisesRegex(ValueError, 'invalid interface section name'):
                        launcher.load_configuration(self.config)
                    self.reject_cli(BASE+sections, 'invalid interface section name')

    def test_corrected_load_recovers_without_partial_or_shared_state(self):
        good = interface('aux')
        bad = interface('bad/name', 20)
        for sections in (bad+good, good+bad):
            with self.subTest(sections=sections):
                self.reject_cli(BASE+sections, 'invalid interface section name')
                args = self.parse(BASE+sections.replace('bad/name', 'other'))
                records = {item['name']: item for item in args.interfaces}
                self.assertEqual(set(records), {'aux', 'other'})
                self.assertEqual(str(records['aux']['address']), '198.19.0.2/24')
                self.assertEqual(str(records['other']['address']), '198.20.0.2/24')
                records['aux']['port'] = 'changed'
                fresh = self.parse(BASE+good)
                self.assertEqual(fresh.interfaces[0]['port'], 'net_tap19')
                self.assertEqual(self.parse(BASE).interfaces, ())
                self.assertEqual(launcher.CONFIG_DEFAULTS['interfaces'], ())

    def test_valid_name_boundaries_and_source_spelling_difference(self):
        for name in ('x', 'XX', 'a'*32, 'Mixed_09-name'):
            with self.subTest(name=name):
                args = self.parse(BASE+interface(name))
                self.assertEqual(args.interfaces[0]['name'], name)
        # Literal source sections are not silently accepted by the Ker schema.
        self.reject_cli(BASE+'[portXX]\naddr=198.19.0.2\n', 'unknown section [portXX]')


if __name__ == '__main__':
    unittest.main()
