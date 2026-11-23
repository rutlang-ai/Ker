"""Malformed interface names through the actual typed reader and CLI.

Configuration evidence only: no F-Stack numeric port ABI or traffic claim.
"""
import contextlib
import io
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


    def bond_config(self, auxiliary):
        return (BASE.replace('port=net_tap0', 'port=net_bonding0')
                .replace('eal=--no-huge --no-pci',
                         'nb_bond=1\neal=--no-huge --no-pci --vdev=net_tap0 --vdev=net_tap1')
                + '[bond0]\nmode=4\nslave=0,1\nsocket_id=0\n' + auxiliary)

    def test_semantic_interface_errors_precede_bond_capability_query(self):
        good = interface('aux')
        cases = (
            (good+'mtu=2001\nmax_mtu=2000\n', 'additional interface MTU'),
            (good+'max_mtu=9001\n', 'additional interface max_mtu'),
            (good+'queues=0\n', 'additional interface queues'),
            (good+'rss=yes\nqueues=1\n', 'additional interface RSS'),
            (good+'rx_lcores=0,0\nqueues=2\n', 'RX lcores'),
            (good+'mbuf_mode=unknown\n', 'additional interface mbuf_mode'),
            (good+'tx_offloads=unknown\n', 'additional interface tx_offloads'),
            (good+'address=198.18.0.2/24\n', 'duplicates an existing address'),
            (good+'address=198.18.0.3/24\n', 'networks must not overlap'),
            (good+'address=198.19.0.255/24\n', 'subnet broadcast'),
            (good+'vip_addresses6=2001:db8:2::3/64\n', 'requires its interface address6'),
        )
        for auxiliary, diagnostic in cases:
            for sections in (auxiliary, interface('other', 20)+auxiliary):
                with self.subTest(diagnostic=diagnostic, preceding_valid=sections != auxiliary):
                    self.reject_cli(self.bond_config(sections), diagnostic)

    def test_validated_bond_queries_selected_limits_once_and_recovers(self):
        # This executable supplies only the worker limits protocol, not a PMD
        # or packet result. Actual query execution is observable in the log.
        self.worker.write_text('#!' + sys.executable + '\nfrom pathlib import Path\nimport sys\n'
            + 'with Path(' + repr(str(self.marker)) + ').open("a") as log:\n'
            + '    log.write(" ".join(sys.argv[1:]) + "\\n")\n'
            + 'print(' + repr('{"max_numa_nodes": 3}') + ')\n')
        valid = self.bond_config(interface('aux'))
        def parse(text, *extra):
            self.config.write_text(text)
            return launcher.parse_arguments(['--config', str(self.config),
                '--io-worker', str(self.worker), *extra, '--', '/bin/true'])
        args = parse(valid)
        self.assertEqual(self.marker.read_text().splitlines(), ['--dpdk-limits'])
        self.assertEqual(args.bonds[0]['socket_id'], 0)
        self.assertEqual(args.interfaces[0]['name'], 'aux')
        self.marker.unlink()
        # Main CLI corrections must be applied before validation/query.
        invalid_primary = valid.replace('[network]\n', '[network]\nmtu=2001\nmax_mtu=2000\n')
        self.reject_cli(invalid_primary, '--mtu must not exceed --max-mtu')
        args = parse(invalid_primary, '--mtu', '1500')
        self.assertEqual(self.marker.read_text().splitlines(), ['--dpdk-limits'])
        self.marker.unlink()
        # Selected-build bounds still apply; no fixed NUMA limit is assumed.
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            parse(valid.replace('socket_id=0', 'socket_id=3'))
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(self.marker.read_text().splitlines(), ['--dpdk-limits'])
        self.marker.unlink()
        args = parse(valid.replace('socket_id=0', 'socket_id=2'))
        self.assertEqual(args.bonds[0]['socket_id'], 2)
        self.assertEqual(self.marker.read_text().splitlines(), ['--dpdk-limits'])


if __name__ == '__main__':
    unittest.main()
