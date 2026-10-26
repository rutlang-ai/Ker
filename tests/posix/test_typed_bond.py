"""Source-derived bond configuration and preflight rejection contracts."""
import contextlib
import configparser
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ker_bond_config', ROOT / 'tools/ker-run.py')
launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
WORKER = Path(os.environ['KER_TEST_IO_WORKER']) if os.environ.get('KER_TEST_IO_WORKER') else None
BASE = '[network]\naddress=198.18.0.2/24\n[dpdk]\nnb_bond=1\nport=net_bonding0\neal=--no-pci --vdev=net_tap0 --vdev=net_tap1\n'
FIELDS = 'mode=4\nslave=0,1\nprimary=0\nsocket_id=0\nmac=AA:BB:CC:DD:EE:FF\nxmit_policy=l34\nlsc_poll_period_ms=100\nup_delay=100\ndown_delay=200\n'


class BondTests(unittest.TestCase):
    def read(self, text):
        return launcher.read_configuration(io.StringIO(text), Path('/configuration'), worker_path=WORKER)

    def parse(self, text, extra=()):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bond.ini'; path.write_text(text)
            return launcher.parse_arguments(['--config', str(path), *(('--io-worker', str(WORKER)) if WORKER else ()), *extra, '--', '/bin/true'])

    def test_full_pinned_fixture_fields(self):
        text = (ROOT / 'tests/upstream/fstack/tests/unit/fixtures/valid_bond.ini').read_text()
        fields = text.split('[bond0]\n', 1)[1]
        args = self.parse(BASE + '[bond0]\n' + fields)
        self.assertEqual(args.bonds, (dict(name='net_bonding0', mode=4, slave=['0', '1'], primary='0',
            socket_id=0, mac='aa:bb:cc:dd:ee:ff', xmit_policy='l34', lsc_poll_period_ms=100, up_delay=100, down_delay=200),))
        self.assertEqual(args.eal_args[-1], '--vdev=net_bonding0,mode=4,member=0,member=1,primary=0,socket_id=0,mac=aa:bb:cc:dd:ee:ff,xmit_policy=l34')
        self.assertNotIn('up_delay', args.eal_args[-1])  # Applied/read back via original PMD APIs.

    def test_extra_keys_fixture_timing_fields_survive_typed_configuration(self):
        values = configparser.ConfigParser(interpolation=None)
        fixture = ROOT / 'tests/upstream/fstack/tests/unit/fixtures/valid_dpdk_extra_keys.ini'
        with fixture.open() as stream:
            values.read_file(stream)
        expected = {key: values.getint('bond0', key)
                    for key in ('lsc_poll_period_ms', 'up_delay', 'down_delay')}
        self.assertEqual(expected, dict(lsc_poll_period_ms=100, up_delay=200, down_delay=300))
        fields = FIELDS
        for key, value in expected.items():
            current = 100 if key != 'down_delay' else 200
            fields = fields.replace(f'{key}={current}\n', f'{key}={value}\n')
        args = self.parse(BASE + '[bond0]\n' + fields)
        for key, value in expected.items():
            self.assertEqual(args.bonds[0][key], value)
            self.assertNotIn(key, args.eal_args[-1])  # Original PMD APIs apply timing fields.
        # A later unrelated parse retains the established single-bond fixture values.
        ordinary = self.parse(BASE + '[bond0]\n' + FIELDS)
        self.assertEqual((ordinary.bonds[0]['up_delay'], ordinary.bonds[0]['down_delay']), (100, 200))

    def test_exact_missing_count_and_bad_section_fixtures(self):
        for name in ('invalid_bond_no_nb_bond.ini', 'invalid_bond_bad_section.ini'):
            path = ROOT / 'tests/upstream/fstack/tests/unit/fixtures' / name
            result = subprocess.run([sys.executable, str(ROOT / 'tools/ker-run.py'), '--config', str(path),
                '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('bond', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_repeated_pinned_bond_strings(self):
        text = (ROOT / 'tests/upstream/fstack/tests/unit/fixtures/valid_bond_vdev_repeat.ini').read_text()
        fields = text.split('[bond0]\n', 1)[1].split('\n[', 1)[0]
        bond = self.read(BASE + '[bond0]\n' + fields)['bonds'][0]
        self.assertEqual(bond['slave'], ['eth0', 'eth1'])
        self.assertEqual(bond['primary'], 'eth1')
        self.assertEqual(bond['mac'], 'cc:dd:ee:ff:00:11')
        self.assertEqual(bond['xmit_policy'], 'l34')

    def test_invalid_counts_members_fields_and_timing(self):
        invalid = [BASE.replace('nb_bond=1', 'nb_bond=0') + '[bond0]\n' + FIELDS,
                   BASE.replace('nb_bond=1', 'nb_bond=2') + '[bond0]\n' + FIELDS,
                   BASE + '[bond01]\n' + FIELDS, BASE + '[bond1]\n' + FIELDS,
                   BASE + '[bond0]\nmode=4\n', BASE + '[bond0]\nslave=0,1\n']
        for field, value in (('mode', '-1'), ('mode', '7'), ('mode', 'bad'), ('slave', ''),
            ('slave', '0,0'), ('slave', '0, 1'), ('slave', 'net_bonding0'), ('primary', '2'),
            ('socket_id', '128'), ('xmit_policy', 'random'), ('mac', '00:00:00:00:00:00'),
            ('mac', '01:11:22:33:44:55'), ('lsc_poll_period_ms', '0'), ('up_delay', '-1'),
            ('down_delay', '2147483648'), ('unknown', '1')):
            invalid.append(BASE + '[bond0]\n' + FIELDS + field + '=' + value + '\n')
        for text in invalid:
            with self.subTest(text=text[-80:]), self.assertRaises(ValueError): self.read(text)

    def test_final_repeated_values_own_storage(self):
        text = BASE + '[bond0]\nmode=bad\nslave=bad\n[bond0]\n' + FIELDS
        first = self.read(text); first['bonds'][0]['slave'].append('other')
        self.assertEqual(self.read(text)['bonds'][0]['slave'], ['0', '1'])

    def test_member_name_limit_is_shared_and_preflighted(self):
        longest = 'x' * 63
        text = BASE + '[bond0]\n' + FIELDS.replace('slave=0,1', 'slave=' + longest).replace(
            'primary=0', 'primary=' + longest)
        with patch.object(launcher, 'query_dpdk_max_numa_nodes', return_value=32) as query, \
                patch.object(launcher.subprocess, 'run') as run:
            self.assertEqual(self.read(text)['bonds'][0]['slave'], [longest])
            query.assert_called_once_with(WORKER)
            run.assert_not_called()
        with patch.object(launcher, 'query_dpdk_max_numa_nodes', return_value=32):
            self.assertEqual(self.parse(text).bonds[0]['slave'], [longest])
        programmatic = dict(name='net_bonding0', mode=4, slave=[longest])
        self.assertEqual(launcher.bond_device_argument(programmatic),
            '--vdev=net_bonding0,mode=4,member=' + longest)

        for member in ('x' * 64, 'x' * 128, '', 'bad/name', 'nämé'):
            invalid_text = BASE + '[bond0]\n' + FIELDS.replace('slave=0,1', 'slave=' + member)
            with self.subTest(length=len(member), member=member[:12]):
                with patch.object(launcher, 'query_dpdk_max_numa_nodes') as query, \
                        patch.object(launcher.subprocess, 'run') as run, \
                        patch.object(launcher.subprocess, 'Popen') as popen:
                    with self.assertRaisesRegex(ValueError, '1..63 ASCII'):
                        self.read(invalid_text)
                    query.assert_not_called(); run.assert_not_called(); popen.assert_not_called()
                    with self.assertRaisesRegex(ValueError, '1..63 ASCII'):
                        launcher.bond_device_argument(dict(name='net_bonding0', mode=4, slave=[member]))
                    with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                        self.parse(invalid_text)
                    query.assert_not_called(); run.assert_not_called(); popen.assert_not_called()

    def test_port_and_raw_bond_conflicts(self):
        for extra in (['--port', 'net_tap0'], ['--eal=--vdev=net_bonding0,mode=4,member=0']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.parse(BASE + '[bond0]\n' + FIELDS, extra)
        args = self.parse(BASE + '[bond0]\n' + FIELDS, ['--eal=--no-pci -- --vdev=net_bonding-app'])
        self.assertEqual(args.eal_args[-2:], ['--', '--vdev=net_bonding-app'])
        args = self.parse(BASE + '[bond0]\n' + FIELDS, ['--eal=--no-pci --file-prefix=eth_bond_worker'])
        self.assertIn('--file-prefix=eth_bond_worker', args.eal_args)


if __name__ == '__main__': unittest.main()
