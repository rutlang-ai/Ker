"""Validate actual typed vdev mapping and errors before backend side effects."""
import configparser
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ker_vdev_config', ROOT / 'tools/ker-run.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
BASE = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_virtio_user0\neal=--no-pci\n'
FIELDS = 'path=/var/run/usvhost\niface=eth0\nqueues=2\nqueue_size=512\nmac=00:11:22:33:44:55\ncq=1\n'


class VdevTests(unittest.TestCase):
    def read(self, text):
        return launcher.read_configuration(io.StringIO(text), Path('/configuration'))

    def parse(self, text, extra=()):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'vdev.ini'
            config.write_text(text)
            return launcher.parse_arguments(['--config', str(config), *extra, '--', '/bin/true'])

    def test_all_pinned_source_fields_reach_eal(self):
        source = configparser.ConfigParser()
        source.read(ROOT / 'tests/upstream/fstack/tests/unit/fixtures/valid_vdev.ini')
        fields = ''.join(key + '=' + value + '\n' for key, value in source['vdev0'].items())
        args = self.parse(BASE + 'nb_vdev=1\n[vdev0]\n' + fields)
        self.assertEqual(args.nb_vdev, 1)
        device = args.vdevs[0]
        for key in ('iface', 'path', 'mac'):
            self.assertEqual(device[key], source['vdev0'][key])
        for key in ('queues', 'queue_size', 'cq'):
            self.assertEqual(device[key], int(source['vdev0'][key]))
        self.assertEqual(args.eal_args, ['--no-pci', '--vdev=net_virtio_user0,iface=eth0,path=/var/run/usvhost,queues=2,queue_size=512,mac=00:11:22:33:44:55,cq=1'])

    def test_original_missing_count_fixture_rejected_before_library_resolution(self):
        source = ROOT / 'tests/upstream/fstack/tests/unit/fixtures/invalid_vdev_no_nb_vdev.ini'
        result = subprocess.run([sys.executable, str(ROOT / 'tools/ker-run.py'), '--config', str(source),
            '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('nb_vdev', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_final_repeated_values_and_sections(self):
        text = BASE + 'nb_vdev=bad\nnb_vdev=1\n[vdev0]\nqueues=bad\npath=/old\nmac=bad\n[vdev0]\n' + FIELDS
        first = self.read(text)
        self.assertEqual(first['vdevs'][0]['path'], '/var/run/usvhost')
        self.assertEqual(first['vdevs'][0]['queues'], 2)
        first['vdevs'][0]['queues'] = 100
        self.assertEqual(self.read(text)['vdevs'][0]['queues'], 2)

    def test_pinned_repeated_vdev_strings(self):
        source = (ROOT / 'tests/upstream/fstack/tests/unit/fixtures/valid_bond_vdev_repeat.ini').read_text()
        fields = source.split('[vdev0]\n', 1)[1].split('\n[', 1)[0]
        device = self.read(BASE + 'nb_vdev=1\n[vdev0]\n' + fields)['vdevs'][0]
        self.assertEqual(device['iface'], 'net_pcap_b')
        self.assertEqual(device['path'], '/tmp/b')
        self.assertEqual(device['mac'], '66:77:88:99:aa:bb')

    def test_strict_counts_sections_fields_and_bounds(self):
        invalid = [
            BASE + '[vdev0]\n' + FIELDS,
            BASE + 'nb_vdev=0\n[vdev0]\n' + FIELDS,
            BASE + 'nb_vdev=-1\n', BASE + 'nb_vdev=17\n',
            BASE + 'nb_vdev=1\n', BASE + 'nb_vdev=2\n[vdev0]\n' + FIELDS,
            BASE + 'nb_vdev=1\n[vdev01]\n' + FIELDS,
            BASE + 'nb_vdev=1\n[vdev1]\n' + FIELDS,
            BASE + 'nb_vdev=1\n[vdevbad]\n' + FIELDS,
            BASE + 'nb_vdev=1\n[vdev0]\niface=eth0\n',
        ]
        for field, value in (
            ('queues', '0'), ('queues', '129'), ('queues', '2x'),
            ('queue_size', '3'), ('queue_size', '65536'), ('queue_size', '0'),
            ('cq', '2'), ('cq', '0'), ('path', ''), ('path', '/bad,path'),
            ('path', 'x' * 4096), ('iface', 'x' * 16), ('iface', 'a,b'),
            ('mac', '00:00:00:00:00:00'), ('mac', '01:11:22:33:44:55'),
            ('mac', 'not-a-MAC'), ('extra', '1')):
            invalid.append(BASE + 'nb_vdev=1\n[vdev0]\n' + FIELDS + field + '=' + value + '\n')
        for text in invalid:
            with self.subTest(text=text[-100:]), self.assertRaises(ValueError):
                self.read(text)

    def test_defaults_relative_paths_and_multiple_devices(self):
        values = self.read('[dpdk]\nnb_vdev=2\n[vdev0]\npath=first.sock\n[vdev1]\npath=second.sock\n')
        self.assertEqual([d['name'] for d in values['vdevs']], ['net_virtio_user0', 'net_virtio_user1'])
        self.assertEqual(values['vdevs'][0], dict(name='net_virtio_user0', path='/configuration/first.sock', queues=1, queue_size=256, cq=0))
        self.assertEqual(self.read('[dpdk]\nnb_vdev=0\n')['vdevs'], ())

    def test_raw_eal_conflicts_port_selection_and_separator(self):
        text = BASE + 'nb_vdev=1\n[vdev0]\n' + FIELDS
        for options in (['--eal=--vdev=net_virtio_user0,path=/other'],
                        ['--eal=--vdev net_tap0'], ['--port', 'net_tap0']):
            with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.parse(text, options)
        args = self.parse(text, ['--eal=--no-pci -- --vdev=application-argument'])
        self.assertEqual(args.eal_args[-2:], ['--', '--vdev=application-argument'])
        self.assertTrue(args.eal_args[1].startswith('--vdev=net_virtio_user0,'))


if __name__ == '__main__':
    unittest.main()
