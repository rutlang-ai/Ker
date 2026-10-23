"""Validate active queues separately from the virtual device's queue capacity."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('queue_config', ROOT / 'tools/ker-run.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
BASE = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\neal=--no-pci\n'
AUX = '[interface.aux]\naddress=198.19.0.2/24\nport=net_tap1\neal=--no-pci\n'


class QueueConfigTests(unittest.TestCase):
    def parse(self, text, options=()):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'queues.ini'
            path.write_text(text)
            return launcher.parse_arguments(['--config', str(path), *options, '--', '/bin/true'])

    def test_default_override_and_final_value(self):
        self.assertEqual(self.parse(BASE).queues, 1)
        self.assertEqual(self.parse(BASE + 'queues=bad\nqueues=2\n').queues, 2)
        self.assertEqual(self.parse(BASE + 'queues=2\n', ['--queues', '3']).queues, 3)
        self.assertEqual(self.parse(BASE, ['--queues', '16']).queues, 16)

    def test_additional_interfaces_inherit_or_override(self):
        self.assertEqual(self.parse(BASE + 'queues=2\n' + AUX).interfaces[0]['queues'], 2)
        self.assertEqual(self.parse(BASE + AUX + 'queues=3\n', ['--queues', '2']).interfaces[0]['queues'], 3)

    def test_capacity_is_not_implicitly_active(self):
        args = self.parse(BASE.replace('port=net_tap0', 'port=net_virtio_user0') + 'nb_vdev=1\n[vdev0]\npath=/tmp/vhost\nqueues=2\ncq=1\n')
        self.assertEqual(args.queues, 1)
        self.assertEqual(args.vdevs[0]['queues'], 2)

    def test_rss_requires_multiple_queues_and_respects_final_boolean(self):
        self.assertTrue(self.parse(BASE + 'queues=2\nrss=bad\nrss=1\n').rss)
        self.assertFalse(self.parse(BASE + 'queues=2\nrss=1\n', ['--no-rss']).rss)
        args = self.parse(BASE + 'queues=2\nrss=1\n' + AUX + 'rss=0\n')
        self.assertFalse(args.interfaces[0]['rss'])
        for text in (BASE + 'rss=1\n', BASE + 'queues=2\nrss=1\n' + AUX + 'queues=1\n',
                     BASE + 'queues=2\nrss=1\n' + AUX + 'rss=maybe\n'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.parse(text)

    def test_invalid_counts_fail_before_backend(self):
        for value in ('0', '-1', '17', 'bad'):
            for text in (BASE + 'queues=' + value + '\n', BASE + AUX + 'queues=' + value + '\n'):
                with self.subTest(text=text), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    self.parse(text)


if __name__ == '__main__':
    unittest.main()
