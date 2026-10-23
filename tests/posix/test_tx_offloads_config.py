import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('tx_offload_config', ROOT / 'tools/ker-run.py')
launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
BASE = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\neal=--no-pci\n'
AUX = '[interface.aux]\naddress=198.19.0.2/24\nport=net_tap1\neal=--no-pci\n'
class OffloadConfigTests(unittest.TestCase):
    def parse(self, text, options=()):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'offloads.ini'; config.write_text(text)
            return launcher.parse_arguments(['--config', str(config), *options, '--', '/bin/true'])
    def test_default_and_final_precedence(self):
        self.assertEqual(self.parse(BASE).tx_offloads, 'off')
        self.assertEqual(self.parse(BASE + 'tx_offloads=bad\ntx_offloads=tso\n').tx_offloads, 'tso')
        self.assertEqual(self.parse(BASE + 'tx_offloads=tso\n', ['--tx-offloads', 'checksum']).tx_offloads, 'checksum')
    def test_interfaces_inherit_or_override(self):
        self.assertEqual(self.parse(BASE + 'tx_offloads=checksum\n' + AUX).interfaces[0]['tx_offloads'], 'checksum')
        self.assertEqual(self.parse(BASE + 'tx_offloads=tso\n' + AUX + 'tx_offloads=off\n').interfaces[0]['tx_offloads'], 'off')
    def test_invalid_modes(self):
        for value in ('1', 'TSO', 'unknown'):
            for text in (BASE + 'tx_offloads=' + value + '\n', BASE + AUX + 'tx_offloads=' + value + '\n'):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): self.parse(text)
if __name__ == '__main__':
    unittest.main()
