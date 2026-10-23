"""Additional interface configuration must fail before any EAL side effects."""
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
spec = importlib.util.spec_from_file_location('multiport_configuration', ROOT / 'tools/ker-run.py')
launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
BASE = '[network]\naddress=198.18.0.2/24\naddress6=2001:db8:1::2/64\n[dpdk]\nport=net_tap0\neal=--no-pci\n'
AUX = '[interface.aux]\naddress=198.19.0.2/24\naddress6=2001:db8:2::2/64\nport=net_tap1\neal=--no-pci\n'


class MultiportTests(unittest.TestCase):
    def parse(self, text, extra=()):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'interfaces.ini'; path.write_text(text)
            return launcher.parse_arguments(['--config', str(path), *extra, '--', '/bin/true'])

    def test_defaults_final_sections_and_independent_storage(self):
        self.assertEqual(self.parse(BASE).interfaces, ())
        text = BASE + AUX + 'mtu=bad\n[interface.aux]\nmtu=1600\nmax_mtu=2000\n'
        args = self.parse(text)
        self.assertEqual(len(args.interfaces), 1)
        self.assertEqual(args.interfaces[0]['name'], 'aux')
        self.assertEqual(args.interfaces[0]['mtu'], 1600)
        self.assertEqual(args.interfaces[0]['max_mtu'], 2000)
        args.interfaces[0]['mtu'] = 9000
        self.assertEqual(self.parse(text).interfaces[0]['mtu'], 1600)
        self.assertEqual(self.parse(BASE + AUX, ['--mtu', '1800']).interfaces[0]['mtu'], 1800)

    def test_reject_missing_unknown_and_malformed_interface_fields(self):
        for text in (BASE + '[interface.bad/name]\naddress=198.19.0.2/24\nport=x\neal=--no-pci\n',
                     BASE + '[interface.aux]\naddress=198.19.0.2/24\n',
                     BASE + AUX + 'gateway=198.19.0.1\n', BASE + AUX + 'port=\n', BASE + AUX + 'eal=\n'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): self.parse(text)

    def test_address_ownership_and_mtu_rejections(self):
        for text in (AUX + 'mtu=2001\nmax_mtu=2000\n', AUX + 'mtu=1279\n',
                     AUX + 'max_mtu=9001\n', AUX + 'mbuf_mode=unknown\n',
                     AUX + 'address=198.18.0.9/24\n', AUX + 'address6=2001:db8:1::9/64\n',
                     AUX + 'address=0.0.0.0/24\n', AUX + 'address6=::/64\n',
                     AUX + 'vip_addresses=198.18.0.2/32\n',
                     AUX + 'vip_addresses=198.19.0.2/32\n',
                     AUX + 'address6=fe80::1%host/64\n'):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): self.parse(BASE + text)

    def test_missing_ipv6_primary_and_maximum_interface_count(self):
        without6 = AUX.replace('address6=2001:db8:2::2/64\n', '') + 'vip_addresses6=2001:db8:2::3/128\n'
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): self.parse(BASE + without6)
        text = BASE
        for index in range(7):
            text += f'[interface.port{index}]\naddress=198.{19 + index}.0.2/24\nport=net_tap{index + 1}\neal=--no-pci\n'
        self.assertEqual(len(self.parse(text).interfaces), 7)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(text + '[interface.toomany]\naddress=198.30.0.2/24\nport=x\neal=--no-pci\n')

    def test_duplicate_ip_rejected_before_library_or_worker_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.ini'; path.write_text(BASE + AUX + 'vip_addresses=198.18.0.2/32\n')
            result = subprocess.run([sys.executable, str(ROOT / 'tools/ker-run.py'), '--config', str(path),
                '--library', '/missing-library', '--io-worker', '/missing-worker', '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__': unittest.main()
