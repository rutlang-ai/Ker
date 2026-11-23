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

    def primary_vips(self, text, ipv4='', ipv6=''):
        return text.replace('[dpdk]', ipv4 + ipv6 + '[dpdk]')

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

    def test_additional_interface_rejects_ipv4_directed_broadcasts_before_setup(self):
        cases = (
            AUX.replace('address=198.19.0.2/24', 'address=198.19.0.255/24'),
            AUX + 'vip_addresses=198.19.0.255/24\n',
            AUX.replace('address=198.19.0.2/24', 'address=198.19.0.127/25'),
            AUX + 'vip_addresses=198.19.0.127/25\n',
        )
        for text in cases:
            with self.subTest(text=text), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                self.parse(BASE + text)
            self.assertEqual(error.exception.code, 2)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'broadcast.ini'
                path.write_text(BASE + text)
                result = subprocess.run([sys.executable, str(ROOT / 'tools/ker-run.py'),
                    '--config', str(path), '--library', '/missing-library',
                    '--io-worker', '/missing-worker', '--', '/bin/true'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('subnet broadcast', result.stderr)
                self.assertNotIn('missing-library', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_additional_interface_keeps_valid_ipv4_prefix_boundaries_and_ipv6(self):
        cases = (
            AUX.replace('address=198.19.0.2/24', 'address=198.19.0.255/23') +
            'vip_addresses=198.19.0.254/23\n',
            AUX.replace('address=198.19.0.2/24', 'address=198.19.0.255/31') +
            'vip_addresses=198.19.0.253/31\n',
            AUX.replace('address=198.19.0.2/24', 'address=198.19.0.255/32') +
            'vip_addresses=198.19.0.253/32\n',
            AUX.replace('address6=2001:db8:2::2/64', 'address6=2001:db8:2::ffff/64') +
            'vip_addresses6=2001:db8:2::dead/128\n',
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(len(self.parse(BASE + text).interfaces), 1)

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

    def test_cross_interface_prefix_overlap_rejected_for_primary_and_vips(self):
        cases = (
            # Primary VIP versus auxiliary primary.
            self.primary_vips(BASE, 'vip_addresses=198.0.0.20/8\n',
                              'vip_addresses6=2001:db8::20/32\n') + AUX,
            self.primary_vips(BASE, ipv6='vip_addresses6=2001:db8::20/32\n') + AUX,
            # Auxiliary VIP versus primary.
            BASE + AUX + 'vip_addresses=198.18.0.20/16\n'
            'vip_addresses6=2001:db8:1::20/32\n',
            BASE + AUX + 'vip_addresses6=2001:db8::20/32\n',
            # An auxiliary VIP versus a second auxiliary primary/VIP.
            BASE + AUX +
            'vip_addresses=198.0.0.20/8\nvip_addresses6=2001:db8::20/32\n'
            '[interface.other]\naddress=198.20.0.2/24\nport=net_tap2\neal=--no-pci\n'
            'address6=2001:db8:3::2/64\nvip_addresses=198.1.0.20/8\n'
            'vip_addresses6=2001:db8:1::20/32\n',
            BASE + AUX + 'vip_addresses6=2001:db8::20/32\n'
            '[interface.other]\naddress=198.20.0.2/24\nport=net_tap2\neal=--no-pci\n'
            'address6=2001:db8:3::2/64\nvip_addresses6=2001:db8:1::20/32\n',
            # Primary address versus a broader VIP prefix on an auxiliary port.
            BASE + '[interface.aux]\naddress=198.19.0.2/24\nport=net_tap1\neal=--no-pci\n'
            'address6=2001:db8:2::2/64\nvip_addresses=198.0.0.20/8\n'
            'vip_addresses6=2001:db8::20/32\n',
        )
        for text in cases:
            with self.subTest(text=text), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                self.parse(text)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.parse(BASE, ['--vlan', '100=198.18.1.2/16,2001:db8:1:1::2/48'])

    def test_overlapping_prefixes_on_same_interface_remain_valid(self):
        text = (self.primary_vips(BASE, 'vip_addresses=198.18.0.3/25\n',
                                  'vip_addresses6=2001:db8:1::3/80\n') + AUX +
                'vip_addresses=198.19.0.3/25\n'
                'vip_addresses6=2001:db8:2::3/80\n')
        self.assertEqual(len(self.parse(text).interfaces), 1)

    def test_disjoint_multiinterface_vip_prefixes_remain_valid(self):
        text = (self.primary_vips(BASE, 'vip_addresses=198.18.1.3/24\n',
                                  'vip_addresses6=2001:db8:1:1::3/64\n') + AUX +
                'vip_addresses=198.19.1.3/24\n'
                'vip_addresses6=2001:db8:2:1::3/64\n')
        self.assertEqual(len(self.parse(text).interfaces), 1)

    def test_overlap_rejection_precedes_library_and_worker_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'overlap.ini'
            path.write_text(self.primary_vips(BASE, 'vip_addresses=198.19.0.20/25\n') + AUX)
            result = subprocess.run([sys.executable, str(ROOT / 'tools/ker-run.py'), '--config', str(path),
                '--library', '/missing-library', '--io-worker', '/missing-worker', '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('overlap', result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__': unittest.main()
