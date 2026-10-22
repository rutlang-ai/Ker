"""Real launcher INI parsing and pre-launch rejection; no worker mocks."""
import configparser
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[2] / 'tools/ker-run.py'
spec = importlib.util.spec_from_file_location('ker_run_config', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class ConfigTests(unittest.TestCase):
    def read(self, text):
        return launcher.read_configuration(io.StringIO(text), Path('/configuration'), 'fixture.ini')

    def test_base_virtaddr_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-pci']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).base_virtaddr)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'base.ini'
            for value in ('0x200000000', '0X400000001', '0xffffffffff000000'):
                config.write_text('[dpdk]\nbase_virtaddr=' + value + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual(args.eal_args, ['--no-pci', '--base-virtaddr=' + hex(int(value, 16))])
                args = launcher.parse_arguments(base + ['--config', str(config), '--base-virtaddr', '0x600000000', '--', '/bin/true'])
                self.assertEqual(args.base_virtaddr, 0x600000000)
            for value in ('0', '0x0', '-0x1000000', '0xgg', '8589934592', '0x10000000000000000', '0xffffffffffffffff'):
                config.write_text('[dpdk]\nbase_virtaddr=' + value + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + ['--base-virtaddr=' + value, '--', '/bin/true'])
        for raw in ('--base-virtaddr=0x200000000', '--base-virtaddr 0x200000000'):
            with self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--eal=' + raw, '--base-virtaddr', '0x400000000', '--', '/bin/true'])
        args = launcher.parse_arguments(base + ['--eal=--no-pci -- --base-virtaddr=0x800000000 --',
            '--base-virtaddr', '0x400000000', '--', '/bin/true'])
        self.assertEqual(args.eal_args, ['--no-pci', '--base-virtaddr=0x400000000', '--', '--base-virtaddr=0x800000000', '--'])

    def test_file_prefix_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-pci']
        args = launcher.parse_arguments(base + ['--', '/bin/true'])
        self.assertIsNone(args.file_prefix)
        self.assertEqual(args.eal_args, ['--no-pci'])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'prefix.ini'
            for value in ('mytest', 'A1.b_c-d', 'x' * 64):
                config.write_text('[dpdk]\nfile_prefix=' + value + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual(args.eal_args, ['--no-pci', '--file-prefix=' + value])
                args = launcher.parse_arguments(base + ['--config', str(config), '--file-prefix', 'cli', '--', '/bin/true'])
                self.assertEqual(args.file_prefix, 'cli')
                self.assertEqual(args.eal_args, ['--no-pci', '--file-prefix=cli'])
            for value in ('', '.', '..', '../escape', '/absolute', 'a/b', 'a b', 'a%b', 'x' * 65, '中文', '-bad'):
                config.write_text('[dpdk]\nfile_prefix=' + value + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + ['--file-prefix=' + value, '--', '/bin/true'])
        for raw in ('--file-prefix raw', '--file-prefix=raw'):
            args = launcher.parse_arguments(base + ['--eal=' + raw, '--', '/bin/true'])
            self.assertIsNone(args.file_prefix)
            with self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--eal=' + raw, '--file-prefix', 'typed', '--', '/bin/true'])
        suffix = ['--address', '198.18.0.2/24', '--port', 'net_tap0',
                  '--eal=--no-pci -- --file-prefix=ignored -- --file-prefix=also-ignored']
        args = launcher.parse_arguments(suffix + ['--file-prefix', 'typed', '--', '/bin/true'])
        self.assertEqual(args.eal_args, ['--no-pci', '--file-prefix=typed', '--',
            '--file-prefix=ignored', '--', '--file-prefix=also-ignored'])
        with self.assertRaises(SystemExit):
            launcher.parse_arguments(base + ['--eal=--file-prefix=active -- --file-prefix=ignored',
                '--file-prefix', 'typed', '--', '/bin/true'])

    def test_eal_log_level_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-pci']
        args = launcher.parse_arguments(base + ['--', '/bin/true'])
        self.assertIsNone(args.eal_log_level)
        self.assertEqual(args.eal_args, ['--no-pci'])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'log.ini'
            for value in (1, 4, 7, 8):
                config.write_text('[dpdk]\nlog_level=' + str(value) + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual(args.eal_args, ['--no-pci', '--log-level=' + str(value)])
                args = launcher.parse_arguments(base + ['--config', str(config), '--eal-log-level', '5',
                    '--log-level', '7', '--', '/bin/true'])
                self.assertEqual(args.eal_log_level, 5)
                self.assertEqual(args.log_level, 7)
                self.assertEqual(args.eal_args, ['--no-pci', '--log-level=5'])
            for value in ('0', '-1', '9', '1.5', 'invalid'):
                config.write_text('[dpdk]\nlog_level=' + value + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + ['--eal-log-level', value, '--', '/bin/true'])
        for raw in ('--log-level 7', '--log-level=7', '--log-level debug', '--log-level=debug'):
            args = launcher.parse_arguments(base + ['--eal=' + raw, '--', '/bin/true'])
            self.assertIsNone(args.eal_log_level)
            with self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--eal=' + raw, '--eal-log-level', '4', '--', '/bin/true'])
        for raw in ('--log-level=lib.eal:debug', '--log-level lib.eal:debug',
                    '--log-level=lib[.]eal,debug'):
            args = launcher.parse_arguments(base + ['--eal=' + raw, '--eal-log-level', '7', '--', '/bin/true'])
            self.assertEqual(args.eal_args, raw.split() + ['--log-level=7'])
        raw_suffix = ['--address', '198.18.0.2/24', '--port', 'net_tap0',
            '--eal=--no-pci -- --log-level=debug -- --log-level 7']
        args = launcher.parse_arguments(raw_suffix + ['--eal-log-level', '4', '--', '/bin/true'])
        self.assertEqual(args.eal_args,
            ['--no-pci', '--log-level=4', '--', '--log-level=debug', '--', '--log-level', '7'])

    def test_eal_memory_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-pci']
        args = launcher.parse_arguments(base + ['--', '/bin/true'])
        self.assertIsNone(args.memory_mb); self.assertIsNone(args.no_huge)
        self.assertEqual(args.eal_args, ['--no-pci'])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'memory.ini'
            for text, huge_disabled in (('yes', True), ('1', True), ('off', False), ('0', False)):
                config.write_text('[dpdk]\nmemory=128\nno_huge=' + text + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual(args.memory_mb, 128); self.assertIs(args.no_huge, huge_disabled)
                self.assertEqual(args.eal_args, ['--no-pci', '-m', '128'] + (['--no-huge'] if huge_disabled else []))
                option = '--hugepages' if huge_disabled else '--no-huge'
                args = launcher.parse_arguments(base + ['--config', str(config), '--memory-mb', '64', option, '--', '/bin/true'])
                self.assertEqual(args.memory_mb, 64); self.assertIs(args.no_huge, not huge_disabled)
            for field, values in (('memory', ('0', '-1', '2147483648', '1.5', 'invalid')),
                                  ('no_huge', ('perhaps',))):
                for value in values:
                    config.write_text('[dpdk]\n' + field + '=' + value + '\n')
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
        for value in ('0', '-1', '2147483648', '1.5', 'invalid'):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--memory-mb', value, '--', '/bin/true'])
        raw = ['--address', '198.18.0.2/24', '--port', 'net_tap0',
               '--eal=--no-pci --file-prefix=raw-prefix -- -m 96 --no-huge -- --file-prefix=raw-suffix']
        args = launcher.parse_arguments(raw + ['--memory-mb', '64', '--no-huge', '--', '/bin/true'])
        self.assertEqual(args.eal_args, ['--no-pci', '--file-prefix=raw-prefix', '-m', '64',
            '--no-huge', '--', '-m', '96', '--no-huge', '--', '--file-prefix=raw-suffix'])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'memory-after-eal-separator.ini'
            config.write_text('[dpdk]\nmemory=48\nno_huge=yes\n')
            args = launcher.parse_arguments(raw + ['--config', str(config), '--', '/bin/true'])
            self.assertEqual(args.eal_args, ['--no-pci', '--file-prefix=raw-prefix', '-m', '48',
                '--no-huge', '--', '-m', '96', '--no-huge', '--', '--file-prefix=raw-suffix'])
        # Each selector is independent: conflicting-looking options after the
        # first EAL terminator are application arguments, not active EAL policy.
        args = launcher.parse_arguments(['--address', '198.18.0.2/24', '--port', 'net_tap0',
            '--eal=--no-pci -- -m 96 --no-huge -- --file-prefix=tail', '--no-huge', '--', '/bin/true'])
        self.assertEqual(args.eal_args,
            ['--no-pci', '--no-huge', '--', '-m', '96', '--no-huge', '--', '--file-prefix=tail'])
        args = launcher.parse_arguments(['--address', '198.18.0.2/24', '--port', 'net_tap0',
            '--eal=--no-pci -- --no-huge -- --file-prefix=tail', '--memory-mb', '64', '--', '/bin/true'])
        self.assertEqual(args.eal_args,
            ['--no-pci', '-m', '64', '--', '--no-huge', '--', '--file-prefix=tail'])
        args = launcher.parse_arguments(['--address', '198.18.0.2/24', '--port', 'net_tap0',
            '--eal=--no-pci -- --no-huge -- --file-prefix=tail', '--hugepages', '--', '/bin/true'])
        self.assertEqual(args.eal_args, ['--no-pci', '--', '--no-huge', '--', '--file-prefix=tail'])
        for selection in ('-m 64', '-m64', '--memory-size 64', '--memory-size=64',
                          '--numa-mem 64', '--socket-mem=64'):
            with self.subTest(selection=selection), self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--eal=' + selection, '--memory-mb', '128', '--', '/bin/true'])
        for option in ('--no-huge', '--hugepages'):
            with self.subTest(option=option), self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--eal=--no-huge', option, '--', '/bin/true'])
        with self.assertRaises(SystemExit):
            launcher.parse_arguments(base + ['--eal=--in-memory', '--no-huge', '--', '/bin/true'])
        with self.assertRaises(SystemExit):
            launcher.parse_arguments(base + ['--no-huge', '--hugepages', '--', '/bin/true'])

    def test_tx_delay_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments(base + ['--', '/bin/true']).tx_delay_us, 0)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'tx.ini'
            for value in (0, 1, 100):
                config.write_text('[dpdk]\npkt_tx_delay=' + str(value) + '\n')
                self.assertEqual(launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true']).tx_delay_us, value)
                self.assertEqual(launcher.parse_arguments(base + ['--config', str(config), '--tx-delay-us', '10', '--', '/bin/true']).tx_delay_us, 10)
            for value in ('-1', '101', '1.5', 'true', 'invalid', '999999999999999999999999999'):
                for mode in ('ini', 'cli'):
                    config.write_text('[dpdk]\npkt_tx_delay=' + value + '\n' if mode == 'ini' else '')
                    options = [] if mode == 'ini' else ['--tx-delay-us', value]
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_numa_configuration_and_cli_override(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertTrue(launcher.parse_arguments(base + ['--', '/bin/true']).numa)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'numa.ini'
            for text, expected in (('yes', True), ('1', True), ('off', False), ('0', False)):
                config.write_text('[dpdk]\nnuma_on=' + text + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertIs(args.numa, expected)
                option = '--no-numa' if expected else '--numa'
                args = launcher.parse_arguments(base + ['--config', str(config), option, '--', '/bin/true'])
                self.assertIs(args.numa, not expected)
                self.assertEqual(args.eal_args, ['--no-huge'])
            config.write_text('[dpdk]\nnuma_on=perhaps\n')
            result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_memory_channels_configuration_and_conflicts(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).memory_channels)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'channel.ini'
            for value in (1, 4, 2147483647):
                config.write_text('[dpdk]\nchannel=' + str(value) + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual(args.eal_args, ['--no-huge', '-n', str(value)])
                args = launcher.parse_arguments(base + ['--config', str(config), '--memory-channels', '2', '--', '/bin/true'])
                self.assertEqual(args.eal_args, ['--no-huge', '-n', '2'])
            for value in ('0', '-1', '2147483648', '1.5', 'true', 'invalid'):
                for mode in ('ini', 'cli'):
                    config.write_text('[dpdk]\nchannel=' + value + '\n' if mode == 'ini' else '')
                    options = [] if mode == 'ini' else ['--memory-channels', value]
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
        for option in ('--no-shconf', '--in-memory'):
            with self.subTest(option=option), self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--eal=' + option, '--memory-channels', '4', '--', '/bin/true'])
        for selection in ('-n 4', '-n4', '--memory-channels 4', '--memory-channels=4'):
            with self.subTest(selection=selection), self.assertRaises(SystemExit):
                launcher.parse_arguments(base + ['--eal=' + selection, '--memory-channels', '2', '--', '/bin/true'])
            args = launcher.parse_arguments(base + ['--eal=' + selection, '--', '/bin/true'])
            self.assertIsNone(args.memory_channels)
        raw = ['--address', '198.18.0.2/24', '--port', 'net_tap0',
               '--eal=--no-huge -- --no-shconf -n 9 -- -n 10']
        args = launcher.parse_arguments(raw + ['--memory-channels', '2', '--', '/bin/true'])
        self.assertEqual(args.eal_args, ['--no-huge', '-n', '2', '--', '--no-shconf', '-n', '9', '--', '-n', '10'])

    def test_idle_wait_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments(base + ['--', '/bin/true']).idle_sleep_us, 1000)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'idle.ini'
            for value in (0, 1, 20, 100000):
                config.write_text('[dpdk]\nidle_sleep=' + str(value) + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual(args.idle_sleep_us, value)
                args = launcher.parse_arguments(base + ['--config', str(config), '--idle-sleep-us', '10', '--', '/bin/true'])
                self.assertEqual(args.idle_sleep_us, 10)
            for value in ('-1', '100001', '1.5', 'true', 'invalid', '999999999999999999999999999'):
                for mode in ('ini', 'cli'):
                    config.write_text('[dpdk]\nidle_sleep=' + value + '\n' if mode == 'ini' else '')
                    options = [] if mode == 'ini' else ['--idle-sleep-us', value]
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_promiscuous_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).promiscuous)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'promiscuous.ini'
            for text, expected in (('yes', True), ('1', True), ('off', False), ('0', False)):
                config.write_text('[dpdk]\npromiscuous=' + text + '\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertIs(args.promiscuous, expected)
                option = '--no-promiscuous' if expected else '--promiscuous'
                args = launcher.parse_arguments(base + ['--config', str(config), option, '--', '/bin/true'])
                self.assertIs(args.promiscuous, not expected)
            config.write_text('[dpdk]\npromiscuous=perhaps\n')
            result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_vlan_ipv4_gateway(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        vlan = ['--vlan', '100=198.19.100.2/24']
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'gateway.ini'
            config.write_text('[vlan.100]\naddresses=198.19.100.2/24,2001:db8:100::2/64\ngateway=198.19.100.1\ngateway6=fe80::1\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
            self.assertEqual([(tag, str(ip)) for tag, ip in args.vlan_gateways], [(100, '198.19.100.1')])
            self.assertEqual([(tag, str(ip)) for tag, ip in args.vlan_gateways6], [(100, 'fe80::1')])
            args = launcher.parse_arguments(base + ['--config', str(config), '--vlan-gateway', '100=198.19.100.3', '--', '/bin/true'])
            self.assertEqual([(tag, str(ip)) for tag, ip in args.vlan_gateways], [(100, '198.19.100.3')])
            for value in ('0.0.0.0', '127.0.0.1', '224.0.0.1', '255.255.255.255', '198.19.100.255',
                          '198.19.100.2', 'fe80::1', 'invalid'):
                for mode in ('ini', 'cli'):
                    config.write_text('[vlan.100]\naddresses=198.19.100.2/24\n' +
                        ('gateway=' + value + '\n' if mode == 'ini' else ''))
                    options = [] if mode == 'ini' else ['--vlan-gateway', '100=' + value]
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
            for extra in (
                    ['--vlan-gateway', '200=198.19.100.1'],
                    ['--vlan-gateway', '4095=198.19.100.1'],
                    ['--vlan-gateway', '100=198.19.100.1', '--vlan-gateway', '100=198.19.100.3'],
                    ['--gateway', '198.18.0.1', '--vlan-gateway', '100=198.19.100.1']):
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + vlan + extra + ['--', '/bin/true'])
            for extra in ([], ['--vlan', '100=2001:db8::2/64']):
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + extra + ['--vlan-gateway', '100=198.19.100.1', '--', '/bin/true'])
            # /31 has no subnet broadcast: the other point-to-point endpoint is a valid next hop.
            args = launcher.parse_arguments(base + ['--vlan', '100=198.19.100.0/31',
                '--vlan-gateway', '100=198.19.100.1', '--', '/bin/true'])
            self.assertEqual(str(args.vlan_gateways[0][1]), '198.19.100.1')

    def test_vlan_ipv6_gateway(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        vlan = ['--vlan', '100=2001:db8:1::2/64']
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'gateway.ini'
            config.write_text('[vlan.100]\naddresses=2001:db8:1::2/64\ngateway6=2001:db8:1::1\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
            self.assertEqual([(tag, str(ip)) for tag, ip in args.vlan_gateways6], [(100, '2001:db8:1::1')])
            args = launcher.parse_arguments(base + ['--config', str(config), '--vlan-gateway6', '100=fe80::1', '--', '/bin/true'])
            self.assertEqual([(tag, str(ip)) for tag, ip in args.vlan_gateways6], [(100, 'fe80::1')])
            for value in ('100=::', '100=::1', '100=ff02::1', '100=fe80::1%ker.100',
                          '100=::ffff:198.18.0.1', '100=198.18.0.1', '4095=fe80::1', 'x=fe80::1'):
                result = subprocess.run([sys.executable, str(SOURCE), *base, *vlan,
                    '--vlan-gateway6', value, '--library', '/missing-library', '--', '/bin/true'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                config.write_text('[vlan.100]\naddresses=2001:db8:1::2/64\ngateway6=' + value.split('=', 1)[1] + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                # The final two values have invalid tags only; their IP itself is valid in INI vlan.100.
                if value.split('=', 1)[0] == '100':
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
            for extra in (
                    ['--vlan-gateway6', '200=fe80::1'],
                    ['--vlan-gateway6', '100=2001:db8:1::2'],
                    ['--vlan-gateway6', '100=fe80::1', '--vlan-gateway6', '100=fe80::2'],
                    ['--address6', '2001:db8:3::2/64', '--gateway6', '2001:db8:3::1', '--vlan-gateway6', '100=fe80::1']):
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + vlan + extra + ['--', '/bin/true'])
            for extra in ([], ['--vlan', '100=198.19.0.2/24']):
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + extra + ['--vlan-gateway6', '100=fe80::1', '--', '/bin/true'])

    def test_ipv6_and_mixed_vlan_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        mixed = '100=198.19.100.2/24,2001:db8:100::2/64,2001:db8:100::3/128'
        args = launcher.parse_arguments(base + ['--vlan', mixed, '--vlan', '200=2001:db8:200::2/64', '--', '/bin/true'])
        self.assertIsNone(args.address6)
        self.assertEqual([v.version for v in args.vlans[0][1]], [4, 6, 6])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'vlan.ini'
            config.write_text('[vlan.100]\naddresses=2001:db8:100::2/64\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--vlan', mixed, '--', '/bin/true'])
            self.assertEqual(len(args.vlans[0][1]), 3)
            for addresses in ('::/64', '::1/128', 'ff02::1/64', 'fe80::2%eth0/64',
                              '::ffff:198.18.0.3/128', '2001:db8::2/129',
                              '2001:db8::2/64,2001:db8::2/128',
                              ','.join(f'2001:db8::{i}/64' for i in range(2, 11))):
                for mode in ('ini', 'cli'):
                    config.write_text('[vlan.100]\naddresses=' + addresses + '\n' if mode == 'ini' else '')
                    options = [] if mode == 'ini' else ['--vlan', '100=' + addresses]
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
            config.write_text('')
            for options in (
                    ['--address6', '2001:db8::2/64', '--vlan', '100=2001:db8::2/128'],
                    ['--address6', '2001:db8::2/64', '--vip-address6', '2001:db8::3/64', '--vlan', '100=2001:db8::3/128'],
                    ['--vlan', '100=2001:db8::2/64', '--vlan', '200=2001:db8::2/128']):
                with self.assertRaises(SystemExit):
                    launcher.parse_arguments(base + options + ['--', '/bin/true'])
            maximum = [item for tag in range(100, 116) for item in ('--vlan', f'{tag}=' +
                ','.join(f'2001:db8:1234:5678:9abc:def0:{tag:x}:{i:x}/128' for i in range(2, 10)))]
            args = launcher.parse_arguments(base + maximum + ['--', '/bin/true'])
            self.assertEqual(len(args.vlans), 16)
            self.assertTrue(all(len(values) == 8 for _, values in args.vlans))

    def test_ipv6_vip_configuration_and_prelaunch_rejection(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments(base + ['--', '/bin/true']).vip_addresses6, [])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'vip6.ini'
            config.write_text('[network]\naddress6=2001:db8:1::2/64\nvip_addresses6=2001:db8:1::3/64,2001:db8:1::4/96\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
            self.assertEqual(list(map(str, args.vip_addresses6)), ['2001:db8:1::3/64', '2001:db8:1::4/96'])
            args = launcher.parse_arguments(base + ['--config', str(config), '--vip-address6',
                '2001:db8:2::5/128', '--', '/bin/true'])
            self.assertEqual(list(map(str, args.vip_addresses6)), ['2001:db8:2::5/128'])
            for count in (32, 33):
                config.write_text('[network]\naddress6=2001:db8:1::2/64\nvip_addresses6=' +
                    ','.join(f'2001:db8:1::{i:x}/64' for i in range(16, 16 + count)) + '\n')
                if count == 32:
                    self.assertEqual(len(launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true']).vip_addresses6), 32)
                else:
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
            for value in ('::/64', '::1/128', 'ff02::1/64', '::ffff:198.18.0.3/128',
                          'fe80::3%eth0/64', '198.18.0.3/24', '2001:db8::3/129',
                          '2001:db8:1::2/96', '2001:db8:1::3/64,2001:db8:1::3/96'):
                for mode in ('ini', 'cli'):
                    config.write_text('[network]\naddress6=2001:db8:1::2/64\n' +
                        ('vip_addresses6=' + value + '\n' if mode == 'ini' else ''))
                    options = [] if mode == 'ini' else ['--vip-address6', value]
                    result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                        *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
            config.write_text('[network]\naddress6=2001:db8:1::2/64\n')
            for options in (
                    ['--vip-address6', '2001:db8:1::3/64', '--vip-address6', '2001:db8:1::3/96'],
                    ['--vip-address6', '2001:db8:1::2/128'],
                    [item for i in range(16, 49) for item in ('--vip-address6', f'2001:db8:1::{i:x}/128')]):
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('--vip-address6', result.stderr)
            config.write_text('[network]\nvip_addresses6=2001:db8::3/64\n')
            result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('requires --address6', result.stderr)

    def test_ephemeral_port_range_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertNotIn('net.ipv4.ip_local_port_range', launcher.parse_arguments(base + ['--', '/bin/true']).sysctls)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'ports.ini'
            config.write_text('[network]\nephemeral_ports=40000-40007\n')
            args = launcher.parse_arguments([*base, '--config', str(config), '--', '/bin/true'])
            self.assertEqual(args.sysctls['net.ipv4.ip_local_port_range'], '40000 40007')
            args = launcher.parse_arguments([*base, '--config', str(config), '--ephemeral-ports',
                '41000-41007', '--', '/bin/true'])
            self.assertEqual(args.sysctls['net.ipv4.ip_local_port_range'], '41000 41007')
        for text, expected in [('1024-1024', (1024, 1024)), ('1024-65535', (1024, 65535)), ('65535-65535', (65535, 65535))]:
            self.assertEqual(launcher.ephemeral_ports(text), expected)
        for value in ('0-4', '1-1', '1023-1024', '4-3', '1-65536', '-1-3', '1', '1:3', '1-2-3', 'x-y', ' 1-2', '1-2\n'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                launcher.ephemeral_ports(value)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'ports.ini'
            for text, options in [('[network]\nephemeral_ports=4-3\n', []),
                    ('[network]\nephemeral_ports=1-1\n', []),
                    ('', ['--ephemeral-ports', '1-1']),
                    ('', ['--ephemeral-ports', '4-3']),
                    ('[network]\nephemeral_ports=40000-40007\n[sysctl]\nnet.ipv4.ip_local_port_range=41000 41007\n', []),
                    ('', ['--ephemeral-ports', '40000-40007', '--sysctl', 'net.ipv4.ip_local_port_range=41000 41007'])]:
                config.write_text(text)
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    *options, '--library', '/missing-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_ephemeral_range_conflicts_with_unprivileged_port_start_sysctl(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        generic = launcher.parse_arguments(base + ['--sysctl',
            'net.ipv4.ip_unprivileged_port_start=2000', '--', '/bin/true'])
        self.assertEqual(generic.sysctls['net.ipv4.ip_unprivileged_port_start'], '2000')
        range_key = 'net.ipv4.ip_local_port_range'
        boundary_key = 'net.ipv4.ip_unprivileged_port_start'
        generic_pair = ['--sysctl', range_key + '=50000 50007',
                        '--sysctl', boundary_key + '=50000']
        cli_order = launcher.parse_arguments(base + generic_pair + ['--', '/bin/true'])
        self.assertEqual(list(cli_order.sysctls), [range_key, boundary_key])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'ports.ini'
            ttl_key = 'net.ipv4.ip_default_ttl'
            syncookies_key = 'net.ipv4.tcp_syncookies'
            config.write_text('[sysctl]\n' + ttl_key + '=65\n' + boundary_key + '=1024\n' +
                range_key + '=40000 40007\n' + syncookies_key + '=1\n')
            ini_order = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
            self.assertEqual(list(ini_order.sysctls), [ttl_key, boundary_key, range_key, syncookies_key])
            cli_override_order = launcher.parse_arguments(base + ['--config', str(config),
                '--sysctl', range_key + '=50000 50007', '--sysctl', boundary_key + '=50000',
                '--', '/bin/true'])
            self.assertEqual(list(cli_override_order.sysctls),
                [ttl_key, syncookies_key, range_key, boundary_key])
            self.assertEqual(cli_override_order.sysctls[range_key], '50000 50007')
            self.assertEqual(cli_override_order.sysctls[boundary_key], '50000')
            cli_aba_order = launcher.parse_arguments(base + ['--config', str(config),
                '--sysctl', range_key + '=50000 50007', '--sysctl', boundary_key + '=50000',
                '--sysctl', range_key + '=51000 51007', '--', '/bin/true'])
            self.assertEqual(list(cli_aba_order.sysctls),
                [ttl_key, syncookies_key, boundary_key, range_key])
            self.assertEqual(cli_aba_order.sysctls[range_key], '51000 51007')
            conflicts = [
                ('[network]\nephemeral_ports=1024-1024\n',
                 ['--sysctl', 'net.ipv4.ip_unprivileged_port_start=2000']),
                ('[sysctl]\nnet.ipv4.ip_unprivileged_port_start=2000\n',
                 ['--ephemeral-ports', '1024-1024']),
                ('[network]\nephemeral_ports=1024-1024\n[sysctl]\n'
                 'net.ipv4.ip_unprivileged_port_start=2000\n', []),
                ('', ['--ephemeral-ports', '1024-1024', '--sysctl',
                      'net.ipv4.ip_unprivileged_port_start=2000']),
            ]
            for text, options in conflicts:
                with self.subTest(config=text, options=options):
                    config.write_text(text)
                    result = subprocess.run([sys.executable, str(SOURCE), *base,
                        '--config', str(config), *options, '--library', '/missing-library',
                        '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('--ephemeral-ports conflicts with sysctl '
                        'net.ipv4.ip_unprivileged_port_start', result.stderr)
                    self.assertNotIn('/missing-library', result.stderr)
                    self.assertNotIn('Traceback', result.stderr)

    def test_vlan_configuration_and_cli_replacement(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments([*base, '--', '/bin/true']).vlans, ())
        values = self.read('[vlan.100]\naddresses=198.19.100.2/24,198.19.100.3/24\n[vlan.200]\naddresses=198.19.200.2/24\n')
        self.assertEqual([tag for tag, _ in values['vlans']], [100, 200])
        self.assertEqual(len(values['vlans'][0][1]), 2)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'vlan.ini'
            config.write_text('[vlan.100]\naddresses=198.19.100.2/24\n')
            args = launcher.parse_arguments([*base, '--config', str(config), '--vlan', '200=198.19.200.2/24', '--', '/bin/true'])
            self.assertEqual([tag for tag, _ in args.vlans], [200])
        for value in ('0=198.19.1.2/24', '4095=198.19.1.2/24', 'x=198.19.1.2/24',
                      '100=', '100=::1/64', '100=224.0.0.1/24', '100=0.0.0.0/24',
                      '100=198.19.1.2/24,198.19.1.2/24'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                launcher.vlan_setting(value)
        for options in (['--vlan', '100=198.18.0.2/24'],
                        ['--vlan', '100=198.19.1.2/24', '--vlan', '100=198.19.2.2/24'],
                        ['--vlan', '100=198.19.1.2/24', '--vlan', '200=198.19.1.2/24']):
            with self.subTest(options=options), self.assertRaises(SystemExit):
                launcher.parse_arguments([*base, *options, '--', '/bin/true'])
        for text in ('[vlan.100]\nunknown=1\n', '[vlan.4095]\naddresses=198.19.1.2/24\n'):
            with self.assertRaises(ValueError):
                self.read(text)

    def test_mbuf_mode_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments([*base, "--", "/bin/true"]).mbuf_mode, 'large')
        self.assertEqual(launcher.parse_arguments([*base, '--mbuf-mode', 'scatter', '--', '/bin/true']).mbuf_mode, 'scatter')
        self.assertEqual(self.read('[dpdk]\nmbuf_mode=scatter\n')['mbuf_mode'], 'scatter')
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'mode.ini'
            config.write_text('[dpdk]\nmbuf_mode=scatter\n')
            self.assertEqual(launcher.parse_arguments([*base, '--config', str(config), '--mbuf-mode', 'large', '--', '/bin/true']).mbuf_mode, 'large')
            config.write_text('[dpdk]\nmbuf_mode=invalid\n')
            result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                                     '--library', '/must-not-resolve', '--', '/bin/true'],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertIn('--mbuf-mode', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_ipv6_gateway_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).gateway6)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gateway.ini'
            path.write_text('[network]\naddress6=2001:db8:1::2/64\ngateway6=2001:db8:1::1\n')
            args = launcher.parse_arguments(base + ['--config', str(path), '--', '/bin/true'])
            self.assertEqual(str(args.gateway6), '2001:db8:1::1')
            args = launcher.parse_arguments(base + ['--config', str(path), '--gateway6', 'fe80::1', '--', '/bin/true'])
            self.assertEqual(str(args.gateway6), 'fe80::1')
        for options in (['--gateway6', '2001:db8::1'], *(
                ['--address6', '2001:db8::2/64', '--gateway6', address]
                for address in ('192.0.2.1', '::', '::1', 'ff02::1', '::ffff:192.0.2.1', 'fe80::1%eth0'))):
            result = subprocess.run([sys.executable, str(SOURCE), *base, *options,
                '--library', '/missing-ker-library', '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_ipv6_address_configuration(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).address6)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'ipv6.ini'
            config.write_text('[network]\naddress6=2001:db8:1::99/64\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
            self.assertEqual(str(args.address6), '2001:db8:1::99/64')
            args = launcher.parse_arguments(base + ['--config', str(config), '--address6',
                '2001:db8:1::2/96', '--', '/bin/true'])
            self.assertEqual(str(args.address6), '2001:db8:1::2/96')
            self.assertEqual(str(args.address), '198.18.0.2/24')
        for address in ('fe80::100/64', '2001:db8::2/128'):
            self.assertEqual(str(launcher.parse_arguments(base + ['--address6', address,
                '--', '/bin/true']).address6), address)
        for address in ('198.18.0.2/24', '::/64', '::1/128', 'ff02::1/64',
                        '::ffff:192.0.2.1/128', 'fe80::2%eth0/64', '2001:db8::2/129'):
            result = subprocess.run([sys.executable, str(SOURCE), *base, '--address6', address,
                '--library', '/missing-ker-library', '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('Traceback', result.stderr)

    def test_max_mtu_policy_and_cli_override(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        args = launcher.parse_arguments(base + ['--', '/bin/true'])
        self.assertEqual((args.mtu, args.max_mtu), (1500, 9000))
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'mtu.ini'
            for mtu, ceiling in ((1280, 1280), (1500, 2000), (2000, 2000), (9000, 9000)):
                config.write_text(f'[network]\nmtu={mtu}\nmax_mtu={ceiling}\n')
                args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual((args.mtu, args.max_mtu), (mtu, ceiling))
            config.write_text('[network]\nmtu=9000\nmax_mtu=2000\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--max-mtu', '9000', '--', '/bin/true'])
            self.assertEqual((args.mtu, args.max_mtu), (9000, 9000))
            args = launcher.parse_arguments(base + ['--config', str(config), '--mtu', '2000', '--', '/bin/true'])
            self.assertEqual((args.mtu, args.max_mtu), (2000, 2000))

    def test_max_mtu_rejection_precedes_launch_setup(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'mtu.ini'
            for mtu, ceiling in ((9000, '2000'), (2001, '2000'), (1500, 'bad'),
                                 (1500, '1279'), (1500, '9001'), (1500, '65535')):
                config.write_text(f'[network]\nmtu={mtu}\nmax_mtu={ceiling}\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', str(Path(directory) / 'missing'), '--', '/bin/true'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                diagnostic = result.stderr.strip().splitlines()[-1]
                self.assertIn('max_mtu' if ceiling == 'bad' else '--max-mtu', diagnostic)
                if ceiling == '2000':
                    self.assertIn('must not exceed', diagnostic)
                self.assertNotIn('Traceback', result.stderr)
                self.assertNotIn('No such file or directory', result.stderr)
            result = subprocess.run([sys.executable, str(SOURCE), *base, '--mtu', '9000',
                '--max-mtu', '2000', '--library', str(Path(directory) / 'missing'), '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('--max-mtu', result.stderr)

    def test_network_sysctl_merge_and_bounds(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments(base + ['--', '/bin/true']).sysctls, {})
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'sysctl.ini'
            config.write_text('[sysctl]\nnet.ipv4.ip_default_ttl=65\nnet.ipv4.tcp_rmem=4096 87380 6291456\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--sysctl',
                'net.ipv4.ip_default_ttl=66', '--sysctl', 'net.ipv4.ip_default_ttl=67', '--', '/bin/true'])
            self.assertEqual(args.sysctls, {'net.ipv4.ip_default_ttl': '67',
                'net.ipv4.tcp_rmem': '4096 87380 6291456'})
            config.write_text('[sysctl]\n' + ''.join(f'net.ipv4.key{i}=1\n' for i in range(32)))
            self.assertEqual(len(launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true']).sysctls), 32)

    def test_network_sysctl_rejection_before_setup(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        bad = ['net.ipv4.ttl', 'net.ipv4.ttl=', 'kernel.hostname=x', 'net/ipv4/ttl=1',
            'net..ttl=1', 'net.ipv4.=1', 'net.ipv4.ttl=1\n2', 'net.ipv4.' + 'x' * 128 + '=1',
            'net.ipv4.ttl=' + 'x' * 257]
        for value in bad:
            result = subprocess.run([sys.executable, str(SOURCE), *base, '--sysctl', value,
                '--library', '/missing-ker-library', '--', '/bin/true'], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertNotIn('Traceback', result.stderr)
        for options in ([item for i in range(33) for item in ('--sysctl', f'net.ipv4.key{i}=1')],
                        ['--tcp-ecn', 'on', '--sysctl', 'net.ipv4.tcp_ecn=1']):
            with self.assertRaises(SystemExit) as error:
                launcher.parse_arguments(base + options + ['--', '/bin/true'])
            self.assertEqual(error.exception.code, 2)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'bad.ini'
            for text in ('[sysctl]\nnet.ipv4.ttl=1\n  2\n', '[sysctl]\nkernel.hostname=x\n'):
                config.write_text(text)
                with self.assertRaises(SystemExit) as error:
                    launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
                self.assertEqual(error.exception.code, 2)

    def test_vip_addresses_and_cli_replacement(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments(base + ['--', '/bin/true']).vip_addresses, [])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'vip.ini'
            config.write_text('[network]\nvip_addresses = 198.18.0.3/24, 198.18.0.4/24\n')
            args = launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true'])
            self.assertEqual(list(map(str, args.vip_addresses)), ['198.18.0.3/24', '198.18.0.4/24'])
            args = launcher.parse_arguments(base + ['--config', str(config), '--vip-address', '198.18.0.5',
                '--vip-address', '198.18.0.6/25', '--', '/bin/true'])
            self.assertEqual(list(map(str, args.vip_addresses)), ['198.18.0.5/32', '198.18.0.6/25'])
            config.write_text('[network]\nvip_addresses=' + ','.join(
                '198.18.0.' + str(i) + '/24' for i in range(3, 35)) + '\n')
            self.assertEqual(len(launcher.parse_arguments(base + ['--config', str(config),
                '--', '/bin/true']).vip_addresses), 32)
            config.write_text('[network]\nvip_addresses=\n')
            self.assertEqual(launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true']).vip_addresses, [])

    def test_vip_rejection_precedes_library_resolution(self):
        base = ['--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'vip.ini'
            cases = ['198.18.0.2/24', '198.18.0.3/24,198.18.0.3/25', '::1/128',
                     'bad', '198.18.0.3/33', '198.18.0.3/24,,198.18.0.4/24',
                     ','.join('198.18.0.' + str(i) + '/24' for i in range(3, 36))]
            for value in cases:
                config.write_text('[network]\nvip_addresses=' + value + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', str(Path(directory) / 'missing'), '--', '/bin/true'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('vip', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_lcore_mask_syntax_precedence_and_actual_eal_tokens(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).lcore_mask)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cores.ini'
            for value, expected in [('0X5', '5'), ('  0x5  ', '5'), ('A0', 'a0'), ('0001', '1')]:
                path.write_text('[dpdk]\nlcore_mask=' + value + '\n')
                args = launcher.parse_arguments(base + ['--config', str(path), '--', '/bin/true'])
                self.assertEqual(args.lcore_mask, expected)
                self.assertEqual(args.eal_args, ['--no-huge', '-c', expected])
                self.assertEqual(int(args.lcore_mask, 16).bit_count(), int(value, 16).bit_count())
                self.assertEqual(str(args.address), '192.0.2.2/24')
                self.assertEqual(args.port, 'net_tap0')
                override = launcher.parse_arguments(base + ['--config', str(path), '--lcore-mask', '2', '--', '/bin/true'])
                self.assertEqual(override.eal_args, ['--no-huge', '-c', '2'])
            for value in ('ZZZ_NOT_HEX', '0x1Z', '', '   ', '0', '0x0000', '-1', '+1', '1 2', '0x'):
                path.write_text('[dpdk]\nlcore_mask=' + value + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(path),
                    '--library', str(Path(directory) / 'missing'), '--io-worker', str(Path(directory) / 'missing-worker'),
                    '--', '/bin/true'], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('nonzero hexadecimal', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
            # Validate only the winning value after CLI precedence.
            path.write_text('[dpdk]\nlcore_mask=invalid\n')
            self.assertEqual(launcher.parse_arguments(base + ['--config', str(path), '--lcore-mask', '2',
                '--', '/bin/true']).eal_args[-2:], ['-c', '2'])
        raw = ['--address', '192.0.2.2/24', '--port', 'net_tap0',
               '--eal=--no-huge -- --lcores=0@1 -c 7 -- -c 8']
        args = launcher.parse_arguments(raw + ['--lcore-mask', '2', '--', '/bin/true'])
        self.assertEqual(args.eal_args,
            ['--no-huge', '-c', '2', '--', '--lcores=0@1', '-c', '7', '--', '-c', '8'])

    def test_lcore_mask_rejects_competing_eal_cpu_selection(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--lcore-mask', '1']
        for selection in ('-c 2', '-c2', '-l 1', '-l1', '--lcores=0@1', '--lcores 0@1'):
            with self.subTest(selection=selection), self.assertRaises(SystemExit) as caught:
                launcher.parse_arguments(base + ['--eal=' + selection, '--', '/bin/true'])
            self.assertEqual(caught.exception.code, 2)
        args = launcher.parse_arguments(base + ['--eal=--log-level=7 --main-lcore=0', '--', '/bin/true'])
        self.assertEqual(args.eal_args, ['--log-level=7', '--main-lcore=0', '-c', '1'])

    def test_mtu_defaults_ranges_and_cli_precedence(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertEqual(launcher.parse_arguments(base + ['--', '/bin/true']).mtu, 1500)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'mtu.ini'
            config.write_text('[network]\nmtu=9000\n')
            self.assertEqual(launcher.parse_arguments(base + ['--config', str(config), '--', '/bin/true']).mtu, 9000)
            self.assertEqual(launcher.parse_arguments(base + ['--config', str(config), '--mtu', '1280', '--', '/bin/true']).mtu, 1280)
            for text in ('not-a-number', '1279', '9001', '65535'):
                config.write_text('[network]\nmtu=' + text + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(config),
                    '--library', str(Path(directory) / 'missing'), '--', '/bin/true'], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertIn('mtu', result.stderr)
            for text in ('0', '9001', '65535'):
                with self.assertRaises(SystemExit) as caught:
                    launcher.parse_arguments(base + ['--mtu', text, '--', '/bin/true'])
                self.assertEqual(caught.exception.code, 2)

    def test_tcp_ecn_policy_and_cli_override(self):
        base = ['--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge']
        self.assertIsNone(launcher.parse_arguments(base + ['--', '/bin/true']).tcp_ecn)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ecn.ini'
            for mode, value in [('off', 0), ('passive', 2), ('on', 1)]:
                path.write_text('[network]\ntcp_ecn=' + mode + '\n')
                parsed = launcher.parse_arguments(base + ['--config', str(path), '--', '/bin/true'])
                self.assertEqual(str(parsed.address), '192.0.2.2/24')
                self.assertEqual(parsed.port, 'net_tap0')
                self.assertEqual(parsed.eal_args, ['--no-huge'])
                self.assertEqual(parsed.tcp_ecn, mode)
                self.assertEqual(launcher.TCP_ECN[parsed.tcp_ecn], value)
                self.assertEqual(launcher.parse_arguments(base + ['--config', str(path),
                    '--tcp-ecn', 'off', '--', '/bin/true']).tcp_ecn, 'off')
            for mode in ('1', 'garbage', ''):
                path.write_text('[network]\ntcp_ecn=' + mode + '\n')
                result = subprocess.run([sys.executable, str(SOURCE), *base, '--config', str(path),
                    '--library', str(Path(directory) / 'missing'), '--', '/bin/true'],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('tcp-ecn', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_basic_and_multiple_sections(self):
        values = self.read('[network]\naddress=192.0.2.2/24\ngateway=192.0.2.1\n'
                           '[dpdk]\nport=net_tap0\neal=--no-huge\n'
                           '[logging]\ndirectory=logs\nlevel=7\n'
                           '[capture]\ndirectory=pcap\nsnaplen=96\nmax_bytes=4096\nnsec=yes\n'
                           '[runtime]\nshutdown_timeout_ms=1000\nstats=stats.json\n')
        self.assertEqual(str(values['address']), '192.0.2.2/24')
        self.assertEqual(str(values['gateway']), '192.0.2.1')
        self.assertEqual(values['port'], 'net_tap0')
        self.assertEqual(values['eal'], '--no-huge')
        self.assertEqual(values['log_dir'], Path('/configuration/logs'))
        self.assertEqual(values['stats'], Path('/configuration/stats.json'))
        self.assertEqual((values['pcap_snaplen'], values['pcap_max_bytes'], values['pcap_nsec']), (96, 4096, True))
        self.assertEqual(values['shutdown_timeout_ms'], 1000)

    def test_comments_whitespace_and_literal_interpolation(self):
        values = self.read('; comment\n# comment\n [dpdk] \n port = net_tap0 ; inline\n'
                           'eal = --file-prefix=100%literal#value\n')
        self.assertEqual(values, dict(port='net_tap0', eal='--file-prefix=100%literal#value'))

    def test_empty_value_empty_input_and_missing_final_newline(self):
        self.assertEqual(self.read('[dpdk]\neal=\n'), {'eal': ''})
        self.assertEqual(self.read(''), {})
        self.assertEqual(self.read('\n'), {})
        self.assertEqual(self.read('[dpdk]\nport=net_tap0'), {'port': 'net_tap0'})

    def test_colon_and_multiline(self):
        values = self.read('[dpdk]\nport:net_tap0\neal=--no-huge\n  --no-pci\n  --no-shconf\n')
        self.assertEqual(values['port'], 'net_tap0')
        self.assertEqual(values['eal'].split(), ['--no-huge', '--no-pci', '--no-shconf'])

    def test_bom_and_open_file(self):
        self.assertEqual(self.read('\ufeff[dpdk]\nport=net_tap0\n'), {'port': 'net_tap0'})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            path.write_bytes(b'\xef\xbb\xbf[dpdk]\nport=net_tap0\n')
            self.assertEqual(launcher.load_configuration(path), {'port': 'net_tap0'})
            with path.open(encoding='utf-8') as stream:
                self.assertEqual(launcher.read_configuration(stream, path.parent, path), {'port': 'net_tap0'})
            with self.assertRaises(FileNotFoundError):
                launcher.load_configuration(Path(directory) / 'missing')
            for prefix in (b'\xefA', b'\xef\xbbX'):
                path.write_bytes(prefix + b'\n[dpdk]\nport=net_tap0\n')
                with self.assertRaises(UnicodeError):
                    launcher.load_configuration(path)

    def test_syntax_errors_include_line(self):
        for text, line in (('[dpdk\nport=x\n', 1), ('[dpdk]\ninvalid_no_eq\n', 2),
                           ('[dpdk]\nbare_line_no_eq\n', 2)):
            with self.subTest(text=text), self.assertRaises(configparser.Error) as caught:
                self.read(text)
            self.assertIn(str(line), str(caught.exception))

    def test_explicit_boundaries(self):
        for text in ('port=x\n', '[unknown]\nport=x\n', '[dpdk]\nunknown=x\n',
                     '[DEFAULT]\nport=x\n', '[dpdk]\nport=a\nport=b\n',
                     '[dpdk]\nall_multicast=perhaps\n', '[network]\naddress=invalid\n'):
            with self.subTest(text=text), self.assertRaises((configparser.Error, ValueError)):
                self.read(text)

    def test_cli_overrides_file_and_keeps_application_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            path.write_text('[network]\naddress=192.0.2.2/24\n[dpdk]\nport=file-port\neal=\nall_multicast=yes\n'
                            '[capture]\nnsec=yes\n[runtime]\nstats=file.json\n')
            args = launcher.parse_arguments(['--config', str(path), '--port', 'cli-port',
                '--no-all-multicast', '--no-pcap-nsec', '--stats', 'cli.json', '--',
                '/bin/program', '--config', 'application.ini'])
            self.assertEqual(args.port, 'cli-port')
            self.assertEqual(args.stats, Path('cli.json'))
            self.assertFalse(args.all_multicast or args.pcap_nsec)
            self.assertEqual(args.command, ['/bin/program', '--config', 'application.ini'])

    def test_eal_is_validated_after_cli_overrides_and_tokens_are_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.ini'
            path.write_text('[network]\naddress=192.0.2.2/24\n[dpdk]\nport=file-port\n'
                            'eal=--file-prefix="unterminated\n')
            with self.assertRaises(SystemExit) as caught:
                launcher.parse_arguments(['--config', str(path), '--', '/bin/true'])
            self.assertEqual(caught.exception.code, 2)

            args = launcher.parse_arguments(['--config', str(path),
                '--eal=--file-prefix="prefix with spaces" --no-huge', '--', '/bin/true'])
            self.assertEqual(args.eal_args, ['--file-prefix=prefix with spaces', '--no-huge'])

            args = launcher.parse_arguments(['--address', '192.0.2.2/24', '--port', 'cli-port',
                '--eal=--file-prefix="prefix with spaces"', '--', '/bin/true'])
            self.assertEqual(args.eal_args, ['--file-prefix=prefix with spaces'])

    def test_bad_configuration_is_rejected_before_resolving_or_starting_workers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.ini'
            for text in ('[dpdk]\nunknown=x\n', '[runtime]\nshutdown_timeout_ms=60001\n',
                         '[logging]\nlevel=9\n', '[capture]\nsnaplen=0\n', '[network]\naddress=bad\n'):
                path.write_text(text)
                result = subprocess.run([sys.executable, str(SOURCE), '--config', str(path),
                    '--address', '192.0.2.2/24', '--port', 'net_tap0', '--eal=--no-huge',
                    '--library', str(Path(directory) / 'nonexistent-library'),
                    '--io-worker', str(Path(directory) / 'nonexistent-worker'), '--', '/bin/true'],
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn('Traceback', result.stderr)

            path.write_text('[network]\naddress=192.0.2.2/24\n[dpdk]\nport=net_tap0\n'
                            'eal=--file-prefix="unterminated\n')
            result = subprocess.run([sys.executable, str(SOURCE), '--config', str(path),
                '--library', str(Path(directory) / 'nonexistent-library'), '--io-worker',
                str(Path(directory) / 'nonexistent-worker'), '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('--eal:', result.stderr)
            self.assertNotIn('nonexistent-library', result.stderr)
            self.assertNotIn('Traceback', result.stderr)

            result = subprocess.run([sys.executable, str(SOURCE), '--address', '192.0.2.2/24',
                '--port', 'net_tap0', '--eal=--file-prefix="unterminated', '--library',
                str(Path(directory) / 'nonexistent-library'), '--io-worker',
                str(Path(directory) / 'nonexistent-worker'), '--', '/bin/true'],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('--eal:', result.stderr)
            self.assertNotIn('nonexistent-library', result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
