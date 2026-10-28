"""Individually selectable source scenarios through Ker's production reader/CLI.

These are configuration tests, not network or F-Stack ABI evidence. Existing
source-case completion counts are deliberately unchanged by this regression batch.
"""
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tools/ker-run.py'
spec = importlib.util.spec_from_file_location('fstack_config_cases', SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
BASE = '[network]\naddress=198.18.0.2/24\n[dpdk]\nport=net_tap0\neal=--no-huge --no-pci\n'


def upstream(file, case):
    def decorate(method):
        method.source_id = f'tests/unit/test_ff_{file}.c::{case}'
        return method
    return decorate


def ini(case):
    return upstream('ini_parser', 'test_ini_parse_' + case)


def cfg(case):
    return upstream('config', 'test_' + case)


class SourceCases(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='ker-config-case-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / 'case.ini'
        self.marker = self.root / 'executed'
        self.worker = self.root / 'worker'
        self.worker.write_text('#!/bin/sh\ntouch "' + str(self.marker) + '"\nexit 99\n')
        self.worker.chmod(0o700)

    def read(self, text):
        return launcher.read_configuration(io.StringIO(text), self.root, 'case.ini')

    def parse(self, text=BASE, *extra):
        self.path.write_text(text)
        return launcher.parse_arguments(['--config', str(self.path), *extra, '--', '/bin/true'])

    def reject(self, text, diagnostic, *extra):
        self.path.write_text(text)
        self.reject_file(diagnostic, *extra)

    def reject_file(self, diagnostic, *extra):
        result = subprocess.run([sys.executable, str(SOURCE), '--config', str(self.path),
            '--library', '/missing-library', '--io-worker', str(self.worker),
            *extra, '--', str(self.worker)], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('error:', result.stderr)
        self.assertIn(diagnostic, result.stderr.split('error:', 1)[1])
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(self.marker.exists(), result.stderr)
        # Every failed CLI load is followed by a real successful parse in this
        # process. Invalid input must not change defaults or retain records.
        recovered = self.parse()
        self.assertEqual(str(recovered.address), '198.18.0.2/24')
        self.assertEqual(recovered.interfaces, ())
        self.assertEqual(recovered.vlans, ())

    @ini('stream_valid_basic')
    def test_ini_basic(self):
        values = self.read('[network]\naddress=192.168.1.10/24\ngateway=192.168.1.1\n')
        self.assertEqual(str(values['address']), '192.168.1.10/24')
        self.assertEqual(str(values['gateway']), '192.168.1.1')
        self.assertEqual(set(values), {'address', 'gateway'})

    @ini('stream_multiple_sections')
    def test_ini_sections(self):
        values = self.read('[logging]\nlevel=7\n[dpdk]\nlog_level=3\n[logging]\ndirectory=logs\n')
        self.assertEqual(values, {'log_level': 7, 'log_dir': self.root/'logs', 'eal_log_level': 3})

    @ini('stream_comment_lines')
    def test_ini_comments(self):
        self.assertEqual(self.read('; [unknown]\n# broken=value\n[logging]\n; level=bad\nlevel=4\n'), {'log_level': 4})

    @ini('stream_inline_comment')
    def test_ini_inline_comment(self):
        values = self.read('[logging]\nlevel=4 ; ignored\ndirectory=a;b\n')
        self.assertEqual(values['log_level'], 4)
        self.assertEqual(values['log_dir'], self.root/'a;b')

    @ini('stream_whitespace_strip')
    def test_ini_whitespace(self):
        self.assertEqual(self.read('[logging]\n \tlevel \t= \t5 \t\n directory = logs \n'),
                         {'log_level': 5, 'log_dir': self.root/'logs'})

    @ini('stream_empty_value')
    def test_ini_empty_value(self):
        self.assertEqual(self.read('[dpdk]\neal=\n')['eal'], '')
        self.reject(BASE+'[logging]\nlevel=\n', '[logging] level:')

    @ini('stream_invalid_syntax')
    def test_ini_invalid_syntax(self):
        self.reject(BASE+'[logging]\nlevel=4\nbroken line\n', 'broken line')

    @ini('stream_bom_utf8')
    def test_ini_bom(self):
        self.assertEqual(self.read('\ufeff[logging]\nlevel=6\n'), {'log_level': 6})
        self.reject(BASE+'\ufeff[logging]\nlevel=6\n', 'case.ini:')

    @ini('file_normal')
    def test_ini_file(self):
        self.path.write_text('[logging]\ndirectory=relative\nlevel=3\n')
        with self.path.open() as stream:
            values = launcher.read_configuration(stream, self.path.parent, self.path)
        self.assertEqual(values, {'log_dir': self.root/'relative', 'log_level': 3})
        self.assertTrue(stream.closed)

    @ini('filename_not_exist')
    def test_ini_missing_file(self):
        missing = self.root/'does-not-exist.ini'
        with self.assertRaises(FileNotFoundError):
            launcher.load_configuration(missing)
        self.assertFalse(missing.exists())
        self.assertEqual(self.parse().port, 'net_tap0')

    @ini('filename_normal')
    def test_ini_filename(self):
        nested = self.root/'space directory'
        nested.mkdir()
        path = nested/'settings.ini'
        path.write_text('[capture]\ndirectory=../captures\n')
        self.assertEqual(launcher.load_configuration(path)['pcap_dir'], nested/'../captures')
        self.assertEqual(launcher.load_configuration(path)['pcap_dir'].resolve(), self.root/'captures')

    @ini('stream_long_key_name')
    def test_ini_long_key(self):
        prefix = 'net.ipv4.'+'k'*50
        first, second = prefix+'a', prefix+'b'
        values = self.read(f'[sysctl]\n{first}=1\n{second}=2\n{first}=3\n')['sysctls']
        self.assertEqual(values, [(second, '2'), (first, '3')])
        self.assertEqual(len(first), 60)

    @ini('stream_zero_byte_input')
    def test_ini_empty_stream(self):
        self.assertEqual(self.read(''), {})
        self.assertEqual(self.read('\n'), {})
        self.assertEqual(self.read('# comment\n; comment\n'), {})
        self.assertEqual(self.parse().mtu, 1500)

    @ini('stream_section_no_close_bracket')
    def test_ini_unclosed_section(self):
        self.reject(BASE+'[logging\nlevel=4\n', '[logging')

    @ini('stream_no_trailing_newline')
    def test_ini_no_final_newline(self):
        self.assertEqual(self.read('[logging]\nlevel=5'), {'log_level': 5})
        self.assertEqual(self.read('[logging]\nlevel=5\n'), {'log_level': 5})

    @ini('stream_colon_separator')
    def test_ini_colon(self):
        self.assertEqual(self.read('[logging]\nlevel:6\ndirectory:a:b\n'),
                         {'log_level': 6, 'log_dir': self.root/'a:b'})

    @ini('stream_bare_line_no_separator')
    def test_ini_bare_line(self):
        self.reject(BASE+'[network]\nnot_a_setting\n', 'not_a_setting')

    @ini('stream_partial_bom_not_recognized')
    def test_ini_partial_bom(self):
        # Byte-equivalent UTF-8 leading EF followed by non-BB input is invalid
        # UTF-8, rather than a second accepted BOM spelling.
        self.path.write_bytes(b'\xefAC\n'+BASE.encode())
        with self.assertRaises(UnicodeError):
            launcher.load_configuration(self.path)
        self.reject_file("'utf-8' codec")

    @ini('stream_bom_third_byte_mismatch')
    def test_ini_bom_mismatch(self):
        self.path.write_bytes(b'\xef\xbbX\n'+BASE.encode())
        with self.assertRaises(UnicodeError):
            launcher.load_configuration(self.path)
        self.reject_file("'utf-8' codec")

    @cfg('ff_load_config_no_dpdk_section')
    def test_config_no_dpdk(self):
        args = self.parse('[network]\naddress=198.18.0.2/24\n', '--port', 'net_tap0', '--eal=--no-pci')
        self.assertEqual(args.eal_args, ['--no-pci'])
        self.assertEqual(args.memory_channels, None)
        self.assertEqual(args.interfaces, ())

    @cfg('ff_load_config_invalid_lcore_mask')
    def test_config_bad_lcore(self):
        self.reject(BASE+'[dpdk]\nlcore_mask=ZZZ_NOT_HEX\n', 'lcore')

    @cfg('ff_load_config_dual_vlan')
    def test_config_dual_vlan(self):
        args = self.parse(BASE+'[vlan.10]\naddresses=198.19.0.2/24\n[vlan.20]\naddresses=198.20.0.2/24\n')
        self.assertEqual([(tag, tuple(map(str, addresses))) for tag, addresses in args.vlans],
                         [(10, ('198.19.0.2/24',)), (20, ('198.20.0.2/24',))])
        self.assertEqual(self.parse().vlans, ())

    @cfg('ff_load_config_with_vip_addr')
    def test_config_vip(self):
        args = self.parse(BASE+'[network]\nvip_addresses=198.18.0.3/24,198.18.0.4/24\n')
        self.assertEqual(tuple(map(str, args.vip_addresses)), ('198.18.0.3/24', '198.18.0.4/24'))
        self.assertEqual(self.parse().vip_addresses, [])

    @cfg('ff_load_config_argv_override')
    def test_config_cli_override(self):
        args = self.parse(BASE+'[network]\nmtu=2000\n', '--mtu', '1600', '--eal=--no-pci')
        self.assertEqual(args.mtu, 1600)
        self.assertEqual(args.eal_args, ['--no-pci'])
        self.assertEqual(self.parse().mtu, 1500)

    @cfg('ff_load_config_empty_ini')
    def test_config_empty(self):
        args = self.parse('', '--address', '198.18.0.2/24', '--port', 'net_tap0', '--eal=--no-pci')
        self.assertEqual(args.mtu, 1500)
        self.assertEqual(args.bonds, ())
        self.assertEqual(args.vdevs, ())
        self.assertEqual(args.sysctls, {})

    @cfg('vlan_cfg_handler_isolated')
    def test_config_missing_path(self):
        missing = self.root/'missing.ini'
        result = subprocess.run([sys.executable, str(SOURCE), '--config', str(missing),
            '--io-worker', str(self.worker), '--', str(self.worker)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('No such file or directory', result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.parse().vlans, ())

    @cfg('ipfw_pr_cfg_handler_isolated')
    def test_config_invalid_process_mode(self):
        self.reject(BASE, 'unrecognized arguments', '--proc-type', 'bogus_proc_type')

    @cfg('port_cfg_handler_addr_parse')
    def test_config_address(self):
        args = self.parse(BASE.replace('198.18.0.2/24', '192.168.1.10/24'))
        self.assertEqual(str(args.address.ip), '192.168.1.10')
        self.assertEqual(str(args.address.netmask), '255.255.255.0')
        self.reject(BASE.replace('198.18.0.2/24', '192.168.1.999/24'), 'address:')

    @cfg('ff_load_config_lcore_mask_no_bits')
    def test_config_zero_lcore(self):
        self.reject(BASE+'[dpdk]\nlcore_mask=0\n', 'lcore')

    @cfg('bond_cfg_handler_no_nb_bond')
    def test_config_bond_without_count(self):
        self.reject(BASE+'[bond0]\nmode=4\nslave=0,1\n', 'bond sections require')

    @cfg('bond_cfg_handler_bad_section')
    def test_config_bond_bad_index(self):
        self.reject(BASE+'[dpdk]\nnb_bond=1\n[bondXX]\nmode=4\nslave=0,1\n', 'bond section must be [bond0]')

    @cfg('parse_lcore_mask_uppercase_0X_succeeds')
    def test_config_uppercase_lcore(self):
        args = self.parse(BASE+'[dpdk]\nlcore_mask=0X1\n')
        self.assertEqual(args.lcore_mask, '1')
        self.assertIn('-c', args.eal_args)
        self.assertEqual(args.eal_args[-2:], ['-c', '1'])

    @cfg('vlan_cfg_handler_bad_section_returns_zero')
    def test_config_vlan_bad_index(self):
        self.reject(BASE+'[vlan.XX]\naddresses=198.19.0.2/24\n', 'VLAN')

    @cfg('vdev_cfg_handler_no_nb_vdev_returns_zero')
    def test_config_vdev_without_count(self):
        self.reject(BASE+'[vdev0]\npath=vhost.sock\n', 'vdev sections require')

    @cfg('port_cfg_handler_bad_section_returns_zero')
    def test_config_interface_bad_name(self):
        self.reject(BASE+'[interface.bad/name]\naddress=198.19.0.2/24\nport=net_tap1\neal=--no-pci\n', 'invalid interface section name')

    @cfg('ff_load_config_repeat_keys_no_leak')
    def test_config_repeat_keys(self):
        args = self.parse(BASE+'[network]\nmtu=broken\nmtu=1600\n[dpdk]\nmbuf_mode=bad\nmbuf_mode=scatter\n')
        self.assertEqual((args.mtu, args.mbuf_mode), (1600, 'scatter'))
        self.assertEqual((self.parse().mtu, self.parse().mbuf_mode), (1500, 'large'))

    @cfg('parse_lcore_mask_blank_and_multibit')
    def test_config_multibit_lcore(self):
        args = self.parse(BASE+'[dpdk]\nlcore_mask=  0x5  \n')
        self.assertEqual(args.lcore_mask, '5')
        self.assertEqual(args.eal_args[-2:], ['-c', '5'])

    @cfg('parse_lcore_mask_all_blank_returns_error')
    def test_config_blank_lcore(self):
        self.reject(BASE+'[dpdk]\nlcore_mask=   \n', 'lcore')

    @cfg('parse_lcore_mask_mid_nonhex_returns_error')
    def test_config_mid_nonhex_lcore(self):
        self.reject(BASE+'[dpdk]\nlcore_mask=12Z3\n', 'lcore')

    @cfg('ff_load_config_vlan_vip_addr')
    def test_config_vlan_vips(self):
        args = self.parse(BASE+'[vlan.10]\naddresses=198.19.0.2/24,198.19.0.3/24\n')
        self.assertEqual(tuple(map(str, args.vlans[0][1])), ('198.19.0.2/24', '198.19.0.3/24'))
        self.assertEqual(self.parse().vlans, ())

    @cfg('ff_check_config_kni_method_reject_ok')
    def test_config_exception_reject(self):
        args = self.parse(BASE+'[dpdk]\nexception_mode=ports\nexception_iface=ker_exception0\nexception_policy=reject\n')
        self.assertEqual(args.exception_policy, 'reject')
        self.assertEqual(self.parse().exception_policy, 'accept')

    @cfg('ff_check_config_kni_method_invalid_fails')
    def test_config_exception_invalid(self):
        self.reject(BASE+'[dpdk]\nexception_policy=invalid\n', 'invalid exception mode or accept/reject policy')

    @cfg('mtu_defaults_legacy')
    def test_config_mtu_defaults(self):
        args = self.parse()
        self.assertEqual((args.mtu, args.max_mtu, args.mbuf_mode), (1500, 9000, 'large'))
        self.assertTrue(args.mtu_enable)  # Ker typed default differs from F-Stack.

    @cfg('mtu_large_9000')
    def test_config_jumbo(self):
        args = self.parse(BASE+'[network]\nmtu=9000\nmax_mtu=9000\n')
        self.assertEqual((args.mtu, args.max_mtu, args.mbuf_mode), (9000, 9000, 'large'))
        self.assertEqual(self.parse().mtu, 1500)

    @cfg('mtu_scatter_mode')
    def test_config_scatter(self):
        args = self.parse(BASE+'[network]\nmtu=9000\n[dpdk]\nmbuf_mode=scatter\n')
        self.assertEqual((args.mtu, args.mbuf_mode), (9000, 'scatter'))
        self.assertEqual(self.parse().mbuf_mode, 'large')

    @cfg('mtu_invalid_mode_fails')
    def test_config_bad_storage_mode(self):
        self.reject(BASE+'[dpdk]\nmbuf_mode=unsupported\n', 'mbuf-mode')

    @cfg('mtu_max_mtu_non_numeric_fails')
    def test_config_nonnumeric_ceiling(self):
        self.reject(BASE+'[network]\nmax_mtu=not-a-number\n', '[network] max_mtu:')

    @cfg('mtu_port_over_max_fails')
    def test_config_over_ceiling(self):
        self.reject(BASE+'[network]\nmtu=2001\nmax_mtu=2000\n', '--mtu must not exceed --max-mtu')
        args = self.parse(BASE+'[network]\nmtu=2001\nmax_mtu=2000\n', '--mtu', '2000')
        self.assertEqual((args.mtu, args.max_mtu), (2000, 2000))

    @cfg('mtu_disabled_port_over_1500_fails')
    def test_config_disabled_jumbo(self):
        self.reject(BASE+'[network]\nmtu=1501\n[dpdk]\nmtu_enable=0\n', '--mtu must not exceed --max-mtu')
        args = self.parse(BASE+'[dpdk]\nmtu_enable=0\n')
        self.assertEqual(args.mtu, 1500)
        self.assertFalse(args.mtu_enable)
        self.assertEqual(args.max_mtu, 1500)

    @cfg('mtu_large_65535_fails')
    def test_config_oversized_jumbo(self):
        self.reject(BASE+'[network]\nmtu=65535\nmax_mtu=65535\n', '--mtu must be in 1280..9000')


if __name__ == '__main__':
    unittest.main()
