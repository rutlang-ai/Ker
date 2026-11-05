import importlib.util
from pathlib import Path
import json
import re
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[2] / 'tools/ci/native_tests.py'
spec = importlib.util.spec_from_file_location('native_tests', SCRIPT)
native_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_tests)


class SockoptProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ker-native-sockopt-profile-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / 'cmake-build'
        self.build.mkdir()
        kernel = self.root / 'kernel'
        kernel.mkdir()
        (kernel / '.config').write_text('\n'.join((
            'CONFIG_NETFILTER_XTABLES=y', 'CONFIG_NETFILTER_XT_MATCH_MARK=y',
            'CONFIG_IP_NF_IPTABLES=y', 'CONFIG_IP_NF_FILTER=y',
            'CONFIG_IP6_NF_IPTABLES=y', 'CONFIG_IP6_NF_FILTER=y', '')))
        manifest = {'config_fragment': 'config/native-linux-mptcp-sockopt.config',
                    'kernel': str(kernel), 'fingerprint': 'profile-fingerprint'}
        (self.root / 'native-linux.json').write_text(json.dumps(manifest))
        (self.build / 'CMakeCache.txt').write_text(
            f'KER_NATIVE_LINUX_BUILD:PATH={self.root}\n')
        evidence = {'status': 'PASS_IMPORTED_LINUX', 'returncode': 0,
                    'fingerprint': 'profile-fingerprint', 'cases': [str(i) for i in range(11)]}
        (self.build / 'linux-original-mptcp-sockopt-shell.json').write_text(json.dumps(evidence))

    def test_requires_profile_and_accounts_exact_original_shell_entry(self):
        inventory = [{'name': native_tests.LINUX_MPTCP_SOCKOPT_PROFILE_TEST}]
        junit = self.root / 'sockopt.xml'; junit.write_text('<testsuite/>')
        with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
             mock.patch.object(native_tests.subprocess, 'run',
                 return_value=subprocess.CompletedProcess(['ctest'], 0)), \
             mock.patch.object(native_tests, 'report_junit') as report:
            native_tests.run_sockopt_profile(self.build, junit)
            call = native_tests.subprocess.run.call_args.args[0]
        self.assertIn('-R', call)
        self.assertEqual(call[call.index('-R') + 1], '^' + re.escape(
            native_tests.LINUX_MPTCP_SOCKOPT_PROFILE_TEST) + '$')
        report.assert_called_once()

    def test_profile_inventories_fail_closed_for_missing_mandatory_entry(self):
        with self.assertRaisesRegex(RuntimeError, 'missing required tests'):
            native_tests.validate_default_profile_inventory({'linux-original-mptcp-sockopt-ipv4'})
        with self.assertRaisesRegex(RuntimeError, 'original shell test exactly once'):
            native_tests.validate_sockopt_profile_inventory([])
        default_tests = {'native-c24-ingress-freeze-tap', 'native-c28-broker-owned-cutover-tap',
                         'native-c28-broker-owned-cutover-abort-tap',
                         'native-c28-cutover-start-cancel-destroy-retry'}
        with self.assertRaisesRegex(RuntimeError, 'must run in its fingerprinted'):
            native_tests.validate_default_profile_inventory(
                default_tests | {native_tests.LINUX_MPTCP_SOCKOPT_PROFILE_TEST})

    def test_refuses_sockopt_entry_on_default_profile_graph(self):
        (self.root / 'native-linux.json').write_text(json.dumps({'kernel': str(self.root / 'kernel')}))
        inventory = [{'name': native_tests.LINUX_MPTCP_SOCKOPT_PROFILE_TEST}]
        with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory):
            with self.assertRaisesRegex(RuntimeError, 'dedicated netfilter kernel profile'):
                native_tests.run_sockopt_profile(self.build, self.root / 'sockopt.xml')


if __name__ == '__main__':
    unittest.main()
