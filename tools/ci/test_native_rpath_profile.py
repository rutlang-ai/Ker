"""A complete dual-stack reverse-path entry and exact native profile are mandatory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class RpathProfileTests(unittest.TestCase):
    def test_candidate_bound_native_rpath_gate(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/unit/rpath-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'missing-clock-control', 'wrong-profile', 'missing-multipath',
                         'skipped', 'wrong-fingerprint', 'failed-evidence', 'missing-counter', 'leaked-namespace'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_RPATH_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name),
                    dict(name=native_tests.LINUX_RPATH_REALTIME_TEST)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                if mutation == 'missing-clock-control':
                    inventory = [dict(name=name)]
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-rpath-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + option + '=y' for option in
                           ('DUMMY', 'IP_ROUTE_MULTIPATH', 'NETFILTER_XTABLES', 'IP_NF_IPTABLES', 'IP_NF_RAW', 'IP_NF_MATCH_RPFILTER', 'IP6_NF_IPTABLES', 'IP6_NF_RAW', 'IP6_NF_MATCH_RPFILTER', 'NF_TABLES', 'NF_TABLES_INET', 'NFT_FIB_IPV4', 'NFT_FIB_IPV6', 'NFT_FIB_INET')]
                if mutation == 'missing-multipath':
                    options.remove('CONFIG_IP_ROUTE_MULTIPATH=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                junit = root / 'junit.xml'; junit.write_text(
                    f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase>' +
                    f'<testcase name="{native_tests.LINUX_RPATH_REALTIME_TEST}"/></testsuite>')
                evidence = json.loads(fixture.read_text()); evidence['fingerprint'] = 'candidate'
                if mutation == 'wrong-fingerprint':
                    evidence['fingerprint'] = 'other'
                elif mutation == 'failed-evidence':
                    evidence['status'] = 'FAIL'
                elif mutation == 'missing-counter':
                    evidence['commands'] = [r for r in evidence['commands'] if r['arguments'] != ['-t', 'raw', '-vS']]
                elif mutation == 'leaked-namespace':
                    evidence['native_fixture']['namespaces_deleted'] = 1
                (root / (name + '.json')).write_text(json.dumps(evidence))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_rpath_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_rpath_profile(root, junit)

    def test_default_graph_excludes_rpath_entry(self):
        with self.assertRaisesRegex(RuntimeError, 'rpath'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_RPATH_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
