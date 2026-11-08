"""The complete original nexthop entry and its real native nexthop and clsact facilities are mandatory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class NexthopProfileTests(unittest.TestCase):
    def test_candidate_bound_native_nexthop_gate(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/unit/nexthop-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-clsact',
                         'skipped', 'wrong-fingerprint', 'failed-evidence', 'missing-route', 'leaked-nexthop'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_NEXTHOP_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-nexthop-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + option + '=y' for option in
                           ('VETH', 'NET_VRF', 'IP_ROUTE_MULTIPATH', 'IP_MULTIPLE_TABLES', 'IPV6_MULTIPLE_TABLES', 'NET_CLS_ACT', 'NET_SCH_INGRESS')]
                if mutation == 'missing-clsact':
                    options.remove('CONFIG_NET_CLS_ACT=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                junit = root / 'junit.xml'; junit.write_text(f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase></testsuite>')
                evidence = json.loads(fixture.read_text()); evidence['fingerprint'] = 'candidate'
                if mutation == 'wrong-fingerprint':
                    evidence['fingerprint'] = 'other'
                elif mutation == 'failed-evidence':
                    evidence['status'] = 'FAIL'
                elif mutation == 'missing-route':
                    evidence['commands'] = [r for r in evidence['commands'] if 'nhid' not in r['arguments']]
                elif mutation == 'leaked-nexthop':
                    evidence['cleanup_state']['links'].append(dict(ifname='vrf-h1'))
                (root / (name + '.json')).write_text(json.dumps(evidence))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_nexthop_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_nexthop_profile(root, junit)

    def test_default_graph_excludes_nexthop_entry(self):
        with self.assertRaisesRegex(RuntimeError, 'nexthop'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_NEXTHOP_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
