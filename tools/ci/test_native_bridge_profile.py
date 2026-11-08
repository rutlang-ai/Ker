"""The complete original bridge entry and its real native VLAN facilities are mandatory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class BridgeProfileTests(unittest.TestCase):
    def test_candidate_bound_native_bridge_gate(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/unit/bridge-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'missing-control', 'wrong-profile', 'missing-vlan',
                         'skipped', 'skipped-control', 'failed-control', 'wrong-fingerprint', 'failed-evidence', 'missing-phase', 'leaked-bridge'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_BRIDGE_PROFILE_TEST
                control = native_tests.LINUX_BRIDGE_REALTIME_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name), dict(name=control)]
                if mutation == 'missing-control':
                    inventory = [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-bridge-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + option + '=y' for option in
                           ('VETH', 'NET_VRF', 'VLAN_8021Q', 'IP_ROUTE_MULTIPATH', 'IP_MULTIPLE_TABLES', 'IPV6_MULTIPLE_TABLES', 'BRIDGE', 'BRIDGE_VLAN_FILTERING')]
                if mutation == 'missing-vlan':
                    options.remove('CONFIG_BRIDGE_VLAN_FILTERING=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                junit = root / 'junit.xml'; junit.write_text(
                    f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase>' +
                    f'<testcase name="{control}">' +
                    ('<skipped/>' if mutation == 'skipped-control' else
                     '<failure message="control failed"/>' if mutation == 'failed-control' else '') +
                    '</testcase></testsuite>')
                evidence = json.loads(fixture.read_text()); evidence['fingerprint'] = 'candidate'
                if mutation == 'wrong-fingerprint':
                    evidence['fingerprint'] = 'other'
                elif mutation == 'failed-evidence':
                    evidence['status'] = 'FAIL'
                elif mutation == 'missing-phase':
                    evidence['commands'] = [r for r in evidence['commands'] if 'vlan_default_pvid' not in r['arguments']]
                elif mutation == 'leaked-bridge':
                    evidence['cleanup_state']['links'].append(dict(ifname='br1'))
                (root / (name + '.json')).write_text(json.dumps(evidence))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_bridge_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_bridge_profile(root, junit)

    def test_default_graph_excludes_bridge_entry(self):
        with self.assertRaisesRegex(RuntimeError, 'bridge'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_BRIDGE_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
