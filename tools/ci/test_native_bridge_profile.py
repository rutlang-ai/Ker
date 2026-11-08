"""All five complete bridge entries and the native realtime ABI control are mandatory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class BridgeProfileTests(unittest.TestCase):
    def test_candidate_bound_native_bridge_gate(self):
        fixtures = Path(__file__).resolve().parents[2] / 'tests/unit'
        files = dict(native_tests.LINUX_BRIDGE_PROFILE_TESTS)
        fixture_by_program = {
            'router_bridge.sh': 'bridge-transcript.json',
            'router_bridge_vlan.sh': 'bridge-vlan-transcript.json',
            'router_bridge_1d.sh': 'bridge-1d-transcript.json',
            'router_bridge_vlan_upper.sh': 'bridge-vlan-upper-transcript.json',
            'router_bridge_pvid_vlan_upper.sh': 'bridge-pvid-upper-transcript.json',
        }
        control = native_tests.LINUX_BRIDGE_REALTIME_TEST
        cases = [('complete', None), ('wrong-profile', None), ('missing-vlan', None),
                 ('missing-control', None), ('duplicate-control', None),
                 ('skipped-control', None), ('failed-control', None), ('failed-ctest', None)]
        evidence_mutations = ('missing-entry', 'duplicate-entry', 'skipped-entry',
                              'wrong-fingerprint', 'failed-evidence', 'wrong-program',
                              'missing-phase', 'leaked-bridge', 'missing-clock')
        cases.extend((mutation, target) for target in files for mutation in evidence_mutations)
        for mutation, target in cases:
            with self.subTest(mutation=mutation, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                expected = set(files) | {control}
                inventory = [dict(name=name) for name in sorted(expected)]
                affected = target or next(iter(files))
                if mutation == 'missing-entry': inventory.remove(dict(name=affected))
                elif mutation == 'duplicate-entry': inventory.append(dict(name=affected))
                elif mutation == 'missing-control': inventory.remove(dict(name=control))
                elif mutation == 'duplicate-control': inventory.append(dict(name=control))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-bridge-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + name + '=y' for name in
                           ('VETH', 'NET_VRF', 'VLAN_8021Q', 'IP_ROUTE_MULTIPATH',
                            'IP_MULTIPLE_TABLES', 'IPV6_MULTIPLE_TABLES', 'BRIDGE', 'BRIDGE_VLAN_FILTERING')]
                if mutation == 'missing-vlan': options.remove('CONFIG_BRIDGE_VLAN_FILTERING=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                entries = []
                for name in sorted(expected):
                    status = ('<skipped/>' if (mutation == 'skipped-control' and name == control or
                                                 mutation == 'skipped-entry' and name == target) else
                              '<failure message="failed"/>' if mutation == 'failed-control' and name == control else '')
                    entries.append(f'<testcase name="{name}">{status}</testcase>')
                junit = root / 'junit.xml'
                junit.write_text('<testsuite>' + ''.join(entries) + '</testsuite>')
                for name, program in files.items():
                    report = json.loads((fixtures / fixture_by_program[program]).read_text())
                    report['fingerprint'] = 'candidate'
                    if name == target:
                        if mutation == 'wrong-fingerprint': report['fingerprint'] = 'other'
                        elif mutation == 'failed-evidence': report['status'] = 'FAIL'
                        elif mutation == 'wrong-program': report['program'] = 'wrong.sh'
                        elif mutation == 'missing-phase':
                            if program == 'router_bridge_pvid_vlan_upper.sh':
                                report['commands'] = [r for r in report['commands'] if 'upper_after' not in r]
                            elif program in ('router_bridge_1d.sh', 'router_bridge_vlan_upper.sh'):
                                report['commands'] = [r for r in report['commands'] if 'port_after' not in r]
                            else:
                                report['commands'] = [r for r in report['commands'] if r['tool'] != 'bridge']
                        elif mutation == 'leaked-bridge': report['cleanup_state']['links'].append(dict(ifname='br1'))
                        elif mutation == 'missing-clock':
                            next(r for r in report['commands'] if r['arguments'][:2] == ['vrf', 'exec']).pop('native_clock_reads')
                    (root / (name + '.json')).write_text(json.dumps(report))
                result = subprocess.CompletedProcess([], 1 if mutation == 'failed-ctest' else 0)
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=result):
                    if mutation == 'complete': native_tests.run_bridge_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError): native_tests.run_bridge_profile(root, junit)

    def test_default_graph_excludes_all_bridge_entries(self):
        for name in native_tests.LINUX_BRIDGE_PROFILE_TESTS:
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'bridge'):
                native_tests.validate_default_profile_inventory({name})


if __name__ == '__main__':
    unittest.main()
