"""All original bridge entries, native realtime ABI controls, and VLAN contract control are mandatory."""
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
            'router_bridge_vlan_upper_pvid.sh': 'bridge-upper-pvid-transcript.json',
            'bridge_mdb_host.sh': 'bridge-mdb-host-transcript.json',
            'bridge_sticky_fdb.sh': 'bridge-sticky-transcript.json',
            'bridge_fdb_learning_limit.sh': 'bridge-learning-transcript.json',
            'bridge_mdb_port_down.sh': 'bridge-mdb-port-transcript.json',
            'bridge_port_isolation.sh': 'bridge-isolation-transcript.json',
            'bridge_vlan_unaware.sh': 'bridge-unaware-transcript.json',
            'bridge_vlan_aware.sh': 'bridge-aware-transcript.json',
            'bridge_locked_port.sh': 'bridge-locked-transcript.json',
            'bridge_vlan_mcast.sh': 'bridge-mcast-transcript.json',
            'ip6_forward_instats_vrf.sh': 'forwarding-instats-transcript.json',
            'bridge_igmp.sh': 'bridge-igmp-transcript.json',
            'bridge_mld.sh': 'bridge-mld-transcript.json',
            'bridge_mdb.sh': 'bridge-mdb-transcript.json',
            'bridge_mdb_max.sh': 'bridge-mdb-max-transcript.json',
            'pedit_ip.sh': 'pedit-ip-transcript.json',
            'pedit_l4port.sh': 'pedit-l4port-transcript.json',
            'pedit_dsfield.sh': 'pedit-dsfield-transcript.json',
            'tc_flower_port_range.sh': 'tc-flower-port-range-transcript.json',
            'tc_flower_l2_miss.sh': 'tc-flower-l2-miss-transcript.json',
            'tc_flower_cfm.sh': 'tc-flower-cfm-transcript.json',
            'tc_chains.sh': 'tc-chains-transcript.json',
            'skbedit_priority.sh': 'skbedit-priority-transcript.json',
            'tc_vlan_modify.sh': 'tc-vlan-modify-transcript.json',
        }
        control = native_tests.LINUX_BRIDGE_REALTIME_TEST
        packet_control = native_tests.LINUX_BRIDGE_PACKET_REALTIME_TEST
        vlan_contract = native_tests.LINUX_BRIDGE_VLAN_CONTRACT_TEST
        cases = [('complete', None), ('wrong-profile', None), ('missing-vlan', None), ('missing-snooping', None),
                 ('missing-control', None), ('duplicate-control', None),
                 ('skipped-control', None), ('failed-control', None), ('failed-ctest', None)]
        cases.extend((mutation, None) for mutation in ('missing-packet-control', 'duplicate-packet-control',
                                                      'skipped-packet-control', 'failed-packet-control'))
        cases.extend(('missing-tc', option) for option in ('NET_CLS_ACT', 'NET_SCH_INGRESS', 'NET_CLS_FLOWER', 'NET_ACT_GACT', 'NET_ACT_MIRRED', 'NET_ACT_PEDIT', 'NET_ACT_SKBEDIT', 'NET_SCH_PRIO', 'NET_ACT_VLAN', 'NET_TC_SKB_EXT', 'SKB_EXTENSIONS', 'XFRM_USER', 'DUMMY'))
        evidence_mutations = ('missing-entry', 'duplicate-entry', 'skipped-entry',
                              'wrong-fingerprint', 'failed-evidence', 'wrong-program',
                              'missing-phase', 'leaked-bridge', 'missing-proof')
        cases.extend((mutation, target) for target in files for mutation in evidence_mutations)
        for mutation, target in cases:
            with self.subTest(mutation=mutation, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                expected = set(files) | {control, packet_control, vlan_contract}
                inventory = [dict(name=name) for name in sorted(expected)]
                affected = target or next(iter(files))
                if mutation == 'missing-packet-control': inventory.remove(dict(name=packet_control))
                elif mutation == 'duplicate-packet-control': inventory.append(dict(name=packet_control))
                elif mutation == 'missing-entry': inventory.remove(dict(name=affected))
                elif mutation == 'duplicate-entry': inventory.append(dict(name=affected))
                elif mutation == 'missing-control': inventory.remove(dict(name=control))
                elif mutation == 'duplicate-control': inventory.append(dict(name=control))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-bridge-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + name + '=y' for name in
                           ('VETH', 'NET_VRF', 'VLAN_8021Q', 'IP_ROUTE_MULTIPATH',
                            'IP_MULTIPLE_TABLES', 'IPV6_MULTIPLE_TABLES', 'BRIDGE', 'BRIDGE_VLAN_FILTERING', 'BRIDGE_IGMP_SNOOPING', 'NET_CLS_ACT', 'NET_SCH_INGRESS', 'NET_CLS_FLOWER', 'NET_ACT_GACT', 'NET_ACT_MIRRED', 'NET_ACT_PEDIT', 'NET_TC_SKB_EXT', 'SKB_EXTENSIONS', 'XFRM_USER', 'DUMMY')]
                options.extend(['CONFIG_NET_ACT_SKBEDIT=y', 'CONFIG_NET_SCH_PRIO=y', 'CONFIG_NET_ACT_VLAN=y'])
                if mutation == 'missing-tc': options.remove('CONFIG_' + target + '=y')
                if mutation == 'missing-vlan': options.remove('CONFIG_BRIDGE_VLAN_FILTERING=y')
                if mutation == 'missing-snooping': options.remove('CONFIG_BRIDGE_IGMP_SNOOPING=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                entries = []
                for name in sorted(expected):
                    status = ('<skipped/>' if (mutation == 'skipped-control' and name == control or
                                                 mutation == 'skipped-packet-control' and name == packet_control or
                                                 mutation == 'skipped-entry' and name == target) else
                              '<failure message="failed"/>' if (mutation == 'failed-control' and name == control or
                                                                   mutation == 'failed-packet-control' and name == packet_control) else '')
                    entries.append(f'<testcase name="{name}">{status}</testcase>')
                junit = root / 'junit.xml'
                junit.write_text('<testsuite>' + ''.join(entries) + '</testsuite>')
                for name, program in files.items():
                    if mutation != 'complete' and target != name:
                        # A gate mutation changes one report at a time. Other
                        # reports need only satisfy the outer status, program,
                        # and fingerprint check; their full contracts are
                        # exercised by the complete fixture pass.
                        report = dict(status='PASS_IMPORTED_LINUX', fingerprint='candidate',
                                      program=program)
                    else:
                        report = json.loads((fixtures / fixture_by_program[program]).read_text())
                        report['fingerprint'] = 'candidate'
                    if name == target:
                        if mutation == 'wrong-fingerprint': report['fingerprint'] = 'other'
                        elif mutation == 'failed-evidence': report['status'] = 'FAIL'
                        elif mutation == 'wrong-program': report['program'] = 'wrong.sh'
                        elif mutation == 'missing-phase':
                            if program == 'ip6_forward_instats_vrf.sh':
                                report['commands'] = [r for r in report['commands'] if r['arguments'][:1] != ['xfrm']]
                            elif program in ('pedit_ip.sh', 'pedit_l4port.sh', 'pedit_dsfield.sh', 'tc_flower_port_range.sh', 'tc_flower_l2_miss.sh', 'tc_flower_cfm.sh', 'tc_chains.sh', 'skbedit_priority.sh'):
                                report['commands'] = [r for r in report['commands'] if r['tool'] != 'tc']
                            elif program == 'tc_vlan_modify.sh':
                                report['commands'] = [r for r in report['commands'] if not
                                    (r['tool'] == 'tc' and r['arguments'][:2] == ['filter', 'add'])]
                            elif program == 'router_bridge_vlan_upper_pvid.sh':
                                report['commands'] = [r for r in report['commands'] if 'pvid_after' not in r]
                            elif program == 'router_bridge_pvid_vlan_upper.sh':
                                report['commands'] = [r for r in report['commands'] if 'upper_after' not in r]
                            elif program in ('router_bridge_1d.sh', 'router_bridge_vlan_upper.sh'):
                                report['commands'] = [r for r in report['commands'] if 'port_after' not in r]
                            elif program == 'bridge_port_isolation.sh':
                                report['commands'] = [r for r in report['commands'] if 'isolated' not in r['arguments']]
                            else:
                                report['commands'] = [r for r in report['commands'] if r['tool'] != 'bridge']
                        elif mutation == 'leaked-bridge':
                            report['cleanup_state']['links'].append(dict(ifname='router' if program == 'ip6_forward_instats_vrf.sh' else 'br0' if program in ('bridge_mdb_host.sh', 'bridge_sticky_fdb.sh', 'bridge_fdb_learning_limit.sh', 'bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh', 'bridge_vlan_aware.sh', 'bridge_locked_port.sh', 'bridge_vlan_mcast.sh', 'bridge_igmp.sh', 'bridge_mld.sh', 'bridge_mdb.sh', 'bridge_mdb_max.sh', 'tc_vlan_modify.sh') else 'br1'))
                        elif mutation == 'missing-proof' and program == 'ip6_forward_instats_vrf.sh':
                            report['mixed_poll_control']['returncode'] = 1
                        elif mutation == 'missing-proof' and program in ('pedit_ip.sh', 'pedit_l4port.sh', 'pedit_dsfield.sh', 'tc_flower_port_range.sh', 'tc_flower_l2_miss.sh', 'tc_flower_cfm.sh', 'tc_chains.sh'):
                            report['packet_trace'] = []
                        elif mutation == 'missing-proof' and program == 'bridge_mdb_host.sh':
                            next(r for r in report['commands'] if r['tool'] == 'bridge').pop('mdb_after')
                        elif mutation == 'missing-proof' and program == 'bridge_fdb_learning_limit.sh':
                            next(r for r in report['commands'] if r['arguments'][:2] == ['vrf', 'exec']).pop('learning_after')
                        elif mutation == 'missing-proof' and program in ('bridge_mdb_port_down.sh', 'bridge_port_isolation.sh', 'bridge_vlan_unaware.sh', 'bridge_vlan_aware.sh', 'bridge_locked_port.sh', 'bridge_vlan_mcast.sh', 'bridge_igmp.sh', 'bridge_mld.sh', 'bridge_mdb.sh', 'bridge_mdb_max.sh'):
                            report['packet_trace'] = []
                        elif mutation == 'missing-proof' and program == 'tc_vlan_modify.sh':
                            report['vlan_packet_observer']['frames'] = []
                        elif mutation == 'missing-proof' and program == 'bridge_sticky_fdb.sh':
                            report['packet_trace'] = []
                        elif mutation == 'missing-proof':
                            next(r for r in report['commands'] if r['arguments'][:2] == ['vrf', 'exec']).pop('native_clock_reads')
                    (root / (name + '.json')).write_text(json.dumps(report))
                result = subprocess.CompletedProcess([], 1 if mutation == 'failed-ctest' else 0)
                validate_evidence = native_tests.validate_bridge_evidence
                def validate_selected(contract, evidence):
                    if mutation == 'complete' or (target is not None and
                            evidence.get('program') == files[target]):
                        validate_evidence(contract, evidence)
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=result), \
                     mock.patch.object(native_tests, 'validate_bridge_evidence', side_effect=validate_selected):
                    if mutation == 'complete': native_tests.run_bridge_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError): native_tests.run_bridge_profile(root, junit)

    def test_default_graph_excludes_all_bridge_entries(self):
        for name in native_tests.LINUX_BRIDGE_PROFILE_TESTS:
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'bridge'):
                native_tests.validate_default_profile_inventory({name})


if __name__ == '__main__':
    unittest.main()
