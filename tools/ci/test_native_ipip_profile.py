"""A complete five-namespace IPIP entry and exact native profile are mandatory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class IpipProfileTests(unittest.TestCase):
    def test_candidate_bound_native_ipip_gate(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/unit/ipip-mtu-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'missing-control', 'skipped-control',
                         'wrong-profile', 'missing-nat', 'skipped', 'wrong-fingerprint', 'failed-evidence',
                         'missing-counter', 'leaked-namespace'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_IPIP_PROFILE_TEST
                control = 'linux-mixed-poll-timeout-control'
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation != 'missing-control':
                    inventory.append(dict(name=control))
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-ipip-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + option + '=y' for option in
                           ('NET_IPIP', 'NF_CONNTRACK', 'NETFILTER_XTABLES', 'IP_NF_IPTABLES', 'IP_NF_FILTER', 'NETFILTER_XT_MATCH_CONNTRACK')]
                if mutation == 'missing-nat':
                    options.remove('CONFIG_NET_IPIP=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                cases = f'<testcase name="{name}">' + ('<skipped/>' if mutation == 'skipped' else '') + '</testcase>'
                if mutation != 'missing-control':
                    cases += f'<testcase name="{control}">' + ('<skipped/>' if mutation == 'skipped-control' else '') + '</testcase>'
                junit = root / 'junit.xml'; junit.write_text('<testsuite>' + cases + '</testsuite>')
                evidence = json.loads(fixture.read_text()); evidence['fingerprint'] = 'candidate'
                if mutation == 'wrong-fingerprint':
                    evidence['fingerprint'] = 'other'
                elif mutation == 'failed-evidence':
                    evidence['status'] = 'FAIL'
                elif mutation == 'missing-counter':
                    evidence['commands'] = [r for r in evidence['commands'] if r['tool'] != 'iptables']
                elif mutation == 'leaked-namespace':
                    evidence['native_fixture']['namespaces_deleted'] = 3
                (root / (name + '.json')).write_text(json.dumps(evidence))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_ipip_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_ipip_profile(root, junit)

    def test_default_graph_excludes_ipip_entry(self):
        with self.assertRaisesRegex(RuntimeError, 'IPIP'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_IPIP_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
