"""A complete four-namespace NAT entry and exact native profile are mandatory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class NatProfileTests(unittest.TestCase):
    def test_candidate_bound_native_nat_gate(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/unit/nat-icmp-related-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-nat',
                         'skipped', 'wrong-fingerprint', 'failed-evidence', 'missing-counter', 'leaked-namespace'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_NAT_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-nat-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + option + '=y' for option in
                           ('NF_CONNTRACK', 'NF_NAT', 'NF_TABLES', 'NF_TABLES_INET', 'NFT_CT', 'NFT_NAT', 'NFT_MASQ')]
                if mutation == 'missing-nat':
                    options.remove('CONFIG_NFT_NAT=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                junit = root / 'junit.xml'; junit.write_text(f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase></testsuite>')
                evidence = json.loads(fixture.read_text()); evidence['fingerprint'] = 'candidate'
                if mutation == 'wrong-fingerprint':
                    evidence['fingerprint'] = 'other'
                elif mutation == 'failed-evidence':
                    evidence['status'] = 'FAIL'
                elif mutation == 'missing-counter':
                    evidence['commands'] = [r for r in evidence['commands'] if r['arguments'][-1:] != ['redir6']]
                elif mutation == 'leaked-namespace':
                    evidence['native_fixture']['namespaces_deleted'] = 3
                (root / (name + '.json')).write_text(json.dumps(evidence))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_nat_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_nat_profile(root, junit)

    def test_default_graph_excludes_nat_entry(self):
        with self.assertRaisesRegex(RuntimeError, 'NAT'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_NAT_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
