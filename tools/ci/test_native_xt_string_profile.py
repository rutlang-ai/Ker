"""The complete original string entry and its real native algorithms are mandatory."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class StringProfileTests(unittest.TestCase):
    def test_candidate_bound_native_xt_string_gate(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/unit/xt-string-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-bm',
                         'skipped', 'wrong-fingerprint', 'failed-evidence', 'missing-counter', 'leaked-namespace'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_XT_STRING_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-xt-string-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_' + option + '=y' for option in
                           ('DUMMY', 'NETFILTER_XTABLES', 'IP_NF_IPTABLES', 'IP_NF_FILTER', 'NETFILTER_XT_MATCH_STRING', 'TEXTSEARCH', 'TEXTSEARCH_BM', 'TEXTSEARCH_KMP')]
                if mutation == 'missing-bm':
                    options.remove('CONFIG_TEXTSEARCH_BM=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                junit = root / 'junit.xml'; junit.write_text(f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase></testsuite>')
                evidence = json.loads(fixture.read_text()); evidence['fingerprint'] = 'candidate'
                if mutation == 'wrong-fingerprint':
                    evidence['fingerprint'] = 'other'
                elif mutation == 'failed-evidence':
                    evidence['status'] = 'FAIL'
                elif mutation == 'missing-counter':
                    evidence['commands'] = [r for r in evidence['commands'] if r['arguments'] != ['-v', '-S', 'OUTPUT']]
                elif mutation == 'leaked-namespace':
                    evidence['native_fixture']['namespaces_deleted'] = 0
                (root / (name + '.json')).write_text(json.dumps(evidence))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_xt_string_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_xt_string_profile(root, junit)

    def test_default_graph_excludes_xt_string_entry(self):
        with self.assertRaisesRegex(RuntimeError, 'xt_string'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_XT_STRING_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
