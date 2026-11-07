"""Reject skipped zone cases and incomplete native conntrack profile evidence."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class ConntrackProfileTests(unittest.TestCase):
    def test_candidate_bound_native_zone_gate(self):
        fixture = Path(__file__).resolve().parents[2] / 'tests/unit/conntrack-dump-flush-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-zones', 'skipped',
                         'wrong-fingerprint', 'wrong-program', 'all-original-skipped', 'failed-evidence',
                         'missing-flush', 'leaked-socket', 'forced-shutdown'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_CONNTRACK_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-conntrack.config',
                    kernel=str(root), fingerprint='candidate')))
                options = ['CONFIG_NF_CONNTRACK=y', 'CONFIG_NF_CONNTRACK_ZONES=y', 'CONFIG_NF_CT_NETLINK=y']
                if mutation == 'missing-zones':
                    options.remove('CONFIG_NF_CONNTRACK_ZONES=y')
                (root / '.config').write_text('\n'.join(options) + '\n')
                junit = root / 'junit.xml'; junit.write_text(f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase></testsuite>')
                evidence = json.loads(fixture.read_text())
                if mutation == 'wrong-fingerprint':
                    evidence['fingerprint'] = 'other'
                elif mutation == 'wrong-program':
                    evidence['program'] = 'other'
                elif mutation == 'all-original-skipped':
                    evidence['original'] = evidence['original_missing_backend_control']
                elif mutation == 'failed-evidence':
                    evidence['status'] = 'FAIL'
                elif mutation == 'missing-flush':
                    evidence['native_fixture']['writes'] = 40
                elif mutation == 'leaked-socket':
                    evidence['native_fixture']['live'] = 1
                elif mutation == 'forced-shutdown':
                    evidence['stats']['shutdown_timed_out'] = True
                (root / (name + '.json')).write_text(json.dumps(evidence))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_conntrack_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_conntrack_profile(root, junit)

    def test_default_graph_requires_explicit_conntrack_profile(self):
        with self.assertRaisesRegex(RuntimeError, 'conntrack'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_CONNTRACK_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
