"""The hosted forwarding gate rejects absent coverage and mismatched proof."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class ForwardingProfileTests(unittest.TestCase):
    def test_required_profile_and_candidate_evidence(self):
        transcript = Path(__file__).resolve().parents[2] / 'tests/unit/forwarding-router-vid1-transcript.json'
        for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-multipath',
                         'skipped', 'failed-ctest', 'wrong-fingerprint', 'failed-evidence', 'missing-native-traffic'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_FORWARDING_PROFILE_TEST
                inventory = [dict(name=n) for n in native_tests.LINUX_FORWARDING_PROFILE_TESTS]
                if mutation == 'missing-entry':
                    inventory.pop()
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-forwarding.config',
                    kernel=str(root), fingerprint='candidate')))
                (root / '.config').write_text('' if mutation == 'missing-multipath' else 'CONFIG_IP_ROUTE_MULTIPATH=y\n')
                junit = root / 'junit.xml'; junit.write_text('<testsuite>' + ''.join(f'<testcase name="{n}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase>'
                    for n in native_tests.LINUX_FORWARDING_PROFILE_TESTS) + '</testsuite>')
                evidence = json.loads(transcript.read_text())
                evidence.update(program='router_vid_1.sh', status='FAIL' if mutation == 'failed-evidence' else 'PASS_IMPORTED_LINUX',
                                fingerprint='other' if mutation == 'wrong-fingerprint' else 'candidate')
                if mutation == 'missing-native-traffic':
                    evidence['mib_after'] = evidence['mib_before']
                (root / (name + '.json')).write_text(json.dumps(evidence))
                mtu = json.loads(transcript.with_name('forwarding-mtu-transcript.json').read_text())
                mtu.update(status='PASS_IMPORTED_LINUX', fingerprint='candidate')
                (root / 'linux-original-forwarding-mtu.json').write_text(json.dumps(mtu))
                result = subprocess.CompletedProcess([], 1 if mutation == 'failed-ctest' else 0)
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=result):
                    if mutation == 'complete':
                        native_tests.run_forwarding_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_forwarding_profile(root, junit)

    def test_default_graph_rejects_forwarding_without_its_kernel_profile(self):
        with self.assertRaisesRegex(RuntimeError, 'forwarding'):
            native_tests.validate_default_profile_inventory({native_tests.LINUX_FORWARDING_PROFILE_TEST})


if __name__ == '__main__':
    unittest.main()
