"""The hosted forwarding gate rejects incomplete originals and clock controls."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class ForwardingProfileTests(unittest.TestCase):
    def test_required_profile_and_candidate_evidence(self):
        fixtures = Path(__file__).resolve().parents[2] / 'tests/unit'
        names = native_tests.LINUX_FORWARDING_PROFILE_TESTS
        control = native_tests.LINUX_BROADCAST_REALTIME_TEST
        files = dict(zip(names, ('forwarding-router-vid1-transcript.json', 'forwarding-mtu-transcript.json',
                                'broadcast-transcript.json')))
        for target in (*names, control):
            for mutation in ('complete', 'missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-multipath',
                             'skipped', 'missing-junit', 'duplicate-junit', 'failed-ctest',
                             'wrong-fingerprint', 'wrong-program', 'failed-evidence', 'missing-native-traffic'):
                with self.subTest(target=target, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary); required = {*names, control}
                    inventory = [dict(name=n) for n in sorted(required)]
                    if mutation == 'missing-entry': inventory = [x for x in inventory if x['name'] != target]
                    if mutation == 'duplicate-entry': inventory.append(dict(name=target))
                    (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                    (root / 'native-linux.json').write_text(json.dumps(dict(
                        config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-forwarding.config',
                        kernel=str(root), fingerprint='candidate')))
                    (root / '.config').write_text('' if mutation == 'missing-multipath' else 'CONFIG_IP_ROUTE_MULTIPATH=y\n')
                    cases = sorted(required)
                    if mutation == 'missing-junit': cases.remove(target)
                    if mutation == 'duplicate-junit': cases.append(target)
                    junit = root / 'junit.xml'; junit.write_text('<testsuite>' + ''.join(f'<testcase name="{n}">' +
                        ('<skipped/>' if mutation == 'skipped' and n == target else '') + '</testcase>' for n in cases) + '</testsuite>')
                    for name, program in names.items():
                        evidence = json.loads((fixtures / files[name]).read_text())
                        selected = name == (target if target != control else next(iter(names)))
                        evidence.update(program='other.sh' if selected and mutation == 'wrong-program' else program,
                            status='FAIL' if selected and mutation == 'failed-evidence' else 'PASS_IMPORTED_LINUX',
                            fingerprint='other' if selected and mutation == 'wrong-fingerprint' else 'candidate')
                        if selected and mutation == 'missing-native-traffic':
                            # MTU has its own actual packet-length/rejection contract.
                            if program == 'min_max_mtu.sh': evidence['commands'] = []
                            else: evidence['mib_after'] = evidence['mib_before']
                        (root / (name + '.json')).write_text(json.dumps(evidence))
                    result = subprocess.CompletedProcess([], 1 if mutation == 'failed-ctest' else 0)
                    with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                         mock.patch.object(native_tests.subprocess, 'run', return_value=result):
                        if mutation == 'complete': native_tests.run_forwarding_profile(root, junit)
                        else:
                            with self.assertRaises(RuntimeError): native_tests.run_forwarding_profile(root, junit)

    def test_default_graph_rejects_forwarding_without_its_kernel_profile(self):
        for name in native_tests.LINUX_FORWARDING_PROFILE_TESTS:
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'forwarding'):
                native_tests.validate_default_profile_inventory({name})


if __name__ == '__main__': unittest.main()
