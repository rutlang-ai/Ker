"""Reject incomplete original macvtap configuration and result evidence."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class MacvtapProfileTests(unittest.TestCase):
    def test_profile_gate_rejects_missing_driver_and_incomplete_original_cases(self):
        for mutation in ('missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-driver',
                         'missing-sysfs', 'skipped', 'wrong-fingerprint', 'missing-case',
                         'duplicate-case', 'failed-evidence', 'complete'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_MACVTAP_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-macvtap.config',
                    kernel=str(root), fingerprint='candidate')))
                config = ['CONFIG_DUMMY=y', 'CONFIG_MACVLAN=y', 'CONFIG_MACVTAP=y',
                          'CONFIG_TAP=y', 'CONFIG_SYSFS=y']
                if mutation == 'missing-driver':
                    config.remove('CONFIG_MACVTAP=y')
                if mutation == 'missing-sysfs':
                    config.remove('CONFIG_SYSFS=y')
                (root / '.config').write_text('\n'.join(config) + '\n')
                junit = root / 'junit.xml'
                junit.write_text(f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase></testsuite>')
                cases = ['tap.test_packet_valid_udp_gso', 'tap.test_packet_valid_udp_csum',
                         'tap.test_packet_crash_tap_invalid_eth_proto']
                if mutation == 'missing-case':
                    cases.pop()
                if mutation == 'duplicate-case':
                    cases[-1] = cases[0]
                (root / (name + '.json')).write_text(json.dumps(dict(
                    status='FAIL' if mutation == 'failed-evidence' else 'PASS_IMPORTED_LINUX',
                    fingerprint='other' if mutation == 'wrong-fingerprint' else 'candidate',
                    original=dict(cases=cases))))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_macvtap_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_macvtap_profile(root, junit)


if __name__ == '__main__':
    unittest.main()
