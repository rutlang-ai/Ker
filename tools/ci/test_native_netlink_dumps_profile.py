"""Do not qualify dump close-with-reference from TAP success alone."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class NetlinkDumpsProfileTests(unittest.TestCase):
    def test_gate_rejects_missing_native_reference_path_and_partial_cases(self):
        for mutation in ('missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-mqueue',
                         'skipped', 'wrong-fingerprint', 'missing-case', 'duplicate-case',
                         'failed-evidence', 'ignored-notify-error', 'leaked-queue', 'complete'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_NETLINK_DUMPS_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-netlink-dumps.config',
                    kernel=str(root), fingerprint='candidate')))
                (root / '.config').write_text('' if mutation == 'missing-mqueue' else 'CONFIG_POSIX_MQUEUE=y\n')
                junit = root / 'junit.xml'
                junit.write_text(f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase></testsuite>')
                cases = ['global.test_sanity', 'global.close_in_progress', 'global.close_with_ref']
                if mutation == 'missing-case':
                    cases.pop()
                if mutation == 'duplicate-case':
                    cases[-1] = cases[0]
                native = dict(generic_netlinks=3, mq_opens=1, mq_notifications=1,
                              mq_closes=1, notified_netlink_closes=1, live=0)
                if mutation == 'ignored-notify-error':
                    native['mq_notifications'] = 0
                if mutation == 'leaked-queue':
                    native['live'] = 1
                (root / (name + '.json')).write_text(json.dumps(dict(
                    status='FAIL' if mutation == 'failed-evidence' else 'PASS_IMPORTED_LINUX',
                    fingerprint='other' if mutation == 'wrong-fingerprint' else 'candidate',
                    original=dict(cases=cases), native_fixture=native)))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_netlink_dumps_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_netlink_dumps_profile(root, junit)


if __name__ == '__main__':
    unittest.main()
