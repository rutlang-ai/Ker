"""Require the complete original shell and native namespace lifetime evidence."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class NamespaceNameProfileTests(unittest.TestCase):
    def test_gate_rejects_missing_driver_and_partial_native_lifecycle(self):
        for mutation in ('missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-driver', 'skipped',
                         'wrong-fingerprint', 'failed-evidence', 'missing-move', 'conflict-accepted',
                         'wrong-error', 'leaked-namespace', 'leaked-socket', 'complete'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); name = native_tests.LINUX_NETNS_NAME_PROFILE_TEST
                inventory = [] if mutation == 'missing-entry' else [dict(name=name)]
                if mutation == 'duplicate-entry':
                    inventory.append(dict(name=name))
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-netns-name.config',
                    kernel=str(root), fingerprint='candidate')))
                (root / '.config').write_text('' if mutation == 'missing-driver' else 'CONFIG_DUMMY=y\n')
                junit = root / 'junit.xml'; junit.write_text(f'<testsuite><testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' else '') + '</testcase></testsuite>')
                records = [dict(operation='move', returncode=rc, errno=17) for rc in (0, 1, 0, 1, 0)]
                records += [dict(operation='ip', returncode=0) for _ in range(25)]
                if mutation == 'missing-move':
                    records.pop(0)
                elif mutation == 'conflict-accepted':
                    records[1]['returncode'] = 0
                elif mutation == 'wrong-error':
                    records[1]['errno'] = 95
                native = dict(namespaces_created=2, namespaces_deleted=1 if mutation == 'leaked-namespace' else 2,
                              netlinks=47, live=1 if mutation == 'leaked-socket' else 0)
                (root / (name + '.json')).write_text(json.dumps(dict(
                    status='FAIL' if mutation == 'failed-evidence' else 'PASS_IMPORTED_LINUX',
                    fingerprint='other' if mutation == 'wrong-fingerprint' else 'candidate',
                    original=dict(returncode=0, stdout='netns-name.sh [  OK  ]\n', stderr=''),
                    commands=records, native_fixture=native)))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_netns_name_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_netns_name_profile(root, junit)


if __name__ == '__main__':
    unittest.main()
