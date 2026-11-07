"""The dedicated original net profile must fail closed on incomplete evidence."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import native_tests


class NetProfileTests(unittest.TestCase):
    def test_incomplete_profile_cannot_be_reported_as_passing(self):
        for mutation in ('missing-entry', 'duplicate-entry', 'wrong-profile', 'missing-dccp',
                         'skipped', 'wrong-fingerprint', 'failed-evidence', 'complete'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                names = sorted(native_tests.LINUX_NET_PROFILE_TESTS)
                inventory = [dict(name=name) for name in names]
                if mutation == 'missing-entry':
                    inventory.pop()
                if mutation == 'duplicate-entry':
                    inventory.append(inventory[0])
                (root / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={root}\n')
                (root / 'native-linux.json').write_text(json.dumps(dict(
                    config_fragment='wrong' if mutation == 'wrong-profile' else 'config/native-linux-net-selftests.config',
                    kernel=str(root), fingerprint='candidate')))
                (root / '.config').write_text('CONFIG_TUN=y\n' +
                    ('' if mutation == 'missing-dccp' else 'CONFIG_IP_DCCP=y\n'))
                junit = root / 'junit.xml'
                junit.write_text('<testsuite>' + ''.join(
                    f'<testcase name="{name}">' +
                    ('<skipped/>' if mutation == 'skipped' and index == 0 else '') + '</testcase>'
                    for index, name in enumerate(names)) + '</testsuite>')
                for name in names:
                    (root / (name + '.json')).write_text(json.dumps(dict(
                        status='FAIL' if mutation == 'failed-evidence' else 'PASS_IMPORTED_LINUX',
                        fingerprint='other' if mutation == 'wrong-fingerprint' else 'candidate')))
                with mock.patch.object(native_tests, 'ctest_inventory', return_value=inventory), \
                     mock.patch.object(native_tests.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    if mutation == 'complete':
                        native_tests.run_net_profile(root, junit)
                    else:
                        with self.assertRaises(RuntimeError):
                            native_tests.run_net_profile(root, junit)


if __name__ == '__main__':
    unittest.main()
