import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

path = Path(__file__).resolve().parents[2] / 'tools/ci/native_tests.py'
spec = importlib.util.spec_from_file_location('complete_native_profiles', path)
profiles = importlib.util.module_from_spec(spec); spec.loader.exec_module(profiles)


class CompleteProfileGates(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.build = self.root / 'cmake'; self.build.mkdir()
        self.kernel = self.root / 'kernel'; self.kernel.mkdir()
        self.manifest = dict(config_fragment='config/native-linux-mptcp-connect.config',
                             fingerprint='connect-profile', kernel=str(self.kernel))
        self.write_manifest()
        (self.kernel / '.config').write_text('\n'.join(('CONFIG_NF_TABLES=y', 'CONFIG_NF_TABLES_INET=y',
                                                       'CONFIG_NFT_SOCKET=y', 'CONFIG_NFT_TPROXY=y')))
        (self.build / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={self.root}\n')
        self.junit = self.root / 'junit.xml'; self.junit.write_text('<testsuite/>')
        self.inventory = [{'name': name} for name in sorted(profiles.LINUX_MPTCP_CONNECT_PROFILE_TESTS)]
        self.inventory.append({'name': profiles.LINUX_MPTCP_SOCKOPT_PROFILE_TEST})
        for item in self.inventory[:-1]:
            (self.build / (item['name'] + '.json')).write_text(json.dumps(dict(
                status='PASS_IMPORTED_LINUX', returncode=0, fingerprint='connect-profile', cases=list(range(68)))))

    def write_manifest(self):
        (self.root / 'native-linux.json').write_text(json.dumps(self.manifest))

    def run_gate(self):
        with mock.patch.object(profiles, 'ctest_inventory', return_value=self.inventory), \
             mock.patch.object(profiles.subprocess, 'run', return_value=subprocess.CompletedProcess(['ctest'], 0)), \
             mock.patch.object(profiles, 'report_junit') as junit:
            profiles.run_connect_profile(self.build, self.junit)
            self.assertEqual(junit.call_args.kwargs['required'], profiles.LINUX_MPTCP_CONNECT_PROFILE_TESTS)

    def test_all_four_complete_entries_are_mandatory(self):
        self.run_gate()
        self.inventory.pop(0)
        with self.assertRaisesRegex(RuntimeError, 'each original shell entry'):
            self.run_gate()

    def test_one_missing_original_assertion_cannot_be_covered_by_other_entries(self):
        name = sorted(profiles.LINUX_MPTCP_CONNECT_PROFILE_TESTS)[0]
        path = self.build / (name + '.json')
        evidence = json.loads(path.read_text()); evidence['cases'].pop(); path.write_text(json.dumps(evidence))
        with self.assertRaisesRegex(RuntimeError, 'incomplete original connect shell'):
            self.run_gate()

    def test_green_evidence_from_another_kernel_profile_is_rejected(self):
        name = sorted(profiles.LINUX_MPTCP_CONNECT_PROFILE_TESTS)[0]
        path = self.build / (name + '.json')
        evidence = json.loads(path.read_text()); evidence['fingerprint'] = 'default'; path.write_text(json.dumps(evidence))
        with self.assertRaisesRegex(RuntimeError, 'fingerprint differs'):
            self.run_gate()

    def test_default_kernel_cannot_replace_nftables_profile(self):
        self.manifest.pop('config_fragment'); self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, 'dedicated netfilter kernel profile'):
            self.run_gate()


if __name__ == '__main__': unittest.main()
