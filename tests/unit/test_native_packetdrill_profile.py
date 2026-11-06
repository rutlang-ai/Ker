import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('packetdrill_profiles', Path(__file__).resolve().parents[2] / 'tools/ci/native_tests.py')
profiles = importlib.util.module_from_spec(spec); spec.loader.exec_module(profiles)


class PacketdrillProfileGate(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.build = self.root / 'build'; self.build.mkdir()
        self.kernel = self.root / 'kernel'; self.kernel.mkdir()
        (self.build / 'CMakeCache.txt').write_text(f'KER_NATIVE_LINUX_BUILD:PATH={self.root}\n')
        self.manifest = dict(config_fragment='config/native-linux-packetdrill.config',
                             fingerprint='tun-fq-profile', kernel=str(self.kernel))
        (self.root / 'native-linux.json').write_text(json.dumps(self.manifest))
        (self.kernel / '.config').write_text('CONFIG_TUN=y\nCONFIG_NET_SCH_FQ=y\nCONFIG_HIGH_RES_TIMERS=y\nCONFIG_HZ=1000\n')
        self.evidence = dict(status='PASS_IMPORTED_LINUX', fingerprint='tun-fq-profile',
            original_scripts=[dict(script=f'{i}.pkt', returncode=0, stderr='') for i in range(24)],
            entries=[dict(arguments=[f'--ip_version=ipv{family}', f'{i}.pkt'], returncode=0, stderr='')
                     for i in range(24) for family in (4, 6)])
        self.junit = self.root / 'junit.xml'; self.junit.write_text('<testsuite/>')

    def gate(self):
        (self.build / 'linux-original-packetdrill.json').write_text(json.dumps(self.evidence))
        with mock.patch.object(profiles, 'ctest_inventory', return_value=[dict(name='linux-original-packetdrill')]), \
             mock.patch.object(profiles.subprocess, 'run', return_value=subprocess.CompletedProcess(['ctest'], 0)), \
             mock.patch.object(profiles, 'report_junit'):
            profiles.run_packetdrill_profile(self.build, self.junit)

    def test_green_exit_with_hidden_helper_error_is_rejected(self):
        self.gate()
        self.evidence['entries'][0]['stderr'] = 'native sysctl failed'
        with self.assertRaisesRegex(RuntimeError, 'helper errors'): self.gate()

    def test_duplicate_family_cannot_replace_missing_ipv6(self):
        self.evidence['entries'][1]['arguments'][0] = '--ip_version=ipv4'
        with self.assertRaisesRegex(RuntimeError, 'missing or duplicated'): self.gate()

    def test_host_or_default_profile_cannot_substitute_for_native_tun(self):
        self.manifest.pop('config_fragment')
        (self.root / 'native-linux.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(RuntimeError, 'dedicated TUN/FQ'): self.gate()


if __name__ == '__main__': unittest.main()
