"""Tests for the private DPDK runtime directory used by session fixtures."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().parents[1] / 'posix' / 'dpdk_runtime.py'
SPEC = importlib.util.spec_from_file_location('dpdk_runtime', HELPER)
dpdk_runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dpdk_runtime)


class DpdkRuntimeTests(unittest.TestCase):
    def test_private_runtime_overrides_namespace_root_defaults(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / 'runtime'
            env = dpdk_runtime.private_runtime_environment(runtime, {
                'RUNTIME_DIRECTORY': '/var/run',
                'XDG_RUNTIME_DIR': '/run/user/0',
            })
            self.assertEqual(env['RUNTIME_DIRECTORY'], str(runtime.resolve()))
            self.assertEqual(env['XDG_RUNTIME_DIR'], str(runtime.resolve()))
            self.assertEqual(runtime.stat().st_uid, os.getuid())
            self.assertEqual(runtime.stat().st_mode & 0o777, 0o700)
            # Match DPDK's runtime layout creation while proving it stays in
            # this fixture-owned directory instead of a global runtime path.
            (runtime / 'dpdk').mkdir(mode=0o700)
            self.assertTrue((runtime / 'dpdk').is_dir())

    def test_private_runtime_is_owned_and_writable_by_mapped_namespace_root(self):
        unshare = shutil.which('unshare')
        if not unshare:
            self.skipTest('unshare is unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / 'runtime'
            env = dpdk_runtime.private_runtime_environment(runtime, {
                'RUNTIME_DIRECTORY': '/var/run',
                'XDG_RUNTIME_DIR': '/run/user/0',
            })
            probe = (
                'import os,pathlib,sys; p=pathlib.Path(sys.argv[1]); '
                'assert os.getuid()==0; '
                'assert int(open("/proc/self/uid_map").read().split()[0])==0; '
                'assert p.stat().st_uid==os.getuid(); '
                'assert p.stat().st_mode & 0o777==0o700; '
                'assert os.environ["RUNTIME_DIRECTORY"]==str(p); '
                'assert os.environ["XDG_RUNTIME_DIR"]==str(p); '
                'd=p/"dpdk"; d.mkdir(mode=0o700); (d/"probe").touch()'
            )
            result = subprocess.run([unshare, '-Urn', sys.executable, '-c', probe, str(runtime.resolve())],
                env=env, text=True, capture_output=True, timeout=10)
            if result.returncode and ('Operation not permitted' in result.stderr or
                                      'unshare failed' in result.stderr):
                self.skipTest('user/network namespaces are unavailable: ' + result.stderr.strip())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((runtime / 'dpdk' / 'probe').is_file())

    def test_rejects_runtime_directory_with_group_or_other_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / 'runtime'
            runtime.mkdir(mode=0o755)
            runtime.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, 'must be private'):
                dpdk_runtime.private_runtime_environment(runtime)

    def test_rejects_path_that_is_not_a_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / 'runtime-file'
            runtime.touch()
            with self.assertRaises((FileExistsError, NotADirectoryError, RuntimeError)):
                dpdk_runtime.private_runtime_environment(runtime)


if __name__ == '__main__':
    unittest.main(verbosity=2)
