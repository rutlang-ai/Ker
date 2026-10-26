"""Exercise real process locks without fetching or compiling a Linux tree."""
import importlib.util
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BUILDER = Path(__file__).resolve().parents[2] / 'tools/build-native-linux.py'
SPEC = importlib.util.spec_from_file_location('native_builder', BUILDER)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
CHILD = """
import importlib.util,sys
spec=importlib.util.spec_from_file_location('builder',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
print('waiting',flush=True)
sys.stdin.readline()
with m.artifact_lock(sys.argv[2]):
 print('entered',flush=True)
 sys.stdin.readline()
"""

class ArtifactLockTests(unittest.TestCase):
    def start(self, path):
        child = subprocess.Popen([sys.executable, '-u', '-c', CHILD, str(BUILDER), str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        self.addCleanup(self.stop, child)
        self.line(child, 'waiting')
        child.stdin.write('go\n'); child.stdin.flush()
        return child

    def stop(self, child):
        if child.poll() is None: child.kill()
        child.wait(timeout=5)
        for stream in (child.stdin, child.stdout, child.stderr): stream.close()

    def line(self, child, expected):
        self.assertTrue(select.select([child.stdout], [], [], 5)[0], expected)
        self.assertEqual(child.stdout.readline().strip(), expected)

    def test_same_output_waits_and_reuses_lock_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = self.start(temporary); self.line(first, 'entered')
            inode = (Path(temporary) / '.ker-native-build.lock').stat().st_ino
            second = self.start(temporary)
            self.assertFalse(select.select([second.stdout], [], [], .2)[0])
            first.stdin.write('\n'); first.stdin.flush(); self.assertEqual(first.wait(timeout=5), 0)
            self.line(second, 'entered')
            self.assertEqual((Path(temporary) / '.ker-native-build.lock').stat().st_ino, inode)

    def test_separate_output_does_not_wait(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = self.start(Path(temporary) / 'a'); self.line(first, 'entered')
            second = self.start(Path(temporary) / 'b'); self.line(second, 'entered')

    def test_process_death_releases_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            first = self.start(temporary); self.line(first, 'entered')
            second = self.start(temporary)
            self.assertFalse(select.select([second.stdout], [], [], .2)[0])
            first.kill(); first.wait(timeout=5)
            self.line(second, 'entered')

    def test_cli_holds_lock_around_all_mutating_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            entered = []
            def check_lock(args):
                import fcntl
                with (Path(temporary) / '.ker-native-build.lock').open('a+') as stream:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                entered.append(True)
            with patch.object(sys, 'argv', [str(BUILDER), '--build', temporary]), patch.object(MODULE, 'build_artifacts', check_lock):
                MODULE.main()
            self.assertEqual(entered, [True])

if __name__ == '__main__': unittest.main()
