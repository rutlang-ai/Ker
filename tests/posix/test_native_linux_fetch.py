import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

BUILDER = Path(__file__).resolve().parents[2] / 'tools/build-native-linux.py'
spec = importlib.util.spec_from_file_location('native_builder', BUILDER)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def git(repo, *arguments):
    return subprocess.check_output(['git', '-C', str(repo), *arguments], text=True,
                                   stderr=subprocess.DEVNULL).strip()


class NativeFetchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ker-native-fetch-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.origin = self.root / 'origin'
        self.cache = self.root / 'cache.git'
        self.origin.mkdir()
        git(self.origin, 'init', '--initial-branch=main')
        self.revisions = []
        for value in ['first', 'second', 'third']:
            (self.origin / 'payload').write_text(value)
            git(self.origin, 'add', 'payload')
            git(self.origin, '-c', 'user.name=Ker Test', '-c', 'user.email=ker@example.invalid',
                'commit', '-m', value)
            self.revisions.append(git(self.origin, 'rev-parse', 'HEAD'))
        subprocess.run(['git', 'init', '--bare', str(self.cache)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_concurrent_shallow_fetches_share_canonical_lock(self):
        alias = self.root / 'cache-alias'
        alias.symlink_to(self.cache, target_is_directory=True)
        marker = self.root / 'fetch-active'
        start = self.root / 'start'
        receipts = [self.root / f'fetch-runner-{index}' for index in range(2)]
        program = r"""
import importlib.util, os, pathlib, sys, time
spec = importlib.util.spec_from_file_location('native_builder', sys.argv[1])
builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
original = builder._run_fetch_attempt
marker = pathlib.Path(sys.argv[5]); start = pathlib.Path(sys.argv[6])
receipt = pathlib.Path(sys.argv[7])
def observed(command, timeout):
    # Record entry at the runner boundary before checking overlap. This proves
    # both child processes reached the real fetch runner, even if locking regresses.
    receipt.write_text(f'{os.getpid()}\n{command!r}\n')
    # An overlap is a deterministic failure, while the operation itself is
    # a real shallow Git fetch of a distinct commit from a local repository.
    descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        time.sleep(0.2)
        return original(command, timeout)
    finally: marker.unlink()
builder._run_fetch_attempt = observed
while not start.exists(): time.sleep(0.005)
builder.fetch(pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4])
"""
        processes = [subprocess.Popen([sys.executable, '-c', program, str(BUILDER),
                     str(path), self.origin.as_uri(), revision, str(marker), str(start),
                     str(receipt)],
                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                     for path, revision, receipt in zip([self.cache, alias], self.revisions,
                                                        receipts)]
        try:
            start.touch()
            for process in processes:
                output, errors = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 0, output + errors)
        finally:
            for process in processes:
                if process.poll() is None: process.kill(); process.communicate()
        self.assertFalse(marker.exists())
        for receipt in receipts:
            self.assertTrue(receipt.is_file(), f'fetch runner was not reached: {receipt}')
            self.assertIn('fetch', receipt.read_text())
        for revision in self.revisions[:2]: git(self.cache, 'cat-file', '-e', revision + '^{commit}')

    def test_failed_fetch_releases_lock_and_present_commit_skips_fetch(self):
        attempts = []
        def fail_fetch(command, timeout):
            attempts.append((list(command), timeout))
            raise RuntimeError('injected fetch failure')
        with mock.patch.object(builder, '_run_fetch_attempt', side_effect=fail_fetch):
            with self.assertRaisesRegex(RuntimeError, 'injected fetch failure'):
                builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        self.assertEqual(len(attempts), 1)
        self.assertIn('fetch', attempts[0][0])
        # The failed attempt must release the cache lock so a real runner can
        # acquire it and populate the requested commit.
        builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        with mock.patch.object(builder, '_run_fetch_attempt') as run_fetch:
            builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
            run_fetch.assert_not_called()

    def test_fetch_disables_background_maintenance_for_shallow_cache(self):
        # Git 2.54+ uses maintenance.auto instead of gc.auto for post-fetch
        # background maintenance. Such a process can rewrite .git/shallow
        # while the next of the builder's pinned fetches is reading it.
        builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        self.assertEqual(git(self.cache, 'config', '--bool', 'maintenance.auto'), 'false')
        self.assertEqual(git(self.cache, 'config', '--get', 'gc.auto'), '0')
        for revision in self.revisions[1:]:
            builder.fetch(self.cache, self.origin.as_uri(), revision)
        for revision in self.revisions:
            git(self.cache, 'cat-file', '-e', revision + '^{commit}')


if __name__ == '__main__': unittest.main()
