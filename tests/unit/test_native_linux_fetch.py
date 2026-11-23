import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest


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

    def test_sequential_shallow_fetches_disable_auto_maintenance(self):
        for revision in self.revisions:
            builder.fetch(self.cache, self.origin.as_uri(), revision)
            self.assertEqual(git(self.cache, 'config', '--bool', 'maintenance.auto'), 'false')
            self.assertEqual(git(self.cache, 'config', '--get', 'gc.auto'), '0')

        for revision in self.revisions:
            git(self.cache, 'cat-file', '-e', revision + '^{commit}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
