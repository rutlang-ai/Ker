import contextlib
import importlib.util
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock


sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).resolve().parents[2] / 'tools' / 'ker-run.py'
SPEC = importlib.util.spec_from_file_location('ker_run', MODULE_PATH)
ker_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ker_run)


WORKER = f'''#!{sys.executable}
import json, os, sys
args = sys.argv
fd = int(args[args.index('--control-fd') + 1])
print('KER_IO_READY ' + json.dumps({{'mac': '02:00:00:00:00:01'}}), flush=True)
while os.read(fd, 1):
    pass
print('KER_IO_DONE {{}}', flush=True)
sys.exit(int(os.environ.get('FAKE_WORKER_EXIT', '0')))
'''

APP_GUARD = f'''#!{sys.executable}
import os, sys
status = b'KER_NATIVE_READY\\n'
if os.environ.get('FAKE_NATIVE_DONE') == '1':
    status += b'KER_NATIVE_DONE\\n'
os.write(int(os.environ['KER_STARTUP_FD']), status)
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
'''


class KerRunMainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory(prefix='ker-run-test-')
        cls.root = Path(cls.tempdir.name)
        cls.worker = cls.root / 'ker-io-worker'
        cls.guard = cls.root / 'ker-app'
        cls.library = cls.root / 'libker-posix.so'
        cls.worker.write_text(WORKER)
        cls.guard.write_text(APP_GUARD)
        cls.worker.chmod(0o755)
        cls.guard.chmod(0o755)
        cls.library.touch()

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def run_launcher(self, app_code, *, native_done, worker_code=0, signal_app=False):
        env = os.environ.copy()
        env.update(FAKE_NATIVE_DONE='1' if native_done else '0',
                   FAKE_WORKER_EXIT=str(worker_code))
        if signal_app:
            app = 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'
        else:
            app = f'import sys; sys.exit({app_code})'
        argv = ['ker-run.py', '--address', '192.0.2.2/24', '--port', 'fake0',
                '--eal', '', '--library', str(self.library), '--io-worker', str(self.worker),
                '--', sys.executable, '-c', app]
        with open(os.devnull, 'w') as sink, mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(sys, 'argv', argv), \
                contextlib.redirect_stderr(sink):
            return ker_run.main()

    def test_missing_native_done_overrides_nonzero_app_exit(self):
        self.assertEqual(self.run_launcher(7, native_done=False), 125)

    def test_worker_failure_overrides_nonzero_app_exit(self):
        self.assertEqual(self.run_launcher(7, native_done=True, worker_code=9), 125)

    def test_successful_backend_preserves_nonzero_app_exit(self):
        self.assertEqual(self.run_launcher(7, native_done=True), 7)

    def test_missing_done_overrides_ordinary_143_exit(self):
        self.assertEqual(self.run_launcher(143, native_done=False), 125)

    def test_actual_child_signal_is_preserved_with_incomplete_shutdown(self):
        self.assertEqual(self.run_launcher(0, native_done=False, signal_app=True),
                         128 + signal.SIGTERM)


if __name__ == '__main__':
    unittest.main(verbosity=2)
