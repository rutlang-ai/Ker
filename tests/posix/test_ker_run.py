import contextlib
import importlib.util
import io
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
import json, os, signal, sys, time
from pathlib import Path
args = sys.argv
fd = int(args[args.index('--control-fd') + 1])
port = args[args.index('--port') + 1]
if port == 'aux0' and os.environ.get('FAKE_AUX_MALFORMED') == '1':
    print('KER_IO_DONE not-json', flush=True)
    sys.exit(0)
if port == 'aux0' and os.environ.get('FAKE_AUX_SIGNAL') == '1':
    Path(os.environ['FAKE_AUX_PID_FILE']).write_text(str(os.getpid()))
    def stop(signum, frame):
        print('KER_IO_DONE {{}}', flush=True)
        Path(os.environ['FAKE_AUX_DONE_FILE']).write_text(str(time.monotonic_ns()))
        sys.exit(0)
    signal.signal(signal.SIGTERM, stop)
    print('KER_IO_READY ' + json.dumps({{'mac': '02:00:00:00:00:02'}}), flush=True)
    while True: signal.pause()
print('KER_IO_READY ' + json.dumps({{'mac': '02:00:00:00:00:01'}}), flush=True)
while os.read(fd, 1):
    pass
print('KER_IO_DONE {{}}', flush=True)
sys.exit(int(os.environ.get('FAKE_AUX_WORKER_EXIT' if port == 'aux0' else 'FAKE_WORKER_EXIT', '0')))
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
        cls.config = cls.root / 'multiport.ini'
        cls.config.write_text('[interface.aux]\naddress=198.19.0.2/24\n'
                              'port=aux0\neal=--no-pci\n')
        cls.aux_pid_file = cls.root / 'aux.pid'
        cls.aux_done_file = cls.root / 'aux.done'
        cls.app_start_file = cls.root / 'app.start'
        cls.app_done_file = cls.root / 'app.done'
        cls.worker.write_text(WORKER)
        cls.guard.write_text(APP_GUARD)
        cls.worker.chmod(0o755)
        cls.guard.chmod(0o755)
        cls.library.touch()

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def run_launcher(self, app_code, *, native_done, worker_code=0, signal_app=False,
                     config=None, app_source=None, extra_env=None, capture_stderr=False):
        env = os.environ.copy()
        env.update(FAKE_NATIVE_DONE='1' if native_done else '0',
                   FAKE_WORKER_EXIT=str(worker_code))
        if extra_env:
            env.update(extra_env)
        if app_source is not None:
            app = app_source
        elif signal_app:
            app = 'import os, signal; os.kill(os.getpid(), signal.SIGTERM)'
        else:
            app = f'import sys; sys.exit({app_code})'
        argv = ['ker-run.py', '--address', '192.0.2.2/24', '--port', 'fake0',
                '--eal', '', '--library', str(self.library), '--io-worker', str(self.worker),
                *(('--config', str(config)) if config else ()),
                '--', sys.executable, '-c', app]
        with (io.StringIO() if capture_stderr else open(os.devnull, 'w')) as stderr, \
                mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(sys, 'argv', argv), \
                contextlib.redirect_stderr(stderr):
            result = ker_run.main()
            message = stderr.getvalue() if capture_stderr else ''
        return (result, message) if capture_stderr else result

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

    def graceful_auxiliary_loss(self):
        self.aux_pid_file.unlink(missing_ok=True)
        self.aux_done_file.unlink(missing_ok=True)
        self.app_start_file.unlink(missing_ok=True)
        self.app_done_file.unlink(missing_ok=True)
        app = f'''import os, signal, sys, time
from pathlib import Path
start = time.monotonic_ns()
Path(os.environ['FAKE_APP_START_FILE']).write_text(str(start))
pid_file = Path(os.environ['FAKE_AUX_PID_FILE'])
deadline = time.monotonic() + 1
while not pid_file.exists() and time.monotonic() < deadline: time.sleep(0.001)
os.kill(int(pid_file.read_text()), signal.SIGTERM)
deadline = time.monotonic() + 1
exited = False
while time.monotonic() < deadline:
    try:
        state = Path('/proc/' + pid_file.read_text() + '/stat').read_text().rsplit(')', 1)[1].split()[0]
    except FileNotFoundError:
        break
    if state == 'Z':
        exited = True
        break
    time.sleep(0.001)
Path(os.environ['FAKE_APP_DONE_FILE']).write_text(f'{{time.monotonic_ns()}} {{int(exited)}}')
sys.exit(0)
'''
        result, stderr = self.run_launcher(0, native_done=True, config=self.config, app_source=app,
            capture_stderr=True, extra_env={'FAKE_AUX_SIGNAL': '1',
                'FAKE_AUX_PID_FILE': str(self.aux_pid_file),
                'FAKE_AUX_DONE_FILE': str(self.aux_done_file),
                'FAKE_APP_START_FILE': str(self.app_start_file),
                'FAKE_APP_DONE_FILE': str(self.app_done_file)})
        return result, stderr

    def test_graceful_auxiliary_exit_during_successful_app_wait_is_failure(self):
        result, stderr = self.graceful_auxiliary_loss()
        self.assertTrue(self.aux_done_file.exists(), 'auxiliary worker did not emit KER_IO_DONE')
        self.assertEqual(result, 125)
        self.assertIn('additional DPDK worker stopped while the application was running: aux', stderr)
        worker_exit = int(self.aux_done_file.read_text())
        app_start = int(self.app_start_file.read_text())
        app_exit, auxiliary_exited = map(int, self.app_done_file.read_text().split())
        self.assertLess(worker_exit, app_exit, 'auxiliary must exit before the application')
        self.assertEqual(auxiliary_exited, 1, 'auxiliary process must be exited before app success')
        self.assertLess(app_exit - app_start, 250_000_000,
                        'application must exit during its first 250 ms wait interval')

    def test_successful_app_allows_coordinator_initiated_auxiliary_shutdown(self):
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config), 0)

    def test_auxiliary_nonzero_exit_remains_an_infrastructure_failure(self):
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config,
            extra_env={'FAKE_AUX_WORKER_EXIT': '9'}), 125)

    def test_malformed_auxiliary_completion_remains_an_infrastructure_failure(self):
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config,
            extra_env={'FAKE_AUX_MALFORMED': '1'}), 125)


if __name__ == '__main__':
    unittest.main(verbosity=2)
