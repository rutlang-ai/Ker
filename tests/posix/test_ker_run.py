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
if os.environ.get('FAKE_STARTUP_LOSS_ROLE'):
    role = 'primary' if port == 'fake0' else port
    delay_port = os.environ['FAKE_STARTUP_DELAY_PORT']
    if port == delay_port:
        Path(os.environ['FAKE_STARTUP_DELAY_FILE']).write_text('waiting')
        time.sleep(0.25)
    print('KER_IO_READY ' + json.dumps({{'mac': '02:00:00:00:00:03'}}), flush=True)
    if role == os.environ['FAKE_STARTUP_LOSS_ROLE']:
        delay_file = Path(os.environ['FAKE_STARTUP_DELAY_FILE'])
        while not delay_file.exists(): time.sleep(0.001)
        time.sleep(0.03)
        print('KER_IO_DONE {{}}', flush=True)
        sys.exit(0)
    while os.read(fd, 1): pass
    print('KER_IO_DONE {{}}', flush=True)
    sys.exit(0)
if os.environ.get('FAKE_TEARDOWN') == '1':
    role = 'AUX' if port == 'aux0' else 'PRIMARY'
    Path(os.environ[f'FAKE_{{role}}_PID_FILE']).write_text(str(os.getpid()))
    print('KER_IO_READY ' + json.dumps({{'mac': '02:00:00:00:00:02'}}), flush=True)
    stop_file = Path(os.environ['FAKE_TEARDOWN_FILE'])
    while not stop_file.exists(): time.sleep(0.001)
    if os.environ.get(f'FAKE_{{role}}_TEARDOWN_MALFORMED') == '1':
        print('KER_IO_DONE not-json', flush=True)
    else:
        print('KER_IO_DONE {{}}', flush=True)
    Path(os.environ[f'FAKE_{{role}}_DONE_FILE']).write_text('done')
    sys.exit(int(os.environ.get(f'FAKE_{{role}}_EXIT', '0')))
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
from pathlib import Path
status = b'KER_NATIVE_READY\\n'
if os.environ.get('FAKE_NATIVE_DONE') == '1':
    status += b'KER_NATIVE_DONE\\n'
if os.environ.get('FAKE_APP_MARKER'):
    Path(os.environ['FAKE_APP_MARKER']).write_text('spawned')
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
        cls.multi_config = cls.root / 'multiport-two-aux.ini'
        cls.multi_config.write_text('[interface.aux0]\naddress=198.19.0.2/24\n'
            'port=aux0\neal=--no-pci\n[interface.aux1]\naddress=198.20.0.2/24\n'
            'port=aux1\neal=--no-pci\n')
        cls.aux_pid_file = cls.root / 'aux.pid'
        cls.aux_done_file = cls.root / 'aux.done'
        cls.app_start_file = cls.root / 'app.start'
        cls.app_done_file = cls.root / 'app.done'
        cls.teardown_file = cls.root / 'native.stopping'
        cls.primary_pid_file = cls.root / 'primary.pid'
        cls.primary_done_file = cls.root / 'primary.done'
        cls.teardown_start_file = cls.root / 'teardown.start'
        cls.teardown_app_done_file = cls.root / 'teardown.app.done'
        cls.startup_delay_file = cls.root / 'startup-delay'
        cls.app_marker_file = cls.root / 'app-spawned'
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

    def startup_worker_loss(self, role):
        self.startup_delay_file.unlink(missing_ok=True)
        self.app_marker_file.unlink(missing_ok=True)
        return self.run_launcher(0, native_done=True, config=self.multi_config,
            capture_stderr=True, extra_env={
                'FAKE_STARTUP_LOSS_ROLE': role, 'FAKE_STARTUP_DELAY_PORT': 'aux1',
                'FAKE_STARTUP_DELAY_FILE': str(self.startup_delay_file),
                'FAKE_APP_MARKER': str(self.app_marker_file)})

    def test_primary_loss_during_later_aux_startup_prevents_app_spawn(self):
        result, stderr = self.startup_worker_loss('primary')
        self.assertTrue(self.startup_delay_file.exists())
        self.assertEqual(result, 125)
        self.assertIn('primary DPDK worker exited before application startup', stderr)
        self.assertFalse(self.app_marker_file.exists())

    def test_earlier_aux_loss_during_later_aux_startup_prevents_app_spawn(self):
        result, stderr = self.startup_worker_loss('aux0')
        self.assertTrue(self.startup_delay_file.exists())
        self.assertEqual(result, 125)
        self.assertIn('additional DPDK worker aux0 exited before application startup', stderr)
        self.assertFalse(self.app_marker_file.exists())

    def test_worker_loss_is_rechecked_immediately_before_app_spawn(self):
        self.app_marker_file.unlink(missing_ok=True)
        with mock.patch.object(ker_run, 'startup_worker_failure',
                               side_effect=[None, None, 'primary DPDK worker exited before application startup']) as check:
            result, stderr = self.run_launcher(0, native_done=True, config=self.multi_config,
                capture_stderr=True, extra_env={'FAKE_APP_MARKER': str(self.app_marker_file)})
        self.assertEqual(check.call_count, 3)
        self.assertEqual(result, 125)
        self.assertIn('primary DPDK worker exited before application startup', stderr)
        self.assertFalse(self.app_marker_file.exists())

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

    def graceful_native_teardown(self, *, native_done=True, primary_exit=0, aux_exit=0, delay=0,
                                 malformed_primary=False, malformed_aux=False):
        for path in (self.teardown_file, self.primary_pid_file, self.aux_pid_file,
                     self.primary_done_file, self.aux_done_file, self.teardown_start_file,
                     self.teardown_app_done_file):
            path.unlink(missing_ok=True)
        app = '''import os, sys, time
from pathlib import Path
Path(os.environ['FAKE_TEARDOWN_START_FILE']).write_text(str(time.monotonic_ns()))
startup = int(os.environ['KER_STARTUP_FD'])
os.write(startup, b'KER_NATIVE_STOPPING\\n')
time.sleep(float(os.environ.get('FAKE_TEARDOWN_DELAY', '0')))
for fd in (int(os.environ['KER_PACKET_FD']), int(os.environ['KER_PACKET_CONTROL_FD'])):
    os.close(fd)
for interface in os.environ['KER_PACKET_INTERFACES'].split(';'):
    for fd in interface.split('|')[:2]: os.close(int(fd))
Path(os.environ['FAKE_TEARDOWN_FILE']).write_text('stop')
all_exited = True
for role in ('PRIMARY', 'AUX'):
    pid = Path(os.environ[f'FAKE_{role}_PID_FILE']).read_text()
    done = Path(os.environ[f'FAKE_{role}_DONE_FILE'])
    deadline = time.monotonic() + 1
    while not done.exists() and time.monotonic() < deadline: time.sleep(0.001)
    while time.monotonic() < deadline:
        try: state = Path('/proc/' + pid + '/stat').read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError: break
        if state == 'Z': break
        time.sleep(0.001)
    else:
        all_exited = False
if os.environ.get('FAKE_NATIVE_DONE') == '1':
    os.write(startup, b'KER_NATIVE_DONE\\n')
Path(os.environ['FAKE_TEARDOWN_APP_DONE_FILE']).write_text(
    f'{time.monotonic_ns()} {int(all_exited)}')
os.close(startup)
sys.exit(0)
'''
        return self.run_launcher(0, native_done=native_done, config=self.config,
            app_source=app, capture_stderr=True, extra_env={
                'FAKE_TEARDOWN': '1', 'FAKE_TEARDOWN_FILE': str(self.teardown_file),
                'FAKE_PRIMARY_PID_FILE': str(self.primary_pid_file),
                'FAKE_PRIMARY_DONE_FILE': str(self.primary_done_file),
                'FAKE_AUX_PID_FILE': str(self.aux_pid_file),
                'FAKE_AUX_DONE_FILE': str(self.aux_done_file),
                'FAKE_TEARDOWN_START_FILE': str(self.teardown_start_file),
                'FAKE_TEARDOWN_APP_DONE_FILE': str(self.teardown_app_done_file),
                'FAKE_TEARDOWN_DELAY': str(delay),
                'FAKE_PRIMARY_EXIT': str(primary_exit), 'FAKE_AUX_EXIT': str(aux_exit),
                'FAKE_PRIMARY_TEARDOWN_MALFORMED': '1' if malformed_primary else '0',
                'FAKE_AUX_TEARDOWN_MALFORMED': '1' if malformed_aux else '0'})

    def test_native_stopping_authorizes_graceful_worker_exit(self):
        result, stderr = self.graceful_native_teardown()
        self.assertEqual(result, 0, stderr)
        self.assertTrue(self.primary_done_file.exists())
        self.assertTrue(self.aux_done_file.exists())
        app_done, all_exited = map(int, self.teardown_app_done_file.read_text().split())
        elapsed = app_done - int(self.teardown_start_file.read_text())
        self.assertEqual(all_exited, 1, 'both worker processes must exit before app success')
        self.assertLess(elapsed, 250_000_000, 'STOPPING and worker exits must complete in the app wait interval')

    def test_native_stopping_seen_during_wait_timeout_allows_orderly_worker_exit(self):
        result, stderr = self.graceful_native_teardown(delay=0.3)
        self.assertEqual(result, 0, stderr)

    def test_native_stopping_does_not_mask_missing_done(self):
        result, stderr = self.graceful_native_teardown(native_done=False)
        self.assertEqual(result, 125)
        self.assertIn('native Linux shutdown did not complete', stderr)

    def test_native_stopping_does_not_mask_nonzero_auxiliary_exit(self):
        result, _ = self.graceful_native_teardown(aux_exit=9)
        self.assertEqual(result, 125)

    def test_native_stopping_does_not_mask_nonzero_primary_exit(self):
        result, _ = self.graceful_native_teardown(primary_exit=9)
        self.assertEqual(result, 125)

    def test_native_stopping_does_not_mask_malformed_primary_completion(self):
        result, _ = self.graceful_native_teardown(malformed_primary=True)
        self.assertEqual(result, 125)

    def test_native_stopping_does_not_mask_malformed_auxiliary_completion(self):
        result, _ = self.graceful_native_teardown(malformed_aux=True)
        self.assertEqual(result, 125)


if __name__ == '__main__':
    unittest.main(verbosity=2)
