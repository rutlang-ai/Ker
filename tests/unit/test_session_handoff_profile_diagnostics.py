#!/usr/bin/env python3
"""Verify the non-FRAME profile's real early-marker diagnostic wrapper."""
import importlib.util
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / 'posix' / 'session-native-packets.py'
LAUNCHER = Path(__file__).resolve().parents[2] / 'tools' / 'ker_session_run.py'


class HandoffProfileDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(FIXTURE.parent))
        spec = importlib.util.spec_from_file_location('session_native_packets_diag_test', FIXTURE)
        cls.fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fixture)
        launcher_spec = importlib.util.spec_from_file_location('ker_session_run_eof_test', LAUNCHER)
        cls.launcher = importlib.util.module_from_spec(launcher_spec)
        launcher_spec.loader.exec_module(cls.launcher)

    def test_nonframe_peer_marker_uses_redirected_stderr_and_failure_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='session-handoff-marker-') as directory:
            stderr_path = Path(directory) / 'runner.stderr'
            with stderr_path.open('wb') as stderr:
                process = subprocess.Popen([sys.executable, '-c',
                    "import sys; print('runner failed at active dequeue', file=sys.stderr)"],
                    stdout=subprocess.PIPE, stderr=stderr)
            diagnostics = []
            def failure_snapshot(reason):
                diagnostics.append(reason)
                return RuntimeError('profile snapshot: ' + reason)
            with self.assertRaisesRegex(RuntimeError, 'profile snapshot: runner failed before KER_SESSION_TEST_NONFRAME_PEER_KILLED') as caught:
                self.fixture.record_handoff_marker(process, 'KER_SESSION_TEST_NONFRAME_PEER_KILLED',
                    stderr_path, failure_snapshot)
            process.wait(timeout=3)
            if process.stdout is not None:
                process.stdout.close()
            self.assertEqual(process.returncode, 0)
            self.assertEqual(len(diagnostics), 1)
            self.assertIn('runner failed at active dequeue', diagnostics[0])
            self.assertIn('runner failed at active dequeue', str(caught.exception))

    def test_nonframe_callsite_uses_profile_failure_diagnostics(self):
        source = FIXTURE.read_text()
        branch = source[source.index("if mode == 'nonframe-active-reap':", source.index('def run_live_handoff_profile')):]
        branch = branch[:branch.index("            if mode == 'frame-positive':")]
        self.assertIn("record_handoff_marker(runner, 'KER_SESSION_TEST_NONFRAME_PEER_KILLED'", branch)
        self.assertIn('runner_stderr_path, fatal_profile_diagnostics)', branch)

    def test_bounded_capture_does_not_wait_for_descendant_pipe_writers(self):
        process = subprocess.Popen([sys.executable, '-c',
            'import subprocess,sys; p=subprocess.Popen([sys.executable,"-c",'
            '"import time; time.sleep(10)"]); print(p.pid, flush=True)'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 2)[0],
                'child PID did not become readable before the bounded-capture test')
            started = time.monotonic()
            output, errors = self.fixture.communicate_bounded(process, timeout=0.2)
            self.assertLess(time.monotonic() - started, 2)
            child_pid = int(output.decode().strip())
            self.assertEqual(errors, b'')
            self.assertIsNotNone(process.poll())
        finally:
            try:
                import os
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    def test_frame_owner_waits_for_exit_after_stdout_eof(self):
        source = LAUNCHER.read_text()
        finish = source[source.index('    def finish_frame_owner_output():'):
            source.index('    def validate_frame_commit_drain_bijection():')]
        self.assertIn('wait_after_pipe_eof(worker,', finish)
        process = subprocess.Popen([sys.executable, '-c',
            'import os,sys; os.close(1); sys.stdin.buffer.read(1)'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(select.select([process.stdout], [], [], 1)[0])
            self.assertIsNone(process.poll(), 'fixture must observe EOF before process exit')
            process.stdin.write(b'x')
            process.stdin.flush()
            process.stdin.close()
            self.assertEqual(self.launcher.wait_after_pipe_eof(process, 1,
                'fixture process did not exit'), 0)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=1)

    def test_failure_diagnostics_use_bounded_capture_for_fallbacks(self):
        source = FIXTURE.read_text()
        diagnostic_helpers = source[source.index('            def startup_failure(reason):'):
            source.index('            try:\n                ready_line = line(runner')]
        diagnostic_helpers += source[source.index('            def fatal_profile_diagnostics(reason):'):
            source.index("            require(not select.select([app_pidfd, owner_pidfd, peer_pidfd]")]
        diagnostic_helpers += source[source.index('            if profile_expects_failure:'):
            source.index("            if mode == 'timeout':")]
        self.assertNotIn('communicate()', diagnostic_helpers)
        self.assertIn('communicate_bounded(', diagnostic_helpers)

    def test_positive_modes_are_not_classified_as_fatal_negative_profiles(self):
        source = FIXTURE.read_text()
        branch = source[source.index('            if profile_expects_failure:'):
            source.index("            if mode == 'timeout':")]
        self.assertEqual(self.fixture.HANDOFF_SUCCESS_PROFILES, ('positive', 'frame-positive'))
        self.assertFalse(self.fixture.handoff_profile_expects_failure('positive'))
        self.assertFalse(self.fixture.handoff_profile_expects_failure('frame-positive'))
        self.assertFalse(self.fixture.handoff_profile_expects_failure('nonframe-active-reap'))
        self.assertTrue(self.fixture.handoff_profile_expects_failure('bad-capability'))
        self.assertTrue(self.fixture.handoff_profile_expects_failure('peer-death'))
        self.assertTrue(self.fixture.handoff_profile_expects_failure('timeout'))
        with self.assertRaisesRegex(ValueError, 'unsupported handoff profile: typo'):
            self.fixture.handoff_profile_expects_failure('typo')
        self.assertIn('runner.communicate(timeout=20)', branch)
        self.assertIn('for mode in HANDOFF_NEGATIVE_PROFILES:', source)
        self.assertIn('profile_expects_failure = handoff_profile_expects_failure(mode)', source)


if __name__ == '__main__':
    unittest.main()
