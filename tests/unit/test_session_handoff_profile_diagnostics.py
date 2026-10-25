#!/usr/bin/env python3
"""Verify the non-FRAME profile's real early-marker diagnostic wrapper."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / 'posix' / 'session-native-packets.py'


class HandoffProfileDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(FIXTURE.parent))
        spec = importlib.util.spec_from_file_location('session_native_packets_diag_test', FIXTURE)
        cls.fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fixture)

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
        started = time.monotonic()
        try:
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

    def test_failure_diagnostics_use_bounded_capture_for_fallbacks(self):
        source = FIXTURE.read_text()
        diagnostic_helpers = source[source.index('            def startup_failure(reason):'):
            source.index('            try:\n                ready_line = line(runner')]
        diagnostic_helpers += source[source.index('            def fatal_profile_diagnostics(reason):'):
            source.index("            require(not select.select([app_pidfd, owner_pidfd, peer_pidfd]")]
        diagnostic_helpers += source[source.index("            if mode != 'positive':"):
            source.index("            if mode == 'timeout':")]
        self.assertNotIn('communicate()', diagnostic_helpers)
        self.assertIn('communicate_bounded(', diagnostic_helpers)


if __name__ == '__main__':
    unittest.main()
