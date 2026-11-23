#!/usr/bin/env python3
"""Verify the non-FRAME profile's real early-marker diagnostic wrapper."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
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


if __name__ == '__main__':
    unittest.main()
