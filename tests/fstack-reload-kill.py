#!/usr/bin/env python3
"""Exercise the Ker signal adapter with the pinned F-Stack harness assertions."""

from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest import mock

UPSTREAM = Path(__file__).resolve().parent / "upstream/fstack/tests/unit"
sys.path.insert(0, str(UPSTREAM))
import test_reload_harness as harness

HELPER = Path(__file__).resolve().parents[1] / "tools/fstack-reload-kill.sh"


class AdapterTests(unittest.TestCase):
    def test_capabilities_from_bash(self):
        result = subprocess.check_output(["bash", str(HELPER), "--capabilities"], text=True)
        self.assertEqual(result, "pidfd-identity-v1\n")

    def test_wait_timeout_does_not_escalate(self):
        with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"]) as target:
            try:
                identity = harness.checks.identity(target.pid)
                self.assertEqual(harness.checks.signal_owned(identity, "STOP", 0.05), 3)
                self.assertIsNone(target.poll())
                self.assertEqual(harness.checks.signal_owned(identity, "CONT"), 0)
                self.assertEqual(harness.checks.signal_owned(identity, "TERM", 1), 0)
                self.assertEqual(target.wait(timeout=2), -signal.SIGTERM)
            finally:
                if target.poll() is None:
                    target.kill()


if __name__ == "__main__":
    methods = (
        "test_identity_mismatch_refused",
        "test_explicit_signal_does_not_escalate",
        "test_wrapper_validation_before_signals",
    )
    suite = unittest.TestSuite(harness.OwnedProcessTests(name) for name in methods)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(AdapterTests))
    with (mock.patch.object(harness, "KILL", HELPER),
          mock.patch.object(harness.checks, "KILL_TOOL", str(HELPER)),
          mock.patch.object(harness.OwnedProcessTests, "setUpClass"),
          mock.patch.object(harness.OwnedProcessTests, "tearDownClass")):
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
