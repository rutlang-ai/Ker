#!/usr/bin/env python3
"""Regression tests for bounded Codex event delivery."""
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import dispatch_codex


class DispatchCodexTest(unittest.TestCase):
    def test_small_event_remains_inline(self):
        event = {"event": "changed", "pr": "owner/repo#1"}
        with mock.patch.object(dispatch_codex, "persist_event") as persist:
            message = dispatch_codex.event_message(event)
        self.assertIn(json.dumps(event, ensure_ascii=False, sort_keys=True), message)
        persist.assert_not_called()

    def test_oversized_event_uses_deterministic_atomic_file_reference(self):
        event = {"event": "changed", "pr": "owner/repo#1", "detail": "é" * 40000}
        expected = (json.dumps(event, ensure_ascii=False, sort_keys=True)).encode("utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(Path, "home", return_value=Path(temporary)),
                mock.patch.object(dispatch_codex, "validate_state_path", side_effect=lambda p: p.resolve()),
            ):
                message = dispatch_codex.event_message(event)
                repeated = dispatch_codex.event_message(event)
            self.assertLess(len(message.encode("utf-8")), dispatch_codex.INLINE_EVENT_LIMIT)
            self.assertEqual(message, repeated)
            encoded_path = message.split("stored at ", 1)[1].split(". Read and parse", 1)[0]
            path = Path(json.loads(encoded_path))
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(path.parent.glob("*.tmp")), [])

    def test_queue_failure_keeps_oversized_event_reference_for_retry(self):
        event = {"event": "changed", "detail": "x" * 70000}
        payload = json.dumps(event)
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(sys, "argv", ["dispatch_codex.py", "--thread", "thread-1"]),
                mock.patch.object(sys, "stdin", io.StringIO(payload)),
                mock.patch.object(Path, "home", return_value=Path(temporary)),
                mock.patch.object(dispatch_codex, "validate_state_path", side_effect=lambda p: p.resolve()),
                mock.patch.object(dispatch_codex.subprocess, "run", return_value=
                                  subprocess.CompletedProcess(["codex"], 4, "", "queue failed")) as run,
            ):
                self.assertEqual(dispatch_codex.main(), 4)
                first_message = run.call_args.args[0][-1]
                reference = json.loads(first_message.split("stored at ", 1)[1].split(". Read and parse", 1)[0])
                self.assertTrue(Path(reference).is_file())
                sys.stdin.seek(0)
                self.assertEqual(dispatch_codex.main(), 4)
                self.assertEqual(run.call_args.args[0][-1], first_message)
                self.assertEqual(len(list(Path(reference).parent.glob("event-*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
