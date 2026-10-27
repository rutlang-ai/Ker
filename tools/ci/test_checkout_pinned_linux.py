#!/usr/bin/env python3
"""Offline fault-injection tests for the pinned Linux checkout retry helper."""
from __future__ import annotations

from pathlib import Path
import subprocess
import unittest
from unittest import mock

import checkout_pinned_linux as checkout


PINNED = "1" * 40


def completed(command, returncode=0, stdout=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout)


class PinnedLinuxCheckoutTests(unittest.TestCase):
    def fake_run(self, responses):
        def run(command, *, cwd):
            self.assertEqual(cwd, Path("/repo"))
            if command[:3] == ["git", "ls-tree", "HEAD"]:
                return completed(command, stdout=f"160000 commit {PINNED}\tthird_party/linux\n")
            return responses.pop(0)
        return run

    def test_retries_429_with_bounded_backoff_then_verifies_gitlink(self):
        responses = [
            completed(["git"], 1, "fatal: clone returned error: 429"),
            completed(["git"], 0),
            completed(["git"], 0, PINNED + "\n"),
        ]
        waits = []
        result = checkout.checkout_pinned_linux(
            Path("/repo"), max_attempts=3, initial_backoff_seconds=15,
            run=self.fake_run(responses), sleep=waits.append, output=lambda _message: None,
        )
        self.assertEqual(result, PINNED)
        self.assertEqual(waits, [15])
        self.assertEqual(responses, [])

    def test_retries_429_only_up_to_limit(self):
        responses = [completed(["git"], 1, "HTTP 429") for _ in range(4)]
        waits = []
        with self.assertRaises(subprocess.CalledProcessError):
            checkout.checkout_pinned_linux(
                Path("/repo"), max_attempts=4, run=self.fake_run(responses),
                sleep=waits.append, output=lambda _message: None,
            )
        self.assertEqual(waits, [15, 30, 60])
        self.assertEqual(responses, [])

    def test_does_not_retry_non_429_errors(self):
        responses = [completed(["git"], 1, "fatal: repository not found")]
        waits = []
        with self.assertRaises(subprocess.CalledProcessError):
            checkout.checkout_pinned_linux(
                Path("/repo"), run=self.fake_run(responses), sleep=waits.append,
                output=lambda _message: None,
            )
        self.assertEqual(responses, [])
        self.assertEqual(waits, [])

    def test_rejects_successful_checkout_at_wrong_gitlink(self):
        responses = [completed(["git"], 0), completed(["git"], 0, "2" * 40)]
        with self.assertRaisesRegex(RuntimeError, "does not match pinned gitlink"):
            checkout.checkout_pinned_linux(
                Path("/repo"), run=self.fake_run(responses), sleep=lambda _delay: None,
                output=lambda _message: None,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
