import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


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

    def test_recognized_connection_reset_retries_same_pinned_fetch_and_verifies(self):
        real_attempt = builder._run_fetch_attempt
        fetch_commands = []

        def attempt(command, timeout):
            fetch_commands.append((list(command), timeout))
            if len(fetch_commands) == 1:
                return subprocess.CompletedProcess(command, 128, '',
                    "fatal: unable to access: Recv failure: Connection reset by peer")
            return real_attempt(command, timeout)

        with mock.patch.object(builder, '_run_fetch_attempt', side_effect=attempt), \
                mock.patch.object(builder, 'sleep') as sleep:
            builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        self.assertEqual(len(fetch_commands), 2)
        for command, timeout in fetch_commands:
            self.assertEqual(command[-2:], [self.origin.as_uri(), self.revisions[0]])
            self.assertIn('--depth=1', command)
            self.assertIn('--no-tags', command)
            self.assertEqual(timeout, builder.FETCH_ATTEMPT_TIMEOUT_SECONDS)
        sleep.assert_called_once_with(builder.FETCH_BACKOFF_SECONDS[0])
        git(self.cache, 'cat-file', '-e', self.revisions[0] + '^{commit}')

    def test_permanent_auth_tls_and_bad_revision_errors_fail_without_retry(self):
        messages = (
            'fatal: Authentication failed',
            'fatal: SSL certificate problem: unable to get local issuer certificate',
            "fatal: couldn't find remote ref deadbeef",
            'fatal: TLS certificate validation failed after connection reset by peer',
        )
        for message in messages:
            with self.subTest(message=message):
                calls = []
                def attempt(command, timeout):
                    calls.append(command)
                    return subprocess.CompletedProcess(command, 128, '', message)
                with mock.patch.object(builder, '_run_fetch_attempt', side_effect=attempt), \
                        mock.patch.object(builder, 'sleep') as sleep:
                    with self.assertRaises(subprocess.CalledProcessError):
                        builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
                self.assertEqual(len(calls), 1)
                sleep.assert_not_called()

    def test_unknown_errors_fail_immediately_and_transient_exhaustion_is_bounded(self):
        for message, expected_attempts, expected_sleeps in (
                ('fatal: unsupported protocol', 1, 0),
                ('fatal: The requested URL returned error: 501', 1, 0),
                ('fatal: The requested URL returned error: 505', 1, 0),
                ('fatal: unable to access: Failed to connect: Connection timed out',
                    builder.FETCH_ATTEMPTS, len(builder.FETCH_BACKOFF_SECONDS))):
            with self.subTest(message=message):
                calls = []
                def attempt(command, timeout):
                    calls.append(command)
                    return subprocess.CompletedProcess(command, 128, '', message)
                with mock.patch.object(builder, '_run_fetch_attempt', side_effect=attempt), \
                        mock.patch.object(builder, 'sleep') as sleep:
                    with self.assertRaises(subprocess.CalledProcessError):
                        builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
                self.assertEqual(len(calls), expected_attempts)
                self.assertEqual(sleep.call_count, expected_sleeps)
        self.assertLessEqual(builder.FETCH_TOTAL_BUDGET_SECONDS, 600)

    def test_successful_fetch_is_verified_and_missing_commit_is_not_accepted(self):
        calls = []
        def attempt(command, timeout):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, '', '')
        with mock.patch.object(builder, '_run_fetch_attempt', side_effect=attempt):
            with self.assertRaisesRegex(RuntimeError, 'commit is absent'):
                builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        self.assertEqual(len(calls), 1)

    def test_permanent_diagnostic_wins_over_timeout_classification(self):
        calls = []
        def attempt(command, timeout):
            calls.append(command)
            raise subprocess.TimeoutExpired(command, timeout,
                stderr='fatal: SSL certificate verification failed; connection timed out')
        with mock.patch.object(builder, '_run_fetch_attempt', side_effect=attempt), \
                mock.patch.object(builder, 'sleep') as sleep:
            with self.assertRaises(subprocess.TimeoutExpired):
                builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_repeated_actual_timeouts_exhaust_finite_attempt_budget(self):
        calls = []
        def attempt(command, timeout):
            calls.append(command)
            raise subprocess.TimeoutExpired(command, timeout,
                stderr='fatal: Operation timed out while connecting')
        with mock.patch.object(builder, '_run_fetch_attempt', side_effect=attempt), \
                mock.patch.object(builder, 'sleep') as sleep:
            with self.assertRaises(subprocess.TimeoutExpired):
                builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        self.assertEqual(len(calls), builder.FETCH_ATTEMPTS)
        self.assertEqual([call.args[0] for call in sleep.call_args_list],
            list(builder.FETCH_BACKOFF_SECONDS))

    def test_hard_timeout_retries_when_diagnostic_is_transient(self):
        real_attempt = builder._run_fetch_attempt
        calls = []

        def attempt(command, timeout):
            calls.append(command)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(command, timeout,
                    stderr='fatal: Operation timed out while connecting')
            return real_attempt(command, timeout)

        with mock.patch.object(builder, '_run_fetch_attempt', side_effect=attempt), \
                mock.patch.object(builder, 'sleep') as sleep:
            builder.fetch(self.cache, self.origin.as_uri(), self.revisions[0])
        self.assertEqual(len(calls), 2)
        sleep.assert_called_once_with(builder.FETCH_BACKOFF_SECONDS[0])
        git(self.cache, 'cat-file', '-e', self.revisions[0] + '^{commit}')

    def test_timeout_kills_fetch_helper_group_and_reaps_git_parent(self):
        pid_file = self.root / 'helper.pid'
        fake_git = self.root / 'fake-git'
        fake_git.write_text('#!/usr/bin/env python3\n'
            'import subprocess, sys, time\n'
            'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])\n'
            'open(sys.argv[1], "w").write(str(child.pid))\n'
            'time.sleep(60)\n')
        fake_git.chmod(0o755)
        processes = []
        real_popen = subprocess.Popen

        def track(*args, **kwargs):
            value = real_popen(*args, **kwargs)
            processes.append(value)
            return value

        with mock.patch.object(builder.subprocess, 'Popen', side_effect=track):
            with self.assertRaises(subprocess.TimeoutExpired):
                builder._run_fetch_attempt([str(fake_git), str(pid_file)], timeout=0.2)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)
        helper_pid = int(pid_file.read_text())
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                stat_fields = Path(f'/proc/{helper_pid}/stat').read_text().split(') ', 1)[1].split()
                state = stat_fields[0]
            except FileNotFoundError:
                state = None
            if state in (None, 'Z'):
                break
            time.sleep(0.02)
        self.assertIn(state, (None, 'Z'), 'fetch helper survived the bounded group kill')


if __name__ == '__main__':
    unittest.main(verbosity=2)
