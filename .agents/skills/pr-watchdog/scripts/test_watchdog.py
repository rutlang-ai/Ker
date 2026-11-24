#!/usr/bin/env python3
"""Regression tests for watcher discovery and error event delivery."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stdout
import poll_prs
import watchdog


class DiscoveryTest(unittest.TestCase):
    def test_all_discovered_commands_must_exit_before_replacement(self):
        found = [(11, ['python', 'poll', 'thread-one']), (12, ['python', 'poll', 'thread-two'])]
        with mock.patch.object(watchdog, 'matching_processes', side_effect=[[], [12]]):
            self.assertEqual(watchdog.remaining_processes(found), [12])
        with mock.patch.object(watchdog, 'matching_processes', side_effect=[[], []]):
            self.assertEqual(watchdog.remaining_processes(found), [])

    def test_discovers_without_manifest_and_rejects_overlapping_sets(self):
        command = ['/usr/bin/python3', '/repo/scripts/poll_prs.py', 'owner/repo#1',
                   '--state-file', '/state/poll.json', '--on-change-command', 'enqueue']
        path = mock.Mock()
        path.parent.name = '123'
        path.read_bytes.return_value = b'\0'.join(x.encode() for x in command) + b'\0'
        with mock.patch.object(Path, 'glob', return_value=[path]):
            self.assertEqual(watchdog.discover_pollers(['owner/repo#1'], Path('/state/poll.json')),
                             [(123, command)])
            with self.assertRaisesRegex(RuntimeError, 'overlapping PR watch'):
                watchdog.discover_pollers(['owner/repo#1', 'owner/repo#2'], Path('/state/poll.json'))
            with self.assertRaisesRegex(RuntimeError, 'overlapping PR watch'):
                watchdog.discover_pollers(['owner/repo#1'], Path('/other/poll.json'))
            self.assertEqual(watchdog.discover_pollers(['owner/repo#3'], Path('/state/poll.json')), [])


class ErrorDeliveryTest(unittest.TestCase):
    def run_cycle(self, state, error=None, fail_dispatch=False):
        dispatched = []
        def deliver(command, event):
            dispatched.append(event)
            if fail_dispatch:
                raise RuntimeError('queue unavailable')
        with (mock.patch.object(sys, 'argv', ['poll_prs.py', 'owner/repo#1', '--once',
                      '--state-file', str(state), '--on-change-command', 'enqueue']),
              mock.patch.object(poll_prs, 'validate_state_path', return_value=state),
              mock.patch.object(poll_prs, 'query_pr', side_effect=error, return_value=object()),
              mock.patch.object(poll_prs, 'summary', return_value={'state': 'OPEN'}),
              mock.patch.object(poll_prs, 'dispatch_event', side_effect=deliver),
              redirect_stdout(io.StringIO())):
            result = poll_prs.main()
        return result, dispatched

    def test_error_is_dispatched_once_then_recovery_is_dispatched(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)/'poll.json'
            result, events = self.run_cycle(state, RuntimeError('token revoked'))
            self.assertEqual(result, 1)
            self.assertEqual(events[0]['event'], 'poll_error')
            self.assertTrue(json.loads(state.read_text())['prs']['owner/repo#1']['error_dispatched'])
            _, events = self.run_cycle(state, RuntimeError('token revoked'))
            self.assertEqual(events, [])
            result, events = self.run_cycle(state)
            self.assertEqual(result, 0)
            self.assertEqual(events[0]['event'], 'changed')
            self.assertNotIn('last_error', json.loads(state.read_text())['prs']['owner/repo#1'])

    def test_failed_error_dispatch_is_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)/'poll.json'
            self.run_cycle(state, RuntimeError('denied'), fail_dispatch=True)
            self.assertFalse(json.loads(state.read_text())['prs']['owner/repo#1']['error_dispatched'])
            _, events = self.run_cycle(state, RuntimeError('denied'))
            self.assertEqual(events[0]['event'], 'poll_error')


if __name__ == '__main__':
    unittest.main()
