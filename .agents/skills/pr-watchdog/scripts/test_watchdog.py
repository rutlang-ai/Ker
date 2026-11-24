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

    def test_discovers_canonical_url_and_skips_option_values(self):
        command = ['/usr/bin/python3', '/repo/scripts/poll_prs.py',
                   'https://github.com/owner/repo/pull/1', '--state-file',
                   '/state/poll.json', '--on-change-command', 'owner/repo#999']
        path = mock.Mock()
        path.parent.name = '123'
        path.read_bytes.return_value = b'\0'.join(x.encode() for x in command) + b'\0'
        with mock.patch.object(Path, 'glob', return_value=[path]):
            self.assertEqual(watchdog.discover_pollers(['owner/repo#1'], Path('/state/poll.json')),
                             [(123, command)])
            with self.assertRaisesRegex(RuntimeError, 'overlapping PR watch'):
                watchdog.discover_pollers(
                    ['owner/repo#1', 'owner/repo#2'], Path('/state/poll.json'))

    def test_discovery_matches_mixed_case_identifiers_to_lowercase_watch_key(self):
        commands = [
            (['/usr/bin/python3', '/repo/scripts/poll_prs.py',
              'https://github.com/OWNER/Repo/pull/1', '--state-file', '/state/poll.json'], False),
            (['/usr/bin/python3', '/repo/scripts/poll_prs.py',
              'OWNER/Repo#1', '--state-file', '/state/poll.json'], False),
            (['/usr/bin/python3', '/repo/scripts/poll_prs.py',
              '1', '--state-file', '/state/poll.json'], True),
        ]
        for pid, (command, numeric) in enumerate(commands, 201):
            path = mock.Mock()
            path.parent.name = str(pid)
            path.read_bytes.return_value = b'\0'.join(x.encode() for x in command) + b'\0'
            with (
                mock.patch.object(Path, 'glob', return_value=[path]),
                mock.patch.object(watchdog, 'process_repo', return_value='OWNER/Repo') as process_repo,
            ):
                found = watchdog.discover_pollers(['owner/repo#1'], Path('/state/poll.json'))
            self.assertEqual(found, [(pid, command)])
            if numeric:
                process_repo.assert_called_once_with(pid)
            else:
                process_repo.assert_not_called()

    def test_discovers_numeric_identifier_in_poller_repository(self):
        command = ['/usr/bin/python3', '/repo/scripts/poll_prs.py', '7',
                   '--state-file', '/state/poll.json', '--interval', 'owner/other#8']
        path = mock.Mock()
        path.parent.name = '321'
        path.read_bytes.return_value = b'\0'.join(x.encode() for x in command) + b'\0'
        with (
            mock.patch.object(Path, 'glob', return_value=[path]),
            mock.patch.object(watchdog, 'process_repo', return_value='owner/repo') as process_repo,
        ):
            self.assertEqual(watchdog.discover_pollers(['owner/repo#7'], Path('/state/poll.json')),
                             [(321, command)])
        process_repo.assert_called_once_with(321)

    def test_optional_hook_metadata_is_defensive(self):
        self.assertIsNone(watchdog.poller_thread([
            'python', 'poll_prs.py', 'owner/repo#1', '--state-file', '/state.json',
        ]))
        self.assertIsNone(watchdog.poller_thread([
            'python', 'poll_prs.py', '--on-change-command', 'custom-hook --thread custom',
        ]))
        self.assertIsNone(watchdog.poller_thread([
            'python', 'poll_prs.py', '--on-change-command', 'dispatch_codex.py --thread',
        ]))
        self.assertIsNone(watchdog.poller_thread([
            'python', 'poll_prs.py', '--on-change-command',
            'custom-hook --config /tmp/dispatch_codex.py --thread value',
        ]))
        self.assertEqual(watchdog.poller_thread([
            'python', 'poll_prs.py', '--on-change-command',
            'python /scripts/dispatch_codex.py --thread abc',
        ]), 'abc')

    def test_status_and_stop_accept_a_running_direct_poller(self):
        command = ['/usr/bin/python3', '/repo/scripts/poll_prs.py', 'owner/repo#1',
                   '--state-file', '/state/poll.json']
        for action in ('status', 'stop'):
            output = io.StringIO()
            with tempfile.TemporaryDirectory() as temporary:
                state_path = Path(temporary) / 'state.json'
                poll_prs.save_state(state_path, {'prs': {
                    'owner/repo#1': {'fingerprint': 'current'},
                }})
                with (
                    mock.patch.object(sys, 'argv', ['watchdog.py', action, 'owner/repo#1']),
                    mock.patch.object(watchdog.Path, 'home', return_value=Path(temporary)),
                    mock.patch.object(watchdog, 'validate_state_path',
                                      return_value=state_path),
                    mock.patch.object(watchdog, 'discover_pollers', return_value=[(42, command)]),
                    mock.patch.object(watchdog, 'remaining_processes', return_value=[]),
                    mock.patch.object(watchdog.os, 'kill') as kill,
                    redirect_stdout(output),
                ):
                    self.assertEqual(watchdog.main(), 0)
                self.assertEqual(json.loads(output.getvalue())['status'],
                                 'stopped' if action == 'stop' else 'running')
                self.assertEqual(kill.call_count, 1 if action == 'stop' else 0)

    def test_start_reconciles_duplicate_unhooked_pollers_with_explicit_thread(self):
        command = ['/usr/bin/python3', '/repo/scripts/poll_prs.py', 'owner/repo#1',
                   '--state-file', '/state/poll.json']
        found = [(41, command), (42, command)]
        child = mock.Mock()
        child.poll.return_value = 0
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / 'state.json'
            state_path.touch()
            with (
                mock.patch.object(sys, 'argv', [
                    'watchdog.py', 'start', 'owner/repo#1', '--thread', 'thread-abc',
                ]),
                mock.patch.object(watchdog.Path, 'home', return_value=Path(temporary)),
                mock.patch.object(watchdog, 'validate_state_path', return_value=state_path),
                mock.patch.object(watchdog, 'discover_pollers', return_value=found),
                mock.patch.object(watchdog, 'remaining_processes', return_value=[]),
                mock.patch.object(watchdog, 'matching_processes', return_value=[99]),
                mock.patch.object(watchdog, 'load_state', side_effect=[
                    {'prs': {'owner/repo#1': {'fingerprint': 'old'}}},
                    {'prs': {'owner/repo#1': {'fingerprint': 'fresh'}}},
                ]),
                mock.patch.object(watchdog, 'save_state'),
                mock.patch.object(watchdog.subprocess, 'run'),
                mock.patch.object(watchdog.subprocess, 'Popen', return_value=child) as popen,
                mock.patch.object(watchdog.os, 'kill') as kill,
                redirect_stdout(output),
            ):
                self.assertEqual(watchdog.main(), 0)
            self.assertEqual(kill.call_args_list, [
                mock.call(41, watchdog.signal.SIGTERM),
                mock.call(42, watchdog.signal.SIGTERM),
            ])
            self.assertEqual(popen.call_count, 1)
            launch_command = popen.call_args.args[0]
            hook = launch_command[launch_command.index('--on-change-command') + 1]
            self.assertIn('--thread thread-abc', hook)
            self.assertEqual(json.loads(output.getvalue())['thread'], 'thread-abc')

    def test_start_rejects_duplicate_unhooked_pollers_without_thread(self):
        command = ['/usr/bin/python3', '/repo/scripts/poll_prs.py', 'owner/repo#1',
                   '--state-file', '/state/poll.json']
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(sys, 'argv', ['watchdog.py', 'start', 'owner/repo#1']),
                mock.patch.dict(watchdog.os.environ, {'CODEX_THREAD_ID': ''}),
                mock.patch.object(watchdog.Path, 'home', return_value=Path(temporary)),
                mock.patch.object(watchdog, 'validate_state_path',
                                  return_value=Path(temporary) / 'state.json'),
                mock.patch.object(watchdog, 'discover_pollers',
                                  return_value=[(41, command), (42, command)]),
                mock.patch.object(watchdog.os, 'kill') as kill,
                mock.patch.object(watchdog.subprocess, 'Popen') as popen,
            ):
                with self.assertRaisesRegex(RuntimeError, 'provide --thread'):
                    watchdog.main()
            kill.assert_not_called()
            popen.assert_not_called()

    def test_start_rejects_single_unhooked_poller_when_thread_requested(self):
        command = ['/usr/bin/python3', '/repo/scripts/poll_prs.py', 'owner/repo#1',
                   '--state-file', '/state/poll.json']
        with tempfile.TemporaryDirectory() as temporary:
            with (
                mock.patch.object(sys, 'argv', [
                    'watchdog.py', 'start', 'owner/repo#1', '--thread', 'thread-abc',
                ]),
                mock.patch.object(watchdog.Path, 'home', return_value=Path(temporary)),
                mock.patch.object(watchdog, 'validate_state_path',
                                  return_value=Path(temporary) / 'state.json'),
                mock.patch.object(watchdog, 'discover_pollers', return_value=[(41, command)]),
                mock.patch.object(watchdog.os, 'kill') as kill,
                mock.patch.object(watchdog.subprocess, 'Popen') as popen,
                mock.patch.object(watchdog.subprocess, 'run') as run,
            ):
                with self.assertRaisesRegex(RuntimeError, 'stop it, then start again'):
                    watchdog.main()
            kill.assert_not_called()
            popen.assert_not_called()
            run.assert_not_called()

    def test_restart_preserves_retired_fingerprint_and_clears_active_stale_error(self):
        state = {'prs': {
            'owner/repo#1': {'terminal': True, 'fingerprint': 'done',
                             'last_error': 'old error', 'error_dispatched': True},
            'owner/repo#2': {'terminal': False, 'fingerprint': 'old',
                             'error_dispatched': True},
        }}
        watchdog.reset_restart_fingerprints(state, ['owner/repo#1', 'owner/repo#2'])
        self.assertEqual(state['prs']['owner/repo#1']['fingerprint'], 'done')
        self.assertTrue(state['prs']['owner/repo#1']['error_dispatched'])
        self.assertNotIn('fingerprint', state['prs']['owner/repo#2'])
        self.assertNotIn('error_dispatched', state['prs']['owner/repo#2'])

    def test_terminal_records_satisfy_startup_and_health(self):
        records = {'owner/repo#1': {'terminal': True}}
        self.assertTrue(watchdog.startup_ready(records, ['owner/repo#1'], 100))
        self.assertTrue(watchdog.watch_healthy(records, ['owner/repo#1']))
        active = {'owner/repo#1': {
            'fingerprint': 'old', 'last_polled_at': 200,
            'last_dispatch_error': 'changed: queue unavailable',
        }}
        self.assertFalse(watchdog.startup_ready(active, ['owner/repo#1'], 100))
        self.assertFalse(watchdog.watch_healthy(active, ['owner/repo#1']))
        active['owner/repo#1'].pop('last_dispatch_error')
        self.assertTrue(watchdog.startup_ready(active, ['owner/repo#1'], 100))
        self.assertTrue(watchdog.watch_healthy(active, ['owner/repo#1']))
        self.assertFalse(watchdog.watch_healthy(
            {'owner/repo#1': {'last_error': 'query failed'}}, ['owner/repo#1']))


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
