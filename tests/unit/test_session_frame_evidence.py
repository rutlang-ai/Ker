#!/usr/bin/env python3
"""Lifecycle tests for frame evidence capture (no EAL or runtime claim)."""
import importlib.util
from pathlib import Path
import os
import subprocess
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests' / 'posix'))
SOURCE = ROOT / 'tests' / 'posix' / 'session-native-packets.py'
SPEC = importlib.util.spec_from_file_location('session_native_packets_evidence', SOURCE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class EvidenceCaptureLifecycleTests(unittest.TestCase):
    def test_pidfd_readability_is_snapshotted_before_close(self):
        actors = {name: subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.15)'])
            for name in ('app', 'producer', 'consumer')}
        actor_fds = {name: os.pidfd_open(process.pid) for name, process in actors.items()}
        actor_pids = {name: process.pid for name, process in actors.items()}
        resident = subprocess.Popen([sys.executable, '-c', 'pass'])
        resident_fd = os.pidfd_open(resident.pid)
        try:
            FIXTURE._validate_actor_pidfd_mapping(actor_fds, actor_pids)
            with self.assertRaisesRegex(ValueError, 'exactly'):
                FIXTURE._validate_actor_pidfd_mapping({'app': actor_fds['app']}, {'app': actor_pids['app']})
            wrong = dict(actor_fds, producer=actor_fds['consumer'], consumer=actor_fds['producer'])
            with self.assertRaisesRegex(ValueError, 'does not name'):
                FIXTURE._validate_actor_pidfd_mapping(wrong, actor_pids)
            for child in actors.values(): child.wait(timeout=5)
            resident.wait(timeout=5)
            actors, resident_dead = FIXTURE._capture_pidfd_readability(
                actor_fds, resident_fd)
            self.assertEqual(actors, {'app': True, 'producer': True, 'consumer': True})
            self.assertTrue(resident_dead)
            for fd in actor_fds.values(): os.close(fd)
            actor_fds.clear()
            os.close(resident_fd)
            resident_fd = -1
            # The recorded values remain usable after descriptor teardown.
            self.assertEqual(actors, {'app': True, 'producer': True, 'consumer': True})
            self.assertIs(resident_dead, True)
        finally:
            for fd in actor_fds.values(): os.close(fd)
            if resident_fd >= 0: os.close(resident_fd)

    def test_request_hook_and_global_collector_restore_on_exception(self):
        class Connection:
            def request(self, command):
                return {'command': command}

        api = SimpleNamespace(Connection=Connection, STATUS=4, PMD_STATUS=8)
        original = api.Connection.request
        previous = {'mode': 'outer'}
        FIXTURE._active_handoff_evidence = previous
        evidence = {'snapshots': []}
        with self.assertRaisesRegex(RuntimeError, 'injected export failure'):
            with FIXTURE._handoff_evidence_scope(api, evidence):
                result = api.Connection().request(api.STATUS)
                self.assertEqual(result, {'command': api.STATUS})
                self.assertEqual(evidence['snapshots'], [dict(command='STATUS', command_id=4,
                    value={'command': 4})])
                raise RuntimeError('injected export failure')
        self.assertIs(api.Connection.request, original)
        self.assertIs(FIXTURE._active_handoff_evidence, previous)
        FIXTURE._active_handoff_evidence = None


if __name__ == '__main__':
    unittest.main()
