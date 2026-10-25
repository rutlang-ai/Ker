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
        child = subprocess.Popen([sys.executable, '-c', 'pass'])
        actor_fd = os.pidfd_open(child.pid)
        resident = subprocess.Popen([sys.executable, '-c', 'pass'])
        resident_fd = os.pidfd_open(resident.pid)
        try:
            child.wait(timeout=5)
            resident.wait(timeout=5)
            actors, resident_dead = FIXTURE._capture_pidfd_readability(
                {'producer': actor_fd}, resident_fd)
            self.assertTrue(actors['producer'])
            self.assertTrue(resident_dead)
            os.close(actor_fd)
            actor_fd = -1
            os.close(resident_fd)
            resident_fd = -1
            # The recorded values remain usable after descriptor teardown.
            self.assertEqual(actors, {'producer': True})
            self.assertIs(resident_dead, True)
        finally:
            if actor_fd >= 0: os.close(actor_fd)
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
