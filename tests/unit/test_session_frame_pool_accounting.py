#!/usr/bin/env python3
"""Exercise exact pool accounting for dead-consumer WRITING recovery."""
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests' / 'posix'))
SOURCE = ROOT / 'tests' / 'posix' / 'session-native-packets.py'
SPEC = importlib.util.spec_from_file_location('session_native_packets_pool_accounting', SOURCE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class ConsumerWritingPoolAccountingTests(unittest.TestCase):
    def test_prepared_mbuf_is_present_through_write_and_freed_once_on_cancel(self):
        deferred = {'pool_before': 1, 'pool_after': 1}
        completed = {'pool': 1}
        cancelled = {'pool': 0}
        self.assertTrue(FIXTURE.consumer_writing_pool_transition_is_exact(
            deferred, completed, cancelled))

    def test_existing_pool_objects_do_not_change_the_relative_transition(self):
        deferred = {'pool_before': 4, 'pool_after': 4}
        self.assertTrue(FIXTURE.consumer_writing_pool_transition_is_exact(
            deferred, {'pool': 4}, {'pool': 3}))

    def test_rejects_the_old_plus_one_expectation_and_missing_or_extra_free(self):
        deferred = {'pool_before': 2, 'pool_after': 2}
        self.assertFalse(FIXTURE.consumer_writing_pool_transition_is_exact(
            deferred, {'pool': 3}, {'pool': 2}))
        self.assertFalse(FIXTURE.consumer_writing_pool_transition_is_exact(
            deferred, {'pool': 2}, {'pool': 2}))
        self.assertFalse(FIXTURE.consumer_writing_pool_transition_is_exact(
            deferred, {'pool': 2}, {'pool': 0}))

    def test_rejects_invalid_baseline_or_changed_deferred_snapshot(self):
        self.assertFalse(FIXTURE.consumer_writing_pool_transition_is_exact(
            {'pool_before': 0, 'pool_after': 0}, {'pool': 0}, {'pool': -1}))
        self.assertFalse(FIXTURE.consumer_writing_pool_transition_is_exact(
            {'pool_before': True, 'pool_after': True}, {'pool': 1}, {'pool': 0}))
        self.assertFalse(FIXTURE.consumer_writing_pool_transition_is_exact(
            {'pool_before': 3, 'pool_after': 2}, {'pool': 3}, {'pool': 2}))


if __name__ == '__main__':
    unittest.main()
