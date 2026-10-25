#!/usr/bin/env python3
"""Check that the held RX proof counts the session pool, not the frame pool."""
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / 'tests' / 'posix'
FIXTURE = FIXTURE_DIR / 'session-native-packets.py'
IO_SESSION = ROOT / 'src' / 'posix' / 'io-session.c'
sys.path.insert(0, str(FIXTURE_DIR))
spec = importlib.util.spec_from_file_location('session_native_packets_pool_oracle', FIXTURE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class NonframePoolOracleTests(unittest.TestCase):
    def test_wait_marker_reports_both_distinct_pools(self):
        source = IO_SESSION.read_text()
        marker = source[source.index('KER_SESSION_TEST_NONFRAME_REAP_WAIT'):]
        marker = marker[:marker.index('KER_SESSION_TEST_NONFRAME_REAP_DONE')]
        self.assertIn(r'\"packet_pool_in_use\":%u,\"control_pool_available\":%u,\"control_pool_in_use\":%u', marker)
        self.assertIn('ker_generation_packet_pool_in_use(generation_rings)', marker)
        self.assertIn('rte_mempool_avail_count(message_pool),rte_mempool_in_use_count(message_pool)', marker)

    def test_exact_four_session_objects_and_separate_empty_frame_pool(self):
        before = {'generation': 500, 'token': 12}
        waiting = {'control_pool_available': 496, 'control_pool_in_use': 16,
                   'packet_pool_in_use': 0}
        self.assertTrue(fixture.nonframe_reap_pool_delta_matches(before, waiting))

        old_wrong_pool = dict(waiting, packet_pool_in_use=4)
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(before, old_wrong_pool))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            before, dict(waiting, control_pool_available=495)))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            before, dict(waiting, control_pool_in_use=15)))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            before, dict(waiting, control_pool_in_use=True)))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            dict(generation=True, token=12), waiting))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(before, {}))

    def test_full_reap_preserves_three_live_consumer_queues_then_drains_exactly(self):
        before = {'generation': 500, 'token': 12}
        reaped = {
            'status': 0, 'full_reap_attempts': 1, 'generation_admitted': False,
            'active': [0, 0, 0, 0], 'rings': [0, 0, 1, 0, 0, 1, 0, 1],
            'packet_pool_in_use': 0, 'control_pool_available': 498,
        }
        drained = {
            'generation': 0, 'status': 0, 'rx_drained': 1, 'tx_drained': 2,
            'rings_before': [0, 0, 1, 0, 0, 1, 0, 1], 'rings_after': [0] * 8,
            'active': [0, 0, 0, 0], 'packet_pool_in_use': 0, 'control_pool_available': 501,
        }
        self.assertTrue(fixture.nonframe_reap_retained_matches(before, reaped))
        self.assertTrue(fixture.nonframe_retained_drain_matches(before, reaped, drained))
        self.assertFalse(fixture.nonframe_reap_retained_matches(
            before, dict(reaped, rings=[0] * 8)))
        self.assertFalse(fixture.nonframe_reap_retained_matches(
            before, dict(reaped, control_pool_available=500)))
        self.assertFalse(fixture.nonframe_reap_retained_matches(
            before, dict(reaped, rings=[0, 0, True, 0, 0, 1, 0, 1])))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, tx_drained=1)))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, rings_after=[0, 0, 0, 0, 0, 0, 0, 1])))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, control_pool_available=500)))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, rx_drained=True)))

    def test_runtime_source_has_opt_in_owner_drain_marker(self):
        source = IO_SESSION.read_text()
        branch = source[source.index("command == 'K'"):]
        branch = branch[:branch.index("command == 'd'")]
        self.assertIn('generation_detach_test', branch)
        self.assertIn('generation == 0 && nonframe_reap_active', branch)
        self.assertIn('generation_test_step(generation_rings,&identity,pool,5', branch)
        self.assertIn('KER_SESSION_TEST_NONFRAME_RETAINED_DRAINED', branch)

    def test_status_binds_pool_before_and_after_live_queue_drain(self):
        before = {'generation': 500, 'process': 2}
        owner = {'token': 17, 'generation': 0}
        retained_status = {'generation': 498, 'process': 1}
        self.assertTrue(fixture.nonframe_reap_status_matches(
            before, retained_status, owner, owner, 498, -2))
        final_status = {'generation': 501, 'process': 1}
        self.assertTrue(fixture.nonframe_reap_status_matches(
            before, final_status, owner, owner, 501, 1))
        # A final-restored pool count cannot be claimed before the explicit
        # consumer drain, and the intermediate count cannot pass afterward.
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, retained_status, owner, owner, 501, -2))
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, final_status, owner, owner, 498, 1))
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, final_status, dict(owner, token=18), owner, 501, 1))
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, dict(final_status, process=2), owner, owner, 501, 1))


if __name__ == '__main__':
    unittest.main()
