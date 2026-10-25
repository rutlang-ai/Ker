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


if __name__ == '__main__':
    unittest.main()
