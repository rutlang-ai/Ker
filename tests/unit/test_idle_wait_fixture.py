import importlib.util
from pathlib import Path
import sys
import unittest


POSIX_TESTS = Path(__file__).resolve().parents[1] / 'posix'
sys.path.insert(0, str(POSIX_TESTS))
SPEC = importlib.util.spec_from_file_location('idle_wait_fixture', POSIX_TESTS / 'idle-wait.py')
idle_wait = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(idle_wait)


class IdleWaitFixtureTests(unittest.TestCase):
    def test_maximum_profiles_receive_a_quiet_window_over_three_periods(self):
        maximum = max(profile[3] for profile in idle_wait.IDLE_PROFILES)
        self.assertEqual(maximum, idle_wait.MAX_IDLE_SLEEP_US)
        quiet_seconds = idle_wait.idle_quiet_window_seconds(maximum)
        self.assertEqual(quiet_seconds, 0.35)
        self.assertGreater(quiet_seconds, maximum / 1_000_000)

    def test_quiet_window_has_a_minimum_for_short_and_busy_profiles(self):
        self.assertEqual(idle_wait.idle_quiet_window_seconds(0), 0.35)
        self.assertEqual(idle_wait.idle_quiet_window_seconds(20), 0.35)

    def test_quiet_window_rejects_values_outside_worker_bounds(self):
        for value in (-1, idle_wait.MAX_IDLE_SLEEP_US + 1, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                idle_wait.idle_quiet_window_seconds(value)


if __name__ == '__main__':
    unittest.main()
