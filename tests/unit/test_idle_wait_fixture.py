import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


POSIX_TESTS = Path(__file__).resolve().parents[1] / 'posix'


def _load_idle_wait_fixture():
    spec = importlib.util.spec_from_file_location(
        'idle_wait_fixture', POSIX_TESTS / 'idle-wait.py')
    module = importlib.util.module_from_spec(spec)
    original_sys_path = sys.path[:]
    sys.path.insert(0, str(POSIX_TESTS))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = original_sys_path
    return module


idle_wait = _load_idle_wait_fixture()


class IdleWaitFixtureTests(unittest.TestCase):
    def test_maximum_profile_ack_deadline_bounds_ten_idle_periods(self):
        maximum = max(profile[3] for profile in idle_wait.IDLE_PROFILES)
        self.assertEqual(maximum, idle_wait.MAX_IDLE_SLEEP_US)
        deadline = idle_wait.idle_timeout_ack_deadline_seconds(maximum)
        self.assertEqual(deadline, 2.0)
        self.assertGreater(deadline, maximum / 1_000_000)

    def test_short_and_busy_profiles_get_a_bounded_ack_deadline(self):
        self.assertEqual(idle_wait.idle_timeout_ack_deadline_seconds(0), 1.0)
        self.assertEqual(idle_wait.idle_timeout_ack_deadline_seconds(20), 1.0002)

    def test_ack_deadline_rejects_values_outside_worker_bounds(self):
        for value in (-1, idle_wait.MAX_IDLE_SLEEP_US + 1, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                idle_wait.idle_timeout_ack_deadline_seconds(value)

    def test_wait_for_idle_timeout_marker_observes_armed_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker, arm = root / 'timeout', root / 'arm'

            def observe_arm_then_mark():
                deadline = time.monotonic() + 1
                while not arm.exists() and time.monotonic() < deadline:
                    time.sleep(0.001)
                if arm.exists():
                    marker.touch()

            observer = threading.Thread(target=observe_arm_then_mark)
            observer.start()
            idle_wait.wait_for_idle_timeout_marker(marker, arm, 100_000)
            observer.join(timeout=1)
            self.assertFalse(observer.is_alive())
            self.assertTrue(marker.is_file())

    def test_missing_idle_timeout_marker_fails_at_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(idle_wait, 'IDLE_TIMEOUT_ACK_MARGIN_SECONDS', 0.01):
                with self.assertRaisesRegex(RuntimeError, 'did not complete an idle timeout'):
                    idle_wait.wait_for_idle_timeout_marker(root / 'timeout', root / 'arm', 0)


if __name__ == '__main__':
    unittest.main()
