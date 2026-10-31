import importlib.util
import os
from pathlib import Path
import sys
import threading
import unittest


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
    def test_profiles_cover_zero_and_maximum_idle_waits(self):
        maximum = max(profile[3] for profile in idle_wait.IDLE_PROFILES)
        self.assertEqual(maximum, idle_wait.MAX_IDLE_SLEEP_US)
        self.assertIn(0, [profile[3] for profile in idle_wait.IDLE_PROFILES])
        self.assertGreater(idle_wait.IDLE_TIMEOUT_OBSERVATION_SECONDS, maximum / 1_000_000)

    def test_worker_notifies_only_after_fixture_arms_observation(self):
        arm_read, arm_write = os.pipe()
        notify_read, notify_write = os.pipe()
        received = []

        def worker():
            received.append(os.read(arm_read, 1))
            os.write(notify_write, b'T')

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            idle_wait.observe_idle_timeout(arm_write, notify_read, timeout=1)
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(received, [b'A'])
        finally:
            for fd in (arm_read, arm_write, notify_read, notify_write):
                os.close(fd)

    def test_missing_notification_times_out_without_sleep_fallback(self):
        arm_read, arm_write = os.pipe()
        notify_read, notify_write = os.pipe()
        try:
            with self.assertRaisesRegex(RuntimeError, 'did not complete an idle timeout'):
                idle_wait.observe_idle_timeout(arm_write, notify_read, timeout=0.01)
            self.assertEqual(os.read(arm_read, 1), b'A')
        finally:
            for fd in (arm_read, arm_write, notify_read, notify_write):
                os.close(fd)

    def test_prearm_notification_is_rejected(self):
        arm_read, arm_write = os.pipe()
        notify_read, notify_write = os.pipe()
        os.set_blocking(arm_read, False)
        try:
            os.write(notify_write, b'T')
            with self.assertRaisesRegex(RuntimeError, 'before application readiness'):
                idle_wait.observe_idle_timeout(arm_write, notify_read, timeout=1)
            with self.assertRaises(BlockingIOError):
                os.read(arm_read, 1)
        finally:
            for fd in (arm_read, arm_write, notify_read, notify_write):
                os.close(fd)

    def test_wrong_byte_and_eof_are_rejected_after_arm(self):
        for payload in (b'X', None):
            with self.subTest(payload=payload):
                arm_read, arm_write = os.pipe()
                notify_read, notify_write = os.pipe()
                writer_fd = [notify_write]

                def worker():
                    os.read(arm_read, 1)
                    if payload is None:
                        os.close(writer_fd[0])
                        writer_fd[0] = -1
                    else:
                        os.write(writer_fd[0], payload)

                thread = threading.Thread(target=worker)
                thread.start()
                try:
                    with self.assertRaisesRegex(RuntimeError, 'invalid idle timeout notification'):
                        idle_wait.observe_idle_timeout(arm_write, notify_read, timeout=1)
                    thread.join(timeout=1)
                    self.assertFalse(thread.is_alive())
                finally:
                    for fd in (arm_read, arm_write, notify_read, writer_fd[0]):
                        if fd >= 0:
                            os.close(fd)


if __name__ == '__main__':
    unittest.main()
