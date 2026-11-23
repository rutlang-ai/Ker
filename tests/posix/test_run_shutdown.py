"""Unit checks for concurrent, complete native worker teardown."""
import importlib.util
from pathlib import Path
import threading
import unittest


RUNNER = Path(__file__).resolve().parents[2] / 'tools' / 'ker-run.py'
SPEC = importlib.util.spec_from_file_location('ker_run', RUNNER)
KER_RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KER_RUN)


class RunShutdownTest(unittest.TestCase):
    def test_all_worker_reaps_start_before_any_may_finish(self):
        workers = 5  # Main worker plus four additional interface workers.
        all_started = threading.Barrier(workers)
        reaped = []
        lock = threading.Lock()

        def reap(index):
            all_started.wait(timeout=2)
            with lock:
                reaped.append(index)
            return index

        results = KER_RUN.finish_concurrently(
            [lambda index=index: reap(index) for index in range(workers)])

        self.assertEqual(results, list(range(workers)))
        self.assertCountEqual(reaped, range(workers))

    def test_one_reap_error_does_not_skip_remaining_workers(self):
        reaped = []

        def fail():
            raise RuntimeError('injected worker collection failure')

        def finish():
            reaped.append(True)
            return False

        results = KER_RUN.finish_concurrently([fail, finish])

        self.assertIsInstance(results[0], RuntimeError)
        self.assertEqual(results[1], False)
        self.assertEqual(reaped, [True])


if __name__ == '__main__':
    unittest.main()
