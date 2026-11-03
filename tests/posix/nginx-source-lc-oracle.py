#!/usr/bin/env python3
"""Guard the source harness's intentional strict-exit/perf-summary distinction."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


profile = load('overlap_profile', ROOT / 'tests/posix/nginx-overlap-profile.py')
checker = load('source_reload_checks', ROOT / 'tests/upstream/fstack/tests/integration/common/reload_checks.py')
SUMMARY = ('LC_SUMMARY conns=12 reqs=2400 fail=12 reconnects=12 fresh_n=120 fresh_fail=0 '
           'workers_expected=13 workers_done=13 workers_active=13 worker_errors=0\n')


class SourceLcOracle(unittest.TestCase):
    def test_commit_uses_original_perf_closure_bound(self):
        fields = profile.validate_source_lc(checker, SUMMARY, 1, False)
        self.assertEqual(fields['fail'], '12')
        with self.assertRaises(ValueError):
            checker.summary('lc', SUMMARY)

    def test_abort_requires_uninterrupted_connections(self):
        clean = SUMMARY.replace('fail=12', 'fail=0').replace('reconnects=12', 'reconnects=0')
        profile.validate_source_lc(checker, clean, 0, True)
        with self.assertRaises(ValueError):
            profile.validate_source_lc(checker, SUMMARY, 0, True)
        with self.assertRaises(RuntimeError):
            profile.validate_source_lc(checker, clean, 1, True)

    def test_fresh_failures_are_never_tolerated(self):
        with self.assertRaises(ValueError):
            profile.validate_source_lc(checker, SUMMARY.replace('fresh_fail=0', 'fresh_fail=1'), 1, False)

    def test_extra_closures_are_rejected(self):
        for old, new in [('fail=12', 'fail=13'), ('reconnects=12', 'reconnects=13')]:
            with self.subTest(field=old), self.assertRaises(ValueError):
                profile.validate_source_lc(checker, SUMMARY.replace(old, new), 1, False)

    def test_worker_failure_and_duplicate_summary_are_rejected(self):
        for text in [SUMMARY.replace('worker_errors=0', 'worker_errors=1'),
                     SUMMARY.replace('workers_active=13', 'workers_active=12'), SUMMARY * 2]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                profile.validate_source_lc(checker, text, 1, False)

    def test_abnormal_process_exit_is_not_a_closure(self):
        for result in [-9, 2, 77]:
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                profile.validate_source_lc(checker, SUMMARY, result, False)


if __name__ == '__main__':
    unittest.main()
