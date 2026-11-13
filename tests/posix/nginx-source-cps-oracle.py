#!/usr/bin/env python3
"""Negative controls for source CPS evidence across owner retirement."""
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
checker = load('source_checks', ROOT / 'tests/upstream/fstack/tests/integration/common/reload_checks.py')
SUMMARY = ('CPS_SUMMARY threads=1 n=1000 ok=1000 fail=0 '
           'workers_expected=1 workers_done=1 workers_active=1 worker_errors=0\n')
PROGRESS = ('CPS_PROGRESS elapsed=3.0 n=200 fail=0\n'
            'CPS_PROGRESS elapsed=6.0 n=600 fail=0\n'
            'CPS_PROGRESS elapsed=7.0 n=700 fail=0\n')


class SourceCpsOracle(unittest.TestCase):
    def test_complete_probe_and_post_retirement_progress(self):
        fields, later = profile.validate_source_cps(checker, PROGRESS + SUMMARY, 0, 4)
        self.assertEqual(fields['ok'], '1000')
        self.assertIn('elapsed=7.0', later)

    def test_summary_cannot_hide_empty_or_stopped_traffic(self):
        for progress in ['', PROGRESS.splitlines(True)[0],
                         PROGRESS.replace('n=700', 'n=600')]:
            with self.subTest(progress=progress), self.assertRaises(RuntimeError):
                profile.validate_source_cps(checker, progress + SUMMARY, 0, 4)

    def test_pre_retirement_traffic_does_not_prove_later_service(self):
        for retired_at in [2, 6, 8]:
            with self.subTest(retired_at=retired_at), self.assertRaises(RuntimeError):
                profile.validate_source_cps(checker, PROGRESS + SUMMARY, 0, retired_at)

    def test_any_connection_failure_or_counter_regression_fails(self):
        for progress in [PROGRESS.replace('fail=0', 'fail=1', 1),
                         PROGRESS.replace('n=700', 'n=599'),
                         PROGRESS.replace('elapsed=7.0', 'elapsed=5.0')]:
            with self.subTest(progress=progress), self.assertRaises(RuntimeError):
                profile.validate_source_cps(checker, progress + SUMMARY, 0, 4)

    def test_original_summary_oracle_is_strict(self):
        for summary in [SUMMARY * 2, SUMMARY.replace('fail=0', 'fail=1'),
                        SUMMARY.replace('workers_done=1', 'workers_done=0'),
                        SUMMARY.replace('worker_errors=0', 'worker_errors=1'),
                        SUMMARY.replace('ok=1000', 'ok=999')]:
            with self.subTest(summary=summary), self.assertRaises(ValueError):
                profile.validate_source_cps(checker, PROGRESS + summary, 0, 4)

    def test_abnormal_exit_cannot_be_replaced_by_clean_output(self):
        for code in [-9, 1, 2, 77]:
            with self.subTest(code=code), self.assertRaises(RuntimeError):
                profile.validate_source_cps(checker, PROGRESS + SUMMARY, code, 4)

    def test_summary_must_include_observed_progress(self):
        summary = SUMMARY.replace('n=1000', 'n=500').replace('ok=1000', 'ok=500')
        with self.assertRaises(RuntimeError):
            profile.validate_source_cps(checker, PROGRESS + summary, 0, 4)

    def test_retry_requires_new_requests_past_recovery_interval(self):
        self.assertIsNone(profile.retry_cps_progress(PROGRESS, 8, 600))
        self.assertIsNone(profile.retry_cps_progress(PROGRESS, 7, 700))
        self.assertIn('n=700', profile.retry_cps_progress(PROGRESS, 7, 600))

    def test_retry_rejects_failures_anywhere_in_old_service_interval(self):
        text = PROGRESS.replace('n=200 fail=0', 'n=200 fail=1')
        with self.assertRaises(RuntimeError):
            profile.retry_cps_progress(text, 7, 600)


if __name__ == '__main__':
    unittest.main()
