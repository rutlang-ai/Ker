import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('udp_validation', Path(__file__).resolve().parents[1] / 'tools/validate-udp.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class ReportGuards(unittest.TestCase):
    def matrix(self, kind='functional'):
        return {'scope': 'fixture', 'features': [{'id': 'one', 'kind': kind, 'ctests': ['test-a'], 'note': 'fixture'}]}

    def registered(self, *names):
        return {'tests': [{'name': name, 'properties': [{'name': 'LABELS', 'value': ['native-udp']}]} for name in names]}

    def test_registered_membership_is_exact(self):
        self.assertEqual(validator.selected_tests(self.matrix(), self.registered('test-a')), ['test-a'])
        for registered in (self.registered(), self.registered('test-a', 'test-b')):
            with self.assertRaises(ValueError):
                validator.selected_tests(self.matrix(), registered)

    def test_no_testless_or_duplicate_feature_passes(self):
        matrix = self.matrix(); matrix['features'][0]['ctests'] = []
        with self.assertRaises(ValueError):
            validator.selected_tests(matrix, self.registered())
        matrix = self.matrix(); matrix['features'] *= 2
        with self.assertRaises(ValueError):
            validator.selected_tests(matrix, self.registered('test-a'))

    def test_unsupported_probe_is_not_compatibility_pass(self):
        report = validator.report(self.matrix('unsupported-boundary'), {'test-a': 'passed'}, 0)
        self.assertEqual(report['features'][0]['status'], 'unsupported-confirmed')
        self.assertTrue(report['automated_checks_passed'])
        self.assertFalse(report['all_features_supported_and_validated'])

    def test_manual_gap_remains_unvalidated(self):
        matrix = self.matrix('manual'); matrix['features'][0]['ctests'] = []
        report = validator.report(matrix, {}, 0)
        self.assertEqual(report['features'][0]['status'], 'not-validated')
        self.assertFalse(report['all_features_supported_and_validated'])

    def test_infrastructure_failure_cannot_be_green(self):
        report = validator.report(self.matrix(), {'test-a': 'passed'}, 1)
        self.assertFalse(report['automated_checks_passed'])
        self.assertFalse(report['all_features_supported_and_validated'])

    def test_full_suite_import_still_requires_each_udp_test(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'full.xml'
            path.write_text('<testsuite><testcase name="unrelated"/><testcase name="test-a"/></testsuite>')
            self.assertEqual(validator.junit_results(path, ['test-a'], allow_extra=True), {'test-a': 'passed'})
            path.write_text('<testsuite><testcase name="unrelated"/></testsuite>')
            self.assertEqual(validator.junit_results(path, ['test-a'], allow_extra=True), {'test-a': 'missing'})

    def test_skips_missing_and_failures_do_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'results.xml'
            for child in ('<skipped/>', '<failure/>', '<error/>'):
                path.write_text('<testsuite><testcase name="test-a">' + child + '</testcase></testsuite>')
                self.assertEqual(validator.junit_results(path, ['test-a']), {'test-a': 'failed'})
            path.write_text('<testsuite/>')
            self.assertEqual(validator.junit_results(path, ['test-a']), {'test-a': 'missing'})
            path.write_text('<testsuite><testcase name="test-a"/><testcase name="test-a"/></testsuite>')
            with self.assertRaises(ValueError):
                validator.junit_results(path, ['test-a'])


if __name__ == '__main__':
    unittest.main()
