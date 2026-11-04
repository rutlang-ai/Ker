import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).resolve().parents[1] / 'posix/linux-unix-selftest.py'
spec = importlib.util.spec_from_file_location('linux_unix_selftest', path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class UnixSelftestAccountingTests(unittest.TestCase):
    def result(self, totals='pass:1 fail:0 xfail:0 xpass:0 skip:0 error:0',
               plan='1..1', cases='ok 1 unix_connect.stream.test', returncode=0):
        return dict(returncode=returncode, stderr='', stdout=f'{plan}\n{cases}\n# Totals: {totals}\n')

    def test_pass_requires_full_tap_accounting(self):
        self.assertEqual(runner.tap_result(self.result()), ['unix_connect.stream.test'])

    def test_skip_and_expected_failure_cannot_be_counted_as_pass(self):
        for field in ('fail', 'xfail', 'xpass', 'skip', 'error'):
            totals = 'pass:1 fail:0 xfail:0 xpass:0 skip:0 error:0'.replace(field + ':0', field + ':1')
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                runner.tap_result(self.result(totals=totals))

    def test_missing_duplicate_or_partial_results_fail(self):
        examples = [self.result(plan=''), self.result(plan='1..2'),
                    self.result(cases=''), self.result(returncode=1),
                    self.result(totals='pass:0 fail:0 xfail:0 xpass:0 skip:0 error:0'),
                    self.result(plan='1..2', cases='ok 1 same\nok 2 same',
                                totals='pass:2 fail:0 xfail:0 xpass:0 skip:0 error:0')]
        for result in examples:
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                runner.tap_result(result)


if __name__ == '__main__':
    unittest.main()
