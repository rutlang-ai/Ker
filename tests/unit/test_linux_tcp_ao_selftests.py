import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'linux_tcp_ao_selftest', Path(__file__).resolve().parents[1] / 'posix/linux-tcp-ao-selftest.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class TcpAoEvidenceTests(unittest.TestCase):
    def test_requires_complete_successful_tap(self):
        good = '1..1\nok 1 real assertion\n# Totals: pass:1 fail:0 xfail:0 xpass:0 skip:0 error:0\n'
        self.assertEqual(runner.tap_result(good, 'connect')['passed'], ['real assertion'])
        for broken in (good.replace('1..1', '1..2'), good.replace('ok 1', 'ok 2'),
                       good.replace('skip:0', 'skip:1'), good.replace('fail:0', 'fail:1', 1),
                       good.replace('error:0', 'error:1'), good + 'not ok 2 hidden failure\n'):
            with self.subTest(broken=broken), self.assertRaises(RuntimeError):
                runner.tap_result(broken, 'connect')

    def test_known_upstream_xfail_is_reported_separately(self):
        name = sorted(runner.UPSTREAM_XFAILS)[0]
        output = ('1..2\nok 1 real assertion\nok 2 # XFAIL ' + name +
                  '\n# Totals: pass:1 fail:0 xfail:1 xpass:0 skip:0 error:0\n')
        self.assertEqual(runner.tap_result(output, 'key-management'),
                         dict(passed=['real assertion'], upstream_xfails=[name]))
        for program, text in (('connect', output), ('key-management', output.replace(name, 'new defect')),
                              ('key-management', output.replace('xfail:1', 'xfail:0'))):
            with self.subTest(program=program, text=text), self.assertRaises(RuntimeError):
                runner.tap_result(text, program)

    def test_symlink_blob_is_distinct_from_target_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'discard.c').write_text('original test assertions\n')
            (root / 'accept.c').symlink_to('discard.c')
            self.assertEqual(runner.source_bytes(root / 'accept.c', True), b'discard.c')
            with self.assertRaisesRegex(RuntimeError, 'file type'):
                runner.source_bytes(root / 'accept.c', False)
            with self.assertRaisesRegex(RuntimeError, 'file type'):
                runner.source_bytes(root / 'discard.c', True)


if __name__ == '__main__':
    unittest.main()
