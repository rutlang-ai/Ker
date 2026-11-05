import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'posix/linux-mptcp-socket-selftest.py'
spec = importlib.util.spec_from_file_location('mptcp_socket_runner', path)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class NativeMptcpEvidenceTests(unittest.TestCase):
    def test_upstream_skip_is_failure_even_with_exit_zero(self):
        runner.validate_case(dict(returncode=0, stdout='', stderr=''))
        for code, out, err in ((1, '', ''), (0, '', 'MPTCP_FULL_INFO test skipped'),
                               (0, 'not ok 1', ''), (0, 'XFAIL', '')):
            with self.subTest(code=code, out=out, err=err), self.assertRaises(RuntimeError):
                runner.validate_case(dict(returncode=code, stdout=out, stderr=err))

    def test_host_success_or_missing_full_info_cannot_count_as_native_coverage(self):
        valid = dict(sockets=2, accepts=1, live=0, sent=512, received=512,
                     mptcp=2, negotiated=2, fallback=0, infos=30, full_info=2, inq=0)
        runner.validate_native(valid, 'sockopt', 1)
        for field, value in (('sockets', 0), ('mptcp', 0), ('negotiated', 0),
                             ('full_info', 0), ('received', 511), ('live', 1)):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                runner.validate_native(dict(valid, **{field: value}), 'sockopt', 1)

    def test_inq_requires_bulk_payload_and_native_control_activity(self):
        valid = dict(sockets=8, accepts=4, live=0, sent=5*1024*1024, received=5*1024*1024,
                     mptcp=4, negotiated=2, fallback=1, infos=0, full_info=0, inq=50)
        runner.validate_native(valid, 'inq', 4)
        for updates in (dict(inq=0), dict(sent=256, received=256), dict(accepts=3)):
            with self.subTest(updates=updates), self.assertRaises(RuntimeError):
                runner.validate_native(dict(valid, **updates), 'inq', 4)


if __name__ == '__main__':
    unittest.main()
