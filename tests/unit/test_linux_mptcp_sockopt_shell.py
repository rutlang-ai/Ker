import errno
import importlib.util
import os
from pathlib import Path
import socket
import struct
import unittest
from unittest import mock

root = Path(__file__).resolve().parents[1] / 'posix'
spec = importlib.util.spec_from_file_location('sockopt_ip', root / 'linux-mptcp-sockopt-ip.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
spec = importlib.util.spec_from_file_location('shell_runner', root / 'linux-mptcp-diag-selftest.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)


class TopologyTests(unittest.TestCase):
    def test_native_veth_has_both_namespace_endpoints(self):
        with mock.patch.object(fixture, 'control', return_value=(91, b'')), mock.patch.object(fixture, 'netlink') as send:
            self.assertTrue(fixture.topology(['link', 'add', 'left', 'netns', 'ns1', 'type', 'veth', 'peer', 'name', 'right', 'netns', 'ns2']))
        namespace, kind, message = send.call_args.args
        self.assertEqual((namespace, kind), ('ns1', 16))
        self.assertIn(fixture.string(3, 'left'), message)
        self.assertIn(fixture.string(3, 'right'), message)
        self.assertIn(fixture.integer(28, 91), message)

    def test_ipv6_nodad_and_route_keep_actual_uapi(self):
        with mock.patch.object(fixture, 'ifindex', return_value=7), mock.patch.object(fixture, 'netlink') as send:
            self.assertTrue(fixture.topology(['-net', 'ns', 'addr', 'add', 'dead:beef:1::1/64', 'dev', 'veth', 'nodad']))
            header = struct.unpack('BBBBI', send.call_args.args[2][:8])
            self.assertEqual(header, (socket.AF_INET6, 64, 2, 0, 7))
            self.assertTrue(fixture.topology(['-net', 'ns', 'route', 'add', 'default', 'via', '10.0.1.1', 'dev', 'veth', 'metric', '101']))
            self.assertIn(fixture.integer(6, 101), send.call_args.args[2])

    def test_no_unsupported_topology_success(self):
        self.assertFalse(fixture.topology(['-net', 'ns', 'route', 'flush']))
        self.assertFalse(fixture.topology(['link', 'delete', 'anything']))

    def test_native_netlink_error_is_not_success(self):
        acknowledgment = struct.pack('IHHIIi', 20, 2, 0, 1, 0, -errno.EINVAL)
        response = struct.pack('IIII', len(acknowledgment), 0, 0, 0) + acknowledgment
        with mock.patch.object(fixture, 'channel'), mock.patch.object(fixture, 'exchange', side_effect=[(0, b''), (0, b''), (0, b''), (0, response)]):
            with self.assertRaises(OSError) as raised:
                fixture.netlink('ns', 16, b'invalid')
        self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_short_native_proc_read_is_not_eof(self):
        # proc seq_file may return short reads before the symbol being sought.
        chunks = [(0, b'first\n'), (0, b'000 t mptcp_ioctl\n'), (0, b'')]
        captured = []
        def execve(program, argv, env):
            try:
                captured.append(Path(argv[-1]).read_text())
            finally:
                os.close(int(argv[-1].rsplit('/', 1)[1]))
            raise SystemExit(0)
        environment = dict(KER_MPTCP_REAL_GREP='/usr/bin/grep')
        with mock.patch.dict(os.environ, environment), mock.patch.object(fixture, 'control', side_effect=chunks) as read, mock.patch.object(os, 'execve', side_effect=execve):
            with self.assertRaises(SystemExit): fixture.execute('', ['grep', '-q', ' mptcp_ioctl$', '/proc/kallsyms'])
        self.assertEqual(captured, ['first\n000 t mptcp_ioctl\n'])
        self.assertEqual([x.kwargs if x.kwargs else x.args[-1] for x in read.call_args_list], [0, 6, 24])

    def test_complete_shell_plan_rejects_skips_or_missing_cases(self):
        tap = '1..11\n' + ''.join(f'ok {n} - case {n} # time=1ms\n' for n in range(1, 12))
        self.assertEqual(len(runner.tap_result(tap, 11)), 11)
        for bad in (tap.replace('1..11','1..10'), tap.replace('ok 5 -', 'not ok 5 -'), tap + 'ok 12 - skipped # SKIP\n'):
            with self.assertRaises(RuntimeError): runner.tap_result(bad, 11)


if __name__ == '__main__': unittest.main()
