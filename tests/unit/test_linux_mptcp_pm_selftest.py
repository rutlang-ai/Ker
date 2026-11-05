import importlib.util
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

root = Path(__file__).resolve().parents[1] / 'posix'
spec = importlib.util.spec_from_file_location('linux_pm_runner', root / 'linux-mptcp-pm-selftest.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
wire = runner.scaffold


class OriginalPmEvidenceTests(unittest.TestCase):
    def test_ip_shim_is_executable_beside_the_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / 'build'; parent.mkdir()
            runner.write_ip_shim(parent)
            shim = parent / 'ip'
            self.assertTrue(shim.stat().st_mode & 0o111)
            result = subprocess.run([str(shim), 'unsupported'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('unsupported upstream PM fixture ip command', result.stderr)

    def complete(self):
        return 'TAP version 13\n1..23\n' + ''.join(
            f'ok {i} - pm_netlink: assertion {i} # time=1ms\n' for i in range(1, 24))

    def test_requires_full_default_plan_without_skips_or_failures(self):
        valid = self.complete()
        self.assertEqual(len(runner.tap_result(valid)), 23)
        for broken in (valid.replace('1..23', '1..22'), valid.replace('ok 9 ', 'not ok 9 '),
                       valid.replace('ok 9 ', 'ok 8 '), valid.replace('assertion 9 #', 'assertion 9 # SKIP #'),
                       valid + 'ok 24 - injected # IGNORE Flaky\n', valid.replace('1..23\n', '')):
            with self.subTest(broken=broken), self.assertRaises(RuntimeError):
                runner.tap_result(broken)

    def response(self, packet):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / 'fixture.sock')
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
                listener.bind(path)
                listener.listen(1)

                def reply():
                    channel, _ = listener.accept()
                    with channel:
                        channel.recv(wire.MAX + wire.HEADER.size)
                        channel.sendall(packet)

                thread = threading.Thread(target=reply)
                thread.start()
                try:
                    with mock.patch.dict('os.environ', KER_MPTCP_PM_SOCKET=path):
                        return wire.rpc(wire.PROBE)
                finally:
                    thread.join(timeout=2)
                    self.assertFalse(thread.is_alive())

    def test_rejects_truncated_wrong_operation_and_wrong_magic_responses(self):
        for packet in (b'partial', wire.HEADER.pack(wire.MAGIC, wire.PROBE, 10, 0, 0, 0, 0),
                       wire.HEADER.pack(wire.MAGIC + 1, wire.PROBE, 0, 0, 0, 0, 0),
                       wire.HEADER.pack(wire.MAGIC, wire.STOP, 0, 0, 0, 0, 0),
                       wire.HEADER.pack(wire.MAGIC, wire.PROBE, wire.MAX + 1, 0, 0, 0, 0) + bytes(wire.MAX + 1)):
            with self.subTest(size=len(packet)), self.assertRaises(RuntimeError):
                self.response(packet)

    def test_preserves_kernel_errno_instead_of_successful_stub(self):
        import errno
        with self.assertRaises(OSError) as caught:
            self.response(wire.HEADER.pack(wire.MAGIC, wire.PROBE, 0, 0, -errno.EOPNOTSUPP, 0, 0))
        self.assertEqual(caught.exception.errno, errno.EOPNOTSUPP)
        self.assertEqual(self.response(wire.HEADER.pack(wire.MAGIC, wire.PROBE, 2, 0, 0, 0, 0) + b'1\n'), b'1\n')


if __name__ == '__main__':
    unittest.main()
