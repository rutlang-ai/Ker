import errno
import importlib.util
import os
from pathlib import Path
import socket
import select
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

root = Path(__file__).resolve().parents[1] / 'posix'
spec = importlib.util.spec_from_file_location('diag_runner', root / 'linux-mptcp-diag-selftest.py')
runner = importlib.util.module_from_spec(spec); spec.loader.exec_module(runner)
wire = runner.transport


class OriginalDiagEvidenceTests(unittest.TestCase):
    def complete(self):
        return 'TAP version 13\n1..29\n' + ''.join(f'ok {i} - diag: check {i} # time=1ms\n' for i in range(1, 30))

    def test_requires_all_original_checks_without_skip_failure_or_truncation(self):
        valid = self.complete()
        self.assertEqual(len(runner.tap_result(valid)), 29)
        for broken in (valid.replace('1..29', '1..28'), valid.replace('ok 12 ', 'not ok 12 '),
                       valid.replace('ok 12 ', 'ok 11 '), valid.replace('check 12 #', 'check 12 # SKIP #'),
                       valid.replace('ok 12 - diag: check 12 # time=1ms\n', ''), valid + 'ok 30 - injected # TODO\n'):
            with self.subTest(broken=broken), self.assertRaises(RuntimeError): runner.tap_result(broken)

    def test_successful_script_without_native_matrix_or_cleanup_is_rejected(self):
        valid = dict(mptcp=403, accepts=202, live=0, max_live=245, negotiated=402, fallback=1,
                     netlinks=28, diag_sends=53, diag_receives=156, namespaces_created=2, namespaces_deleted=2)
        runner.validate_counts(valid)
        for field, value in (('mptcp', 0), ('accepts', 201), ('live', 1), ('max_live', 199),
                             ('negotiated', 0), ('fallback', 0), ('netlinks', 0), ('diag_sends', 0),
                             ('diag_receives', 0), ('namespaces_deleted', 1)):
            with self.subTest(field=field), self.assertRaises(RuntimeError): runner.validate_counts(dict(valid, **{field: value}))

    def response(self, packet):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / 'fixture')
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
                listener.bind(path); listener.listen(1)

                def reply():
                    channel, _ = listener.accept()
                    with channel:
                        channel.recv(wire.HEADER.size + wire.MAX); channel.sendall(packet)

                thread = threading.Thread(target=reply); thread.start()
                try:
                    with mock.patch.dict('os.environ', KER_MPTCP_SOCKET_CHANNEL=path):
                        return wire.rpc(wire.FILE, 'namespace', '/proc/net/tcp')
                finally:
                    thread.join(timeout=2); self.assertFalse(thread.is_alive())

    def test_wrong_magic_operation_length_and_truncated_responses_are_rejected(self):
        for packet in (b'partial', wire.HEADER.pack(wire.MAGIC + 1, wire.FILE, 0, 0, 0, 0, 0),
                       wire.HEADER.pack(wire.MAGIC, wire.PIDS, 0, 0, 0, 0, 0),
                       wire.HEADER.pack(wire.MAGIC, wire.FILE, 100, 0, 0, 0, 0)):
            with self.subTest(packet=packet), self.assertRaises(RuntimeError): self.response(packet)

    def test_preserves_native_errno_and_exact_proc_bytes(self):
        data = b'MPTCP 1944 0\n'
        self.assertEqual(self.response(wire.HEADER.pack(wire.MAGIC, wire.FILE, len(data), 0, 0, 0, 0) + data), data)
        with self.assertRaises(OSError) as caught:
            self.response(wire.HEADER.pack(wire.MAGIC, wire.FILE, 0, 0, 0, 0, -errno.ENOENT))
        self.assertEqual(caught.exception.errno, errno.ENOENT)

    def test_timeout_cleanup_reaches_children_in_separate_sessions(self):
        code = 'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"],start_new_session=True); print(p.pid,flush=True); time.sleep(60)'
        parent = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, text=True, start_new_session=True)
        child_pid = int(parent.stdout.readline())
        child = os.pidfd_open(child_pid)
        try:
            runner.kill_tree(parent.pid)
            self.assertEqual(parent.wait(timeout=3), -signal.SIGKILL)
            poll = select.poll(); poll.register(child, select.POLLIN)
            self.assertTrue(poll.poll(3000), 'descendant escaped timeout cleanup')
        finally:
            if parent.poll() is None: runner.kill_tree(parent.pid); parent.wait(timeout=3)
            try: signal.pidfd_send_signal(child, signal.SIGKILL)
            except ProcessLookupError: pass
            os.close(child); parent.stdout.close()


if __name__ == '__main__':
    unittest.main()
