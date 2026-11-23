"""Bound the real UNIX listener's pre-request wait in the source-shell SDK."""

from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from nginx_source_shell_controller import SourceShellController


class OriginDeadlineTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ker-origin-deadline-")
        self.addCleanup(directory.cleanup)
        self.path = str(Path(directory.name) / "origin.sock")
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(self.listener.close)
        self.listener.bind(self.path)
        self.listener.listen(1)
        self.listener.setblocking(False)
        self.actor = object()
        self.controller = object.__new__(SourceShellController)
        self.controller.started = True
        self.controller.listener = self.listener
        self.controller.io_actor = object()
        self.controller.launch = mock.Mock()
        self.controller.profile = SimpleNamespace(deadline_ns=None)

    def connect(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(client.close)
        client.connect(self.path)
        return client

    def test_empty_listener_uses_seconds_and_restores_nonblocking(self):
        # Bound a broken implementation too: the later connection releases its
        # accept, but cannot satisfy the expected socket timeout.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(client.close)
        release = threading.Timer(1.0, client.connect, (self.path,))
        release.start()
        try:
            self.controller.profile.deadline_ns = time.monotonic_ns() + 100_000_000
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                self.controller.accept_origin(self.actor)
            self.assertLess(time.monotonic() - started, 0.9)
            self.assertEqual(self.listener.gettimeout(), 0.0)
            self.controller.launch.backend_handoff.take.assert_called_once_with(
                self.controller.deadline_ns)
            self.controller.launch.accept_origin.assert_not_called()
        finally:
            release.cancel()
            release.join()

    def test_rejected_connection_is_closed_and_listener_stays_nonblocking(self):
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.controller.profile.deadline_ns = time.monotonic_ns() + 3_000_000_000
        client = self.connect()
        client.settimeout(0.5)
        reject = PermissionError("invalid source owner")
        self.controller.launch.accept_origin.side_effect = reject
        with self.assertRaises(PermissionError) as error:
            self.controller.accept_origin(self.actor)
        self.assertIs(error.exception, reject)
        self.assertEqual(client.recv(1), b"")
        self.assertEqual(self.listener.gettimeout(), 0.0)

    def test_expired_deadline_leaves_connection_queued(self):
        self.controller.profile.deadline_ns = time.monotonic_ns()
        self.connect()
        with self.assertRaises(TimeoutError):
            self.controller.accept_origin(self.actor)
        self.controller.launch.accept_origin.assert_not_called()
        channel, _ = self.listener.accept()
        channel.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
