"""Runtime launcher failure boundaries with real local pipes and child processes.

Fixtures exercise coordination only, never stand in for Linux/DPDK networking.
"""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('launcher_existing_fixtures',
                                            ROOT/'tests/posix/test_ker_run.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
launcher = fixtures.ker_run


class LauncherBoundaryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.worker = self.root/'ker-io-worker'
        self.guard = self.root/'ker-app'
        self.library = self.root/'libker-posix.so'
        self.config = self.root/'multiport.ini'
        self.config.write_text('[interface.aux]\naddress=198.19.0.2/24\nport=aux0\neal=--no-pci\n')
        self.worker.write_text(fixtures.WORKER)
        self.guard.write_text(fixtures.APP_GUARD)
        self.worker.chmod(0o700)
        self.guard.chmod(0o700)
        self.library.touch()

    run_launcher = fixtures.KerRunMainTests.run_launcher

    def test_missing_runtime_artifacts_are_errors_before_ipc_or_children(self):
        for artifact in (self.library, self.worker, self.guard):
            original = artifact.read_bytes()
            artifact.unlink()
            with self.subTest(artifact=artifact.name), \
                    mock.patch.object(launcher.socket, 'socketpair') as pair, \
                    mock.patch.object(launcher.subprocess, 'Popen') as spawn:
                result, message = self.run_launcher(0, native_done=True, capture_stderr=True)
                self.assertEqual(result, 125)
                self.assertIn('runtime artifact', message)
                pair.assert_not_called()
                spawn.assert_not_called()
            artifact.write_bytes(original)
            if artifact != self.library:
                artifact.chmod(0o700)
        self.assertEqual(self.run_launcher(0, native_done=True), 0)

    def test_runtime_artifact_types_and_worker_execution_permission(self):
        self.library.unlink()
        self.library.mkdir()
        result, message = self.run_launcher(0, native_done=True, capture_stderr=True)
        self.assertEqual(result, 125)
        self.assertIn('regular file', message)
        self.library.rmdir()
        self.library.touch()
        for artifact in (self.worker, self.guard):
            artifact.chmod(0o600)
            with self.subTest(artifact=artifact.name):
                result, message = self.run_launcher(0, native_done=True, capture_stderr=True)
                self.assertEqual(result, 125)
                self.assertIn('executable', message)
            artifact.chmod(0o700)
        self.assertEqual(self.run_launcher(0, native_done=True), 0)

    def test_partial_primary_channel_setup_unwinds_and_recovers(self):
        def descriptors():
            result = set()
            for value in os.listdir('/proc/self/fd'):
                try:
                    os.fstat(int(value))
                except OSError:
                    continue
                result.add(int(value))
            return result
        pair = launcher.socket.socketpair
        pipe = launcher.os.pipe2
        for kind, position in (('pair', 1), ('pair', 2), ('pair', 3), ('pipe', 1), ('pipe', 2)):
            calls = 0
            original = pair if kind == 'pair' else pipe
            def allocate(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == position:
                    raise OSError(24, 'injected descriptor exhaustion')
                return original(*args, **kwargs)
            before = descriptors()
            target = launcher.socket if kind == 'pair' else launcher.os
            attribute = 'socketpair' if kind == 'pair' else 'pipe2'
            with self.subTest(kind=kind, position=position), \
                    mock.patch.object(target, attribute, side_effect=allocate), \
                    mock.patch.object(launcher.subprocess, 'Popen') as spawn:
                result, message = self.run_launcher(0, native_done=True, capture_stderr=True)
                self.assertEqual(result, 125)
                self.assertIn('IPC setup', message)
                spawn.assert_not_called()
                self.assertEqual(descriptors(), before)
            self.assertEqual(self.run_launcher(0, native_done=True), 0)


if __name__ == '__main__':
    unittest.main()
