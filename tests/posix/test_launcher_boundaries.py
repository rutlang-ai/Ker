"""Runtime launcher failure boundaries with real local pipes and child processes.

Fixtures exercise coordination only, never stand in for Linux/DPDK networking.
"""
import contextlib
import importlib.util
import io
import json
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

    def test_startup_record_deadline_covers_partial_lines_and_bounds(self):
        cases = [
            ('sys.stdout.write("KER_IO_READY "); sys.stdout.flush(); time.sleep(2)', 'timed out'),
            ('time.sleep(2)', 'timed out'),
            ('sys.stdout.write("KER_IO_READY {}")', 'complete startup record'),
            ('pass', 'complete startup record'),
            ('print("x"*100)', 'exceeds limit'),
        ]
        for body, diagnostic in cases:
            with self.subTest(body=body):
                process = subprocess.Popen([sys.executable, '-c', 'import sys,time; '+body],
                                           stdout=subprocess.PIPE, text=True)
                try:
                    with self.assertRaisesRegex(RuntimeError, diagnostic):
                        launcher.read_worker_startup(process, 'test worker', timeout=0.15, maximum=64)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()
        process = subprocess.Popen([sys.executable, '-c',
            'print("KER_IO_READY {}"); print("KER_IO_DONE {}")'], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(launcher.read_worker_startup(process, 'test', timeout=2), 'KER_IO_READY {}')
            tail, _ = process.communicate(timeout=2)
            self.assertEqual(tail, 'KER_IO_DONE {}\n')
        finally:
            if process.poll() is None:
                process.kill(); process.communicate()

    def test_invalid_ready_fields_never_start_application_and_recover(self):
        valid = {'mac': '02:00:00:00:00:01', 'tx_offload_features': 0}
        invalid = [[], None, {}, {**valid, 'mac': 12}, {**valid, 'mac': 'bad'},
                   {**valid, 'tx_offload_features': True}, {**valid, 'tx_offload_features': '1'},
                   {**valid, 'tx_offload_features': -1}, {**valid, 'tx_offload_features': 2},
                   {**valid, 'tx_offload_features': 0x800}]
        original = fixtures.WORKER
        line = "print('KER_IO_READY ' + json.dumps({'mac': '02:00:00:00:00:01', 'tx_offload_features': 0}), flush=True)"
        self.assertIn(line, original)
        for payload in invalid:
            self.worker.write_text(original.replace(line,
                "print('KER_IO_READY ' + " + repr(json.dumps(payload)) + ", flush=True)"))
            with self.subTest(payload=payload):
                marker = self.root/'app-started'
                result, message = self.run_launcher(0, native_done=True,
                    app_source='from pathlib import Path; Path('+repr(str(marker))+').touch()',
                    capture_stderr=True)
                self.assertEqual(result, 125)
                self.assertIn('READY', message)
                self.assertFalse(marker.exists())
        self.worker.write_text(original)
        self.assertEqual(self.run_launcher(0, native_done=True), 0)

    def test_invalid_additional_ready_never_starts_application(self):
        line = "print('KER_IO_READY ' + json.dumps({'mac': '02:00:00:00:00:01', 'tx_offload_features': 0}), flush=True)"
        for payload in ([], {'mac': '02:00:00:00:00:02', 'tx_offload_features': True}):
            replacement = ("print('KER_IO_READY ' + (json.dumps({'mac':'02:00:00:00:00:01',"
                "'tx_offload_features':0}) if port == 'fake0' else " + repr(json.dumps(payload)) + "), flush=True)")
            self.worker.write_text(fixtures.WORKER.replace(line, replacement))
            with self.subTest(payload=payload):
                marker = self.root/'app-started'
                result, message = self.run_launcher(0, native_done=True, config=self.config,
                    app_source='from pathlib import Path; Path('+repr(str(marker))+').touch()',
                    capture_stderr=True)
                self.assertEqual(result, 125)
                self.assertIn('READY', message)
                self.assertFalse(marker.exists())
        self.worker.write_text(fixtures.WORKER)
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config), 0)

    def test_invalid_primary_completion_is_failure_without_traceback(self):
        original = fixtures.WORKER
        line = "print('KER_IO_DONE {\"outstanding\": 0}', flush=True)"
        self.assertIn(line, original)
        for payload in ('not-json', '[]', 'null', '{}', '{"outstanding":true}',
                        '{"outstanding":0.0}', '{"outstanding":"0"}', '{"outstanding":-1}'):
            replacement = "print('KER_IO_DONE ' + " + repr(payload) + ", flush=True)"
            self.worker.write_text(original.replace(line, replacement))
            with self.subTest(payload=payload):
                result, message = self.run_launcher(0, native_done=True, capture_stderr=True)
                self.assertEqual(result, 125)
                self.assertIn('completion', message)
        self.worker.write_text(original)
        self.assertEqual(self.run_launcher(0, native_done=True), 0)

    def test_duplicate_done_cannot_hide_outstanding_ownership(self):
        line = "print('KER_IO_DONE {\"outstanding\": 0}', flush=True)"
        for first, last in ((0, 0), (1, 0), (0, 1)):
            records = ['KER_IO_DONE '+json.dumps({'outstanding': value}) for value in (first, last)]
            replacement = '; '.join('print('+repr(record)+', flush=True)' for record in records)
            self.worker.write_text(fixtures.WORKER.replace(line, replacement))
            with self.subTest(first=first, last=last):
                result, message = self.run_launcher(0, native_done=True, capture_stderr=True)
                self.assertEqual(result, 125)
                self.assertIn('duplicate', message)
        self.worker.write_text(fixtures.WORKER)
        self.assertEqual(self.run_launcher(0, native_done=True), 0)

    def test_primary_collection_failure_still_reaps_all_children(self):
        collect = launcher.collect_worker
        finish = launcher.AdditionalWorker.finish
        for after_collection in (False, True):
            children = []
            finished = []
            def fail(process, stats):
                children.append(process)
                if after_collection:
                    collect(process, stats)
                raise OSError('injected primary collection failure')
            def complete(extra):
                result = finish(extra)
                finished.append(extra.process)
                return result
            with self.subTest(after_collection=after_collection), \
                    mock.patch.object(launcher, 'collect_worker', side_effect=fail), \
                    mock.patch.object(launcher.AdditionalWorker, 'finish', complete):
                result, message = self.run_launcher(0, native_done=True,
                    config=self.config, capture_stderr=True)
            self.assertEqual(result, 125)
            self.assertIn('primary worker collection', message)
            self.assertEqual(len(finished), 1)
            for process in children + finished:
                self.assertIsNotNone(process.returncode)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(process.pid, os.WNOHANG)
            self.assertEqual(self.run_launcher(0, native_done=True, config=self.config), 0)

    def test_malformed_auxiliary_completion_is_failure_and_recovers(self):
        line = "print('KER_IO_DONE {\"outstanding\": 0}', flush=True)"
        # Replace only the final record; startup must succeed for both workers.
        head, separator, tail = fixtures.WORKER.rpartition(line)
        self.assertTrue(separator)
        for payload in ('not-json', '[]', 'null', '{}', '{"outstanding":true}',
                        '{"outstanding":0.0}', '{"outstanding":"0"}', '{"outstanding":-1}'):
            record = "('KER_IO_DONE {\"outstanding\":0}' if port == 'fake0' else " + repr('KER_IO_DONE '+payload) + ")"
            self.worker.write_text(head + 'print('+record+', flush=True)' + tail)
            with self.subTest(payload=payload):
                result, message = self.run_launcher(0, native_done=True,
                    config=self.config, capture_stderr=True)
            self.assertEqual(result, 125)
            self.assertIn('additional worker completion', message)
        self.worker.write_text(fixtures.WORKER)
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config), 0)

    def test_auxiliary_cleanup_failure_does_not_skip_a_peer(self):
        self.config.write_text(self.config.read_text() +
            '[interface.other]\naddress=198.20.0.2/24\nport=aux1\neal=--no-pci\n')
        finish = launcher.AdditionalWorker.finish
        finished = []
        def complete(extra):
            result = finish(extra)
            finished.append(extra.process)
            if extra.interface['name'] == 'aux':
                raise OSError('injected auxiliary cleanup failure')
            return result
        with mock.patch.object(launcher.AdditionalWorker, 'finish', complete):
            result, message = self.run_launcher(0, native_done=True,
                config=self.config, capture_stderr=True)
        self.assertEqual(result, 125)
        self.assertIn('additional worker cleanup', message)
        self.assertEqual(len(finished), 2)
        for process in finished:
            self.assertIsNotNone(process.returncode)
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        self.assertEqual(self.run_launcher(0, native_done=True, config=self.config), 0)


if __name__ == '__main__':
    unittest.main()
