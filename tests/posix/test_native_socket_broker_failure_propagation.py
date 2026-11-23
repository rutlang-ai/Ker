"""Keep late reuseport-client failures visible after child cleanup."""
import importlib.util
import os
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).with_name('native-socket-broker.py')
SPEC = importlib.util.spec_from_file_location('native_socket_broker_failure_test', SOURCE)
BROKER_TEST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BROKER_TEST)


class FakeClient:
    def __init__(self):
        self.stdout = object()
        self.returncode = None
        self.killed = False
        self.waited = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self):
        self.waited = True
        return self.returncode


class FakeBroker:
    def __init__(self, output=b'BROKER_DONE', errors=b'', returncode=0,
            timeout=False, second_output=b'', second_errors=b''):
        self.output = output
        self.errors = errors
        self.returncode = returncode
        self.timeout = timeout
        self.second_output = second_output or output
        self.second_errors = second_errors or errors
        self.calls = 0
        self.killed = False

    def communicate(self, timeout):
        self.calls += 1
        if self.timeout and self.calls == 1:
            raise BROKER_TEST.subprocess.TimeoutExpired('broker', timeout)
        return self.second_output, self.second_errors

    def kill(self):
        self.killed = True
        self.returncode = -9


class ReuseportFailurePropagationTests(unittest.TestCase):
    def test_graceful_source_waits_for_backend_and_primary_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / 'runtime.trace'
            primary = root / 'primary.stderr'
            trace.write_text('stage=graceful_source_state_valid\n')
            stages = iter((
                ('stage=graceful_source_state_valid\nstage=graceful_backend_unbound dispatcher=0 packet_owner=0\n', None),
                (None, b'graceful reload requires an authenticated generation packet-owner\n'),
            ))
            sleeps = []

            def advance(_duration):
                sleeps.append(_duration)
                trace_text, primary_bytes = next(stages)
                if trace_text is not None:
                    trace.write_text(trace_text)
                if primary_bytes is not None:
                    primary.write_bytes(primary_bytes)

            with patch.object(BROKER_TEST.time, 'sleep', side_effect=advance):
                trace_text, primary_stderr = BROKER_TEST.wait_for_graceful_source_rejection_evidence(
                    trace, primary, timeout=1, poll_interval=0.001)

            self.assertEqual(len(sleeps), 2)
            self.assertIn('stage=graceful_source_state_valid', trace_text)
            self.assertIn('stage=graceful_backend_unbound dispatcher=0 packet_owner=0', trace_text)
            self.assertIn(b'graceful reload requires an authenticated generation packet-owner',
                primary_stderr)

    def test_late_assertion_survives_child_cleanup(self):
        client = FakeClient()
        read_failure = AssertionError('injected late client assertion')
        capability_read, capability_write = os.pipe()
        try:
            args = type('Args', (), {
                'reuseport_group_client': Path('/fake/client'),
                'inherited_group_probe': Path('/fake/probe'),
                'preload_library': Path('/fake/preload.so'),
            })()
            with patch.object(BROKER_TEST.subprocess, 'Popen', return_value=client), \
                    patch.object(BROKER_TEST, 'read_line', side_effect=read_failure):
                with self.assertRaisesRegex(AssertionError, 'injected late client assertion'):
                    BROKER_TEST.run_reuseport_group_client(args, Path('/fake/rpc.sock'),
                        None, capability_read)
            self.assertTrue(client.killed)
            self.assertTrue(client.waited)
        finally:
            try:
                os.close(capability_write)
            except OSError:
                pass

    def test_c23_runtime_finalization_failures_are_durable(self):
        failures = (
            ('shutdown', 'nginx shutdown failed', None, {'tx': 1, 'rx': 1,
                'outstanding': 0, 'native': {'passive_opens': 2}}),
            ('timeout', 'did not release nginx descriptors', None, {'tx': 1, 'rx': 1,
                'outstanding': 0, 'native': {'passive_opens': 2}}),
            ('done', 'did not finalize nginx sockets', FakeBroker(output=b'partial'),
                {'tx': 1, 'rx': 1, 'outstanding': 0, 'native': {'passive_opens': 2}}),
            ('malformed', 'Expecting value', FakeBroker(), 'not-json'),
            ('nonmapping', 'JSON object', FakeBroker(), []),
            ('outstanding', 'cleanup evidence missing', FakeBroker(), {'tx': 1, 'rx': 1,
                'outstanding': 1, 'native': {'passive_opens': 2}}),
        )
        for name, message, broker_override, stats in failures:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence_path = root / 'evidence.json'
                evidence = {'qualification': 'PENDING_FINALIZATION',
                    'source_probe_qualification': 'PASS'}
                trace = root / 'trace.log'
                trace.write_text('runtime trace')
                stats_path = root / 'stats.json'
                stats_path.write_text(stats if isinstance(stats, str) else json.dumps(stats))
                broker = broker_override or FakeBroker(timeout=name == 'timeout',
                    second_output=b'')
                if name == 'shutdown':
                    def shutdown():
                        raise RuntimeError('nginx shutdown failed')
                else:
                    shutdown = lambda: None
                with self.assertRaisesRegex((RuntimeError, json.JSONDecodeError), message):
                    BROKER_TEST.finalize_c23_runtime(evidence_path, evidence, shutdown,
                        broker, stats_path, {'nginx_runtime_trace': trace})
                saved = json.loads(evidence_path.read_text())
                self.assertEqual(saved['qualification'], 'UNQUALIFIED')
                self.assertEqual(saved['source_probe_qualification'], 'PASS')
                archived = Path(saved['c22_runtime_artifacts']['nginx_runtime_trace']['path'])
                self.assertEqual(archived.read_text(), 'runtime trace')

    def test_c23_runtime_finalization_passes_only_after_all_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / 'evidence.json'
            evidence = {'qualification': 'PENDING_FINALIZATION',
                'source_probe_qualification': 'PASS'}
            stats_path = root / 'stats.json'
            stats_path.write_text(json.dumps({'tx': 2, 'rx': 2, 'outstanding': 0,
                'native': {'passive_opens': 2}}))
            trace = root / 'trace.log'
            trace.write_text('final runtime trace')
            broker = FakeBroker()
            result = BROKER_TEST.finalize_c23_runtime(evidence_path, evidence,
                lambda: None, broker, stats_path, {'nginx_runtime_trace': trace})
            self.assertTrue(result)
            saved = json.loads(evidence_path.read_text())
            self.assertEqual(saved['qualification'], 'PASS')
            self.assertEqual(saved['finalization']['status'], 'PASS')

    def test_c23_archive_io_failure_is_durable_and_other_logs_are_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / 'evidence.json'
            evidence = {'qualification': 'PENDING_FINALIZATION',
                'source_probe_qualification': 'PASS'}
            stats_path = root / 'stats.json'
            stats_path.write_text(json.dumps({'tx': 2, 'rx': 2, 'outstanding': 0,
                'native': {'passive_opens': 2}}))
            trace = root / 'trace.log'
            trace.write_text('trace')
            error_log = root / 'error.log'
            error_log.write_text('error')
            original_write_bytes = Path.write_bytes

            def fail_one_archive(path, data):
                if path.name == 'nginx_runtime_trace':
                    raise OSError('injected archive disk error')
                return original_write_bytes(path, data)

            with patch.object(Path, 'write_bytes', fail_one_archive):
                with self.assertRaisesRegex(RuntimeError, 'could not archive'):
                    BROKER_TEST.finalize_c23_runtime(evidence_path, evidence,
                        lambda: None, FakeBroker(), stats_path,
                        {'nginx_runtime_trace': trace, 'nginx_error_log': error_log})
            saved = json.loads(evidence_path.read_text())
            self.assertEqual(saved['qualification'], 'UNQUALIFIED')
            self.assertIn('injected archive disk error',
                saved['artifact_archive_errors']['nginx_runtime_trace'])
            archived_error = Path(saved['c22_runtime_artifacts']['nginx_error_log']['path'])
            self.assertEqual(archived_error.read_text(), 'error')

    def test_c23_source_failure_still_archives_outer_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / 'evidence.json'
            evidence = {'qualification': 'UNQUALIFIED',
                'source_probe_qualification': 'UNQUALIFIED'}
            trace = root / 'trace.log'
            trace.write_text('runtime available after source failure')
            result = BROKER_TEST.finalize_c23_failure_if_needed(evidence_path, evidence,
                'source_probe', RuntimeError('baseline oracle failed'),
                {'nginx_runtime_trace': trace})
            self.assertFalse(result)
            saved = json.loads(evidence_path.read_text())
            archived = Path(saved['c22_runtime_artifacts']['nginx_runtime_trace']['path'])
            self.assertEqual(archived.read_text(), trace.read_text())
            self.assertEqual(saved['finalization']['phase'], 'source_probe')


if __name__ == '__main__':
    unittest.main()
