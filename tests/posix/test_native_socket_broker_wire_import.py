"""Import preflight for the opt-in C22 provider-wire fixture."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock
import unittest
import tempfile


FIXTURE = Path(__file__).with_name('native-socket-broker-readiness.py')
C_HELPER = FIXTURE.with_name('nginx-owner-group-controller.c')
FIXTURE_SPEC = importlib.util.spec_from_file_location('_broker_wire_fixture_cleanup',
    FIXTURE)
fixture = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(fixture)


class BrokerWireFixtureImportTests(unittest.TestCase):
    def test_fixture_and_real_provider_module_import_from_source_paths(self):
        spec = importlib.util.spec_from_file_location('_broker_wire_fixture_preflight',
            FIXTURE)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)

        self.assertEqual(fixture.ROOT, FIXTURE.resolve().parents[2])
        self.assertIs(fixture.array.__class__, __import__('array').__class__)
        provider_path = fixture.ROOT / 'tools' / 'nginx_source_c22_provider.py'
        provider_spec = importlib.util.spec_from_file_location(
            '_c22_provider_import_preflight', provider_path)
        self.assertIsNotNone(provider_spec)
        self.assertIsNotNone(provider_spec.loader)
        provider = importlib.util.module_from_spec(provider_spec)
        provider_spec.loader.exec_module(provider)
        self.assertTrue(callable(provider.SourceShellC22Provider))

    def test_controller_failure_requests_one_existing_authenticated_stop(self):
        manager = SimpleNamespace(ready=True, stopped=False, stop_attempted=False,
            supervisor=(1234, 0, 0, 99), app=(5678, 0, 0, 88))
        app = SimpleNamespace(returncode=None, pid=5678)
        app.poll = lambda: app.returncode
        app.kill = lambda: setattr(app, 'returncode', -9)
        app.wait = lambda timeout: app.returncode

        def signal_supervisor(pid, signum):
            self.assertEqual(pid, 1234)
            self.assertEqual(signum, fixture.signal.SIGTERM)
            manager.stopped = True
            app.returncode = 0

        with mock.patch.object(fixture.os, 'getpid', return_value=1234), \
                mock.patch.object(fixture, 'start_ticks', return_value=99), \
                mock.patch.object(fixture.os, 'kill', side_effect=signal_supervisor) as kill:
            cleanup = fixture._bounded_controller_failure_cleanup(
                manager, app, 1234, timeout=0.02)
        kill.assert_called_once_with(1234, fixture.signal.SIGTERM)
        self.assertTrue(cleanup['stop_signal_sent'])
        self.assertTrue(cleanup['stop_acknowledged'])
        self.assertTrue(cleanup['app_exited'])
        self.assertFalse(cleanup['fallback_kill'])

    def test_controller_failure_does_not_repeat_an_attempted_stop(self):
        manager = SimpleNamespace(ready=True, stopped=False, stop_attempted=True,
            supervisor=(1234, 0, 0, 99), app=(5678, 0, 0, 88))
        app = SimpleNamespace(returncode=None, pid=5678)
        app.poll = lambda: app.returncode
        app.kill = lambda: setattr(app, 'returncode', -9)
        app.wait = lambda timeout: app.returncode
        with mock.patch.object(fixture.os, 'getpid', return_value=1234), \
                mock.patch.object(fixture.os, 'kill') as kill:
            cleanup = fixture._bounded_controller_failure_cleanup(
                manager, app, 1234, timeout=0.02)
        kill.assert_not_called()
        self.assertFalse(cleanup['stop_signal_sent'])
        self.assertFalse(cleanup['stop_acknowledged'])
        self.assertTrue(cleanup['fallback_kill'])
        self.assertEqual(app.returncode, -9)

    def test_cleanup_settlement_requires_complete_exact_native_counters(self):
        manager = SimpleNamespace(ready=True, stopped=True)
        native = {'buffer_allocations': 4, 'buffer_releases': 4,
            'buffer_shutdown_releases': 0, 'buffers_live': 0, 'buffer_bytes': 0,
            'buffer_option_guards_live': 0}
        stats = {'outstanding': 0, 'control_eof': True, 'worker_exit_code': 0,
            'shutdown_timed_out': False, 'rx_decision_enabled': False,
            'rx_decision_settled': False, 'run_shutdown': True,
            'run_shutdown_ack': True, 'native': native}
        self.assertTrue(fixture._controller_failure_settled(manager, 0, 143, stats))

        bad_counters = []
        missing_allocations = dict(native)
        missing_allocations.pop('buffer_allocations')
        bad_counters.append(missing_allocations)
        missing_releases = dict(native)
        missing_releases.pop('buffer_releases')
        bad_counters.append(missing_releases)
        bad_counters.extend((
            {**native, 'buffer_allocations': True},
            {**native, 'buffer_bytes': False},
            {**native, 'buffer_releases': -1},
            {**native, 'buffer_allocations': 5},
            {**native, 'buffer_shutdown_releases': 1},
        ))
        for counters in bad_counters:
            with self.subTest(counters=counters):
                self.assertFalse(fixture._native_shutdown_counters_clean(counters))
                self.assertFalse(fixture._controller_failure_settled(manager, 0, 143,
                    {**stats, 'native': counters}))

        for outstanding in (False, -1):
            with self.subTest(stats_outstanding=outstanding):
                self.assertFalse(fixture._controller_failure_settled(manager, 0, 143,
                    {**stats, 'outstanding': outstanding}))
        self.assertFalse(fixture._controller_failure_settled(manager, 0, 143,
            {**stats, 'rx_decision_enabled': True}))
        self.assertFalse(fixture._controller_failure_settled(manager, 0, 143,
            {**stats, 'worker_exit_code': False}))

    def test_settled_cleanup_never_changes_qualification_failure(self):
        manager = SimpleNamespace(ready=True, stopped=True, stop_attempted=True,
            app=(5678, 0, 0, 88))
        app = SimpleNamespace(poll=lambda: 0)
        stats = {'outstanding': 0, 'control_eof': True, 'worker_exit_code': 0,
            'shutdown_timed_out': False, 'rx_decision_enabled': False,
            'rx_decision_settled': False, 'run_shutdown': True, 'run_shutdown_ack': True,
            'native': {'buffer_allocations': 4, 'buffer_releases': 4,
                'buffer_shutdown_releases': 0, 'buffers_live': 0, 'buffer_bytes': 0,
                'buffer_option_guards_live': 0}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stats_path = root / 'stats.json'
            stats_path.write_text(json.dumps(stats), encoding='utf-8')
            args = SimpleNamespace(mode='source-c22-provider-wire',
                source_c22_receipt=root / 'provider.json', stats=stats_path)
            state = {'manager': manager, 'app': app, 'stats_before': None,
                'controller_failure_cleanup': {'stop_acknowledged': True}}
            fixture._write_controller_failure_receipt(args, state,
                RuntimeError('provider wire failed'), 143)
            receipt = json.loads(Path(str(args.source_c22_receipt) +
                '.controller-failure.json').read_text(encoding='utf-8'))
        self.assertEqual(receipt['classification'], 'SETTLED')
        self.assertEqual(receipt['qualification_result'], 'FAIL')

    def test_helper_failure_stderr_capture_is_bounded_and_keeps_exit_status(self):
        process = subprocess.Popen([sys.executable, '-c',
            "import sys; sys.stderr.write('x' * 12000); sys.exit(7)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        captured, reader = fixture._start_bounded_stderr_capture(process.stderr, limit=4096)
        diagnostic = fixture._helper_failure_diagnostic(process, captured, reader)
        reader.join(timeout=0.2)
        process.stderr.close()
        self.assertEqual(diagnostic['returncode_before_cleanup'], 7)
        self.assertEqual(len(bytes.fromhex(diagnostic['stderr_hex'])), 4096)
        self.assertTrue(diagnostic['stderr_truncated'])

    def test_watch_rights_claim_uses_creation_api_not_describe_flags(self):
        source = C_HELPER.read_text(encoding='utf-8')
        receipt_source = FIXTURE.read_text(encoding='utf-8')
        self.assertIn('ker_socket_client_owner_generation_watch_create(&client, plan)',
            source)
        self.assertIn('int described_status_flags = -1;', source)
        self.assertIn('described_status_flags != 0', source)
        self.assertNotIn('rights != KER_SOCKET_BROKER_READ', source)
        self.assertIn("'generation_watch_describe_reports_logical_rights': False",
            receipt_source)
        self.assertIn('owner_generation_watch_create API; server assigns READ in generation_watch_create',
            receipt_source)


if __name__ == '__main__':
    unittest.main()
