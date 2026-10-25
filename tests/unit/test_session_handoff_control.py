#!/usr/bin/env python3
"""Exercise the checked-in nested handoff control path with real pipes only.

The control tests prove launcher pipe writes/closure. The marker tests feed the
actual nested handoff function the marker sequence emitted by the C success and
error paths. Neither proves EAL, packet, or native handoff behavior.
"""
import errno
import ast
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import types
import time
import unittest


SOURCE = Path(__file__).resolve().parents[2] / 'tools' / 'ker_session_run.py'
PROFILE_SOURCE = Path(__file__).resolve().parents[1] / 'posix' / 'session-native-packets.py'


def nested_code(code, name):
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            if item.co_name == name:
                return item
            found = nested_code(item, name)
            if found is not None:
                return found
    return None


def cell(value):
    return (lambda: value).__closure__[0]


class StopAtWorkerMarker(Exception):
    pass


class Actor:
    pid = 12345
    returncode = None

    @staticmethod
    def poll():
        return None

    def wait(self, timeout=None):
        return self.returncode


class HandoffControlPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module = compile(SOURCE.read_text(), str(SOURCE), 'exec')
        cls.function_code = nested_code(module, 'perform_test_handoff')
        if cls.function_code is None:
            raise RuntimeError('could not locate actual perform_test_handoff code object')
        spec = importlib.util.spec_from_file_location('ker_session_run_for_cleanup_test', SOURCE)
        cls.launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.launcher)

    def exercise(self, mode, expected, expect_closed):
        read_fd, write_fd = os.pipe()
        metrics = {'exception_endpoint_name': 'ker_test0'}
        closed = []

        def close(fd):
            closed.append(fd)
            os.close(fd)

        def wait_marker(_process, _prefix, timeout=10):
            raise StopAtWorkerMarker

        values = {
            'api': None,
            'app': Actor(),
            'args': None,
            'close': close,
            'control_w': write_fd,
            'handoff_fd': read_fd,
            'handoff_mode': mode,
            'handoff_udp_ready': False,
            'frame_death_complete': False,
            'frame_death_worker_expected_code': None,
            'metrics': metrics,
            'peer_control_w': -1,
            'peer_worker': Actor(),
            'peer_worker_pidfd': -1,
            'publish': lambda: None,
            'ready': lambda *_args, **_kwargs: None,
            'wait_marker': wait_marker,
            'worker': Actor(),
            'worker_pidfd': -1,
        }
        function = types.FunctionType(self.function_code,
            {'os': os, 'RuntimeError': RuntimeError,
             'tap_interfaces_for_process': lambda _pid: {'ker_test0'}},
            'perform_test_handoff', closure=tuple(cell(values[name]) for name in self.function_code.co_freevars))
        try:
            with self.assertRaises(StopAtWorkerMarker):
                function()
            observed = os.read(read_fd, 8)
            self.assertEqual(observed, expected)
            current_fd = function.__closure__[self.function_code.co_freevars.index('control_w')].cell_contents
            self.assertEqual(current_fd, -1 if expect_closed else write_fd)
            self.assertEqual(closed, [write_fd] if expect_closed else [])
            if expect_closed:
                self.assertEqual(os.read(read_fd, 1), b'')
        finally:
            os.close(read_fd)
            if not expect_closed:
                os.close(write_fd)

    def marker_function(self, mode, markers, metrics):
        read_fd, write_fd = os.pipe()
        calls = []

        def wait_marker(_process, prefix, timeout=10):
            calls.append(prefix)
            if not markers:
                raise AssertionError('unexpected marker wait: ' + prefix)
            actual, value = markers.pop(0)
            if actual != prefix:
                raise AssertionError(f'expected marker wait {actual}, got {prefix}')
            return value

        values = {
            'api': None,
            'app': Actor(),
            'args': None,
            'close': os.close,
            'control_w': write_fd,
            'handoff_fd': read_fd,
            'handoff_mode': mode,
            'handoff_udp_ready': False,
            'frame_death_complete': False,
            'frame_death_worker_expected_code': None,
            'metrics': metrics,
            'peer_control_w': -1,
            'peer_worker': Actor(),
            'peer_worker_pidfd': -1,
            'publish': lambda: None,
            'ready': lambda *_args, **_kwargs: None,
            'tap_interfaces_for_process': lambda _pid: {'ker_test0'},
            'wait_marker': wait_marker,
            'worker': Actor(),
            'worker_pidfd': -1,
        }
        function = types.FunctionType(self.function_code,
            {'os': os, 'errno': errno, 'RuntimeError': RuntimeError,
             'subprocess': __import__('subprocess'),
             'select': select,
             'signal': signal,
             'signal_pidfd': self.launcher.signal_pidfd,
             'pidfd_process_stopped': self.launcher.pidfd_process_stopped,
             'resume_pidfd_if_live': self.launcher.resume_pidfd_if_live,
             'wait_pidfd_process_stopped': self.launcher.wait_pidfd_process_stopped,
             'tap_interfaces_for_process': values['tap_interfaces_for_process']},
            'perform_test_handoff', closure=tuple(cell(values[name]) for name in self.function_code.co_freevars))
        return function, calls, read_fd, write_fd

    def test_positive_handoff_writes_one_h(self):
        self.exercise('positive', b'H', expect_closed=False)

    def test_successor_owner_key_comes_from_completed_handoff_metrics(self):
        self.assertEqual(self.launcher.handoff_successor_owner_key(
            {'handoff': {'new_owner_key': 37}}), 37)
        for metrics in ({}, {'handoff': {}}, {'handoff': {'new_owner_key': 0}},
                        {'handoff': {'new_owner_key': True}}):
            with self.subTest(metrics=metrics), self.assertRaises(RuntimeError):
                self.launcher.handoff_successor_owner_key(metrics)

    def test_actual_udp_trigger_binds_successor_key_locally(self):
        trigger = nested_code(compile(SOURCE.read_text(), str(SOURCE), 'exec'), 'trigger_handoff_udp')
        self.assertIsNotNone(trigger)
        self.assertIn('expected_key', trigger.co_varnames)
        self.assertNotIn('expected_key', trigger.co_freevars)
        self.assertNotIn('expected_key', trigger.co_names)

    def test_actual_wire_wait_has_no_runner_startup_scope_dependency(self):
        compiled = compile(PROFILE_SOURCE.read_text(), str(PROFILE_SOURCE), 'exec')
        code = nested_code(compiled, 'wait_wire_payload')
        self.assertIsNotNone(code)
        self.assertNotIn('startup', code.co_names)
        self.assertNotIn('drain_startup', code.co_names)

    def test_rejected_handoffs_pipeline_two_h_commands(self):
        self.exercise('prepare-enoent', b'HH', expect_closed=False)

    def test_control_hup_closes_writer_after_h(self):
        self.exercise('handoff-control-hup', b'H', expect_closed=True)

    def test_hup_boundary_wait_failure_still_resumes_exact_worker(self):
        read_fd, write_fd = os.pipe()
        child = subprocess.Popen([os.sys.executable, '-c', 'import time; time.sleep(30)'])
        pidfd = os.pidfd_open(child.pid)
        metrics = {'exception_endpoint_name': 'ker_test0'}
        closed = []

        def close(fd):
            closed.append(fd)
            os.close(fd)

        def wait_marker(_process, prefix, timeout=10):
            if prefix != 'KER_SESSION_HANDOFF_BOUNDARY':
                raise AssertionError('unexpected marker wait: ' + prefix)
            self.launcher.signal_pidfd(pidfd, signal.SIGSTOP)
            self.launcher.wait_pidfd_process_stopped(pidfd, child.pid)
            raise StopAtWorkerMarker

        values = {
            'api': None, 'app': Actor(), 'args': None, 'close': close,
            'control_w': write_fd, 'handoff_fd': read_fd, 'handoff_mode': 'handoff-control-hup',
            'handoff_udp_ready': False,
            'frame_death_complete': False,
            'frame_death_worker_expected_code': None,
            'metrics': metrics, 'peer_control_w': -1, 'peer_worker': Actor(), 'peer_worker_pidfd': -1,
            'publish': lambda: None, 'ready': lambda *_args, **_kwargs: None,
            'wait_marker': wait_marker, 'worker': child, 'worker_pidfd': pidfd,
        }
        function = types.FunctionType(self.function_code,
            {'os': os, 'RuntimeError': RuntimeError, 'select': select,
             'signal': signal, 'sys': __import__('sys'),
             'tap_interfaces_for_process': lambda _pid: {'ker_test0'},
             'signal_pidfd': self.launcher.signal_pidfd,
             'pidfd_process_stopped': self.launcher.pidfd_process_stopped,
             'resume_pidfd_if_live': self.launcher.resume_pidfd_if_live,
             'wait_pidfd_process_stopped': self.launcher.wait_pidfd_process_stopped},
            'perform_test_handoff',
            closure=tuple(cell(values[name]) for name in self.function_code.co_freevars))
        try:
            with self.assertRaises(StopAtWorkerMarker):
                function()
            self.assertEqual(os.read(read_fd, 1), b'H')
            self.assertEqual(closed, [write_fd])
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if select.select([pidfd], [], [], 0)[0]:
                    self.fail('worker exited instead of being resumed')
                state = next(line.split()[1] for line in Path(f'/proc/{child.pid}/status').read_text().splitlines()
                    if line.startswith('State:'))
                if state not in ('T', 't'):
                    break
                time.sleep(0.005)
            self.assertNotIn(state, ('T', 't'))
        finally:
            if not select.select([pidfd], [], [], 0)[0]:
                self.launcher.signal_pidfd(pidfd, signal.SIGCONT)
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill(); child.wait()
            os.close(pidfd)
            os.close(read_fd)

    def test_two_valid_rejections_use_same_replay_marker_without_success_marker(self):
        metrics = {'exception_endpoint_name': 'ker_test0'}
        markers = [
            ('KER_SESSION_HANDOFF_BOUNDARY', {'idle': True}),
            ('KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED', {'status': -errno.EPERM, 'same_replay': True}),
            ('KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED', {'status': -errno.ENOENT}),
            ('KER_SESSION_HANDOFF_BOUNDARY', {'idle': True}),
            ('KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED', {'status': -errno.EPERM, 'same_replay': True}),
            ('KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED', {'status': -errno.ENOENT}),
        ]
        function, calls, read_fd, write_fd = self.marker_function('prepare-enoent', markers, metrics)
        try:
            function()
            self.assertEqual(os.read(read_fd, 2), b'HH')
            self.assertEqual(calls, [
                'KER_SESSION_HANDOFF_BOUNDARY',
                'KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED',
                'KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED',
                'KER_SESSION_HANDOFF_BOUNDARY',
                'KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED',
                'KER_SESSION_TEST_HANDOFF_PREPARE_RESUMED'])
            self.assertEqual(markers, [])
            self.assertEqual(metrics['stage'], 'handoff-rejected')
            self.assertEqual(metrics['handoff_protocol']['replay_verified'], [True, True])
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def exercise_malformed_rejection(self, mode):
        metrics = {'exception_endpoint_name': 'ker_test0'}
        markers = [
            ('KER_SESSION_HANDOFF_BOUNDARY', {'idle': True}),
            ('KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED', {'status': -errno.EPERM, 'same_replay': True}),
        ]
        function, calls, read_fd, write_fd = self.marker_function(mode, markers, metrics)
        function.__closure__[self.function_code.co_freevars.index('worker')].cell_contents.returncode = 125
        try:
            with self.assertRaisesRegex(RuntimeError, 'malformed PREPARE reply'):
                function()
            self.assertEqual(os.read(read_fd, 1), b'H')
            self.assertEqual(calls, ['KER_SESSION_HANDOFF_BOUNDARY', 'KER_SESSION_TEST_HANDOFF_PREPARE_REJECTED'])
            self.assertEqual(markers, [])
            self.assertEqual(metrics['stage'], 'handoff-malformed-reply')
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_malformed_error_does_not_wait_for_success_replay_marker(self):
        self.exercise_malformed_rejection('bad-prepare-error-generation')

    def test_malformed_success_does_not_wait_for_success_replay_marker(self):
        self.exercise_malformed_rejection('bad-prepare-success')

    def test_peer_cleanup_distinguishes_control_only_and_committed_packet_owner(self):
        validate = self.launcher.validate_handoff_peer_cleanup
        packet = {'status': 0}
        validate({}, True, 0, None)
        validate({'handoff': {'stage': 'committed'}}, True, 0, packet)
        validate({}, False, None, None)
        for metrics, code, stats in (
                ({}, 0, packet),
                ({'handoff': {'stage': 'committed'}}, 0, None),
                ({}, 1, None),
                ({'handoff': {'stage': 'committed'}}, 0, {'status': 1})):
            with self.subTest(metrics=metrics, code=code, stats=stats):
                with self.assertRaises(RuntimeError):
                    validate(metrics, True, code, stats)

    def test_mode_specific_trigger_lifecycle_keeps_frame_and_death_profiles_open(self):
        complete = self.launcher.handoff_trigger_complete
        close_trigger = self.launcher.close_completed_handoff_trigger
        u2_modes = ('frame-positive', 'frame-full', 'frame-death-prepared',
            'frame-death-producer-active-consumer',
            'frame-death-consumer-prepared', 'frame-death-consumer-writing')
        for mode in u2_modes:
            with self.subTest(mode=mode):
                self.assertFalse(complete(mode, True, 1))
                self.assertTrue(complete(mode, True, 2))
                calls = []
                self.assertEqual(close_trigger(mode, True, 1, 17, calls.append), 17)
                self.assertEqual(calls, [])
                self.assertIsNone(close_trigger(mode, True, 2, 17, calls.append))
                self.assertEqual(calls, [17])
        self.assertTrue(complete('positive', True, 0))
        self.assertFalse(complete('positive', False, 0))
        self.assertEqual(self.launcher.handoff_trigger_action(b'U'), 'udp')
        self.assertEqual(self.launcher.handoff_trigger_action(b'H'), 'handoff')
        self.assertEqual(self.launcher.handoff_trigger_action(b''), 'invalid')
        self.assertEqual(self.launcher.handoff_trigger_action(b'X'), 'invalid')

    def test_frame_marker_stream_consumes_only_enabled_prefix_in_exact_order(self):
        prepare = ('KER_SESSION_FRAME_NEGATIVE_PREPARES_PASS', {'variants': 12,
            'datagram_queued': True, 'ring_unchanged': True, 'pool_unchanged': True,
            'frame_length': 60, 'frame_hex': '00' * 60})
        cancel = ('KER_SESSION_FRAME_CANCEL_REPLAY_PASS', {'prepared_replay': True,
            'bad_commit_denied': True, 'bad_cancel_denied': True, 'cancel_replay': True,
            'datagram_queued': True, 'pool_restored': True})
        committed = ('KER_SESSION_FRAME_COMMITTED', {'object_index': 4})

        def reader(records):
            remaining = list(records)
            def ready(prefix, process=None):
                if not remaining:
                    raise RuntimeError('unexpected marker ' + prefix)
                actual, value = remaining.pop(0)
                if actual != prefix:
                    raise RuntimeError('out-of-order marker: expected ' + prefix + ', got ' + actual)
                return value
            return ready, remaining

        ready, remaining = reader([prepare, cancel, committed])
        result = self.launcher.read_frame_commit_sequence(object(), ready, True)
        self.assertEqual(result, (prepare[1], cancel[1], committed[1]))
        self.assertEqual(remaining, [])
        ready, remaining = reader([committed])
        self.assertEqual(self.launcher.read_frame_commit_sequence(object(), ready, False),
            (None, None, committed[1]))
        self.assertEqual(remaining, [])
        for records in ([cancel, committed], [prepare, prepare, cancel, committed],
                        [prepare, cancel, cancel, committed]):
            ready, _ = reader(records)
            with self.assertRaises(RuntimeError):
                self.launcher.read_frame_commit_sequence(object(), ready, True)

    def test_frame_commit_release_bijection_binds_exact_lease_and_u2_bytes(self):
        payload=b'KER-A09-HANDOFF-UDP seq=2\n'
        ip=bytearray(20);ip[0]=0x45;ip[2:4]=(20+8+len(payload)).to_bytes(2,'big')
        ip[8]=64;ip[9]=17;ip[12:16]=bytes((198,18,0,2));ip[16:20]=bytes((198,18,0,1))
        udp=bytes.fromhex('afc8afc9')+(8+len(payload)).to_bytes(2,'big')+b'\0\0'
        frame=bytes.fromhex('024b45520001024b455200020800')+bytes(ip)+udp+payload
        commit=dict(port=0,queue=0,generation=0,length=len(frame),object_index=7,
            pool_tag=91,tx_lease_id=123,packet_pointer='0xabc',frame_hex=frame.hex())
        release=dict(sequence=2,consumer_generation=1,object_index=7,lease_id=123,
            pool_tag=91,packet_pointer='0xabc',length=len(frame),frame_hex=frame.hex())
        result=self.launcher.validate_frame_commit_drain_bijection([commit],[release],payload)
        self.assertEqual(result['committed'],1);self.assertEqual(result['drained'],1)
        for bad in ({**release,'lease_id':124},{**release,'packet_pointer':'0xabd'},
                    {**release,'sequence':0},{**release,'frame_hex':(frame+b'!').hex()}):
            with self.subTest(bad=bad):
                with self.assertRaises(RuntimeError):
                    self.launcher.validate_frame_commit_drain_bijection([commit],[bad],payload)
        with self.assertRaises(RuntimeError):
            self.launcher.validate_frame_commit_drain_bijection([commit,commit],[release],payload)

    def test_owner_clear_marker_requires_exact_pid_and_schema(self):
        validate = self.launcher.validate_parked_owner_cleared
        validate({'pid': 42, 'owner_key': 0}, 42)
        for record in ({'pid': 41, 'owner_key': 0}, {'pid': 42, 'owner_key': 3},
                       {'pid': True, 'owner_key': 0}, {'pid': 42, 'owner_key': 0, 'extra': 1}):
            with self.subTest(record=record):
                with self.assertRaises(RuntimeError):
                    validate(record, 42)

    def test_failure_collector_fallback_preserves_original_reason(self):
        tree = ast.parse(PROFILE_SOURCE.read_text())
        profile = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_run_live_handoff_profile_impl')
        wrapper = next(node for node in ast.walk(profile)
            if isinstance(node, ast.FunctionDef) and node.name == 'fatal_profile_diagnostics')
        emitted = []
        namespace = {'json': json, 'mode': 'frame-positive',
            '_fatal_profile_diagnostics': lambda _reason: (_ for _ in ()).throw(OSError('capture failed')),
            'print': lambda *args, **kwargs: emitted.append(args[0]),
            'Exception': Exception, 'RuntimeError': RuntimeError}
        module = ast.Module(body=[wrapper], type_ignores=[])
        exec(compile(ast.fix_missing_locations(module), str(PROFILE_SOURCE), 'exec'), namespace)
        error = namespace['fatal_profile_diagnostics']('original frame failure')
        self.assertIn('original frame failure', str(error))
        self.assertIn('capture failed', str(error))
        record = json.loads(emitted[0].split(' ', 1)[1])
        self.assertEqual(record['reason'], 'original frame failure')
        self.assertIn('diagnostic_capture_error', record)


if __name__ == '__main__':
    unittest.main()
