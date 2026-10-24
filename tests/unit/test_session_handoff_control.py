#!/usr/bin/env python3
"""Exercise the checked-in nested handoff control path with real pipes only.

The control tests prove launcher pipe writes/closure. The marker tests feed the
actual nested handoff function the marker sequence emitted by the C success and
error paths. Neither proves EAL, packet, or native handoff behavior.
"""
import errno
import importlib.util
import os
from pathlib import Path
import select
import signal
import subprocess
import types
import time
import unittest


SOURCE = Path(__file__).resolve().parents[2] / 'tools' / 'ker_session_run.py'


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
            'handoff_mode': mode,
            'metrics': metrics,
            'peer_control_w': -1,
            'peer_worker': Actor(),
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
            'handoff_mode': mode,
            'metrics': metrics,
            'peer_control_w': -1,
            'peer_worker': Actor(),
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
            'control_w': write_fd, 'handoff_mode': 'handoff-control-hup',
            'metrics': metrics, 'peer_control_w': -1, 'peer_worker': Actor(),
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


if __name__ == '__main__':
    unittest.main()
