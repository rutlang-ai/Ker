#!/usr/bin/env python3
"""Exercise the checked-in nested handoff control path with real pipes only.

The control tests prove launcher pipe writes/closure. The marker tests feed the
actual nested handoff function the marker sequence emitted by the C success and
error paths. Neither proves EAL, packet, or native handoff behavior.
"""
import errno
import ast
import io
import importlib.util
import json
import os
from pathlib import Path
import select
import selectors
import signal
import subprocess
import sys
import types
import time
import unittest


SOURCE = Path(__file__).resolve().parents[2] / 'tools' / 'ker_session_run.py'
PROFILE_SOURCE = Path(__file__).resolve().parents[1] / 'posix' / 'session-native-packets.py'
sys.path.insert(0, str(PROFILE_SOURCE.parent))
PROFILE_SPEC = importlib.util.spec_from_file_location('session_native_packets_line_reader_test', PROFILE_SOURCE)
PROFILE = importlib.util.module_from_spec(PROFILE_SPEC)
PROFILE_SPEC.loader.exec_module(PROFILE)


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
            'handoff_udp_ready': False,
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
            'handoff_udp_ready': False,
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

    def test_frame_positive_trigger_fd_closes_after_second_udp_before_app_exit(self):
        read_fd, write_fd = os.pipe()
        handoff_seen = False
        sequence = 0
        try:
            for command in (b'U', b'H', b'U'):
                os.write(write_fd, command)
                self.assertTrue(select.select([read_fd], [], [], 1)[0])
                data = os.read(read_fd, 1)
                action = self.launcher.handoff_trigger_action(data)
                if action == 'udp':
                    sequence += 1
                elif action == 'handoff':
                    handoff_seen = True
                else:
                    self.fail('unexpected trigger command: ' + repr(data))
                read_fd = self.launcher.close_completed_handoff_trigger(
                    'frame-positive', handoff_seen, sequence, read_fd, os.close)
                if command != b'U' or sequence != 2:
                    self.assertIsNotNone(read_fd)
            self.assertIsNone(read_fd)
            self.assertTrue(self.launcher.handoff_trigger_complete(
                'frame-positive', handoff_seen, sequence))
            self.launcher.require_complete_handoff_trigger('frame-positive', handoff_seen, sequence)
            with self.assertRaises(BrokenPipeError):
                os.write(write_fd, b'U')
            os.close(write_fd)
            write_fd = -1
        finally:
            if read_fd is not None:
                os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_incomplete_trigger_eof_before_sigterm_is_rejected(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'H')
            self.assertEqual(self.launcher.handoff_trigger_action(os.read(read_fd, 1)), 'handoff')
            os.close(write_fd)
            write_fd = -1
            self.assertTrue(select.select([read_fd], [], [], 1)[0])
            self.assertEqual(os.read(read_fd, 1), b'')
            with self.assertRaisesRegex(RuntimeError, 'EOF before'):
                self.launcher.reject_handoff_trigger_eof('frame-positive', True, 0)
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_sigterm_first_rejects_incomplete_sequence_before_pipe_eof(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b'H')
            self.assertEqual(self.launcher.handoff_trigger_action(os.read(read_fd, 1)), 'handoff')
            with self.assertRaisesRegex(RuntimeError, 'exited before'):
                self.launcher.require_complete_handoff_trigger('frame-positive', True, 0)
            os.close(write_fd)
            write_fd = -1
            self.assertTrue(select.select([read_fd], [], [], 1)[0])
            self.assertEqual(os.read(read_fd, 1), b'')
            with self.assertRaisesRegex(RuntimeError, 'EOF before'):
                self.launcher.reject_handoff_trigger_eof('frame-positive', True, 0)
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_frame_quiescent_wait_uses_peer_process_at_actual_callsite(self):
        tree = ast.parse(SOURCE.read_text())
        run_session = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and
            node.name == 'run_session')
        assignment = next(node for node in ast.walk(run_session) if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == 'quiescent' for target in node.targets) and
            isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and
            node.value.func.id == 'ready')
        call = assignment.value
        self.assertEqual(len(call.args), 1)
        self.assertEqual(ast.literal_eval(call.args[0]), 'KER_SESSION_FRAME_QUIESCENT')
        self.assertEqual([(item.arg, ast.dump(item.value)) for item in call.keywords],
            [('process', "Name(id='peer_worker', ctx=Load())")])

        worker_read, worker_write = os.pipe()
        peer_read, peer_write = os.pipe()
        worker_line = b'KER_SESSION_FRAME_QUIESCENT {"tx_count":99,"packet_pool_in_use":99}\n'
        peer_line = b'KER_SESSION_FRAME_QUIESCENT {"tx_count":0,"packet_pool_in_use":0}\n'
        os.write(worker_write, worker_line); os.close(worker_write)
        os.write(peer_write, peer_line); os.close(peer_write)
        with io.FileIO(worker_read, 'rb', closefd=True) as worker_stdout, \
                io.FileIO(peer_read, 'rb', closefd=True) as peer_stdout:
            worker = types.SimpleNamespace(stdout=worker_stdout)
            peer_worker = types.SimpleNamespace(stdout=peer_stdout)
            metrics = {}
            ready_code = nested_code(compile(SOURCE.read_text(), str(SOURCE), 'exec'), 'ready')
            ready = types.FunctionType(ready_code,
                {'time': time, 'selectors': selectors, 'RuntimeError': RuntimeError, 'json': json, 'sys': sys},
                'ready', closure=(cell(lambda _line: False), cell(metrics), cell(worker)))
            result = eval(compile(ast.Expression(call), str(SOURCE), 'eval'),
                {'ready': ready, 'peer_worker': peer_worker})
            self.assertEqual(result, {'tx_count': 0, 'packet_pool_in_use': 0})
            self.assertEqual(worker_stdout.readline(), worker_line)

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
            'handoff_udp_ready': False,
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

    def test_session_marker_reader_deadline_covers_partial_pipe_lines(self):
        def run(source):
            return subprocess.Popen([sys.executable, '-c', source], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0)

        partial = run("import sys,time;sys.stdout.buffer.write(b'KER_SESSION_READY {');sys.stdout.flush();time.sleep(1)")
        try:
            self.assertTrue(select.select([partial.stdout], [], [], 2)[0],
                'partial marker bytes did not become readable before the deadline test')
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, 'timed out before a complete line') as raised:
                PROFILE.record(partial, 'KER_SESSION_READY', timeout=0.05)
            self.assertIn("b'KER_SESSION_READY {'", str(raised.exception))
            self.assertLess(time.monotonic() - started, 0.5,
                'partial readable output must not escape the marker deadline')
        finally:
            if partial.poll() is None:
                partial.kill()
            partial.communicate(timeout=1)

        held_stderr = run('import os,time;os.close(1);time.sleep(1)')
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, 'exited early'):
                PROFILE.record(held_stderr, 'KER_SESSION_READY', timeout=1)
            self.assertLess(time.monotonic() - started, 0.5,
                'EOF diagnostics must not wait for inherited stderr writers')
        finally:
            if held_stderr.poll() is None:
                held_stderr.kill()
            held_stderr.communicate(timeout=1)

        wrong_with_inherited_stderr = run(
            "import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(1)'],"
            "stdout=subprocess.DEVNULL);sys.stdout.write('OTHER {\\\"ok\\\":true}\\n');sys.stdout.flush()")
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, 'unexpected output'):
                PROFILE.record(wrong_with_inherited_stderr, 'KER_SESSION_READY', timeout=1)
            self.assertLess(time.monotonic() - started, 0.75,
                'wrong-prefix diagnostics must not wait for descendant-held stderr')
        finally:
            wrong_with_inherited_stderr.communicate(timeout=1)

        split = run("import sys,time;sys.stdout.buffer.write(b'KER_SESSION_READY {');sys.stdout.flush();"
            "time.sleep(0.02);sys.stdout.buffer.write(b'\\\"ok\\\":true}\\n');sys.stdout.flush()")
        try:
            self.assertEqual(PROFILE.record(split, 'KER_SESSION_READY', timeout=1), {'ok': True})
            split.communicate(timeout=1)
        finally:
            if split.poll() is None:
                split.kill(); split.wait()

        partial_eof = run("import sys;sys.stdout.buffer.write(b'KER_SESSION_READY {\\\"ok\\\":true}')")
        try:
            with self.assertRaisesRegex(RuntimeError, 'ended before a complete line'):
                PROFILE.record(partial_eof, 'KER_SESSION_READY', timeout=1)
            partial_eof.communicate(timeout=1)
        finally:
            if partial_eof.poll() is None:
                partial_eof.kill(); partial_eof.wait()


if __name__ == '__main__':
    unittest.main()
