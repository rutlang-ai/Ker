#!/usr/bin/env python3
"""Exercise the checked-in nested handoff control path with real pipes only.

The control tests prove launcher pipe writes/closure. The marker tests feed the
actual nested handoff function the marker sequence emitted by the C success and
error paths. Neither proves EAL, packet, or native handoff behavior.
"""
import errno
import ast
import contextlib
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
import tempfile
import threading
import types
import time
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[2] / 'tools' / 'ker_session_run.py'
PROFILE_SOURCE = Path(__file__).resolve().parents[1] / 'posix' / 'session-native-packets.py'
sys.path.insert(0, str(PROFILE_SOURCE.parent))
PROFILE_SPEC = importlib.util.spec_from_file_location('session_native_packets_capture_test', PROFILE_SOURCE)
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

    def test_fdinfo_handoff_census_requires_complete_identity_stable_snapshot(self):
        with tempfile.TemporaryDirectory(prefix='handoff-fdinfo-') as directory:
            root = Path(directory)
            (root / '3').write_text('pos:\t0\n')
            (root / '4').write_text('iff:\tker_oldtap\n')
            checks = []
            snapshot = self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=root,
                identity_check=lambda: checks.append(True))
            self.assertEqual(snapshot, (frozenset({3, 4}), frozenset({'ker_oldtap'})))
            self.assertEqual(len(checks), 3)
            self.assertEqual(self.launcher.handoff_fdinfo_interfaces(snapshot), ['ker_oldtap'])
            self.launcher.validate_handoff_fdinfo((frozenset({3}), frozenset()), 4, 'ker_oldtap')

    def test_fdinfo_handoff_rejects_original_or_reused_exception_slot(self):
        for descriptor_kind, contents in (
                ('original', 'iff:\tker_oldtap\n'), ('reused', 'pos:\t0\n')):
            with self.subTest(descriptor_kind=descriptor_kind), tempfile.TemporaryDirectory(
                    prefix='handoff-fdinfo-') as directory:
                (Path(directory) / '17').write_text(contents)
                snapshot = self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=directory)
                with self.assertRaisesRegex(RuntimeError, 'descriptor slot open'):
                    self.launcher.validate_handoff_fdinfo(snapshot, 17, 'ker_oldtap')

    def test_fdinfo_handoff_rejects_tap_alias_even_when_exception_slot_is_absent(self):
        with self.assertRaisesRegex(RuntimeError, 'alias to its exception TAP'):
            self.launcher.validate_handoff_fdinfo(
                (frozenset({3, 9}), frozenset({'ker_oldtap'})), 17, 'ker_oldtap')

    def test_fdinfo_handoff_permission_and_midscan_errors_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='handoff-fdinfo-') as directory:
            root = Path(directory)
            (root / '3').write_text('pos:\t0\n')
            with mock.patch.object(Path, 'iterdir', side_effect=PermissionError(errno.EACCES, 'denied')):
                with self.assertRaisesRegex(RuntimeError, 'could not enumerate fdinfo'):
                    self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=root)

            original_read_text = Path.read_text
            def denied_file(path, *args, **kwargs):
                if path.parent == root:
                    raise PermissionError(errno.EPERM, 'denied')
                return original_read_text(path, *args, **kwargs)
            with mock.patch.object(Path, 'read_text', denied_file):
                with self.assertRaisesRegex(RuntimeError, 'could not complete fdinfo census'):
                    self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=root)

            def disappeared_file(path, *args, **kwargs):
                if path.parent == root:
                    raise FileNotFoundError(errno.ENOENT, 'descriptor disappeared')
                return original_read_text(path, *args, **kwargs)
            with mock.patch.object(Path, 'read_text', disappeared_file):
                with self.assertRaisesRegex(RuntimeError, 'could not complete fdinfo census'):
                    self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=root)

            checks = []
            def exits_midscan():
                checks.append(True)
                if len(checks) == 2:
                    raise RuntimeError('captured worker exited during fdinfo inspection')
            with self.assertRaisesRegex(RuntimeError, 'captured worker exited'):
                self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=root, identity_check=exits_midscan)
            self.assertEqual(len(checks), 2)

    def test_fdinfo_handoff_census_rejects_a_new_descriptor_between_scans(self):
        with tempfile.TemporaryDirectory(prefix='handoff-fdinfo-') as directory:
            root = Path(directory)
            (root / '3').write_text('pos:\t0\n')
            checks = []
            def add_reused_old_slot():
                checks.append(True)
                if len(checks) == 2:
                    (root / '17').write_text('pos:\t0\n')
            with self.assertRaisesRegex(RuntimeError, 'fdinfo census changed'):
                self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=root,
                    identity_check=add_reused_old_slot)
            self.assertEqual(len(checks), 3)

    def test_fdinfo_handoff_census_rejects_a_new_tap_alias_between_scans(self):
        with tempfile.TemporaryDirectory(prefix='handoff-fdinfo-') as directory:
            root = Path(directory)
            (root / '3').write_text('pos:\t0\n')
            checks = []
            def add_tap_alias():
                checks.append(True)
                if len(checks) == 2:
                    (root / '17').write_text('iff:\tker_oldtap\n')
            with self.assertRaisesRegex(RuntimeError, 'fdinfo census changed'):
                self.launcher.process_fdinfo_snapshot(12345, fdinfo_dir=root,
                    identity_check=add_tap_alias)
            self.assertEqual(len(checks), 3)

    def test_committed_handoff_metrics_use_validated_fdinfo_interfaces(self):
        tree = ast.parse(SOURCE.read_text())
        handoff = next(node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == 'perform_test_handoff')
        metrics = next(node for node in ast.walk(handoff)
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Subscript) and
                isinstance(target.value, ast.Name) and target.value.id == 'metrics' and
                isinstance(target.slice, ast.Constant) and
                target.slice.value == 'handoff' for target in node.targets))
        metric_call = next(keyword.value for keyword in metrics.value.keywords
            if keyword.arg == 'old_tun_interfaces_after')
        self.assertIsInstance(metric_call, ast.Call)
        self.assertIsInstance(metric_call.func, ast.Name)
        self.assertEqual(metric_call.func.id, 'handoff_fdinfo_interfaces')
        self.assertEqual(self.launcher.handoff_fdinfo_interfaces(
            (frozenset({3}), frozenset({'ker_z', 'ker_a'}))), ['ker_a', 'ker_z'])

    def test_fdinfo_handoff_pidfd_identity_must_remain_live_and_match_pid(self):
        with mock.patch.object(self.launcher.select, 'select', return_value=([44], [], [])):
            with self.assertRaisesRegex(RuntimeError, 'captured worker exited'):
                self.launcher.require_live_process_identity(12345, 44)
        with (mock.patch.object(self.launcher.select, 'select', return_value=([], [], [])),
                mock.patch.object(Path, 'read_text', return_value='Name:\tworker\nPid:\t12346\n')):
            with self.assertRaisesRegex(RuntimeError, 'identity changed'):
                self.launcher.require_live_process_identity(12345, 44)

    def test_frame_profiles_prewarm_original_udp_before_handoff_exhaustively(self):
        tree = ast.parse(PROFILE_SOURCE.read_text())
        test_body = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_run_live_handoff_profile_impl')
        prewarm = next(node for node in ast.walk(test_body)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == 'mode' and
            isinstance(node.test.ops[0], ast.In) and isinstance(node.test.comparators[0], ast.Tuple) and
            'frame-death-producer-active-consumer' in
                {item.value for item in node.test.comparators[0].elts if isinstance(item, ast.Constant)} and
            any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and
                child.func.attr == 'write' and ast.unparse(child).startswith("os.write(handoff_write, b'U')")
                for statement in node.body for child in ast.walk(statement)))
        prewarm_modes = {item.value for item in prewarm.test.comparators[0].elts
            if isinstance(item, ast.Constant)}
        self.assertEqual(prewarm_modes, self.launcher.FRAME_U2_TRIGGER_MODES)
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            node.func.attr == 'write' and ast.unparse(node).startswith("os.write(handoff_write, b'U')")
            for statement in prewarm.body for node in ast.walk(statement)))
        handoff_write = next(node for node in ast.walk(test_body)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            node.func.attr == 'write' and ast.unparse(node).startswith("os.write(handoff_write, b'H')"))
        self.assertLess(prewarm.lineno, handoff_write.lineno,
            'the original Linux UDP prewarm must precede H for every U2 profile')

    def test_consumer_death_markers_use_the_emitted_pool_schema(self):
        counters = [0, 1, 2, 3, 4]
        prepared = {'tx_before': 0, 'pool_before': 6, 'counters_before': counters}
        preserved = {'tx': 0, 'pool': 7, 'counters': counters}
        cancelled = {'tx': 0, 'pool': 6, 'counters': counters}
        self.assertTrue(PROFILE.frame_prepared_consumer_pool_is_exact(prepared, preserved))
        self.assertTrue(PROFILE.frame_cancelled_consumer_pool_is_exact(prepared, cancelled))
        self.assertFalse(PROFILE.frame_prepared_consumer_pool_is_exact(prepared,
            {'tx': 0, 'packet_pool_in_use': 7, 'counters': counters}))
        self.assertFalse(PROFILE.frame_cancelled_consumer_pool_is_exact(prepared,
            {'tx': 0, 'packet_pool_in_use': 6, 'counters': counters}))
        self.assertFalse(PROFILE.frame_prepared_consumer_pool_is_exact(prepared,
            {'tx': 1, 'pool': 7, 'counters': counters}))

    def test_active_consumer_recovery_compares_the_successor_owner(self):
        old_owner = {'sequence': 7, 'token': 14, 'generation': 0}
        successor = {'sequence': 19, 'token': 38, 'generation': 1, 'slot': 1}
        self.assertTrue(PROFILE.active_consumer_kept_handoff_owner(
            {'final_owner': dict(successor, sequence=20)}, {'resident': successor}))
        self.assertFalse(PROFILE.active_consumer_kept_handoff_owner(
            {'final_owner': old_owner}, {'resident': successor}))
        self.assertFalse(PROFILE.active_consumer_kept_handoff_owner(
            {'final_owner': dict(successor, token=39)}, {'resident': successor}))
        self.assertFalse(PROFILE.active_consumer_kept_handoff_owner(
            {'final_owner': dict(successor, sequence=0)}, {'resident': successor}))

    def test_active_consumer_held_owner_uses_completed_handoff_snapshot(self):
        tree = ast.parse(PROFILE_SOURCE.read_text())
        profile = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and
            node.name == '_run_live_handoff_profile_impl')
        owner_compare = next(node for node in ast.walk(profile)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == 'same_owner_snapshot' and len(node.args) == 2 and
            all(isinstance(arg, ast.Name) for arg in node.args) and
            [arg.id for arg in node.args] == ['held_owner', 'handoff_resident_owner'])
        self.assertIsNotNone(owner_compare)
        assignment = next(node for node in ast.walk(profile) if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == 'handoff_resident_owner'
                for target in node.targets))
        self.assertEqual(ast.unparse(assignment.value), "after['handoff']['resident']")

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

    def test_queued_death_waits_for_fixture_live_actor_ack(self):
        source = ast.parse(SOURCE.read_text())
        handoff = next(node for node in ast.walk(source)
            if isinstance(node, ast.FunctionDef) and node.name == 'perform_test_handoff')
        ack = next(node for node in ast.walk(handoff)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == 'wait_for_frame_death_fixture_ack')
        fill = next(node for node in ast.walk(handoff)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            node.func.attr == 'write' and ast.unparse(node).replace(' ', '').startswith("os.write(control_w,b'F')"))
        kill = next(node for node in ast.walk(handoff)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            node.func.attr == 'pidfd_send_signal' and any(isinstance(arg, ast.Attribute) and
            arg.attr == 'SIGKILL' for arg in node.args))
        self.assertLess(ack.lineno, fill.lineno)
        self.assertLess(fill.lineno, kill.lineno)
        runner_impl = next(node for node in ast.walk(source)
            if isinstance(node, ast.FunctionDef) and node.name == '_run_session_impl')
        handoff_dispatch = next(node for node in ast.walk(runner_impl)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == 'action' and
            isinstance(node.test.comparators[0], ast.Constant) and
            node.test.comparators[0].value == 'handoff')
        close_gate = next(node for node in ast.walk(handoff_dispatch)
            if isinstance(node, ast.If) and isinstance(node.test, ast.BoolOp) and
            any(isinstance(value, ast.Compare) and isinstance(value.left, ast.Name) and
                value.left.id == 'handoff_mode' and
                any(isinstance(item, ast.Constant) and item.value == 'frame-death-queued'
                    for item in value.comparators) for value in node.test.values))
        self.assertTrue(any(isinstance(value, ast.Compare) and isinstance(value.left, ast.Name) and
            value.left.id == 'handoff_mode' and
            any(isinstance(item, ast.Constant) and item.value == 'frame-death-queued'
                for item in value.comparators) for value in close_gate.test.values),
            'queued-death mode must retain the trigger read end while perform_test_handoff waits for A')

        profile_source = ast.parse(PROFILE_SOURCE.read_text())
        profile = next(node for node in ast.walk(profile_source)
            if isinstance(node, ast.FunctionDef) and node.name == '_run_live_handoff_profile_impl')
        close_after_h = next(node for node in ast.walk(profile)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == 'mode' and
            isinstance(node.test.ops[0], ast.NotIn) and
            any(isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and
                call.func.attr == 'close' and ast.unparse(call).startswith('os.close(handoff_write)')
                for statement in node.body for call in ast.walk(statement)))
        kept_open_modes = {item.value for item in close_after_h.test.comparators[0].elts
            if isinstance(item, ast.Constant)}
        self.assertIn('frame-death-queued', kept_open_modes,
            'fixture must retain the acknowledgement pipe until queued producer recovery completes')

        read_fd, write_fd = os.pipe()
        fixture_checked = threading.Event()
        killed = threading.Event()
        failures = []

        def runner_first():
            fixture_checked.set()
            try:
                self.launcher.wait_for_frame_death_fixture_ack(read_fd, timeout=1)
                killed.set()
            except BaseException as error:
                failures.append(error)

        runner = threading.Thread(target=runner_first)
        runner.start()
        self.assertTrue(fixture_checked.wait(1))
        self.assertFalse(killed.is_set(), 'producer death ran before the fixture checked live pidfds')
        self.assertEqual(os.write(write_fd, b'A'), 1)
        runner.join(2)
        self.assertFalse(runner.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(killed.is_set(), 'the runner did not proceed after the fixture acknowledgement')
        os.close(read_fd)
        os.close(write_fd)

        trigger_read, trigger_write = os.pipe()
        self.assertTrue(self.launcher.handoff_trigger_complete('frame-death-queued', True, 0))
        self.assertIsNone(self.launcher.close_completed_handoff_trigger(
            'frame-death-queued', True, 0, trigger_read, os.close))
        with self.assertRaises(OSError):
            os.fstat(trigger_read)
        os.close(trigger_write)

    def test_queued_handoff_closes_trigger_pipe_only_after_recovery_ack(self):
        source = ast.parse(SOURCE.read_text())
        runner_impl = next(node for node in ast.walk(source)
            if isinstance(node, ast.FunctionDef) and node.name == '_run_session_impl')
        dispatch = next(node for node in ast.walk(runner_impl)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == 'action' and
            isinstance(node.test.comparators[0], ast.Constant) and
            node.test.comparators[0].value == 'handoff')
        perform_index = next(index for index, statement in enumerate(dispatch.body)
            if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                node.func.id == 'perform_test_handoff' for node in ast.walk(statement)))
        seen_index = next(index for index, statement in enumerate(dispatch.body)
            if isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id == 'handoff_seen' for target in statement.targets) and
            isinstance(statement.value, ast.Constant) and statement.value.value is True)
        close_index = next(index for index, statement in enumerate(dispatch.body)
            if isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id == 'handoff_fd' for target in statement.targets) and
            any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                node.func.id == 'close_completed_handoff_trigger' for node in ast.walk(statement)))
        self.assertLess(perform_index, seen_index)
        self.assertLess(seen_index, close_index,
            'queued trigger must remain open through perform_test_handoff acknowledgement')

        trigger_read, trigger_write = os.pipe()
        ack_read, ack_write = os.pipe()
        acknowledged = threading.Event()
        failures = []

        def wait_for_ack():
            try:
                self.launcher.wait_for_frame_death_fixture_ack(ack_read, timeout=1)
                acknowledged.set()
            except BaseException as error:
                failures.append(error)

        try:
            self.assertEqual(os.write(trigger_write, b'H'), 1)
            self.assertEqual(self.launcher.handoff_trigger_action(os.read(trigger_read, 1)), 'handoff')
            handoff_seen = False
            waiter = threading.Thread(target=wait_for_ack)
            waiter.start()
            self.assertEqual(select.select([ack_read], [], [], 0)[0], [])
            os.fstat(trigger_read)
            self.assertEqual(os.write(ack_write, b'A'), 1)
            waiter.join(2)
            self.assertFalse(waiter.is_alive())
            self.assertEqual(failures, [])
            self.assertTrue(acknowledged.is_set())

            handoff_seen = True
            trigger_read = self.launcher.close_completed_handoff_trigger(
                'frame-death-queued', handoff_seen, 0, trigger_read, os.close)
            self.assertIsNone(trigger_read)
            os.close(trigger_write)
            trigger_write = -1
            os.close(ack_write)
            ack_write = -1
            os.close(ack_read)
            ack_read = -1
        finally:
            for fd in (trigger_read, trigger_write, ack_read, ack_write):
                if fd is not None and fd >= 0:
                    os.close(fd)

    def test_queued_death_ack_timeout_and_eof_do_not_reach_kill(self):
        for close_writer, timeout in ((False, 0.01), (True, 1)):
            with self.subTest(close_writer=close_writer):
                read_fd, write_fd = os.pipe()
                killed = []
                if close_writer:
                    os.close(write_fd)
                try:
                    with self.assertRaisesRegex(RuntimeError, 'fixture did not acknowledge|fixture closed'):
                        self.launcher.wait_for_frame_death_fixture_ack(read_fd, timeout=timeout)
                        killed.append(True)
                    self.assertEqual(killed, [], 'producer death ran without an acknowledgement')
                finally:
                    os.close(read_fd)
                    if not close_writer:
                        os.close(write_fd)

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
            node.name == '_run_session_impl')
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

    def test_actor_death_evidence_accepts_uncaptured_stderr(self):
        decode = self.launcher.decode_optional_stderr
        self.assertEqual(decode(None), '')
        self.assertEqual(decode(b''), '')
        self.assertEqual(decode(b'actor stderr\n'), 'actor stderr\n')
        tree = ast.parse(SOURCE.read_text())
        runner = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_run_session_impl')
        decoded = [node for node in ast.walk(runner)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == 'decode_optional_stderr']
        self.assertEqual(len(decoded), 4, 'all four actor-death evidence sites must use optional stderr decoding')
        self.assertEqual(sorted(ast.unparse(node.args[0]) for node in decoded),
            ['peer_errors', 'peer_errors', 'producer_errors', 'producer_errors'])
        for call in decoded:
            stream_name = ast.unparse(call.args[0])
            expression = ast.Expression(body=call)
            namespace = {'decode_optional_stderr': decode, stream_name: None}
            self.assertEqual(eval(compile(expression, str(SOURCE), 'eval'), namespace), '',
                f'actual evidence value for {stream_name} must accept inherited stderr')
        inherited_stream_mutant = ast.Expression(body=ast.Attribute(
            value=ast.Name(id='producer_errors', ctx=ast.Load()), attr='decode', ctx=ast.Load()))
        with self.assertRaises(AttributeError):
            eval(compile(ast.fix_missing_locations(inherited_stream_mutant),
                         str(SOURCE), 'eval'), {'producer_errors': None})

    def test_lost_prepare_reply_hook_is_installed_before_resident_spawn(self):
        captured = {}

        def fake_popen(command, **kwargs):
            captured['command'] = command
            captured['environment'] = kwargs['env']
            return 'resident-handle'

        base = {'PATH': '/usr/bin'}
        result = PROFILE.start_handoff_resident(fake_popen, ['ker', 'serve'], base,
                                                'frame-lost-prepare-reply', stdin=object())
        self.assertEqual(result, 'resident-handle')
        self.assertEqual(captured['environment']['KER_SESSION_TEST_FRAME_REPLY_LOST'], '1')
        self.assertEqual(captured['environment']['PATH'], base['PATH'])
        self.assertNotIn('KER_SESSION_TEST_FRAME_REPLY_LOST', base)
        captured.clear()
        PROFILE.start_handoff_resident(fake_popen, ['ker', 'serve'], base, 'frame-positive')
        self.assertNotIn('KER_SESSION_TEST_FRAME_REPLY_LOST', captured['environment'])

    def test_frame_death_cleanup_outcomes_are_exhaustive_and_include_writing(self):
        expected = {
            'frame-death-prepared': (-signal.SIGKILL, 0),
            'frame-death-queued': (-signal.SIGKILL, 0),
            'frame-death-producer-active-consumer': (-signal.SIGKILL, 0),
            'frame-death-consumer-prepared': (125, -signal.SIGKILL),
            'frame-death-consumer-writing': (125, -signal.SIGKILL),
            'frame-death-both-prepared': (-signal.SIGKILL, -signal.SIGKILL),
            'frame-lost-prepare-reply': (-signal.SIGKILL, 0),
            'frame-positive': (0, 0),
            'frame-full': (0, 0),
        }
        for mode, outcomes in expected.items():
            with self.subTest(mode=mode):
                self.assertEqual(PROFILE.frame_profile_expected_exit_codes(mode), outcomes)
        for mode in ('frame-death-consumer-prepared', 'frame-death-consumer-writing',
                     'frame-death-both-prepared'):
            self.assertTrue(self.launcher.frame_consumer_death_was_expected(mode), mode)
        for mode in ('frame-death-prepared', 'frame-death-queued',
                     'frame-death-producer-active-consumer', 'frame-positive', 'frame-full'):
            self.assertFalse(self.launcher.frame_consumer_death_was_expected(mode), mode)

    def test_consumer_death_exit_requires_cancel_marker_and_exact_125(self):
        validate = self.launcher.require_frame_consumer_death_worker_exit
        cancelled = {'status': -errno.ESTALE}
        for mode in ('frame-death-consumer-prepared', 'frame-death-consumer-writing'):
            with self.subTest(mode=mode):
                self.assertEqual(validate(mode, 125, cancelled), 125)
                for status in (0, 1, -signal.SIGKILL):
                    with self.subTest(status=status), self.assertRaises(RuntimeError):
                        validate(mode, status, cancelled)
                with self.assertRaises(RuntimeError):
                    validate(mode, 125, {'status': 0})
        with self.assertRaises(ValueError):
            validate('frame-death-prepared', 125, cancelled)

        tree = ast.parse(SOURCE.read_text())
        runner = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_run_session_impl')
        cancel_lines = [node.lineno for node in ast.walk(runner)
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and
            isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'cancelled' and
            any(isinstance(arg, ast.Constant) and
                arg.value == 'KER_SESSION_FRAME_CONSUMER_DEATH_CANCELLED'
                for arg in node.value.args)]
        check_lines = [node.lineno for node in ast.walk(runner)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == 'require_frame_consumer_death_worker_exit']
        communicate_lines = [node.lineno for node in ast.walk(runner)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            node.func.attr == 'communicate' and isinstance(node.func.value, ast.Name) and
            node.func.value.id == 'worker']
        self.assertEqual(len(cancel_lines), 2)
        self.assertEqual(len(check_lines), 2)
        for cancel_line, check_line in zip(sorted(cancel_lines), sorted(check_lines)):
            self.assertLess(cancel_line, check_line,
                'exact stale-consumer cancellation must be observed before accepting producer status')
            self.assertTrue(any(cancel_line < line < check_line for line in communicate_lines),
                'producer exit status must be collected after cancellation and before validation')

    def test_frame_peer_control_stays_open_until_final_quiescence(self):
        read_fd, write_fd = os.pipe()
        closed = []

        def close(fd):
            closed.append(fd)
            os.close(fd)

        try:
            keep = self.launcher.close_peer_control_when_safe('frame-positive', write_fd, close)
            self.assertEqual(keep, write_fd)
            self.assertEqual(select.select([read_fd], [], [], 0)[0], [])
            self.assertEqual(os.write(keep, b'G'), 1)
            self.assertEqual(os.read(read_fd, 1), b'G')
            self.assertEqual(select.select([read_fd], [], [], 0)[0], [])
            keep = self.launcher.close_peer_control_when_safe(
                'frame-positive', keep, close, frame_quiescent=True)
            self.assertEqual(keep, -1)
            self.assertEqual(closed, [write_fd])
            self.assertEqual(os.read(read_fd, 1), b'')
            positive_read, positive_write = os.pipe()
            keep = self.launcher.close_peer_control_when_safe('positive', positive_write, close)
            self.assertEqual(keep, -1)
            self.assertEqual(closed, [write_fd, positive_write])
            self.assertEqual(os.read(positive_read, 1), b'')
            os.close(positive_read)
        finally:
            os.close(read_fd)
            if not closed:
                os.close(write_fd)

        tree = ast.parse(SOURCE.read_text())
        run_session_wrapper = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == 'run_session')
        run_session = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_run_session_impl')
        self.assertTrue(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == '_run_session_impl' for node in ast.walk(run_session_wrapper)))
        calls = [node for node in ast.walk(run_session)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == 'close_peer_control_when_safe']
        self.assertEqual(len(calls), 2)
        calls.sort(key=lambda node: node.lineno)
        worker_waits = [node for node in ast.walk(run_session)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and
            node.func.attr == 'communicate' and isinstance(node.func.value, ast.Name) and
            node.func.value.id == 'worker']
        self.assertTrue(any(calls[0].lineno < node.lineno < calls[1].lineno for node in worker_waits))
        quiescent_lines = [node.lineno for node in ast.walk(run_session)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'ready' and
            node.args and isinstance(node.args[0], ast.Constant) and
            node.args[0].value == 'KER_SESSION_FRAME_QUIESCENT']
        self.assertTrue(quiescent_lines and calls[1].lineno > quiescent_lines[0])
        self.assertTrue(any(keyword.arg == 'frame_quiescent' and
            isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in calls[1].keywords))

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

    def test_frame_positive_uses_success_classification_not_fatal_branch(self):
        tree = ast.parse(PROFILE_SOURCE.read_text())
        wanted = {'_is_fatal_handoff_profile', 'FATAL_HANDOFF_PROFILES',
            'NONFATAL_HANDOFF_PROFILES'}
        definitions = [node for node in tree.body if
            (isinstance(node, ast.FunctionDef) and node.name in wanted) or
            (isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id in wanted for target in node.targets))]
        namespace = {}
        exec(compile(ast.Module(body=definitions, type_ignores=[]), str(PROFILE_SOURCE), 'exec'), namespace)
        profile = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_run_live_handoff_profile_impl')
        fatal_branch = next(node for node in ast.walk(profile)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Call) and
            isinstance(node.test.func, ast.Name) and node.test.func.id == '_is_fatal_handoff_profile')
        self.assertEqual([ast.dump(arg) for arg in fatal_branch.test.args],
            [ast.dump(ast.Name(id='mode', ctx=ast.Load()))])
        classify = namespace['_is_fatal_handoff_profile']
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        inventory = set()
        for node in ast.walk(main):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
                    node.func.id == 'run_live_handoff_profile':
                keyword = next((item for item in node.keywords if item.arg == 'mode'), None)
                inventory.add(ast.literal_eval(keyword.value) if keyword is not None else 'positive')
            if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == 'mode' and \
                    isinstance(node.iter, (ast.Tuple, ast.List)):
                inventory.update(ast.literal_eval(item) for item in node.iter.elts)
        fatal = namespace['FATAL_HANDOFF_PROFILES']
        nonfatal = namespace['NONFATAL_HANDOFF_PROFILES']
        self.assertEqual(fatal & nonfatal, set())
        self.assertEqual(inventory, fatal | nonfatal)
        for mode in sorted((item for item in inventory if item in fatal), key=str):
            with self.subTest(mode=mode):
                self.assertTrue(classify(mode))
        for mode in sorted((item for item in inventory if item in nonfatal), key=str):
            with self.subTest(mode=mode):
                self.assertFalse(classify(mode))
        hup_branch = next(node for node in ast.walk(profile)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == 'mode' and
            any(isinstance(item, ast.Constant) and item.value == 'handoff-control-hup'
                for item in node.test.comparators) and
            any(isinstance(child, ast.Return) for child in ast.walk(node)))
        rejection_branch = next(node for node in ast.walk(profile)
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare) and
            isinstance(node.test.left, ast.Name) and node.test.left.id == 'mode' and
            isinstance(node.test.ops[0], ast.In) and
            isinstance(node.test.comparators[0], (ast.Tuple, ast.List)) and
            {'prepare-enoent','prepare-ebusy','prepare-eperm'} <=
                {item.value for item in node.test.comparators[0].elts if isinstance(item, ast.Constant)} and
            any(isinstance(child, ast.Return) for child in ast.walk(node)))
        self.assertLess(hup_branch.lineno, fatal_branch.lineno)
        self.assertLess(rejection_branch.lineno, fatal_branch.lineno)
        self.assertTrue(any(isinstance(node, (ast.Return, ast.Raise)) for node in ast.walk(hup_branch)))
        self.assertTrue(any(isinstance(node, ast.Return) for node in ast.walk(rejection_branch)))
        with self.assertRaisesRegex(ValueError, 'unknown handoff profile'):
            classify('unexpected-mode')

    def test_timed_out_runner_capture_is_bounded_and_does_not_kill_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid_path = os.path.join(directory, 'child.pid')
            child_code = 'import time; time.sleep(30)'
            parent_code = ('import subprocess,sys,time; child=subprocess.Popen([sys.executable,"-c",' +
                repr(child_code) + ']); open(' + repr(child_pid_path) + ',"w").write(str(child.pid)); '
                'print("ready",flush=True); time.sleep(30)')
            runner = subprocess.Popen([sys.executable, '-c', parent_code], stdout=subprocess.PIPE)
            descendant_pidfd = -1
            try:
                deadline = time.monotonic() + 5
                while not os.path.exists(child_pid_path) and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertTrue(os.path.exists(child_pid_path))
                descendant_pid = int(Path(child_pid_path).read_text())
                descendant_pidfd = os.pidfd_open(descendant_pid)
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    runner.communicate(timeout=0.05)
                output = PROFILE._stop_timed_out_runner(runner, caught.exception)
                self.assertIn(b'ready', output)
                self.assertIsNotNone(runner.returncode)
                self.assertTrue(runner.stdout.closed)
                self.assertEqual(PROFILE._collect_profile_cleanup_output('launcher', runner),
                    (output, b''))
                self.assertFalse(select.select([descendant_pidfd], [], [], 0)[0],
                    'bounded runner capture must not signal an unrelated descendant')
            finally:
                if runner.poll() is None:
                    runner.kill(); runner.wait(timeout=5)
                if descendant_pidfd >= 0:
                    try: signal.pidfd_send_signal(descendant_pidfd, signal.SIGKILL)
                    except ProcessLookupError: pass
                    self.assertTrue(select.select([descendant_pidfd], [], [], 5)[0],
                        'test-owned descendant did not exit after exact pidfd cleanup')
                    os.close(descendant_pidfd)

    def test_frame_failure_record_accepts_redirected_optional_stderr(self):
        tree = ast.parse(PROFILE_SOURCE.read_text())
        decoder = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_decode_captured_pipe_output')
        profile = next(node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == '_run_live_handoff_profile_impl')
        record_assignment = next(node for node in ast.walk(profile)
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id == 'failure_record' for target in node.targets) and
            any(isinstance(child, ast.Constant) and child.value == 'handoff_frame'
                for child in ast.walk(node)))
        full_record_assignment = next(node for node in ast.walk(profile)
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
                target.id == 'failure_record' for target in node.targets) and
            any(isinstance(child, ast.keyword) and child.arg == 'wire_seq1_frames'
                for child in ast.walk(node)))
        full_failure_branch = next(node for node in ast.walk(profile)
            if isinstance(node, ast.If) and any(isinstance(child, ast.Constant) and
                isinstance(child.value, str) and child.value.startswith('KER_SESSION_FRAME_FULL_FAILURE')
                for child in ast.walk(node)))
        startup_scope = next(node for node in profile.body if isinstance(node, ast.With) and
            any(isinstance(item.context_expr, ast.Call) and
                isinstance(item.context_expr.func, ast.Attribute) and item.context_expr.func.attr ==
                'TemporaryDirectory' for item in node.items))
        initial_try = next(index for index, node in enumerate(startup_scope.body)
            if isinstance(node, ast.Try))
        initialized = set()
        for statement in startup_scope.body[:initial_try]:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    initialized.update(child.id for child in ast.walk(target) if isinstance(child, ast.Name))
        self.assertTrue({'wire_stop', 'wire_frames', 'wire_errors', 'wire_lock', 'wire_thread',
            'runner_stderr_path'} <= initialized)
        helper_namespace = {}
        exec(compile(ast.Module(body=[decoder], type_ignores=[]), str(PROFILE_SOURCE), 'exec'),
            helper_namespace)
        with tempfile.TemporaryDirectory() as directory:
            runner_stderr_path = Path(directory) / 'runner.stderr'
            runner_stderr_path.write_text('raw runner stderr\n')
            for context in (None, {'checks': {'same_u2': False}, 'stats_stage': 'interrupted',
                    'proof': {'committed_records': [{'object_index': 4}]},
                    'u2_commits': [], 'u2_releases': [],
                    'wire_observation': {'seq1_count': 1, 'seq2_count': 0},
                    'first_wire_frame': 'abcd'}):
                with self.subTest(context=context):
                    values = dict(json=json, _decode_captured_pipe_output=
                        helper_namespace['_decode_captured_pipe_output'],
                        original_error=RuntimeError('original oracle failure'),
                        failure_stats={'handoff_frame': {'tx_count': 0}},
                        raw_runner_stderr='raw runner stderr\n',
                        runner_stderr_path=runner_stderr_path,
                        runner=types.SimpleNamespace(returncode=143),
                        primary=types.SimpleNamespace(returncode=0),
                        runner_out=None, runner_err=None, resident_out=b'resident output\n',
                        resident_err=None, failure_context=context)
                    isolated = ast.Module(body=[record_assignment], type_ignores=[])
                    exec(compile(ast.fix_missing_locations(isolated), str(PROFILE_SOURCE), 'exec'),
                        values)
                    record = values['failure_record']
                    self.assertEqual(record['reason'], 'original oracle failure')
                    self.assertEqual(record['runner_stdout'], '')
                    self.assertEqual(record['runner_stderr_pipe'], '')
                    self.assertEqual(record['resident_stderr'], '')
                    self.assertEqual(record['runner_stderr'], 'raw runner stderr\n')
                    self.assertEqual(record['runner_returncode'], 143)
                    self.assertEqual(record['resident_returncode'], 0)
                    self.assertEqual(record['handoff_frame'], {'tx_count': 0})
                    self.assertEqual(record['checks'], None if context is None else context['checks'])
                    self.assertEqual(record['u2_commits'], None if context is None else context['u2_commits'])
            full_values = dict(
                mode='frame-full', frame_full_stage='wait-seq2-ack',
                original_error=RuntimeError('bounded seq2 acknowledgement timeout'),
                failure_stats={'stage': 'handoff-complete', 'frame_full_capacity': 64},
                wire_lock=threading.Lock(), wire_frames=[], wire_errors=['no frame peer error'],
                failure_wire_frames=[], failure_wire_errors=['no frame peer error'],
                runner=types.SimpleNamespace(returncode=-15),
                primary=types.SimpleNamespace(returncode=0),
                runner_out=None, runner_err=None, resident_out=None, resident_err=None,
                runner_stderr_path=runner_stderr_path,
                raw_runner_stderr='raw runner stderr\n',
                _decode_captured_pipe_output=helper_namespace['_decode_captured_pipe_output'])
            exec(compile(ast.fix_missing_locations(ast.Module(body=[full_record_assignment],
                type_ignores=[])), str(PROFILE_SOURCE), 'exec'), full_values)
            full_record = full_values['failure_record']
            self.assertEqual(full_record['mode'], 'frame-full')
            self.assertEqual(full_record['stage'], 'wait-seq2-ack')
            self.assertEqual(full_record['runner_stderr_pipe'], '')
            self.assertEqual(full_record['resident_stderr'], '')
            self.assertEqual(full_record['wire_errors'], ['no frame peer error'])

            emitted = []
            runner_stderr_path.write_text('early stderr\n')
            early_values = dict(json=json, mode='frame-full', frame_full_stage='before-resident-ready',
                original_error=RuntimeError('early setup failure'),
                failure_stats=None, stats_path=Path(directory) / 'not-created-stats.json',
                cleanup_outputs={'launcher': (None, None), 'resident': (None, None)},
                runner_out=None, runner_err=None, resident_out=None, resident_err=None,
                wire_lock=threading.Lock(), wire_frames=[], wire_errors=[],
                runner=types.SimpleNamespace(returncode=1), primary=None,
                runner_stderr_path=runner_stderr_path, raw_runner_stderr='early stderr\n',
                _decode_captured_pipe_output=helper_namespace['_decode_captured_pipe_output'],
                print=lambda value, **_kwargs: emitted.append(value))
            exec(compile(ast.fix_missing_locations(ast.Module(body=[full_failure_branch],
                type_ignores=[])), str(PROFILE_SOURCE), 'exec'), early_values)
            self.assertEqual(len(emitted), 1)
            early_record = json.loads(emitted[0].split(' ', 1)[1])
            self.assertEqual(early_record['stage'], 'before-resident-ready')
            self.assertEqual(early_record['runner_stderr'], 'early stderr\n')
            self.assertEqual(early_record['wire_frame_count'], 0)

    def test_record_uses_deadline_for_empty_partial_valid_and_wrong_prefix_pipes(self):
        tree = ast.parse(PROFILE_SOURCE.read_text())
        names = {'read_bounded_line', 'read_bounded_stderr', 'line', 'record'}
        functions = [node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in functions}, names)
        namespace = {'os': os, 'select': select, 'time': time, 'Path': Path,
            'json': json, '_active_handoff_evidence': None,
            'require': lambda value, message: None if value else (_ for _ in ()).throw(RuntimeError(message))}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(PROFILE_SOURCE), 'exec'), namespace)

        def run(source):
            return subprocess.Popen([os.sys.executable, '-c', source], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0)

        empty = run('pass')
        try:
            with self.assertRaisesRegex(RuntimeError, 'exited early'):
                namespace['record'](empty, 'EXPECTED', timeout=1)
            empty.communicate(timeout=1)
        finally:
            if empty.poll() is None:
                empty.kill(); empty.wait()

        held_stderr = run('import os,time;os.close(1);time.sleep(2)')
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, 'exited early'):
                namespace['record'](held_stderr, 'EXPECTED', timeout=1)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            if held_stderr.poll() is None:
                held_stderr.kill()
            held_stderr.communicate(timeout=1)

        partial = run("import sys,time;sys.stdout.buffer.write(b'EXPECTED {');sys.stdout.flush();time.sleep(2)")
        try:
            with self.assertRaisesRegex(RuntimeError, 'timed out before a complete line'):
                namespace['record'](partial, 'EXPECTED', timeout=0.05)
        finally:
            if partial.poll() is None:
                partial.kill()
            partial.communicate(timeout=1)

        partial_eof = run("import sys;sys.stdout.buffer.write(b'EXPECTED {\\\"ok\\\":true}')")
        try:
            with self.assertRaisesRegex(RuntimeError, 'ended before a complete line'):
                namespace['record'](partial_eof, 'EXPECTED', timeout=1)
            partial_eof.communicate(timeout=1)
        finally:
            if partial_eof.poll() is None:
                partial_eof.kill(); partial_eof.wait()

        valid = run("import sys;sys.stdout.buffer.write(b'EXPECTED {\\\"ok\\\":true}\\n');sys.stdout.flush()")
        try:
            self.assertEqual(namespace['record'](valid, 'EXPECTED', timeout=1), {'ok': True})
            valid.communicate(timeout=1)
        finally:
            if valid.poll() is None:
                valid.kill(); valid.wait()

        wrong = run("import sys;sys.stdout.buffer.write(b'OTHER {\\\"ok\\\":true}\\n');sys.stdout.flush()")
        try:
            with self.assertRaisesRegex(RuntimeError, 'unexpected output'):
                namespace['record'](wrong, 'EXPECTED', timeout=1)
            wrong.communicate(timeout=1)
        finally:
            if wrong.poll() is None:
                wrong.kill(); wrong.wait()

    def test_frame_commit_release_bijection_binds_exact_lease_and_u2_bytes(self):
        payload=b'KER-A09-HANDOFF-UDP seq=2\n'
        ip=bytearray(20);ip[0]=0x45;ip[2:4]=(20+8+len(payload)).to_bytes(2,'big')
        ip[8]=64;ip[9]=17;ip[12:16]=bytes((198,18,0,2));ip[16:20]=bytes((198,18,0,1))
        checksum_sum=sum((ip[i]<<8)|ip[i+1] for i in range(0,len(ip),2))
        while checksum_sum>>16:checksum_sum=(checksum_sum&0xffff)+(checksum_sum>>16)
        ip[10:12]=((~checksum_sum)&0xffff).to_bytes(2,'big')
        udp=bytes.fromhex('afc8afc9')+(8+len(payload)).to_bytes(2,'big')+b'\0\0'
        frame=bytes.fromhex('024b45520001024b455200020800')+bytes(ip)+udp+payload
        commit=dict(port=0,queue=0,generation=0,length=len(frame),object_index=7,
            pool_tag=91,tx_lease_id=123,packet_pointer='0xabc',frame_hex=frame.hex())
        release=dict(sequence=0,consumer_generation=1,object_index=7,lease_id=123,
            pool_tag=91,packet_pointer='0xabc',length=len(frame),frame_hex=frame.hex())
        result=self.launcher.validate_frame_commit_drain_bijection([commit],[release],payload)
        self.assertEqual(result['committed'],1);self.assertEqual(result['drained'],1)
        for bad in ({**release,'lease_id':124},{**release,'packet_pointer':'0xabd'},
                    {**release,'sequence':2},{**release,'frame_hex':(frame+b'!').hex()}):
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

    def test_unexpected_exited_worker_record_preserves_available_stdout_and_proof(self):
        process = subprocess.Popen([sys.executable, '-c',
            "import sys; print('KER_SESSION_PARKED_OWNER_EXIT {\\\"result\\\":-32}', flush=True); sys.exit(125)"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        try:
            self.assertEqual(process.wait(timeout=2), 125)
            output = self.launcher.capture_exited_process_stdout(process)
            committed = [{'object_index': 7, 'packet_pointer': '0xabc'}]
            drained = [{'object_index': 7, 'packet_pointer': '0xabc'}]
            handoff = {'same_pointer': True, 'same_bytes': True}
            record = self.launcher.unexpected_worker_exit_record(
                process, output, committed, drained, handoff)
            self.assertEqual(record['returncode'], 125)
            self.assertIn('KER_SESSION_PARKED_OWNER_EXIT', record['stdout'])
            self.assertIn('"result":-32', record['stdout'])
            self.assertEqual(record['frame_committed_records'], committed)
            self.assertEqual(record['frame_drained_records'], drained)
            self.assertEqual(record['handoff_frame'], handoff)
        finally:
            if process.stdout is not None:
                process.stdout.close()

    def test_proc_fd_eacces_remains_fatal_with_non_tun_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = root / '12345'
            fd_path = process / 'fd' / '17'
            fdinfo_path = process / 'fdinfo' / '17'
            fd_path.parent.mkdir(parents=True)
            fdinfo_path.parent.mkdir(parents=True)
            fd_path.symlink_to('/dev/null')
            fdinfo_path.write_text('pos:\t0\nflags:\t02000002\nmnt_id:\t39\nino:\t1292\n')
            (process / 'status').write_text(
                'Name:\tker-worker\nState:\tS (sleeping)\nPid:\t12345\n'
                'Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n'
                'TracerPid:\t0\nEnv:\tDO_NOT_LOG\n')
            original = PermissionError(errno.EACCES, 'Permission denied', str(fd_path))
            real_stat = os.stat

            def denied_fd_stat(path, *args, **kwargs):
                if Path(path) == fd_path:
                    raise original
                return real_stat(path, *args, **kwargs)

            stderr = io.StringIO()
            with mock.patch('os.stat', denied_fd_stat), \
                    contextlib.redirect_stderr(stderr):
                # Exercise the real 3.14 predicate: it suppresses this mocked
                # stat EACCES and returns False, so production must call stat.
                if sys.version_info >= (3, 14):
                    self.assertFalse(fd_path.exists())
                with self.assertRaises(PermissionError) as caught:
                    self.launcher.old_endpoint_fd_path_exists(12345, 17,
                        expected_interface='kex12345678', expected_ifindex=9, owner_key=9,
                        old_tun_interfaces=[], pidfd=None, proc_root=root)
            self.assertIs(caught.exception, original)
            self.assertEqual(caught.exception.errno, errno.EACCES)
            line = next(line for line in stderr.getvalue().splitlines()
                if line.startswith('KER_SESSION_OLD_ENDPOINT_FD_STAT_FAILURE '))
            record = json.loads(line.split(' ', 1)[1])
            self.assertEqual(record['failure']['errno'], errno.EACCES)
            self.assertEqual(record['pre_stat_tun_census']['names'], [])
            self.assertNotIn('iff', record['fdinfo']['fields'])
            self.assertEqual(record['fdlink']['kind'], 'device-path')
            self.assertNotIn('/dev/null', line)
            self.assertNotIn('DO_NOT_LOG', line)
            self.assertEqual(record['process_status']['fields']['TracerPid'], '0')

    def test_proc_fd_diagnostic_read_failure_does_not_mask_original_eacces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = root / '12345'
            fd_path = process / 'fd' / '17'
            fdinfo_path = process / 'fdinfo' / '17'
            fd_path.parent.mkdir(parents=True)
            fdinfo_path.parent.mkdir(parents=True)
            fd_path.symlink_to('socket:[98765]')
            fdinfo_path.write_text('iff:\tkex12345678\n')
            (process / 'status').write_text('State:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\n')
            original = PermissionError(errno.EACCES, 'Permission denied', str(fd_path))
            real_stat = os.stat
            real_open = Path.open

            def denied_fd_stat(path, *args, **kwargs):
                if Path(path) == fd_path:
                    raise original
                return real_stat(path, *args, **kwargs)

            def failed_fdinfo_open(path, *args, **kwargs):
                if path == fdinfo_path:
                    raise OSError(errno.EIO, 'diagnostic read unavailable')
                return real_open(path, *args, **kwargs)

            stderr = io.StringIO()
            with mock.patch('os.stat', denied_fd_stat), \
                    mock.patch.object(Path, 'open', failed_fdinfo_open), \
                    contextlib.redirect_stderr(stderr):
                with self.assertRaises(PermissionError) as caught:
                    self.launcher.old_endpoint_fd_path_exists(12345, 17,
                        expected_interface='kex12345678', expected_ifindex=9, owner_key=9,
                        old_tun_interfaces=['kex12345678'], pidfd=None, proc_root=root)
            self.assertIs(caught.exception, original)
            self.assertEqual(caught.exception.errno, errno.EACCES)
            line = next(line for line in stderr.getvalue().splitlines()
                if line.startswith('KER_SESSION_OLD_ENDPOINT_FD_STAT_FAILURE '))
            record = json.loads(line.split(' ', 1)[1])
            self.assertEqual(record['fdinfo']['error']['errno'], errno.EIO)
            self.assertEqual(record['failure']['errno'], errno.EACCES)

    def test_proc_fd_non_enoent_stat_errors_are_not_treated_as_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = root / '12345'
            fd_path = process / 'fd' / '17'
            fd_path.parent.mkdir(parents=True)
            fd_path.symlink_to('/dev/null')
            real_stat = os.stat
            failures = (errno.EACCES, errno.EBADF, errno.ENOTDIR, errno.EIO, errno.EPERM)
            for error_number in failures:
                with self.subTest(errno=error_number):
                    original = OSError(error_number, 'injected proc fd stat error', str(fd_path))

                    def failed_fd_stat(path, *args, **kwargs):
                        if Path(path) == fd_path:
                            raise original
                        return real_stat(path, *args, **kwargs)

                    stderr = io.StringIO()
                    with mock.patch('os.stat', failed_fd_stat), \
                            contextlib.redirect_stderr(stderr):
                        if error_number == errno.EACCES and sys.version_info >= (3, 14):
                            self.assertFalse(fd_path.exists())
                        with self.assertRaises(OSError) as caught:
                            self.launcher.old_endpoint_fd_path_exists(12345, 17,
                                expected_interface='kex12345678', expected_ifindex=9, owner_key=9,
                                old_tun_interfaces=[], pidfd=None, proc_root=root)
                    self.assertIs(caught.exception, original)
                    self.assertEqual(caught.exception.errno, error_number)
                    line = next(line for line in stderr.getvalue().splitlines()
                        if line.startswith('KER_SESSION_OLD_ENDPOINT_FD_STAT_FAILURE '))
                    record = json.loads(line.split(' ', 1)[1])
                    self.assertEqual(record['failure']['errno'], error_number)

    def test_proc_fd_missing_slot_still_reports_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertFalse(self.launcher.old_endpoint_fd_path_exists(12345, 17,
                expected_interface='kex12345678', expected_ifindex=9, owner_key=9,
                old_tun_interfaces=[], pidfd=None, proc_root=Path(temporary)))

    def test_proc_fd_existing_slot_is_not_reported_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Path(temporary) / '12345'
            (process / 'fd').mkdir(parents=True)
            (process / 'fd' / '17').symlink_to('/dev/null')
            self.assertTrue(self.launcher.old_endpoint_fd_path_exists(12345, 17,
                expected_interface='kex12345678', expected_ifindex=9, owner_key=9,
                old_tun_interfaces=[], pidfd=None, proc_root=Path(temporary)))

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
