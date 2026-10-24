#!/usr/bin/env python3
"""Exercise the checked-in nested handoff control path with real pipes only.

This deliberately stops at the first worker-marker wait. It proves launcher
control writes/closure, not EAL, packet, or native handoff behavior.
"""
import os
from pathlib import Path
import types
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

    @staticmethod
    def poll():
        return None


class HandoffControlPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        module = compile(SOURCE.read_text(), str(SOURCE), 'exec')
        cls.function_code = nested_code(module, 'perform_test_handoff')
        if cls.function_code is None:
            raise RuntimeError('could not locate actual perform_test_handoff code object')

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

    def test_positive_handoff_writes_one_h(self):
        self.exercise('positive', b'H', expect_closed=False)

    def test_rejected_handoffs_pipeline_two_h_commands(self):
        self.exercise('prepare-enoent', b'HH', expect_closed=False)

    def test_control_hup_closes_writer_after_h(self):
        self.exercise('handoff-control-hup', b'H', expect_closed=True)


if __name__ == '__main__':
    unittest.main()
