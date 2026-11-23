#!/usr/bin/env python3
"""Test frame-full-only traceback timer lifetime; no runtime or EAL claim."""
import importlib.util
from pathlib import Path
import sys
from unittest import mock
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests' / 'posix'))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIXTURE = load('session_native_packets_trace_scope', ROOT / 'tests/posix/session-native-packets.py')
RUNNER = load('ker_session_run_trace_scope', ROOT / 'tools/ker_session_run.py')


class FrameFullTracebackScopeTests(unittest.TestCase):
    def assert_scope(self, module, exception=False):
        calls = []
        with mock.patch.object(module.faulthandler, 'dump_traceback_later',
                side_effect=lambda *args, **kwargs: calls.append(('arm', args, kwargs))), \
             mock.patch.object(module.faulthandler, 'cancel_dump_traceback_later',
                side_effect=lambda: calls.append(('cancel',))):
            if exception:
                with self.assertRaisesRegex(RuntimeError, 'injected'):
                    with module._frame_full_traceback_scope(True,
                            'TRACE_TEST_BEGIN') if module is FIXTURE else \
                            module._frame_full_traceback_scope(True):
                        raise RuntimeError('injected')
            else:
                with module._frame_full_traceback_scope(True,
                        'TRACE_TEST_BEGIN') if module is FIXTURE else \
                        module._frame_full_traceback_scope(True):
                    pass
            self.assertEqual([call[0] for call in calls], ['arm', 'cancel'])
            self.assertEqual(calls[0][1][0], 45)
            self.assertIs(calls[0][2]['repeat'], False)

    def test_fixture_scope_cancels_after_success_and_exception(self):
        self.assert_scope(FIXTURE)
        self.assert_scope(FIXTURE, exception=True)

    def test_runner_scope_cancels_after_success_and_exception(self):
        self.assert_scope(RUNNER)
        self.assert_scope(RUNNER, exception=True)

    def test_non_full_profile_does_not_touch_existing_timer(self):
        for module, scope in ((FIXTURE,
                lambda enabled: FIXTURE._frame_full_traceback_scope(enabled, 'TRACE_TEST_BEGIN')),
                (RUNNER, RUNNER._frame_full_traceback_scope)):
            calls = []
            with mock.patch.object(module.faulthandler, 'dump_traceback_later',
                    side_effect=lambda *args, **kwargs: calls.append('arm')), \
                 mock.patch.object(module.faulthandler, 'cancel_dump_traceback_later',
                    side_effect=lambda: calls.append('cancel')):
                with scope(False):
                    pass
            self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
