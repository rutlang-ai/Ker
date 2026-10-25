#!/usr/bin/env python3
"""Check non-FRAME reap pool accounting and the runner's retained-ring drain."""
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import unittest
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / 'tests' / 'posix'
FIXTURE = FIXTURE_DIR / 'session-native-packets.py'
IO_SESSION = ROOT / 'src' / 'posix' / 'io-session.c'
RUNNER = ROOT / 'tools' / 'ker_session_run.py'
GENERATION_RINGS = IO_SESSION
sys.path.insert(0, str(FIXTURE_DIR))
spec = importlib.util.spec_from_file_location('session_native_packets_pool_oracle', FIXTURE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


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


class NonframePoolOracleTests(unittest.TestCase):
    def test_packet_loop_k_dispatch_orders_join_before_drain(self):
        source = GENERATION_RINGS.read_text()
        start = source.index('static int generation_test_nonframe_drain_dispatch(')
        brace = source.index('{', start)
        depth = 0
        end = None
        for offset in range(brace, len(source)):
            if source[offset] == '{':
                depth += 1
            elif source[offset] == '}':
                depth -= 1
                if depth == 0:
                    end = offset + 1
                    break
        self.assertIsNotNone(end)
        dispatch = source[start:end]
        callback_start = source.index('static int generation_frame_drain_control(')
        callback = source[callback_start:source.index('\n}\n#endif', callback_start)]
        self.assertIn("if(command=='K')return generation_test_nonframe_drain_dispatch", callback)
        self.assertIn('generation_test_nonframe_join_context,generation_test_nonframe_drain_context,context', callback)
        self.assertIn('generation_test_join_nonframe_hold(context->rings,&context->identity)', source)
        self.assertIn('return generation_test_nonframe_drain(opaque);', source)

        harness = r'''#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifndef EUCLEAN
#define EUCLEAN 117
#endif
static char tracebuf[8]; static unsigned tracepos; static int join_status;
static int join_hold(void *p) { if (!p) return -EINVAL; tracebuf[tracepos++]='J'; return join_status; }
static int drain(void *p) { if (!p) return -EINVAL; tracebuf[tracepos++]='D'; return 1; }
'''+dispatch+r'''
int main(void) {
 int context=1;
 int ok=generation_test_nonframe_drain_dispatch('K',true,true,true,join_hold,drain,&context);
 if(ok!=1 || strcmp(tracebuf,"JD")) return 1;
 tracepos=0; tracebuf[0]=0;
 if(generation_test_nonframe_drain_dispatch('K',true,false,true,join_hold,drain,&context)!=-EUCLEAN || tracepos) return 7;
 if(generation_test_nonframe_drain_dispatch('K',true,true,false,join_hold,drain,&context)!=-EUCLEAN || tracepos) return 2;
 if(generation_test_nonframe_drain_dispatch('H',true,true,true,join_hold,drain,&context)!=0 || tracepos) return 3;
 if(generation_test_nonframe_drain_dispatch('?',true,true,true,join_hold,drain,&context)!=0 || tracepos) return 4;
 if(generation_test_nonframe_drain_dispatch('K',false,true,true,join_hold,drain,&context)!=0 || tracepos) return 5;
 join_status=-EBUSY;
 if(generation_test_nonframe_drain_dispatch('K',true,true,true,join_hold,drain,&context)!=-EBUSY ||
    tracepos!=1 || tracebuf[0]!='J') return 6;
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='ker-nonframe-dispatch-') as directory:
            source_path = Path(directory) / 'dispatch.c'
            executable = Path(directory) / 'dispatch'
            source_path.write_text(harness)
            compiled = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                       str(source_path), '-o', str(executable)],
                                      capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_runner_executes_actual_retained_drain_marker_reader(self):
        runner_code = compile(RUNNER.read_text(), str(RUNNER), 'exec')
        drain_code = nested_code(runner_code, 'drain_nonframe_retained_packets')
        self.assertIsNotNone(drain_code)
        read_fd, write_fd = os.pipe()
        worker = types.SimpleNamespace(poll=lambda: None)
        marker = {'generation': 0, 'status': 0, 'rx_drained': 1, 'tx_drained': 2}
        waits = []

        def wait_marker(process, prefix):
            waits.append((process, prefix))
            return marker

        values = {'control_w': write_fd, 'handoff_mode': 'nonframe-active-reap',
                  'wait_marker': wait_marker, 'worker': worker}
        drain = types.FunctionType(drain_code,
            {'os': os, 'RuntimeError': RuntimeError, 'json': json},
            'drain_nonframe_retained_packets',
            closure=tuple(cell(values[name]) for name in drain_code.co_freevars))
        try:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                result = drain()
            self.assertEqual(os.read(read_fd, 1), b'K')
            self.assertEqual(result, marker)
            self.assertEqual(waits, [(worker, 'KER_SESSION_TEST_NONFRAME_RETAINED_DRAINED')])
            self.assertIn('KER_SESSION_TEST_NONFRAME_RETAINED_DRAINED ' + json.dumps(marker),
                          output.getvalue())
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_wait_marker_reports_both_distinct_pools(self):
        source = IO_SESSION.read_text()
        marker = source[source.index('KER_SESSION_TEST_NONFRAME_REAP_WAIT'):]
        marker = marker[:marker.index('KER_SESSION_TEST_NONFRAME_REAP_DONE')]
        self.assertIn(r'\"packet_pool_in_use\":%u,\"control_pool_available\":%u,\"control_pool_in_use\":%u', marker)
        self.assertIn('ker_generation_packet_pool_in_use(generation_rings)', marker)
        self.assertIn('rte_mempool_avail_count(message_pool),rte_mempool_in_use_count(message_pool)', marker)

    def test_exact_four_session_objects_and_separate_empty_frame_pool(self):
        before = {'generation': 500, 'token': 12}
        waiting = {'control_pool_available': 496, 'control_pool_in_use': 16,
                   'packet_pool_in_use': 0}
        self.assertTrue(fixture.nonframe_reap_pool_delta_matches(before, waiting))

        old_wrong_pool = dict(waiting, packet_pool_in_use=4)
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(before, old_wrong_pool))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            before, dict(waiting, control_pool_available=495)))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            before, dict(waiting, control_pool_in_use=15)))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            before, dict(waiting, control_pool_in_use=True)))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(
            dict(generation=True, token=12), waiting))
        self.assertFalse(fixture.nonframe_reap_pool_delta_matches(before, {}))

    def test_full_reap_preserves_three_live_consumer_queues_then_drains_exactly(self):
        before = {'generation': 500, 'token': 12}
        reaped = {
            'status': 0, 'full_reap_attempts': 1, 'generation_admitted': False,
            'active': [0, 0, 0, 0], 'rings': [0, 0, 1, 0, 0, 1, 0, 1],
            'packet_pool_in_use': 0, 'control_pool_available': 498,
        }
        drained = {
            'generation': 0, 'status': 0, 'rx_drained': 1, 'tx_drained': 2,
            'rings_before': [0, 0, 1, 0, 0, 1, 0, 1], 'rings_after': [0] * 8,
            'active': [0, 0, 0, 0], 'packet_pool_in_use': 0, 'control_pool_available': 501,
        }
        self.assertTrue(fixture.nonframe_reap_retained_matches(before, reaped))
        self.assertTrue(fixture.nonframe_retained_drain_matches(before, reaped, drained))
        self.assertFalse(fixture.nonframe_reap_retained_matches(
            before, dict(reaped, rings=[0] * 8)))
        self.assertFalse(fixture.nonframe_reap_retained_matches(
            before, dict(reaped, control_pool_available=500)))
        self.assertFalse(fixture.nonframe_reap_retained_matches(
            before, dict(reaped, rings=[0, 0, True, 0, 0, 1, 0, 1])))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, tx_drained=1)))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, rings_after=[0, 0, 0, 0, 0, 0, 0, 1])))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, control_pool_available=500)))
        self.assertFalse(fixture.nonframe_retained_drain_matches(
            before, reaped, dict(drained, rx_drained=True)))

    def test_runtime_source_has_opt_in_owner_drain_marker(self):
        source = IO_SESSION.read_text()
        callback = source[source.index('static int generation_frame_drain_control('):]
        callback = callback[:callback.index('\n}\n#endif')]
        self.assertIn("if(command=='K')return generation_test_nonframe_drain_dispatch", callback)
        self.assertIn('return generation_test_nonframe_drain(opaque);', source)
        self.assertIn('generation_test_step(context->rings,&context->identity,context->message_pool,5', source)
        self.assertIn('KER_SESSION_TEST_NONFRAME_RETAINED_DRAINED', source)

    def test_status_binds_pool_before_and_after_live_queue_drain(self):
        before = {'generation': 500, 'process': 2}
        owner = {'token': 17, 'generation': 0}
        retained_status = {'generation': 498, 'process': 1}
        self.assertTrue(fixture.nonframe_reap_status_matches(
            before, retained_status, owner, owner, 498, -2))
        final_status = {'generation': 501, 'process': 1}
        self.assertTrue(fixture.nonframe_reap_status_matches(
            before, final_status, owner, owner, 501, 1))
        # A final-restored pool count cannot be claimed before the explicit
        # consumer drain, and the intermediate count cannot pass afterward.
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, retained_status, owner, owner, 501, -2))
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, final_status, owner, owner, 498, 1))
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, final_status, dict(owner, token=18), owner, 501, 1))
        self.assertFalse(fixture.nonframe_reap_status_matches(
            before, dict(final_status, process=2), owner, owner, 501, 1))


if __name__ == '__main__':
    unittest.main()
