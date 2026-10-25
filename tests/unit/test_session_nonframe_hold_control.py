#!/usr/bin/env python3
"""Exercise the dedicated nonframe hold byte without consuming production H."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
IO_SESSION = ROOT / 'src' / 'posix' / 'io-session.c'
PACKET_LOOP = ROOT / 'src' / 'posix' / 'session-packet.c'
RUNNER = ROOT / 'tools' / 'ker_session_run.py'


def c_function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for offset in range(opening, len(source)):
        if source[offset] == '{':
            depth += 1
        elif source[offset] == '}':
            depth -= 1
            if depth == 0:
                return source[start:offset + 1]
    raise AssertionError(f'unclosed C function: {signature}')


class NonframeHoldControlTests(unittest.TestCase):
    def test_exact_hook_dispatch_is_used_and_H_remains_production_handoff(self):
        source = IO_SESSION.read_text()
        packet_source = PACKET_LOOP.read_text()
        runner_source = RUNNER.read_text()
        hold = c_function(source, 'static int generation_test_nonframe_hold(')
        join = c_function(source, 'static int generation_test_join_nonframe_hold(')
        callback = c_function(source, 'static int generation_frame_drain_control(')
        self.assertIn('nonframe_reap_requested=getenv("KER_SESSION_TEST_NONFRAME_REAP")!=NULL', source)
        self.assertIn('(generation_frame_drain_test||nonframe_reap_active)?generation_frame_drain_control:NULL', source)
        cleanup = source[source.index('cleanup:\n', source.index('static int secondary(')):]
        self.assertLess(cleanup.index('generation_test_join_nonframe_hold('), cleanup.index('rte_eal_cleanup()'))
        self.assertIn('generation_test_nonframe_hold(command,context,context->nonframe_reap)', callback)
        self.assertIn('if(command!=\'Y\'||!enabled)return 0;', hold)
        self.assertIn("if (count==1 && command=='H') handoff_requested=true;", packet_source)
        self.assertIn('else if (count==1 && test_control)', packet_source)
        self.assertLess(packet_source.index("if (count==1 && command=='H') handoff_requested=true;"),
                        packet_source.index('else if (count==1 && test_control)'))
        runner_start = runner_source.index('def start_nonframe_active_reap():')
        runner_end = runner_source.index('def finish_nonframe_active_reap():', runner_start)
        runner_trigger = runner_source[runner_start:runner_end]
        self.assertIn("os.write(control_w, b'Y')", runner_trigger)
        self.assertNotIn("os.write(control_w, b'H')", runner_trigger)

        harness = r'''#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
struct ker_generation_rings { int identity; };
struct ker_generation_identity { uint64_t session,epoch; uint32_t slot,generation,process,pid; };
struct generation_frame_drain_context { struct ker_generation_rings *rings;
    struct ker_generation_identity identity; bool nonframe_reap; };
static bool generation_test_hold_started;
static bool generation_test_hold_joined;
static _Atomic unsigned generation_test_hold_completed;
static pthread_t generation_test_hold_thread;
static struct { struct ker_generation_rings *rings;
    struct ker_generation_identity identity; } generation_test_hold_context;
static unsigned hold_next_calls, thread_calls, join_calls;
static void *generation_test_hold_rx_dequeue(void *unused) { (void)unused; return 0; }
void ker_generation_test_hold_next_dequeue(void) { hold_next_calls++; }
int pthread_join(pthread_t thread, void **result) { (void)thread; (void)result; join_calls++; return 0; }
int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start)(void *), void *arg) {
    (void)thread; (void)attr; (void)start; (void)arg; thread_calls++; return 0;
}
''' + hold + '\n' + join + r'''
int main(void) {
    struct ker_generation_rings rings={7};
    struct generation_frame_drain_context context={.rings=&rings,
        .identity={.session=55,.epoch=8,.generation=0,.slot=2,.process=1,.pid=42},.nonframe_reap=true};
    if (generation_test_nonframe_hold('H',&context,true)!=0 || hold_next_calls || thread_calls) return 10;
    if (generation_test_nonframe_hold('Y',&context,false)!=0 || hold_next_calls || thread_calls) return 11;
    if (generation_test_nonframe_hold('Y',&context,true)!=1 || hold_next_calls!=1 || thread_calls!=1 ||
        !generation_test_hold_started || generation_test_hold_context.rings!=&rings ||
        generation_test_hold_context.identity.generation!=0 ||
        generation_test_hold_context.identity.slot!=2 || generation_test_hold_context.identity.process!=1) return 12;
    if (generation_test_nonframe_hold('Y',&context,true)!=-EALREADY || hold_next_calls!=1 || thread_calls!=1) return 13;
    atomic_store_explicit(&generation_test_hold_completed,1,memory_order_release);
    struct ker_generation_identity exact=context.identity;
    if (generation_test_join_nonframe_hold(&rings,&exact) || join_calls!=1 || generation_test_hold_started ||
        !generation_test_hold_joined) return 14;
    generation_test_hold_started=true;
    struct ker_generation_identity wrong=exact; wrong.pid++;
    if (generation_test_join_nonframe_hold(&rings,&wrong)!=-EUCLEAN || join_calls!=1) return 15;
    generation_test_hold_started=false;
    context.identity.generation=1;
    generation_test_hold_started=false;
    if (generation_test_nonframe_hold('Y',&context,true)!=-EPERM || hold_next_calls!=1 || thread_calls!=1) return 16;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='ker-session-nonframe-hold-') as directory:
            c_path = Path(directory) / 'hold.c'
            binary = Path(directory) / 'hold'
            c_path.write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(c_path),
                            '-pthread', '-o', str(binary)], check=True,
                           capture_output=True, text=True)
            subprocess.run([str(binary)], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
