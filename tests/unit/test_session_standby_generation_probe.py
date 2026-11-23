#!/usr/bin/env python3
"""Exercise the opt-in generation probe accepted by paired-PMD standby."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'src' / 'posix' / 'io-session.c'


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


class StandbyGenerationProbeTests(unittest.TestCase):
    def test_actual_opt_in_probe_and_standby_callsite(self):
        source = SOURCE.read_text()
        probe = c_function(source, 'static int generation_test_probe_command(')
        standby = c_function(source, 'static int generation_test_standby_command(')
        branch_start = source.index('while (!device_packet && !stopping)')
        branch_end = source.index('if (drain_worker_heartbeat_after_command', branch_start)
        branch = source[branch_start:branch_end]
        self.assertIn('generation_test_standby_command(command,', branch)
        self.assertIn('getenv("KER_SESSION_TEST_NONFRAME_REAP") != NULL', branch)
        self.assertLess(branch.index('generation_test_standby_command(command,'),
                        branch.index("if (command != 'P')"))
        self.assertIn('if (command != \'G\' || !opted_in) return -EAGAIN;', standby)
        self.assertIn('if (!generation_detach_test) return -EOPNOTSUPP;', standby)

        harness = r'''#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
struct ker_generation_rings { int unused; };
struct ker_generation_identity { uint32_t generation; };
struct rte_mempool { int unused; };
static bool generation_rings_enabled = true;
static unsigned calls, observed_step;
static bool observed_detach;
static int generation_test_step(struct ker_generation_rings *r,
    const struct ker_generation_identity *identity, struct rte_mempool *pool,
    unsigned step, bool detach, bool foreign, bool nonowner, bool empty, bool full) {
    (void)r; (void)identity; (void)pool; (void)foreign; (void)nonowner; (void)empty; (void)full;
    calls++; observed_step=step; observed_detach=detach; return 0;
}
''' + probe + '\n' + standby + r'''
int main(void) {
    struct ker_generation_rings rings={0};
    struct ker_generation_identity identity={.generation=1};
    struct rte_mempool pool={0};
    unsigned step=3;
    if (setenv("KER_SESSION_TEST_NONFRAME_REAP","1",1)) return 10;
    int result=generation_test_standby_command('G',true,&rings,&identity,&pool,&step,
        false,false,true,false,false,false,false);
    if (result || calls!=1 || observed_step!=3 || !observed_detach || step!=4) return 11;
    if (generation_test_standby_command('G',false,&rings,&identity,&pool,&step,
        false,false,true,false,false,false,false)!=-EAGAIN || calls!=1 || step!=4) return 12;
    if (generation_test_standby_command('P',true,&rings,&identity,&pool,&step,
        false,false,true,false,false,false,false)!=-EAGAIN || calls!=1 || step!=4) return 13;
    if (generation_test_standby_command('G',true,&rings,&identity,&pool,&step,
        false,false,false,false,false,false,false)!=-EOPNOTSUPP || calls!=1 || step!=4) return 14;
    if (generation_test_standby_command('G',true,NULL,&identity,&pool,&step,
        false,false,true,false,false,false,false)!=-EOPNOTSUPP || calls!=1 || step!=4) return 15;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='ker-session-standby-probe-') as directory:
            c_path = Path(directory) / 'probe.c'
            binary = Path(directory) / 'probe'
            c_path.write_text(harness)
            subprocess.run(['cc', '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra',
                            '-Werror', str(c_path), '-o', str(binary)], check=True,
                           capture_output=True, text=True)
            completed = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
            self.assertIn('KER_SESSION_TEST_GENERATION_PROBE_CONTEXT', completed.stderr)


if __name__ == '__main__':
    unittest.main()
