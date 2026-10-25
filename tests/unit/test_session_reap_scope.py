#!/usr/bin/env python3
"""Exercise the resident's target-specific FRAME recovery classification."""
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


class ReapScopeTests(unittest.TestCase):
    def test_unrelated_frame_state_does_not_block_full_reap_but_target_state_does(self):
        source = SOURCE.read_text()
        target_classifier = c_function(source, 'static bool frame_recovery_targets(unsigned target_index)\n')
        decision = c_function(source, 'static bool nonframe_full_reap_allowed(unsigned target_index,int bind_result)\n')
        enum_start = source.index('enum kind {')
        enum_end = source.index(';', enum_start) + 1
        client_start = source.index('struct client {')
        client_end = source.index('\n};', client_start) + 3
        client_declaration = source[client_start:client_end]
        harness = r'''#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#define CLIENTS 4
#define HANDOFF_NONE 0U
struct ker_session_message { unsigned char bytes[128]; };
struct ker_generation_identity { unsigned char bytes[64]; };
struct ker_generation_cleanup_config { unsigned char bytes[32]; };
struct rte_mbuf;
''' + source[enum_start:enum_end] + '\n' + client_declaration + r'''
static struct client clients[CLIENTS];
static unsigned handoff_state = HANDOFF_NONE;
static int handoff_client = -1, handoff_peer = -1;
''' + target_classifier + '\n' + decision + r'''
int main(void) {
    for (unsigned i=0;i<CLIENTS;i++) {
        clients[i].pidfd=(int)i+10;
        clients[i].handoff_peer_pidfd=-1;
        clients[i].handoff_peer_client_pidfd=-1;
        clients[i].reap_deferred_peer_pidfd=-1;
    }
    /* A live unrelated FRAME producer/consumer pair must not block target 2. */
    clients[0].frame_pending=true;
    clients[0].frame_consumer_client=1;
    clients[0].handoff_peer=1;
    clients[0].handoff_peer_client_pidfd=clients[1].pidfd;
    if (frame_recovery_targets(2) || !nonframe_full_reap_allowed(2,0)) return 10;
    /* A pending/malformed FRAME record on the target remains fail-closed. */
    clients[2].frame_pending=true;
    if (!frame_recovery_targets(2) || nonframe_full_reap_allowed(2,0)) return 11;
    clients[2].frame_pending=false;
    /* A valid producer that names target 2 as its consumer is related. */
    clients[0].frame_consumer_client=2;
    clients[0].handoff_peer=2;
    clients[0].handoff_peer_client_pidfd=clients[2].pidfd;
    if (!frame_recovery_targets(2) || nonframe_full_reap_allowed(2,0)) return 12;
    clients[0].frame_pending=false;
    clients[0].frame_reap_blocked=true;
    clients[0].frame_reap_consumer_client=2;
    if (!frame_recovery_targets(2) || nonframe_full_reap_allowed(2,0)) return 13;
    /* The actual binder must still succeed before the fallback is allowed. */
    if (nonframe_full_reap_allowed(2,1) || nonframe_full_reap_allowed(2,-1)) return 14;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='ker-session-reap-scope-') as directory:
            source_path = Path(directory) / 'scope.c'
            binary_path = Path(directory) / 'scope'
            source_path.write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(source_path),
                '-o', str(binary_path)], check=True, capture_output=True, text=True)
            subprocess.run([str(binary_path)], check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
