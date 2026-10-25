#!/usr/bin/env python3
"""Execute the resident's deferred-frame binder with real pidfds."""
import os
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


class DeferredFramePidfdTests(unittest.TestCase):
    def test_live_ebusy_defer_retry_then_dead_duplicate_fails_closed(self):
        if not hasattr(os, 'pidfd_open'):
            self.skipTest('host Python has no pidfd_open')
        source = SOURCE.read_text()
        dead = c_function(source, 'static int dead(int fd)\n')
        live = c_function(source, 'static bool frame_pidfd_live(int pidfd)\n')
        matches = c_function(source,
            'static bool deferred_frame_consumer_matches(int consumer_pidfd,int saved_pidfd)\n')
        identity_equal = c_function(source,
            'static bool frame_identity_equal(const struct ker_generation_identity *a,\n')
        same_identity = c_function(source,
            'static bool same_generation_identity(const struct ker_generation_identity *a,\n')
        identity = c_function(source,
            'static struct ker_generation_identity generation_identity(const struct client *client)\n')
        binder = c_function(source, 'static int bind_deferred_frame_peer(unsigned target_index)\n')
        harness = (r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#define CLIENTS 4
#define KER_SESSION_SLOTS 2
#define KER_SESSION_GENERATIONS 2
#define KER_SESSION_PROCESSES 2
#define HANDOFF_PARKED 4
enum kind { UNUSED, UNBOUND, MASTER, RESERVED, ATTACHED, RELEASED };
struct ker_generation_identity {
    uint64_t session, epoch;
    unsigned slot, generation, process;
    uint32_t pid;
};
struct client {
    int pidfd, fd, frame_consumer_pidfd, frame_producer_pidfd;
    pid_t pid, reap_deferred_peer_pid, handoff_peer_pid;
    enum kind kind;
    unsigned slot, generation, process, handoff_state, handoff_peer;
    unsigned handoff_peer_slot, handoff_peer_generation, handoff_peer_process;
    unsigned frame_consumer_client, reap_deferred_peer_client, reap_deferred_attempts;
    uint64_t handoff_peer_epoch;
    int handoff_peer_pidfd, handoff_peer_client_pidfd, reap_deferred_peer_pidfd;
    bool generation_admitted, peer_only, frame_pending, reap_deferred;
    bool reap_deferred_peer_is_producer;
    struct ker_generation_identity frame_producer_identity, frame_consumer_identity;
    struct ker_generation_identity reap_deferred_peer_identity;
};
struct slot { uint64_t epoch; };
struct test_directory { uint64_t session; _Atomic uint64_t pmd_owner; };
static struct client clients[CLIENTS];
static struct slot slots[KER_SESSION_SLOTS];
static struct test_directory test_zone;
static struct test_directory *directory = &test_zone;
static uint64_t pmd_key(const struct client *client) {
    return 1 + ((uint64_t)client->slot * KER_SESSION_GENERATIONS + client->generation) * KER_SESSION_PROCESSES + client->process;
}
''' + dead + '\n' + live + '\n' + matches + '\n' + identity_equal + '\n' +
            same_identity + '\n' + identity + '\n' + binder + r'''
int main(void) {
    pid_t peer = fork();
    if (peer < 0) return 10;
    if (peer == 0) { alarm(3); for (;;) pause(); }
    pid_t producer_pid = fork();
    if (producer_pid < 0) return 11;
    if (producer_pid == 0) _exit(0);
    int peerfd = (int)syscall(SYS_pidfd_open, peer, 0);
    int producerfd = (int)syscall(SYS_pidfd_open, producer_pid, 0);
    if (peerfd < 0 || producerfd < 0) return 13;
    if (waitpid(producer_pid, NULL, 0) != producer_pid) return 12;
    int peer_copy = fcntl(peerfd, F_DUPFD_CLOEXEC, 3);
    int producer_copy = fcntl(producerfd, F_DUPFD_CLOEXEC, 3);
    if (peer_copy < 0 || producer_copy < 0) return 14;
    if (!deferred_frame_consumer_matches(peerfd, peer_copy)) return 20;

    directory->session = 77;
    slots[0].epoch = 9;
    clients[1] = (struct client){
        .pidfd=producerfd, .pid=producer_pid, .kind=ATTACHED, .slot=0,
        .generation=0, .process=0, .generation_admitted=true, .frame_pending=true,
        .frame_consumer_pidfd=peer_copy, .frame_producer_pidfd=producer_copy,
        .frame_consumer_client=2, .handoff_peer_client_pidfd=peerfd,
        .reap_deferred_peer_pidfd=-1,
        .frame_producer_identity={.session=77,.epoch=9,.slot=0,.generation=0,
            .process=0,.pid=(uint32_t)producer_pid},
        .frame_consumer_identity={.session=77,.epoch=9,.slot=0,.generation=1,
            .process=0,.pid=(uint32_t)peer}};
    clients[2] = (struct client){
        .pidfd=peerfd, .pid=peer, .kind=ATTACHED, .slot=0, .generation=1,
        .process=0, .generation_admitted=true, .reap_deferred_peer_pidfd=-1};

    /* Simulate the exact reclaim_control EBUSY branch, then its live retry. */
    int reclaim = -EBUSY;
    if (reclaim != -EBUSY) return 15;
    int bound = bind_deferred_frame_peer(1);
    if (bound != 1 || clients[1].reap_deferred_peer_pidfd < 0 ||
        !frame_pidfd_live(clients[1].reap_deferred_peer_pidfd)) return 16;
    clients[1].reap_deferred = true;
    int retry = bind_deferred_frame_peer(1);
    if (retry != 1) return 17;

    if (kill(peer, SIGKILL) || waitpid(peer, NULL, 0) != peer) return 18;
    /* Actual binder now declines the dead exact peer; caller fails closed. */
    if (deferred_frame_consumer_matches(peerfd, peer_copy) ||
        bind_deferred_frame_peer(1) != 0) return 19;
    close(clients[1].reap_deferred_peer_pidfd);
    close(peer_copy); close(producer_copy); close(peerfd); close(producerfd);
    puts("PASS: actual deferred binder bound/retried live peer and rejected its dead duplicate");
    return 0;
}
''')
        with tempfile.TemporaryDirectory(prefix='ker-frame-pidfd-') as temporary:
            source_path = Path(temporary) / 'pidfd-test.c'
            binary_path = Path(temporary) / 'pidfd-test'
            source_path.write_text(harness)
            compiled = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                       str(source_path), '-o', str(binary_path)],
                                      capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(binary_path)], check=True,
                                    capture_output=True, text=True, timeout=5)
            self.assertIn('PASS: actual deferred binder bound/retried live peer and rejected its dead duplicate',
                          result.stdout)

            # Prove the regression fails if the production branch polarity is flipped back.
            wrong_predicate = binder.replace(
                '!deferred_frame_consumer_matches(consumer->pidfd,producer->frame_consumer_pidfd)',
                'deferred_frame_consumer_matches(consumer->pidfd,producer->frame_consumer_pidfd)',
                1)
            self.assertNotEqual(wrong_predicate, binder,
                                'could not construct the live/dead polarity mutation')
            mutated = harness.replace(binder, wrong_predicate, 1)
            mutated_source = Path(temporary) / 'pidfd-mutated.c'
            mutated_binary = Path(temporary) / 'pidfd-mutated'
            mutated_source.write_text(mutated)
            mutated_build = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                            str(mutated_source), '-o', str(mutated_binary)],
                                           capture_output=True, text=True)
            self.assertEqual(mutated_build.returncode, 0, mutated_build.stderr)
            mutated_run = subprocess.run([str(mutated_binary)], capture_output=True,
                                         text=True, timeout=5)
            self.assertEqual(mutated_run.returncode, 16,
                             'inverted actual bind branch was not caught by the regression')


if __name__ == '__main__':
    unittest.main()
