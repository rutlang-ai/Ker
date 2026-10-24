#include "io-session.h"
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %u: %s\n", __LINE__, #x); exit(1); } } while (0)
struct mirror {
    _Atomic uint64_t version, epoch, generation, draining;
    _Atomic int saw_odd, allow_reader, done;
    uint64_t read_epoch, read_generation, read_draining;
};
static void observe_odd(void *arg)
{
    struct mirror *m = arg;
    atomic_store_explicit(&m->saw_odd, 1, memory_order_release);
    while (!atomic_load_explicit(&m->allow_reader, memory_order_acquire)) sched_yield();
}
static void *reader(void *arg)
{
    struct mirror *m = arg;
    CHECK(!ker_session_peer_read_observed(&m->version, &m->epoch, &m->generation, &m->draining,
        &m->read_epoch, &m->read_generation, &m->read_draining, observe_odd, m));
    atomic_store_explicit(&m->done, 1, memory_order_release);
    return NULL;
}
int main(void)
{
    struct mirror m = {0};
    atomic_init(&m.version, 2); atomic_init(&m.epoch, 10);
    atomic_init(&m.generation, 1); atomic_init(&m.draining, 1);
    atomic_init(&m.saw_odd, 0); atomic_init(&m.allow_reader, 0); atomic_init(&m.done, 0);
    pthread_t thread;
    ker_session_peer_write_begin(&m.version);
    atomic_store_explicit(&m.epoch, 20, memory_order_seq_cst);
    CHECK(!pthread_create(&thread, NULL, reader, &m));
    struct timespec pause = {.tv_sec=0, .tv_nsec=1000000};
    for (unsigned i = 0; i < 5000 && !atomic_load_explicit(&m.saw_odd, memory_order_acquire); i++) nanosleep(&pause, NULL);
    CHECK(atomic_load_explicit(&m.saw_odd, memory_order_acquire));
    CHECK(!atomic_load_explicit(&m.done, memory_order_acquire));
    atomic_store_explicit(&m.generation, 0, memory_order_seq_cst);
    atomic_store_explicit(&m.draining, 1, memory_order_seq_cst);
    ker_session_peer_write_end(&m.version);
    atomic_store_explicit(&m.allow_reader, 1, memory_order_release);
    CHECK(!pthread_join(thread, NULL));
    CHECK(m.read_epoch == 20 && m.read_generation == 0 && m.read_draining == 1);
    puts("PASS: peer mirror reader waits for a complete true-to-true replacement tuple");
    return 0;
}
