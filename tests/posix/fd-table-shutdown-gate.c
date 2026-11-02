#define _GNU_SOURCE
#include "fd-table.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

long lkl_syscall(long number, long *parameters);
bool ker_native_ready(void);

static atomic_int native_closes;
static pthread_barrier_t shutdown_entered;

long lkl_syscall(long number, long *parameters)
{
    (void)number;
    (void)parameters;
    atomic_fetch_add_explicit(&native_closes, 1, memory_order_relaxed);
    return 0;
}

bool ker_native_ready(void) { return true; }

static void barrier(void *opaque)
{
    pthread_barrier_t *value = opaque;
    int result = pthread_barrier_wait(value);
    if (result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD) abort();
}

static void export_gate_hook(void *opaque)
{
    pthread_barrier_t *barriers = opaque;
    barrier(&barriers[0]);
    barrier(&barriers[1]);
}

static void shutdown_gate_hook(void *opaque)
{
    barrier(opaque);
}

struct export_result { int fd; int error; };
static void *export_thread(void *opaque)
{
    struct export_result *result = opaque;
    result->fd = ker_fd_export(101, KER_FD_SOCKET, -1, 0, 0, -1);
    result->error = errno;
    return NULL;
}

static void *shutdown_thread(void *opaque)
{
    (void)opaque;
    ker_fd_close_all();
    return NULL;
}

int main(void)
{
    pthread_t exporter, shutdown;
    struct export_result exported = {.fd = -1};
    pthread_barrier_t export_barriers[2];
    if (pthread_barrier_init(&shutdown_entered, NULL, 2) ||
        pthread_barrier_init(&export_barriers[0], NULL, 2) ||
        pthread_barrier_init(&export_barriers[1], NULL, 2)) return 2;
    ker_fd_table_test_set_export_locked_hook(export_gate_hook, export_barriers);
    /* This signals that shutdown is about to contend for the install mutex. */
    ker_fd_table_test_set_shutdown_lock_hook(shutdown_gate_hook, &shutdown_entered);
    if (pthread_create(&exporter, NULL, export_thread, &exported)) return 2;
    barrier(&export_barriers[0]);
    if (pthread_create(&shutdown, NULL, shutdown_thread, NULL)) return 2;
    barrier(&shutdown_entered);
    barrier(&export_barriers[1]);
    pthread_join(exporter, NULL);
    pthread_join(shutdown, NULL);
    if (exported.fd < 0 || ker_fd_get(exported.fd) != NULL ||
        atomic_load_explicit(&native_closes, memory_order_relaxed) != 1) return 1;

    errno = 0;
    int rejected = ker_fd_export(102, KER_FD_SOCKET, -1, 0, 0, -1);
    int rejected_error = errno;
    if (rejected >= 0 || rejected_error != ESHUTDOWN ||
        atomic_load_explicit(&native_closes, memory_order_relaxed) != 2) return 1;
    puts("fd_install_shutdown_race=true rejected_install_closed_native=true");
    return 0;
}
