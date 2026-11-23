// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "host-timer.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <lkl_host.h>

/* Keep the pinned POSIX host's relative CLOCK_REALTIME/SIGEV_THREAD semantics.
 * Own the opaque handle so NULL denotes allocation failure regardless of the
 * host timer_t representation. No Linux clock-event or protocol code changes. */
struct ker_timer { timer_t value; };
static void timer_callback(union sigval value)
{
    void (*routine)(void) = value.sival_ptr;
    routine();
}
static void *timer_alloc(void (*routine)(void))
{
    struct ker_timer *timer = malloc(sizeof(*timer));
    if (!timer) return NULL;
    struct sigevent event = {
        .sigev_notify = SIGEV_THREAD,
        .sigev_value.sival_ptr = routine,
        .sigev_notify_function = timer_callback,
    };
    if (timer_create(CLOCK_REALTIME, &event, &timer->value)) {
        int error = errno;
        free(timer);
        errno = error;
        return NULL;
    }
    return timer;
}
static int timer_set_oneshot(void *opaque, unsigned long ns)
{
    struct ker_timer *timer = opaque;
    struct itimerspec value = {
        .it_value = {.tv_sec = ns / 1000000000UL,
                     .tv_nsec = ns % 1000000000UL},
    };
    /* A zero interval preserves one-shot operation; ns == 0 disarms. */
    return timer_settime(timer->value, 0, &value, NULL);
}
static void timer_free(void *opaque)
{
    struct ker_timer *timer = opaque;
    if (timer_delete(timer->value)) {
        perror("ker: host timer deletion");
        abort(); /* The void callback cannot report an undeleted timer. */
    }
    free(timer);
}
void ker_native_host_timer_init(struct lkl_host_operations *ops)
{
    ops->timer_alloc = timer_alloc;
    ops->timer_set_oneshot = timer_set_oneshot;
    ops->timer_free = timer_free;
}
