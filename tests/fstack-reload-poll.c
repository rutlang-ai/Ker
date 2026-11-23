#include <ker/reload.h>
#include "check.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
static void select_worker(int generation, unsigned slot)
{
    CHECK(!ker_reload_worker_select(generation, slot));
}
static void *state;
static int calls;
static int callback(void *argument)
{
    CHECK(argument == &calls); calls++;
    CHECK(ker_reload_poll(callback, argument) == -EBUSY);
    CHECK(ker_reload_worker_select(0, 0) == -EBUSY);
    CHECK(ker_reload_rx_mark(0, 0) == -EBUSY);
    CHECK(ker_reload_park_ack() == -EBUSY);
    return 7;
}
static void bind_state(void)
{
    CHECK(!ker_reload_bind_state(state, ker_reload_state_size(), 0, 0));
}
static void markers(void)
{
    CHECK(ker_reload_rx_owner() == -1 && !ker_reload_rx_stopped() && ker_reload_rx_allowed());
    CHECK(ker_reload_rx_claim(0, 1, 10) == KER_RELOAD_HANDOVER_INVAL);
    CHECK(ker_reload_poll(callback, &calls) == -ENOTCONN);
    bind_state(); select_worker(0, 0);
    CHECK(!ker_reload_rx_mark(0, 0) && ker_reload_rx_allowed());
    select_worker(1, 1); CHECK(!ker_reload_rx_allowed());
    CHECK(!ker_reload_poll(callback, &calls) && !calls);
    select_worker(0, 0);
    CHECK(ker_reload_rx_claim(0, 0, 10) == KER_RELOAD_HANDOVER_INVAL);
    CHECK(ker_reload_rx_claim(0, 2, 10) == KER_RELOAD_HANDOVER_INVAL);
    CHECK(ker_reload_rx_release(2) == KER_RELOAD_HANDOVER_INVAL);
    CHECK(ker_reload_rx_claim(0, 1, 60) == KER_RELOAD_HANDOVER_TIMEOUT);
    CHECK(ker_reload_rx_owner() == 0);
    CHECK(ker_reload_poll(callback, &calls) == 7 && calls == 1);
    CHECK(ker_reload_set_enabled(0) == -EBUSY);
    CHECK(!ker_reload_rx_release(1));
    CHECK(ker_reload_rx_owner() == 1 && ker_reload_rx_stopped() && !ker_reload_rx_allowed());
    select_worker(1, 1);
    CHECK(!ker_reload_rx_claim(0, 1, 100));
    CHECK(!ker_reload_rx_stopped() && ker_reload_rx_allowed());
    select_worker(0, 0); CHECK(!ker_reload_rx_allowed());
    select_worker(1, 1); CHECK(!ker_reload_rx_claim(0, 1, 10) && ker_reload_rx_allowed());
    select_worker(0, 0);
    CHECK(!ker_reload_rx_mark(0, 0) && ker_reload_rx_allowed());
    select_worker(1, 1); CHECK(!ker_reload_rx_allowed());
    ker_reload_unbind_state(); bind_state(); CHECK(!ker_reload_set_enabled(0));
    select_worker(1, 1); CHECK(ker_reload_rx_allowed());
    select_worker(0, 0); CHECK(ker_reload_rx_allowed());
    CHECK(ker_reload_poll(callback, &calls) == 7 && calls == 2);
}
static void barrier(void)
{
    bind_state(); select_worker(0, 0);
    uint32_t first, second;
    CHECK(!ker_reload_park_arm(&first) && first == 1);
    CHECK(!ker_reload_parked(0, first) && !ker_reload_parked(1, first));
    CHECK(!ker_reload_park_ack());
    CHECK(ker_reload_parked(0, first) && !ker_reload_parked(1, first));
    CHECK(!ker_reload_parked(0, first + 1));
    CHECK(!ker_reload_park_arm(&second) && second == 2);
    CHECK(!ker_reload_parked(0, second));
    CHECK(!ker_reload_park_ack() && ker_reload_parked(0, second));
    CHECK(!ker_reload_parked(128, second));
    select_worker(0, 1); CHECK(!ker_reload_rx_mark(0, 0) && ker_reload_rx_allowed());
    select_worker(1, 2); CHECK(!ker_reload_rx_allowed());
    CHECK(!ker_reload_rx_mark(0, 1));
    select_worker(0, 1); CHECK(!ker_reload_rx_allowed());
    select_worker(1, 2); CHECK(!ker_reload_rx_allowed());
    CHECK(!ker_reload_park_ack());
    CHECK(!ker_reload_rx_release(1));
    select_worker(0, 1); CHECK(!ker_reload_rx_allowed());
    select_worker(1, 2); CHECK(!ker_reload_rx_allowed());
    CHECK(!ker_reload_rx_claim(0, 1, 10) && !ker_reload_rx_stopped() && ker_reload_rx_allowed());
    select_worker(0, 1); CHECK(!ker_reload_rx_allowed());
    CHECK(!ker_reload_rx_mark(0, 0) && ker_reload_rx_allowed());
    select_worker(1, 2); CHECK(!ker_reload_rx_allowed());
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    state = calloc(1, ker_reload_state_size()); CHECK(state);
    CHECK(!ker_reload_state_init(state, ker_reload_state_size(), 0));
    if (!strcmp(argv[1], "markers")) markers();
    else if (!strcmp(argv[1], "barrier")) barrier();
    else CHECK(0);
    ker_reload_unbind_state(); free(state);
    printf("PASS: original same-master poll %s\n", argv[1]);
    return 0;
}
