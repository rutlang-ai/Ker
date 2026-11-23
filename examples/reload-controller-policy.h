#ifndef EXAMPLE_RELOAD_CONTROLLER_POLICY_H
#define EXAMPLE_RELOAD_CONTROLLER_POLICY_H
/* Caller-owned application policy; this is not a Ker library API. */
#include <stdint.h>
#include "ngx_ff_reload_fsm.h"
#define EXAMPLE_RELOAD_WORKERS 4
struct example_reload_worker { unsigned slot; int pid, pidfd; };
struct example_reload_ops {
    int (*quiescent)(void *context);
    int (*drained)(void *context);
    int (*retire)(void *context, const struct example_reload_worker *workers, unsigned count);
};
struct example_reload_controller {
    int state, released;
    uint32_t round, target, park, rollback;
    struct example_reload_worker old[EXAMPLE_RELOAD_WORKERS], next[EXAMPLE_RELOAD_WORKERS];
    unsigned old_count, next_count;
    struct example_reload_ops ops;
    void *context;
};
int example_reload_next(int state, int event);
const char *example_reload_state_name(int state);
int example_reload_controller_init(struct example_reload_controller *controller,
    const struct example_reload_ops *ops, void *context);
int example_reload_controller_add(struct example_reload_controller *controller,
    unsigned slot, int pid, unsigned generation);
int example_reload_controller_event(struct example_reload_controller *controller, int event);
int example_reload_controller_release(struct example_reload_controller *controller);
int example_reload_controller_destroy(struct example_reload_controller *controller);
#endif
