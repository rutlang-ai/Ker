/* Import unchanged reload code with isolated names for the READY scheduling
 * and native handover boundaries. Original state writes and call order stay
 * in that implementation; adapters require native authority around them. */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "nginx-source-bootstrap.h"
__attribute__((visibility("hidden")))
void ker_nginx_source_original_publish_ready(unsigned, uint32_t);
__attribute__((visibility("hidden")))
void ker_nginx_source_original_rx_stopped_set(int);
__attribute__((visibility("hidden")))
int ker_nginx_source_original_queue_mutex(uint16_t, uint16_t, int, int, unsigned);
__attribute__((visibility("hidden")))
int ker_nginx_source_original_rx_release(int);
__attribute__((visibility("hidden")))
int ker_nginx_source_original_rx_release_epoch(uint32_t, int);
#define ff_reload_publish_ready ker_nginx_source_original_publish_ready
#define ff_reload_rx_stopped_set ker_nginx_source_original_rx_stopped_set
#define ff_queue_handover_mutex ker_nginx_source_original_queue_mutex
#define ff_reload_rx_release ker_nginx_source_original_rx_release
#define ff_reload_rx_release_epoch ker_nginx_source_original_rx_release_epoch
#include "../../third_party/fstack-reload/ff_reload.c"
#undef ff_reload_publish_ready
#undef ff_reload_rx_stopped_set
#undef ff_queue_handover_mutex
#undef ff_reload_rx_release
#undef ff_reload_rx_release_epoch

static bool source_abort_fault(const char *name)
{
    const char *fault = getenv("FF_FAULT");
    return fault && !strcmp(fault, name) && getenv("KER_NGINX_SOURCE_ABORT_ENABLE") &&
        ker_fstack_nginx_source_fault_profile();
}

int ff_reload_rx_release(int target)
{
    int owner = ff_reload_rx_owner_gen();
    int stopped = ff_reload_rx_stopped();
    uint32_t epoch = ff_reload_shared_epoch();
    int status = ker_nginx_source_original_rx_release(target);
    if (status != FF_RELOAD_HANDOVER_OK && ker_nginx_source_is_master() &&
            (getenv("KER_NGINX_SOURCE_ABORT_RETRY_ENABLE") ||
             source_abort_fault("flip_fail")) &&
            ker_fstack_nginx_source_fault_profile()) {
        /* The source abort kills the successor before master_abort restores
         * markers. A frozen native queue cannot certify healthy rollback once
         * that owner is dead. Settle the explicitly staged native/C31 abort
         * here, before returning the ORIGINAL failure to the unchanged FSM. */
        if (status != FF_RELOAD_HANDOVER_TIMEOUT || owner != 0 || stopped != 1 ||
                target != 1 || ff_reload_rx_owner_gen() != owner ||
                ff_reload_rx_stopped() != stopped || ff_reload_shared_epoch() != epoch) {
            fprintf(stderr, "ker source master: failed release changed ownership; quarantine required\n");
            abort();
        }
        int native = ker_nginx_source_master_barrier(KER_NGINX_SOURCE_MASTER_ABORT);
        if (native) {
            fprintf(stderr, "ker source master: native abort unconfirmed status=%d; quarantine required\n", native);
            abort();
        }
    }
    return status;
}

int ff_reload_rx_release_epoch(uint32_t epoch, int generation)
{
    int status = ker_nginx_source_original_rx_release_epoch(epoch, generation);
    if (epoch && ker_nginx_source_is_master() &&
        ker_nginx_source_upgrade_enabled()) {
        if (status != FF_RELOAD_HANDOVER_OK ||
            ker_nginx_source_master_barrier(KER_NGINX_SOURCE_MASTER_COMMIT)) {
            fprintf(stderr, "ker source master: cross-master native handover is unconfirmed\n");
            abort();
        }
    }
    return status;
}

void ff_reload_rx_stopped_set(int stopped)
{
    /* The original park-never hook withholds every park acknowledgement.
     * Keep the broker on the still-current listener when no park can be
     * confirmed. The original shared markers and timeout still run. */
    if (stopped && ker_nginx_source_is_master() && !source_abort_fault("park_never")) {
        int status = ker_nginx_source_master_barrier(KER_NGINX_SOURCE_MASTER_PARK);
        if (status) {
            fprintf(stderr, "ker source master: native SYN barrier failed status=%d\n", status);
            /* A lost reply cannot certify native rollback or safe ownership.
             * Never let the source proceed on an uncertain external barrier. */
            abort();
        }
    }
    ker_nginx_source_original_rx_stopped_set(stopped);
}

int ff_queue_handover_mutex(uint16_t port, uint16_t queue,
    int from, int to, unsigned timeout)
{
    int status = ker_nginx_source_original_queue_mutex(port, queue, from, to, timeout);
    if (status == FF_RELOAD_HANDOVER_OK && ker_nginx_source_is_master()) {
        int native = ker_nginx_source_master_barrier(KER_NGINX_SOURCE_MASTER_COMMIT);
        if (native) {
            fprintf(stderr, "ker source master: native handover is unconfirmed status=%d\n", native);
            /* The original owner/unpark operations already ran. Unknown
             * selector/route outcomes require containment failure, not a
             * fabricated successful handover or healthy old-generation abort. */
            abort();
        }
    }
    return status;
}
