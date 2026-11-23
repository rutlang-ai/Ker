#ifndef EXAMPLE_KNI_BRIDGE_INTERNAL_H
#define EXAMPLE_KNI_BRIDGE_INTERNAL_H
#include <stddef.h>
#include <stdint.h>
#define ff_global_cfg example_kni_configuration
#define nb_dev_ports example_kni_wire_ports
#define enable_kni example_kni_enabled
#define kni_rp example_kni_rx_rings
#define kni_inject_rp example_kni_inject_rings
#define kni_stat example_kni_stats
#define kni_rate_limt example_kni_rates
#define ff_kni_is_owner_thread example_kni_is_owner_thread
#define ff_kni_is_runtime_owner example_kni_is_runtime_owner
#define ff_kni_init example_kni_init
#define ff_kni_alloc example_kni_alloc
#define ff_kni_process example_kni_process
#define ff_kni_inject_process example_kni_inject_process
#define ff_kni_enqueue example_kni_enqueue
#include "ff_dpdk_kni.h"
#include "ff_config.h"
#include "stats.inc"
extern struct rte_ring **kni_rp, **kni_inject_rp;
extern struct kni_interface_stats **kni_stat;
int example_kni_prepare(void);
/* Bind caller-owned original reload state and select this caller's generation.
 * The bridge does not create or supervise reload state. */
int example_kni_bind_reload(void *state, size_t size, uint32_t epoch, int generation);
void example_kni_unbind_reload(void);
int example_kni_reload_state_attached(void);
int example_kni_reload_owner_matches(void);
int example_kni_owner_ready(void);
/* Perform the original reload begin/complete transition for the caller. */
int example_kni_activate_reload_owner(void);
/* Owner-gated call into the unchanged original inject processing function. */
void example_kni_poll_inject(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **packets, unsigned count);
/* Caller has stopped/destroyed its devices and owns every allocation/ring. */
int example_kni_reset(void);
#endif
