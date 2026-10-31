#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include "owned-frame-internal.h"
#ifdef FF_USE_PAGE_ARRAY
#error "The caller owned-frame bridge supports only the original copy path"
#endif
#undef ff_cur_lcore_conf
#define ff_cur_lcore_conf() (&example_owned_active->conf)
#define ff_no_hw_mode_nosync example_owned_no_hw
#define ff_traffic example_owned_counts
#define tx_dropped dropped_segments
#define ff_mbuf_copydata example_owned_copydata
#define ff_mbuf_free example_owned_input_free
#define ff_mbuf_tx_offload example_owned_offload
#define ff_divert_tx_mbuf example_owned_divert
#define send_single_packet example_owned_transmit
#define ff_dpdk_if_send example_owned_upstream_send
#include "send.inc"
