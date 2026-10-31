#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include "kni-bridge-internal.h"
struct ff_config ff_global_cfg;
int nb_dev_ports, enable_kni;
struct rte_ring **kni_rp, **kni_inject_rp;
struct kni_interface_stats **kni_stat;
struct kni_ratelimit kni_rate_limt;
static unsigned char *udp_port_bitmap, *tcp_port_bitmap;
#define RTE_KNI_NAMESIZE 16
#define set_bit(n, m) (n | magic_bits[m])
static const int magic_bits[8] = {0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1};
/* This caller supports one ordinary primary, with no reload/secondary ABI. */
static int unsupported_reload(void)
{
    fputs("kni caller: reload owner matching is unsupported\n", stderr);
    abort();
}
#define ff_reload_state_attached unsupported_reload
#define ff_reload_kni_owner_match unsupported_reload
/* Keep known upstream-only diagnostics local to the literal excerpt.
 * This caller supports only port0, whose inject-ring name fits the source bound. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
#include "functions.inc"
#pragma GCC diagnostic pop
int example_kni_prepare(void)
{
    if (rte_eal_process_type() != RTE_PROC_PRIMARY || rte_lcore_id() == LCORE_ID_ANY ||
        rte_eth_dev_count_avail() != 1 || kni_stat || kni_rp || kni_inject_rp) return -1;
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));
    nb_dev_ports = rte_eth_dev_count_avail();
    enable_kni = 1;
    return 0;
}
int example_kni_reset(void)
{
    if (kni_rp && kni_rp[0] && !rte_ring_empty(kni_rp[0])) return -1;
    if (kni_inject_rp && kni_inject_rp[0] && !rte_ring_empty(kni_inject_rp[0])) return -1;
    if (kni_rp) rte_ring_free(kni_rp[0]);
    if (kni_inject_rp) rte_ring_free(kni_inject_rp[0]);
    if (kni_stat) rte_free(kni_stat[0]);
    rte_free(kni_stat); rte_free(kni_rp); rte_free(kni_inject_rp);
    rte_free(udp_port_bitmap); rte_free(tcp_port_bitmap);
    kni_stat = NULL; kni_rp = kni_inject_rp = NULL;
    udp_port_bitmap = tcp_port_bitmap = NULL;
    nb_dev_ports = enable_kni = 0;
    memset(&kni_rate_limt, 0, sizeof(kni_rate_limt));
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));
    return 0;
}
