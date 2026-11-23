#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include "owned-frame-internal.h"
_Thread_local struct example_owned_sender *example_owned_active;
_Thread_local struct example_owned_send_stats example_owned_counts;
static void unsupported(const char *reason)
{
    fprintf(stderr, "owned-frame bridge unsupported: %s\n", reason);
    abort();
}
struct example_owned_sender *example_owned_sender_new(struct rte_mempool *pool,
    uint16_t port, uint16_t queue)
{
    if (!pool || rte_eal_process_type() != RTE_PROC_PRIMARY ||
        rte_lcore_id() == LCORE_ID_ANY || !rte_eth_dev_is_valid_port(port)) {
        errno = EINVAL; return NULL;
    }
    struct rte_eth_dev_info info;
    struct rte_eth_link link;
    if (rte_eth_dev_info_get(port, &info) || queue >= info.nb_tx_queues ||
        rte_eth_link_get_nowait(port, &link) || !link.link_status) {
        errno = ENODEV; return NULL;
    }
    struct example_owned_sender *sender = aligned_alloc(_Alignof(struct example_owned_sender), sizeof(*sender));
    if (!sender) return NULL;
    memset(sender, 0, sizeof(*sender));
    sender->pool = pool; sender->lcore = rte_lcore_id(); sender->queue = queue;
    sender->context.port_id = port;
    sender->conf.socket_id = (uint16_t)rte_socket_id();
    sender->conf.tx_queue_id[port] = queue;
    return sender;
}
void example_owned_sender_delete(struct example_owned_sender *sender) { free(sender); }
int example_owned_no_hw(void)
{
    return !example_owned_active || rte_eal_process_type() != RTE_PROC_PRIMARY ||
        rte_lcore_id() != example_owned_active->lcore;
}
struct rte_mempool *example_owned_pool(unsigned socket)
{
    if (!example_owned_active || socket != example_owned_active->conf.socket_id)
        unsupported("unbound pool/socket");
    return example_owned_active->pool;
}
int example_owned_copydata(void *opaque, void *output, int offset, int length)
{
    ++example_owned_counts.copies;
    if (offset < 0 || length < 0) { ++example_owned_counts.copy_failures; return -1; }
    const void *bytes = rte_pktmbuf_read(opaque, (uint32_t)offset, (uint32_t)length, output);
    if (!bytes) { ++example_owned_counts.copy_failures; return -1; }
    if (bytes != output) memcpy(output, bytes, (size_t)length);
    return 0;
}
void example_owned_input_free(void *packet)
{
    if (packet) { ++example_owned_counts.inputs_freed; rte_pktmbuf_free(packet); }
}
void example_owned_offload(void *opaque, struct ff_tx_offload *metadata)
{
    struct rte_mbuf *packet = opaque;
    if (packet->ol_flags) unsupported("offload metadata");
    memset(metadata, 0, sizeof(*metadata)); /* Actual supported no-offload input. */
}
void example_owned_divert(uint16_t port, uint16_t queue, struct rte_mbuf *packet)
{
    (void)port; (void)queue; (void)packet;
    unsupported("parked generation / cross-process diversion");
}
int example_owned_transmit(struct rte_mbuf *packet, uint16_t port)
{
    if (!example_owned_active || port != example_owned_active->context.port_id)
        unsupported("unbound transmit port");
    if (rte_eth_tx_burst(port, example_owned_active->queue, &packet, 1) == 1) {
        ++example_owned_counts.accepted; return 0;
    }
    example_owned_counts.dropped_segments += packet->nb_segs;
    rte_pktmbuf_free(packet);
    return -1;
}
int example_owned_send(struct example_owned_sender *sender, struct rte_mbuf *packet, int total)
{
    if (example_owned_active) unsupported("nested sender");
    if (packet && packet->ol_flags) {
        example_owned_input_free(packet); errno = ENOTSUP; return -1;
    }
    if (!packet || total <= 0 || total > UINT16_MAX ||
        (sender && (rte_eal_process_type() != RTE_PROC_PRIMARY || rte_lcore_id() != sender->lcore))) {
        example_owned_input_free(packet); errno = EINVAL; return -1;
    }
    example_owned_active = sender;
    int result = example_owned_upstream_send(sender ? &sender->context : NULL, packet, total);
    example_owned_active = NULL;
    return result;
}
void example_owned_send_snapshot(struct example_owned_send_stats *stats)
{
    if (stats) *stats = example_owned_counts;
}
