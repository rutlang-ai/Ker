/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "session-packet.h"
#include "packet-channel.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>

#define KER_SESSION_GENERATION_MAX_SEGS 32U
static int transient(void)
{ return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }

static int generation_packet_message(int fd, struct rte_mbuf *packet, bool linux_ingress)
{
    struct iovec iov[KER_SESSION_GENERATION_MAX_SEGS + 1];
    struct ker_packet_header header = {0};
    uint64_t bytes = 0;
    uint16_t segments = 0;
    if (!packet || packet->pkt_len < 14 || packet->pkt_len > 1518 ||
        !packet->nb_segs || packet->nb_segs > KER_SESSION_GENERATION_MAX_SEGS) return -EMSGSIZE;
    /* The session wire protocol carries frame bytes only. Do not silently
     * discard VLAN stripping or checksum/segmentation work encoded in mbuf
     * metadata. This adapter currently qualifies only complete wire frames. */
    if (packet->ol_flags & (RTE_MBUF_F_RX_VLAN_STRIPPED |
            RTE_MBUF_F_RX_IP_CKSUM_MASK | RTE_MBUF_F_RX_L4_CKSUM_MASK |
            RTE_MBUF_F_TX_OFFLOAD_MASK)) return -EOPNOTSUPP;
    if (linux_ingress) iov[segments++] = (struct iovec){&header, sizeof(header)};
    struct rte_mbuf *segment = packet;
    for (uint16_t i = 0; i < packet->nb_segs; ++i) {
        if (!segment || !segment->buf_addr || segment->data_off > segment->buf_len ||
            segment->data_len > segment->buf_len - segment->data_off || !segment->data_len)
            return -EUCLEAN;
        bytes += segment->data_len;
        if (bytes > packet->pkt_len) return -EUCLEAN;
        iov[segments++] = (struct iovec){rte_pktmbuf_mtod(segment, void *), segment->data_len};
        segment = segment->next;
    }
    if (segment || bytes != packet->pkt_len) return -EUCLEAN;
    struct msghdr message = {.msg_iov = iov, .msg_iovlen = segments};
    ssize_t sent = sendmsg(fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (sent < 0) return transient() ? 0 : -errno;
    size_t expected = (size_t)packet->pkt_len + (linux_ingress ? sizeof(header) : 0);
    return (size_t)sent == expected ? 1 : -EIO;
}

int ker_session_generation_rx_deliver(int packet_fd, struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity, struct rte_mbuf **pending)
{
    if (packet_fd < 0 || !rings || !identity || !pending) return -EINVAL;
    if (!*pending) {
#ifdef KER_SESSION_TEST_HOOKS
        int result = getenv("KER_SESSION_TEST_RX_DEQUEUE_EBUSY") ? -EBUSY :
            ker_generation_rx_dequeue(rings, identity, 0, 0, pending);
#else
        int result = ker_generation_rx_dequeue(rings, identity, 0, 0, pending);
#endif
        if (result == -EBUSY) return 0; /* Reap temporarily closed this generation gate. */
        if (result < 0) return result;
        if (!result) return 0;
    }
    int sent = generation_packet_message(packet_fd, *pending, true);
    if (sent <= 0) return sent;
    if (ker_generation_packet_release(rings, identity, *pending)) return -EUCLEAN;
    *pending = NULL;
    return 1;
}

int ker_session_generation_peer_tx_deliver(int wire_fd, struct ker_generation_rings *rings,
    const struct ker_generation_identity *identity, struct rte_mbuf **pending)
{
    if (wire_fd < 0 || !rings || !identity || !pending) return -EINVAL;
    if (!*pending) {
#ifdef KER_SESSION_TEST_HOOKS
        int result = getenv("KER_SESSION_TEST_TX_DEQUEUE_EBUSY") ? -EBUSY :
            ker_generation_tx_dequeue_peer(rings, identity, 0, 0, pending);
#else
        int result = ker_generation_tx_dequeue_peer(rings, identity, 0, 0, pending);
#endif
        if (result == -EBUSY) return 0; /* Reap temporarily closed this generation gate. */
        if (result < 0) return result;
        if (!result) return 0;
    }
    int sent = generation_packet_message(wire_fd, *pending, false);
    if (sent <= 0) return sent;
    if (ker_generation_packet_release(rings, identity, *pending)) return -EUCLEAN;
    *pending = NULL;
    return 1;
}
