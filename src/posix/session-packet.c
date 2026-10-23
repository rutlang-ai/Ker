/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "session-packet.h"
#include "packet-channel.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>

int ker_session_packet_create(struct rte_ring **rx, struct rte_ring **tx)
{
    *rx = rte_ring_create(KER_SESSION_PACKET_RX, 64, SOCKET_ID_ANY,
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    *tx = rte_ring_create(KER_SESSION_PACKET_TX, 64, SOCKET_ID_ANY,
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!*rx || !*tx) return -ENOMEM;
    int port = rte_eth_from_rings("ker_packet", rx, 1, tx, 1, SOCKET_ID_ANY);
    return port < 0 ? -ENODEV : port;
}
int ker_session_packet_endpoint(int fd, int type)
{
    struct sockaddr_un address;
    socklen_t size = sizeof(address), length = sizeof(int);
    int actual = 0;
    if (fd < 0 || getsockopt(fd, SOL_SOCKET, SO_TYPE, &actual, &length) || actual != type ||
        getpeername(fd, (void *)&address, &size) || address.sun_family != AF_UNIX) return -EINVAL;
    return 0;
}
static int alive(int pidfd)
{
    struct pollfd p = {.fd = pidfd, .events = POLLIN};
    int result;
    do result = poll(&p, 1, 0); while (result < 0 && errno == EINTR);
    return result == 0;
}
static int transient(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static int mtu_control(int fd, uint16_t port)
{
    struct ker_mtu_message message;
    ssize_t n = recv(fd, &message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
    if (n < 0 && transient()) return 0;
    if (!n) return 1; /* Native teardown closes its private seqpacket endpoint. */
    if (n != sizeof(message) || message.magic != KER_MTU_MAGIC || message.status ||
        (message.operation != KER_MTU_GET && message.operation != KER_MTU_SET)) return -EPROTO;
    uint16_t current;
    if (rte_eth_dev_get_mtu(port, &current) || current != 1500) return -EUCLEAN;
    message.status = message.operation == KER_MTU_SET && message.mtu != current ? -EOPNOTSUPP : 0;
    message.mtu = current;
    return send(fd, &message, sizeof(message), MSG_DONTWAIT | MSG_NOSIGNAL) == sizeof(message) ? 0 : -EIO;
}
int ker_session_packet_loop(uint16_t port, int packet_fd, int wire_fd, int mtu_fd,
    int control, int resident_pidfd, _Atomic uint64_t *owner, uint64_t expected_owner,
    struct rte_mbuf *tx_packet, struct rte_mbuf *rx_packet, const volatile sig_atomic_t *stopping)
{
    struct rte_ring *rx = rte_ring_lookup(KER_SESSION_PACKET_RX), *tx = rte_ring_lookup(KER_SESSION_PACKET_TX);
    uint16_t actual_mtu;
    if (!rx || !tx || rx == tx || !rte_ring_empty(rx) || !rte_ring_empty(tx) ||
        rte_ring_get_capacity(rx) != 64 || rte_ring_get_capacity(tx) != 64 ||
        !rte_ring_is_prod_single(rx) || !rte_ring_is_cons_single(rx) ||
        !rte_ring_is_prod_single(tx) || !rte_ring_is_cons_single(tx) ||
        rte_eth_dev_get_mtu(port, &actual_mtu) || actual_mtu != 1500) return -EUCLEAN;
    bool tx_queued = false, tx_pending = false, tx_output = false;
    bool rx_queued = false, rx_pending = false, rx_output = false;
    uint64_t sent = 0, received = 0, to_wire = 0, from_wire = 0;
    struct rte_eth_stats before, after;
    if (rte_eth_stats_get(port, &before)) return -EIO;
    printf("KER_SESSION_PACKET_READY {\"mtu\":1500,\"tx_features\":0,\"rx_ring\":\"%s\",\"tx_ring\":\"%s\"}\n",
        KER_SESSION_PACKET_RX, KER_SESSION_PACKET_TX); fflush(stdout);
    int status = 0;
    for (; !*stopping;) {
        if (!alive(resident_pidfd)) _Exit(125); /* Never clean shared state after resident loss. */
        if (atomic_load_explicit(owner, memory_order_acquire) != expected_owner) { status = -ESTALE; break; }
        short packet_events = (!tx_pending && !tx_queued && !tx_output ? POLLIN : 0) | (rx_output ? POLLOUT : 0);
        short wire_events = (!rx_pending && !rx_queued && !rx_output ? POLLIN : 0) | (tx_output ? POLLOUT : 0);
        struct pollfd fds[] = {{.fd = control, .events = POLLIN}, {.fd = packet_fd, .events = packet_events},
            {.fd = wire_fd, .events = wire_events}, {.fd = mtu_fd, .events = POLLIN},
            {.fd = resident_pidfd, .events = POLLIN}};
        int ready = poll(fds, 5, 0);
        if (ready < 0) { if (errno == EINTR) continue; status = -errno; break; }
        if (fds[4].revents) _Exit(125);
        if (fds[0].revents) break;
        if (fds[3].revents & POLLIN) {
            int result = mtu_control(mtu_fd, port);
            if (result > 0) break;
            if (result < 0) { status = result; break; }
        }
        if (fds[3].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        bool progress = false;
        if (!tx_pending && !tx_queued && !tx_output && (fds[1].revents & POLLIN)) {
            uint8_t bytes[sizeof(struct ker_packet_header) + 1518];
            ssize_t n = recv(packet_fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC);
            if (n < 0) { if (!transient()) { status = -errno; break; } }
            else {
                if (n < (ssize_t)(sizeof(struct ker_packet_header) + 14) || n > (ssize_t)sizeof(bytes)) { status = -EMSGSIZE; break; }
                struct ker_packet_header header; memcpy(&header, bytes, sizeof(header));
                if (header.flags || header.gso_type || header.header_length || header.gso_size ||
                    header.checksum_start || header.checksum_offset) { status = -EOPNOTSUPP; break; }
                rte_pktmbuf_reset(tx_packet);
                void *data = rte_pktmbuf_append(tx_packet, (uint16_t)(n - sizeof(header)));
                if (!data) { status = -ENOSPC; break; }
                memcpy(data, bytes + sizeof(header), (size_t)n - sizeof(header)); tx_pending = true; progress = true;
            }
        }
        if (tx_pending && rte_eth_tx_burst(port, 0, &tx_packet, 1) == 1) {
            tx_pending = false; tx_queued = true; sent++; progress = true;
        }
        if (tx_queued) {
            struct rte_mbuf *packet;
            if (!rte_ring_dequeue(tx, (void **)&packet)) {
                if (packet != tx_packet || packet->nb_segs != 1) { status = -EUCLEAN; break; }
                tx_queued = false; tx_output = true; progress = true;
            }
        }
        if (tx_output) {
            ssize_t n = send(wire_fd, rte_pktmbuf_mtod(tx_packet, void *), tx_packet->pkt_len, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n < 0 && transient()) { /* Keep the complete original object under its resident lease. */ }
            else if (n != tx_packet->pkt_len) { status = n < 0 ? -errno : -EIO; break; }
            else { tx_output = false; to_wire++; progress = true; }
        }
        if (!rx_pending && !rx_queued && !rx_output && (fds[2].revents & POLLIN)) {
            uint8_t bytes[1518];
            ssize_t n = recv(wire_fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC);
            if (n < 0) { if (!transient()) { status = -errno; break; } }
            else {
                if (n < 14 || n > (ssize_t)sizeof(bytes)) { status = -EMSGSIZE; break; }
                rte_pktmbuf_reset(rx_packet);
                void *data = rte_pktmbuf_append(rx_packet, (uint16_t)n);
                if (!data) { status = -ENOSPC; break; }
                memcpy(data, bytes, (size_t)n); rx_pending = true; from_wire++; progress = true;
            }
        }
        if (rx_pending && !rte_ring_enqueue(rx, rx_packet)) { rx_pending = false; rx_queued = true; progress = true; }
        if (rx_queued) {
            struct rte_mbuf *packet;
            if (rte_eth_rx_burst(port, 0, &packet, 1)) {
                if (packet != rx_packet || packet->nb_segs != 1) { status = -EUCLEAN; break; }
                rx_queued = false; rx_output = true; received++; progress = true;
            }
        }
        if (rx_output) {
            struct ker_packet_header header = {0};
            struct iovec iov[] = {{&header, sizeof(header)}, {rte_pktmbuf_mtod(rx_packet, void *), rx_packet->pkt_len}};
            struct msghdr message = {.msg_iov = iov, .msg_iovlen = 2};
            ssize_t n = sendmsg(packet_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n < 0 && transient()) { /* Retain the complete frame; do not reorder or reallocate. */ }
            else if (n < 0 && (errno == ECONNREFUSED || errno == EPIPE || errno == ENOTCONN)) break;
            else if (n != (ssize_t)(sizeof(header) + rx_packet->pkt_len)) { status = n < 0 ? -errno : -EIO; break; }
            else { rx_output = false; progress = true; }
        }
        if (!progress) poll(fds, 5, 1);
    }
    if (rte_eth_stats_get(port, &after) || after.opackets - before.opackets != sent ||
        after.ipackets - before.ipackets != received) status = -EUCLEAN;
    printf("KER_SESSION_PACKET_DONE {\"tx\":%llu,\"rx\":%llu,\"to_wire\":%llu,\"from_wire\":%llu,\"retained\":%u,\"status\":%d}\n",
        (unsigned long long)sent, (unsigned long long)received, (unsigned long long)to_wire,
        (unsigned long long)from_wire, (unsigned)(tx_pending + tx_queued + tx_output + rx_pending + rx_queued + rx_output), status); fflush(stdout);
    return status;
}
