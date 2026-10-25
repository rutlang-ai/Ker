/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "session-packet.h"
#include "packet-channel.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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
    int control, int registration_fd, int resident_pidfd, _Atomic uint64_t *owner, uint64_t expected_owner,
    struct rte_mbuf *tx_packet, struct rte_mbuf *rx_packet,
    struct ker_worker_exception *exception, const volatile sig_atomic_t *stopping,
    ker_session_heartbeat_fn heartbeat_tick, ker_session_heartbeat_fn heartbeat_pump,
    void *heartbeat_context, struct ker_session_packet_stats *stats)
{
    struct rte_ring *rx = rte_ring_lookup(KER_SESSION_PACKET_RX), *tx = rte_ring_lookup(KER_SESSION_PACKET_TX);
    uint16_t actual_mtu;
    if (!rx || !tx || rx == tx || !rte_ring_empty(rx) || !rte_ring_empty(tx) ||
        rte_ring_get_capacity(rx) != 64 || rte_ring_get_capacity(tx) != 64 ||
        !rte_ring_is_prod_single(rx) || !rte_ring_is_cons_single(rx) ||
        !rte_ring_is_prod_single(tx) || !rte_ring_is_cons_single(tx) ||
        rte_eth_dev_get_mtu(port, &actual_mtu) || actual_mtu != 1500) return -EUCLEAN;
    bool tx_queued = false, tx_pending = false, tx_output = false;
    struct rte_mbuf *tx_output_packet = NULL;
    bool exception_reply_queued = false;
    bool rx_queued = false, rx_pending = false, rx_output = false, exception_pending = false;
    bool shared_native_pending = false, shared_native_queued = false;
    bool handoff_requested=false;
#ifdef KER_SESSION_TEST_HOOKS
    bool test_hold_handoff_heartbeat=getenv("KER_SESSION_TEST_HANDOFF_PENDING_HB")!=NULL;
#endif
    bool rx_fragment = false;
    uint64_t exception_to_native = 0, fragment_to_native = 0;
    uint64_t sent = 0, received = 0, to_wire = 0, from_wire = 0;
    uint64_t exception_to_wire = 0, exception_from_wire = 0;
    struct rte_eth_stats before, after;
    if (rte_eth_stats_get(port, &before)) return -EIO;
    printf("KER_SESSION_PACKET_READY {\"mtu\":1500,\"tx_features\":0,\"rx_ring\":\"%s\",\"tx_ring\":\"%s\",\"exception_endpoint_owner_key\":%llu,\"exception_endpoint_ifindex\":%u,\"exception_endpoint_fd_number\":%d}\n",
        KER_SESSION_PACKET_RX, KER_SESSION_PACKET_TX, (unsigned long long)expected_owner,
        exception->endpoint_ifindex, exception->fd); fflush(stdout);
    int status = 0;
    for (; !*stopping;) {
        if (!alive(resident_pidfd)) _Exit(125); /* Never clean shared state after resident loss. */
        int heartbeat_status = heartbeat_tick ? heartbeat_tick(heartbeat_context) : 0;
        if (heartbeat_status < 0) { status = heartbeat_status; break; }
        if (!alive(resident_pidfd)) _Exit(125);
        if (atomic_load_explicit(owner, memory_order_acquire) != expected_owner) { status = -ESTALE; break; }
        short packet_events = (!tx_pending && !tx_queued && !tx_output ? POLLIN : 0) | (rx_output ? POLLOUT : 0);
        short wire_events = (!rx_pending && !rx_queued && !rx_output && !exception_pending && !tx_queued && !tx_output && !exception->session_busy ? POLLIN : 0) | (tx_output ? POLLOUT : 0);
        struct pollfd fds[] = {{.fd = control, .events = POLLIN},
#ifdef KER_SESSION_TEST_HOOKS
            {.fd = registration_fd, .events = test_hold_handoff_heartbeat ? 0 : POLLIN},
#else
            {.fd = registration_fd, .events = POLLIN},
#endif
            {.fd = packet_fd, .events = packet_events},
            {.fd = wire_fd, .events = wire_events}, {.fd = mtu_fd, .events = POLLIN},
            {.fd = resident_pidfd, .events = POLLIN}};
        int ready = poll(fds, 6, 0);
        if (ready < 0) { if (errno == EINTR) continue; status = -errno; break; }
        if (fds[5].revents) _Exit(125);
        if (fds[0].revents) {
            char command=0;
            ssize_t count=(fds[0].revents&POLLIN)?read(control,&command,1):0;
            if (count==1 && command=='H') handoff_requested=true;
#ifdef KER_SESSION_TEST_HOOKS
            else if (count==1 && test_control) {
                int handled=test_control(command,test_control_context);
                if (handled<0) { status=handled; break; }
                if (handled==1) continue;
                break;
            }
#endif
            else break;
        }
        if (handoff_requested) {
            bool local_idle=!tx_pending&&!tx_queued&&!tx_output&&!rx_pending&&!rx_queued&&!rx_output&&
                !exception_pending&&!exception_reply_queued&&!shared_native_pending&&!shared_native_queued&&
                !exception->session_busy&&!exception->session_tx_pending&&!exception->session_native_pending&&
                !exception->session_to_native&&(!exception->session_phase||
                atomic_load_explicit(exception->session_phase,memory_order_acquire)==0)&&
                rte_ring_empty(rx)&&rte_ring_empty(tx)&&exception->pending&&rte_ring_empty(exception->pending);
            bool inputs_idle=!(fds[2].revents&POLLIN)&&!(fds[3].revents&POLLIN)&&!(fds[4].revents&POLLIN);
            if(local_idle&&inputs_idle) {
                if (!alive(resident_pidfd) || atomic_load_explicit(owner,memory_order_acquire)!=expected_owner) _Exit(125);
                if (heartbeat_pump) { int ack=heartbeat_pump(heartbeat_context); if (ack<0) { status=ack; break; } }
                printf("KER_SESSION_HANDOFF_BOUNDARY {\"owner_key\":%llu,\"tx\":%llu,\"rx\":%llu,\"idle\":true}\n",
                    (unsigned long long)expected_owner,(unsigned long long)sent,(unsigned long long)received); fflush(stdout);
                if (rte_eth_stats_get(port,&after) || after.opackets-before.opackets!=sent ||
                    after.ipackets-before.ipackets!=received) _Exit(125);
                if (stats) *stats=(struct ker_session_packet_stats){.tx=sent,.rx=received,
                    .to_wire=to_wire,.from_wire=from_wire,.exception_to_wire=exception_to_wire,
                    .exception_from_wire=exception_from_wire,.exception_to_native=exception_to_native,
                    .fragment_to_native=fragment_to_native,.exception_endpoint_owner_key=expected_owner,
                    .retained=0,.status=0};
#ifdef KER_SESSION_TEST_HOOKS
                /* Hold the exact owner at the completed boundary so the
                 * control-HUP fixture can close its pipe before PREPARE. */
                if (getenv("KER_SESSION_TEST_HANDOFF_CONTROL_HUP") && raise(SIGSTOP)) _Exit(125);
#endif
                return 1;
            }
        }
        if (fds[1].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        if (fds[1].revents & POLLIN) {
            /* Only a pending worker heartbeat may produce data on this
             * authenticated registration socket in the packet loop. */
            if (!alive(resident_pidfd)) _Exit(125);
            heartbeat_status = heartbeat_pump ? heartbeat_pump(heartbeat_context) : 0;
            if (!alive(resident_pidfd)) _Exit(125);
            if (atomic_load_explicit(owner, memory_order_acquire) != expected_owner) { status = -ESTALE; break; }
            if (heartbeat_status != 1) { status = heartbeat_status < 0 ? heartbeat_status : -EPROTO; break; }
        }
        if (fds[4].revents & POLLIN) {
            int result = mtu_control(mtu_fd, port);
            if (result > 0) break;
            if (result < 0) { status = result; break; }
        }
        if (fds[4].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        bool progress = false;
        if (!tx_pending && !tx_queued && !tx_output && (fds[2].revents & POLLIN)) {
            uint8_t bytes[sizeof(struct ker_packet_header) + 1518];
            ssize_t n = recv(packet_fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC);
            if (n < 0) { if (!transient()) { status = -errno; break; } }
            else {
                if (n < (ssize_t)(sizeof(struct ker_packet_header) + 14) || n > (ssize_t)sizeof(bytes)) { status = -EMSGSIZE; break; }
                struct ker_packet_header header; memcpy(&header, bytes, sizeof(header));
                if (!ker_packet_tx_header_simple_supported(&header)) { status = -EOPNOTSUPP; break; }
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
                if (packet != tx_packet && !(exception_reply_queued && packet == rx_packet)) { status = -EUCLEAN; break; }
                if (packet->nb_segs != 1) { status = -EUCLEAN; break; }
                tx_queued = false; tx_output = true; tx_output_packet = packet;
                if (packet == rx_packet) exception_reply_queued = false;
                progress = true;
            }
        }
        if (tx_output) {
            if (tx_output_packet == rx_packet) {
#ifdef KER_SESSION_TEST_HOOKS
                const char *hold_path = getenv("KER_SESSION_TEST_HOLD_EXCEPTION_OUTPUT");
                if (hold_path && access(hold_path, F_OK) == 0) raise(SIGSTOP);
#endif
                atomic_store_explicit(exception->session_phase, 6, memory_order_release);
            }
            ssize_t n = send(wire_fd, rte_pktmbuf_mtod(tx_output_packet, void *), tx_output_packet->pkt_len, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n < 0 && transient()) {
                if (tx_output_packet == rx_packet) atomic_store_explicit(exception->session_phase, 5, memory_order_release);
            }
            else if (n != tx_output_packet->pkt_len) { status = n < 0 ? -errno : -EIO; break; }
            else {
                if (tx_output_packet == rx_packet) {
                    exception_to_wire++; exception->session_busy = false;
                    atomic_store_explicit(exception->session_phase, 0, memory_order_release);
                    rte_pktmbuf_reset(rx_packet);
                }
                tx_output = false; tx_output_packet = NULL; to_wire++; progress = true;
            }
        }
        if (!rx_pending && !rx_queued && !rx_output && !exception->session_busy && (fds[3].revents & POLLIN)) {
            uint8_t bytes[1518];
            ssize_t n = recv(wire_fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_TRUNC);
            if (n < 0) { if (!transient()) { status = -errno; break; } }
            else {
                if (n < 14 || n > (ssize_t)sizeof(bytes)) { status = -EMSGSIZE; break; }
                rte_pktmbuf_reset(rx_packet);
                void *data = rte_pktmbuf_append(rx_packet, (uint16_t)n);
                if (!data) { status = -ENOSPC; break; }
                memcpy(data, bytes, (size_t)n);
                rx_pending = true; from_wire++; progress = true;
            }
        }
        if (rx_pending && !tx_queued && !tx_output) {
            enum ker_exception_route route = ker_worker_exception_route(exception, rx_packet);
            if (route == KER_EXCEPTION_HOST || route == KER_EXCEPTION_SHARED) {
                int admitted = ker_worker_exception_session_enqueue(exception, rx_packet, route == KER_EXCEPTION_SHARED);
                if (admitted) { status = admitted; break; }
                rx_pending = false; exception_pending = true; progress = true;
            } else if (!rte_ring_enqueue(rx, rx_packet)) {
                rx_pending = false; rx_queued = true; rx_fragment = route == KER_EXCEPTION_DROP; progress = true;
            }
        }
        if (!rx_pending && !rx_queued && !rx_output && !tx_queued && !tx_output) {
            int delivered = ker_worker_exception_session_poll(exception, port, 1500, &progress);
            if (delivered < 0) { status = delivered; break; }
            if (delivered == 1) { exception_from_wire++; exception_pending = false; }
            if (delivered == 2) { exception_pending = false; exception_reply_queued = true; tx_queued = true; sent++; }
            if (delivered == 3) {
                exception_from_wire++; exception_pending = false;
#ifdef KER_SESSION_TEST_HOOKS
                const char *hold_path = getenv("KER_SESSION_TEST_HOLD_EXCEPTION_NATIVE");
                if (hold_path && access(hold_path, F_OK) == 0) raise(SIGSTOP);
#endif
                shared_native_pending = true;
            }
        }
        if (shared_native_pending && !rte_ring_enqueue(rx, rx_packet)) {
            shared_native_pending = false; shared_native_queued = true;
            rx_queued = true; progress = true;
        }
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
            if (shared_native_queued) atomic_store_explicit(exception->session_phase, 8, memory_order_release);
            ssize_t n = sendmsg(packet_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (n < 0 && transient()) {
                if (shared_native_queued) atomic_store_explicit(exception->session_phase, 7, memory_order_release);
            }
            else if (n < 0 && (errno == ECONNREFUSED || errno == EPIPE || errno == ENOTCONN)) {
                if (shared_native_queued) atomic_store_explicit(exception->session_phase, 7, memory_order_release);
                break;
            }
            else if (n != (ssize_t)(sizeof(header) + rx_packet->pkt_len)) { status = n < 0 ? -errno : -EIO; break; }
            else {
                rx_output = false;
                if (rx_fragment) { fragment_to_native++; rx_fragment = false; }
                if (shared_native_queued) {
                    shared_native_queued = false; exception_to_native++;
                    exception->session_native_pending = false; exception->session_to_native = false;
                    exception->session_busy = false;
                    atomic_store_explicit(exception->session_phase, 0, memory_order_release);
                    rte_pktmbuf_reset(rx_packet);
                }
                progress = true;
            }
        }
        if (!progress) poll(fds, 6, 1);
    }
    if (rte_eth_stats_get(port, &after) || after.opackets - before.opackets != sent ||
        after.ipackets - before.ipackets != received) status = -EUCLEAN;
    if (stats) *stats=(struct ker_session_packet_stats){.tx=sent,.rx=received,.to_wire=to_wire,
        .from_wire=from_wire,.exception_to_wire=exception_to_wire,.exception_from_wire=exception_from_wire,
        .exception_to_native=exception_to_native,.fragment_to_native=fragment_to_native,
        .exception_endpoint_owner_key=expected_owner,
        .retained=(unsigned)(tx_pending + tx_queued + tx_output + rx_pending + rx_queued + rx_output +
            exception_pending + exception_reply_queued + exception->session_busy + shared_native_pending),.status=status};
    printf("KER_SESSION_PACKET_DONE {\"tx\":%llu,\"rx\":%llu,\"to_wire\":%llu,\"from_wire\":%llu,\"exception_to_wire\":%llu,\"exception_from_wire\":%llu,\"exception_to_native\":%llu,\"fragment_to_native\":%llu,\"exception_endpoint_owner_key\":%llu,\"retained\":%u,\"status\":%d}\n",
        (unsigned long long)sent, (unsigned long long)received, (unsigned long long)to_wire,
        (unsigned long long)from_wire, (unsigned long long)exception_to_wire, (unsigned long long)exception_from_wire,
        (unsigned long long)exception_to_native, (unsigned long long)fragment_to_native, (unsigned long long)expected_owner, (unsigned)(tx_pending + tx_queued + tx_output + rx_pending + rx_queued + rx_output + exception_pending + exception_reply_queued + exception->session_busy + shared_native_pending), status); fflush(stdout);
    return status;
}
