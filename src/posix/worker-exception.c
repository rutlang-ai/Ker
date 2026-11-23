#define _GNU_SOURCE
#include "worker-exception.h"
#include "worker-mbuf.h"
#include "packet-channel.h"
#include "pcap.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#define EXCEPTION_BURST 32
#define EXCEPTION_FRAME (KER_NATIVE_MAX_MTU + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN)

static bool owner(const struct ker_worker_exception *bridge)
{
    return bridge && bridge->pending && bridge->owner == rte_lcore_id();
}
static int exception_open(struct ker_worker_exception *bridge, const char *iface, const char *ring_name, bool session_keeper,
    struct rte_mempool *pool, const struct rte_ether_addr *mac, unsigned mtu, uint16_t ether_type, unsigned capacity, uint32_t rate_limit, uint32_t console_limit, uint32_t general_limit)
{
    if (!bridge || bridge->pending || !pool || !mac || !rte_is_valid_assigned_ether_addr(mac) || !iface || !*iface || strlen(iface) >= IFNAMSIZ || !strcmp(iface, ".") || !strcmp(iface, "..") ||
        mtu < KER_NATIVE_MIN_MTU || mtu > KER_NATIVE_MAX_MTU || ether_type < 1536 ||
        capacity < 4 || capacity > 65536 || (capacity & (capacity - 1))) return -EINVAL;
    for (const unsigned char *p = (const unsigned char *)iface; *p; p++)
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.') return -EINVAL;
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -errno;
    struct ifreq request = {.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_TUN_EXCL};
    strcpy(request.ifr_name, iface);
    if (ioctl(fd, TUNSETIFF, &request) || ioctl(fd, TUNSETOFFLOAD, 0)) {
        int error = errno; close(fd); return -error;
    }
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control < 0) { int error = errno; close(fd); return -error; }
    request.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(request.ifr_hwaddr.sa_data, mac->addr_bytes, RTE_ETHER_ADDR_LEN);
    int error = ioctl(control, SIOCSIFHWADDR, &request);
    if (!error) error = ioctl(control, SIOCGIFHWADDR, &request);
    if (!error && memcmp(request.ifr_hwaddr.sa_data, mac->addr_bytes, RTE_ETHER_ADDR_LEN)) {
        errno = EIO; error = -1;
    }
    request.ifr_mtu = (int)mtu;
    if (!error) error = ioctl(control, SIOCSIFMTU, &request);
    if (!error) error = ioctl(control, SIOCGIFFLAGS, &request);
    if (!error) { request.ifr_flags |= IFF_UP; error = ioctl(control, SIOCSIFFLAGS, &request); }
    int saved = errno;
    close(control);
    if (error) { close(fd); return -saved; }
    char name[RTE_RING_NAMESIZE];
    if (ring_name) { if (strlen(ring_name) >= sizeof(name)) { close(fd); return -ENAMETOOLONG; } strcpy(name, ring_name); }
    else snprintf(name, sizeof(name), "ker_exception_%u", (unsigned)getpid());
    unsigned ring_flags = RING_F_SP_ENQ | RING_F_SC_DEQ | (ring_name ? RING_F_EXACT_SZ : 0);
    struct rte_ring *pending = rte_ring_create(name, capacity, pool->socket_id, ring_flags);
    if (!pending) { int result = rte_errno; close(fd); return -result; }
    *bridge = (struct ker_worker_exception){.fd = fd, .pool = pool, .pending = pending, .owner = rte_lcore_id(),
        .ether_type = ether_type, .rate_limit = rate_limit, .console_limit = console_limit,
        .general_limit = general_limit, .window_start = -1,
        .session_shared = ring_name != NULL, .session_keeper = session_keeper};
    bridge->endpoint_ifindex = if_nametoindex(request.ifr_name);
    return 0;
}
int ker_worker_exception_open(struct ker_worker_exception *bridge, const char *iface,
    struct rte_mempool *pool, const struct rte_ether_addr *mac, unsigned mtu, uint16_t ether_type, unsigned capacity, uint32_t rate_limit, uint32_t console_limit, uint32_t general_limit)
{
    return exception_open(bridge, iface, NULL, false, pool, mac, mtu, ether_type, capacity,
        rate_limit, console_limit, general_limit);
}
int ker_worker_exception_open_session(struct ker_worker_exception *bridge, const char *iface,
    const char *ring_name, struct rte_mempool *pool, const struct rte_ether_addr *mac,
    unsigned mtu, unsigned capacity, _Atomic uint32_t *phase, unsigned *ifindex)
{
    if (!ring_name || !phase || !ifindex) return -EINVAL;
    int result = exception_open(bridge, iface, ring_name, true, pool, mac, mtu, RTE_ETHER_TYPE_ARP,
        capacity, 0, 0, 0);
    if (!result) { bridge->session_phase = phase; bridge->port_mode = true; *ifindex = bridge->endpoint_ifindex; }
    return result;
}
int ker_worker_exception_attach_session(struct ker_worker_exception *bridge, int fd,
    const char *iface, const char *ring_name, struct rte_mempool *pool, unsigned ifindex, struct rte_mbuf *lease_packet, _Atomic uint32_t *phase)
{
    if (!bridge || bridge->pending || fd < 0 || !iface || !ring_name || !pool || !ifindex || !lease_packet || lease_packet->pool != pool || !phase ||
        strlen(ring_name) >= RTE_RING_NAMESIZE) return -EINVAL;
    struct ifreq request = {0};
    if (ioctl(fd, TUNGETIFF, &request)) return -errno;
    if (strcmp(request.ifr_name, iface) || if_nametoindex(request.ifr_name) != ifindex) return -ESTALE;
    struct rte_ring *pending = rte_ring_lookup(ring_name);
    if (!pending || rte_ring_get_capacity(pending) != 64 || !rte_ring_is_prod_single(pending) ||
        !rte_ring_is_cons_single(pending) || !rte_ring_empty(pending)) return -EUCLEAN;
    *bridge = (struct ker_worker_exception){.fd=fd,.pool=pool,.pending=pending,.owner=rte_lcore_id(),
        .ether_type=RTE_ETHER_TYPE_ARP,.session_shared=true,.endpoint_ifindex=ifindex,
        .session_lease_packet=lease_packet,.session_phase=phase,.port_mode=true};
    return 0;
}
int ker_worker_exception_mtu(struct ker_worker_exception *bridge, unsigned *mtu, bool set)
{
    if (!owner(bridge)) return -EXDEV;
    if (!mtu || (set && (*mtu < KER_NATIVE_MIN_MTU || *mtu > KER_NATIVE_MAX_MTU))) return -EINVAL;
    struct ifreq request = {0};
    if (ioctl(bridge->fd, TUNGETIFF, &request)) return -errno;
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control < 0) return -errno;
    int result = 0;
    unsigned requested = *mtu;
    if (set) {
        request.ifr_mtu = (int)requested;
        if (ioctl(control, SIOCSIFMTU, &request)) result = -errno;
    }
    if (!result && ioctl(control, SIOCGIFMTU, &request)) result = -errno;
    if (!result) {
        *mtu = (unsigned)request.ifr_mtu;
        if (set && *mtu != requested) result = -EIO;
    }
    if (close(control) && !result) result = -errno;
    return result;
}
int ker_worker_exception_mtu_busy(struct ker_worker_exception *bridge)
{
    if (!owner(bridge)) return -EXDEV;
    if (!rte_ring_empty(bridge->pending)) return 1;
    struct pollfd event = {.fd = bridge->fd, .events = POLLIN};
    int result;
    do result = poll(&event, 1, 0); while (result < 0 && errno == EINTR);
    if (result < 0) return -errno;
    if (event.revents & (POLLERR | POLLHUP | POLLNVAL)) return -EIO;
    return result > 0 && (event.revents & POLLIN) ? 1 : 0;
}
enum ker_exception_route ker_worker_exception_route(const struct ker_worker_exception *bridge, const struct rte_mbuf *packet)
{
    if (!bridge || !bridge->pending || !packet) return KER_EXCEPTION_NATIVE;
    if (!bridge->port_mode) return ker_worker_exception_matches(bridge, packet) ? KER_EXCEPTION_HOST : KER_EXCEPTION_NATIVE;
    enum ker_exception_class kind = ker_exception_classify(&bridge->filter, packet);
    if (kind == KER_EXCEPTION_FRAGMENT) return KER_EXCEPTION_DROP;
    if (kind == KER_EXCEPTION_NDP || kind == KER_EXCEPTION_ICMP_ERROR || ker_exception_arp(packet)) return KER_EXCEPTION_SHARED;
    bool selected = kind == KER_EXCEPTION_SERVICE;
    return (bridge->reject ? !selected : selected) ? KER_EXCEPTION_HOST : KER_EXCEPTION_NATIVE;
}
bool ker_worker_exception_matches(const struct ker_worker_exception *bridge, const struct rte_mbuf *packet)
{
    if (!bridge || !bridge->pending || !packet || packet->pkt_len < RTE_ETHER_HDR_LEN) return false;
    unsigned char storage[2];
    const unsigned char *type = rte_pktmbuf_read(packet, 12, 2, storage);
    return type && (((unsigned)type[0] << 8) | type[1]) == bridge->ether_type;
}
/* Same console class as the source L2/IP classifier: ARP, multicast,
 * OSPF and neighbor discovery. Read real mbuf geometry, including chains. */
static bool console_packet(const struct rte_mbuf *packet)
{
    struct rte_ether_hdr storage;
    const struct rte_ether_hdr *ether = rte_pktmbuf_read(packet, 0, sizeof(storage), &storage);
    if (ether && rte_is_multicast_ether_addr(&ether->dst_addr)) return true;
    if (ker_exception_arp(packet)) return true;
    enum ker_exception_class kind = ker_exception_classify(NULL, packet);
    return kind == KER_EXCEPTION_OSPF || kind == KER_EXCEPTION_NDP;
}
int ker_worker_exception_enqueue(struct ker_worker_exception *bridge, struct rte_mbuf **packet)
{
    if (!owner(bridge)) return -EXDEV;
    if (!packet || !*packet) return -EINVAL;
    bridge->selected++;
    struct rte_mbuf *owned = *packet;
    *packet = NULL;
    /* Charge attempts before queue admission, including over-limit and full
     * queue drops. Disabled classes retain zero counters. Poll advances the
     * owner's one-second window before receiving each new wire batch. */
    if (bridge->console_limit || bridge->general_limit) {
        bool console = console_packet(owned);
        uint32_t limit = console ? bridge->console_limit : bridge->general_limit;
        if (limit) {
            uint64_t *packets = console ? &bridge->console_packets : &bridge->general_packets;
            uint64_t *charged = console ? &bridge->console_charged : &bridge->general_charged;
            uint64_t *dropped = console ? &bridge->console_dropped : &bridge->general_dropped;
            (*charged)++;
            if (++(*packets) > limit) {
                (*dropped)++;
                rte_pktmbuf_free(owned); bridge->to_host_dropped++; return -ENOBUFS;
            }
        }
    }
    if (rte_ring_enqueue(bridge->pending, owned)) {
        rte_pktmbuf_free(owned); bridge->to_host_dropped++; return -ENOBUFS;
    }
    bridge->enqueued++;
    return 0;
}
static int host_write(int fd, const struct rte_mbuf *packet, unsigned mtu)
{
    if (packet->pkt_len < RTE_ETHER_HDR_LEN || packet->pkt_len > mtu + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN)
        return -EMSGSIZE;
    struct iovec vectors[32];
    unsigned count = 0, bytes = 0;
    for (const struct rte_mbuf *part = packet; part; part = part->next) {
        if (count == 32) return -E2BIG;
        if (part->data_off > part->buf_len || part->data_len > part->buf_len - part->data_off) return -EINVAL;
        vectors[count++] = (struct iovec){rte_pktmbuf_mtod(part, void *), part->data_len};
        bytes += part->data_len;
    }
    if (bytes != packet->pkt_len || count != packet->nb_segs) return -EINVAL;
    unsigned char scratch[14];
    const unsigned char *header = rte_pktmbuf_read(packet, 0, sizeof(scratch), scratch);
    unsigned l2 = header && header[12] == 0x81 && header[13] == 0 ? 18 : 14;
    if (!header || packet->pkt_len < l2 || packet->pkt_len > mtu + l2) return -EMSGSIZE;
    ssize_t result = writev(fd, vectors, (int)count);
    if (result < 0) return -errno;
    return result == bytes ? 0 : -EIO;
}
int ker_worker_exception_poll(struct ker_worker_exception *bridge, uint16_t wire_port,
    unsigned mtu, int64_t now_ns, struct ker_pcap *capture, bool *progress)
{
    if (!owner(bridge)) return -EXDEV;
    if (!progress || now_ns < 0 || mtu < KER_NATIVE_MIN_MTU || mtu > KER_NATIVE_MAX_MTU) return -EINVAL;
    if (bridge->window_start < 0) bridge->window_start = now_ns;
    else if (now_ns < bridge->window_start) return -EIO;
    else if (now_ns - bridge->window_start >= INT64_C(1000000000)) {
        bridge->window_start = now_ns; bridge->window_packets = 0;
        bridge->console_packets = bridge->general_packets = 0;
    }
    struct rte_mbuf *packets[EXCEPTION_BURST];
    unsigned count = rte_ring_dequeue_burst(bridge->pending, (void **)packets, EXCEPTION_BURST, NULL);
    bool limited = bridge->rate_limit && bridge->window_packets >= bridge->rate_limit;
    if (bridge->rate_limit) bridge->window_packets += count;
    unsigned accepted = 0;
    int result = 0;
    if (!limited) for (; accepted < count; accepted++) {
        result = host_write(bridge->fd, packets[accepted], mtu);
        if (result) break;
    }
    bridge->to_host += accepted;
    bridge->to_host_dropped += count - accepted;
    if (limited) bridge->rate_dropped += count;
    for (unsigned i = 0; i < count; i++) rte_pktmbuf_free(packets[i]);
    if (count) *progress = true;
    if (result && result != -EAGAIN && result != -EWOULDBLOCK && result != -EINTR &&
        result != -EMSGSIZE && result != -EINVAL && result != -E2BIG) return result;
    if (result == -EMSGSIZE || result == -EINVAL || result == -E2BIG) bridge->malformed += count - accepted;
    count = 0;
    unsigned char bytes[EXCEPTION_FRAME + 1];
    for (unsigned i = 0; i < EXCEPTION_BURST; i++) {
        ssize_t length = read(bridge->fd, bytes, sizeof(bytes));
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
            result = -errno; break;
        }
        *progress = true; bridge->host_received++;
        unsigned l2 = length >= 14 && bytes[12] == 0x81 && bytes[13] == 0 ? 18 : 14;
        if (length < (ssize_t)l2 || length > (ssize_t)(mtu + l2)) {
            bridge->wire_dropped++; bridge->malformed++; continue;
        }
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(bridge->pool, bytes, (size_t)length);
        if (!packet) { bridge->wire_dropped++; continue; }
        if (capture) {
            struct timespec timestamp;
            if (clock_gettime(CLOCK_REALTIME, &timestamp) || ker_pcap_write(capture, packet, &timestamp)) {
                result = -EIO; bridge->wire_dropped++; rte_pktmbuf_free(packet); break;
            }
        }
        packets[count++] = packet;
    }
    if (count) {
        uint16_t sent = rte_eth_tx_burst(wire_port, 0, packets, (uint16_t)count);
        bridge->from_host += sent; bridge->wire_dropped += count - sent;
        for (unsigned i = sent; i < count; i++) rte_pktmbuf_free(packets[i]);
    }
    return result < 0 && result != -EAGAIN && result != -EWOULDBLOCK && result != -EINTR &&
        result != -EMSGSIZE && result != -EINVAL && result != -E2BIG ? result : 0;
}
#ifdef KER_SESSION_TEST_HOOKS
static void session_test_hold(const char *environment)
{
    const char *path = getenv(environment);
    if (path && access(path, F_OK) == 0) raise(SIGSTOP);
}
#endif
int ker_worker_exception_session_enqueue(struct ker_worker_exception *bridge, struct rte_mbuf *packet, bool to_native)
{
    if (!owner(bridge) || !bridge->session_shared || !packet || bridge->session_busy ||
        packet != bridge->session_lease_packet || packet->pool != bridge->pool || packet->nb_segs != 1)
        return -EPERM;
    if (rte_ring_enqueue(bridge->pending, packet)) return -ENOBUFS;
    bridge->session_busy = true; bridge->session_to_native = to_native;
    if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 1, memory_order_release);
    bridge->selected++; bridge->enqueued++;
    return 0;
}
int ker_worker_exception_session_poll(struct ker_worker_exception *bridge, uint16_t port, unsigned mtu, bool *progress)
{
    if (!owner(bridge) || !bridge->session_shared || !progress || mtu < KER_NATIVE_MIN_MTU || mtu > KER_NATIVE_MAX_MTU)
        return -EINVAL;
    struct rte_mbuf *packet = bridge->session_lease_packet;
    if (!packet || packet->pool != bridge->pool || packet->nb_segs != 1) return -EUCLEAN;
    if (bridge->session_native_pending) return 0;
    if (bridge->session_busy && !bridge->session_tx_pending) {
        struct rte_mbuf *queued = NULL;
        if (rte_ring_dequeue(bridge->pending, (void **)&queued)) return 0;
        if (queued != packet) return -EUCLEAN;
        if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 2, memory_order_release);
#ifdef KER_SESSION_TEST_HOOKS
        session_test_hold("KER_SESSION_TEST_HOLD_EXCEPTION_WRITE");
#endif
        int result = host_write(bridge->fd, packet, mtu);
        if (result == -EAGAIN || result == -EWOULDBLOCK || result == -EINTR) {
            if (rte_ring_enqueue(bridge->pending, packet)) return -EUCLEAN;
            if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 1, memory_order_release);
            return 0;
        }
        /* A nontransient error may follow partial delivery: retain phase 2. */
        if (result) return result;
        bridge->to_host++;
        if (bridge->session_to_native) {
            bridge->session_native_pending = true;
            if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 7, memory_order_release);
            *progress = true;
            return 3; /* TAP copy completed; the same lease still must reach native RX. */
        }
        bridge->session_busy = false;
        if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 0, memory_order_release);
        *progress = true;
        return 1; /* TAP copied the complete host-only frame. */
    }
    if (!bridge->session_busy) {
        struct pollfd event = {.fd=bridge->fd,.events=POLLIN};
        int ready;
        do ready = poll(&event, 1, 0); while (ready < 0 && errno == EINTR);
        if (ready < 0) return -errno;
        if (!ready) return 0;
        if (event.revents & (POLLERR | POLLHUP | POLLNVAL)) return -EIO;
        if (!(event.revents & POLLIN)) return 0;
        if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 3, memory_order_release);
        unsigned char bytes[EXCEPTION_FRAME + 1];
        ssize_t length = read(bridge->fd, bytes, sizeof(bytes));
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 0, memory_order_release);
                return 0;
            }
            return -errno;
        }
        unsigned l2 = length >= 14 && bytes[12] == 0x81 && bytes[13] == 0 ? 18 : 14;
        if (length < (ssize_t)l2 || length > (ssize_t)(mtu + l2)) return -EMSGSIZE;
        rte_pktmbuf_reset(packet);
        void *data = rte_pktmbuf_append(packet, (uint16_t)length);
        if (!data) return -ENOSPC;
        memcpy(data, bytes, (size_t)length);
        bridge->session_busy = true; bridge->session_tx_pending = true;
        if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 4, memory_order_release);
        *progress = true;
    }
    if (bridge->session_tx_pending) {
        if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 4, memory_order_release);
        if (rte_eth_tx_burst(port, 0, &packet, 1) != 1) return 0;
        bridge->session_tx_pending = false; bridge->from_host++;
        if (bridge->session_phase) atomic_store_explicit(bridge->session_phase, 5, memory_order_release);
        *progress = true;
        return 2; /* Same journaled RX mbuf enters the fixed PMD TX ring. */
    }
    return 0;
}
int ker_worker_exception_session_reclaim(struct ker_worker_exception *bridge, struct rte_mbuf *expected)
{
    if (!owner(bridge) || !bridge->session_keeper || !bridge->session_shared || !expected) return -EPERM;
    struct rte_mbuf *packet = NULL;
    unsigned count = 0;
    while (!rte_ring_dequeue(bridge->pending, (void **)&packet)) {
        if (packet != expected || ++count > 1) return -EUCLEAN;
    }
    return (int)count;
}
int ker_worker_exception_close(struct ker_worker_exception *bridge)
{
    if (!bridge || !bridge->pending) return 0;
    if (!owner(bridge)) return -EXDEV;
    if (bridge->session_shared && !bridge->session_keeper) {
        int result = close(bridge->fd); bridge->fd = -1; bridge->pending = NULL;
        return result ? -errno : 0;
    }
    void *packet;
    while (!rte_ring_dequeue(bridge->pending, &packet)) {
        rte_pktmbuf_free(packet); bridge->shutdown_dropped++;
    }
    rte_ring_free(bridge->pending); bridge->pending = NULL;
    int result = close(bridge->fd); bridge->fd = -1;
    return result ? -errno : 0;
}
