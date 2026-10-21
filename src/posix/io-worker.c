#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "packet-channel.h"
#include "pcap.h"
#include "worker-log.h"
#include "worker-clock.h"
#include "worker-mbuf.h"
#include "worker-wait.h"
#include "worker-tx.h"
#include "worker-rx-drain.h"
#include "worker-scatter.h"
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_memory.h>

/* This process transports Ethernet frames only. All socket/TCP behavior runs
 * in the separate imported Linux instance in the application process. */
#define BURST 32
#define WIRE_MAX (KER_NATIVE_MAX_MTU + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN)
static volatile sig_atomic_t stopping;
static void stop_worker(int signal_number) { (void)signal_number; stopping = 1; }

struct ker_worker_rx_queue {
    uint16_t port;
    uint16_t queue;
};

static uint16_t worker_rx_burst(void *context, struct rte_mbuf **packets,
    uint16_t capacity)
{
    const struct ker_worker_rx_queue *queue = context;
    return rte_eth_rx_burst(queue->port, queue->queue, packets, capacity);
}

static void worker_rx_free(void *context, struct rte_mbuf *packet)
{
    (void)context;
    rte_pktmbuf_free(packet);
}
static int number(const char *text)
{
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || *end || value < 0 || value > INT32_MAX) return -1;
    return (int)value;
}
static bool frame_size_supported(const unsigned char *bytes, size_t length, int mtu)
{
    if (length < RTE_ETHER_HDR_LEN) return false;
    bool tagged = bytes[12] == 0x81 && bytes[13] == 0x00;
    size_t header = RTE_ETHER_HDR_LEN + (tagged ? RTE_VLAN_HLEN : 0);
    return length >= header && length <= (size_t)mtu + header;
}
static bool metadata_supported(const struct rte_mbuf *packet)
{
    const uint64_t changed = RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_QINQ_STRIPPED |
        RTE_MBUF_F_RX_LRO | RTE_MBUF_F_RX_SEC_OFFLOAD | RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED;
    return !(packet->ol_flags & changed) &&
        (packet->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) != RTE_MBUF_F_RX_IP_CKSUM_NONE &&
        (packet->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) != RTE_MBUF_F_RX_L4_CKSUM_NONE;
}

static uint16_t tx_burst(void *context, struct rte_mbuf **packets, uint16_t count)
{
    return rte_eth_tx_burst(*(uint16_t *)context, 0, packets, count);
}

int main(int argc, char **argv)
{
    int packet_fd = -1, control_fd = -1, split = 0;
    bool numa = true, all_multicast = false, pcap_nsec = false, log_level_set = false;
    const char *pcap_dir = NULL, *log_dir = NULL;
    int idle_sleep_us = 1000, tx_delay_us = 0;
    int promiscuous = -1;
    int log_level = -1, mtu = KER_NATIVE_DEFAULT_MTU;
    int pcap_snaplen = 65535, pcap_maximum = 16 * 1024 * 1024;
    const char *port_name = NULL, *mbuf_mode = "large";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) { split = i; break; }
        if (!strcmp(argv[i], "--numa")) { numa = true; continue; }
        if (!strcmp(argv[i], "--no-numa")) { numa = false; continue; }
        if (!strcmp(argv[i], "--promiscuous")) { promiscuous = 1; continue; }
        if (!strcmp(argv[i], "--no-promiscuous")) { promiscuous = 0; continue; }
        if (!strcmp(argv[i], "--all-multicast")) { all_multicast = true; continue; }
        if (!strcmp(argv[i], "--pcap-nsec")) { pcap_nsec = true; continue; }
        if (i + 1 >= argc) break;
        if (!strcmp(argv[i], "--tx-delay-us")) tx_delay_us = number(argv[++i]);
        else if (!strcmp(argv[i], "--idle-sleep-us")) idle_sleep_us = number(argv[++i]);
        else if (!strcmp(argv[i], "--packet-fd")) packet_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--control-fd")) control_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--port")) port_name = argv[++i];
        else if (!strcmp(argv[i], "--mbuf-mode")) mbuf_mode = argv[++i];
        else if (!strcmp(argv[i], "--mtu")) mtu = number(argv[++i]);
        else if (!strcmp(argv[i], "--log-dir")) log_dir = argv[++i];
        else if (!strcmp(argv[i], "--log-level")) { log_level = number(argv[++i]); log_level_set = true; }
        else if (!strcmp(argv[i], "--pcap-dir")) pcap_dir = argv[++i];
        else if (!strcmp(argv[i], "--pcap-snaplen")) pcap_snaplen = number(argv[++i]);
        else if (!strcmp(argv[i], "--pcap-max-bytes")) pcap_maximum = number(argv[++i]);
        else break;
    }
    if (tx_delay_us < 0 || tx_delay_us > 100 || idle_sleep_us < 0 || idle_sleep_us > 100000 || (strcmp(mbuf_mode, "large") && strcmp(mbuf_mode, "scatter")) || mtu < KER_NATIVE_MIN_MTU || mtu > KER_NATIVE_MAX_MTU || packet_fd < 0 || control_fd < 0 || !port_name || !split || pcap_snaplen <= 0 || pcap_maximum <= 0 ||
        (log_level_set && (log_level < (int)RTE_LOG_EMERG || log_level > (int)RTE_LOG_DEBUG))) {
        fprintf(stderr, "usage: ker-io-worker --packet-fd N --control-fd N --port NAME [--mtu 1280..9000] [--mbuf-mode large|scatter] [--numa|--no-numa] [--all-multicast] [--idle-sleep-us 0..100000] [--tx-delay-us 0..100] [--promiscuous|--no-promiscuous] [--log-dir DIR] [--log-level 1..8] [--pcap-dir DIR] [--pcap-snaplen N] [--pcap-max-bytes N] [--pcap-nsec] -- EAL_ARGS\n");
        return 2;
    }
    if (fcntl(packet_fd, F_SETFL, O_NONBLOCK) || fcntl(control_fd, F_SETFL, O_NONBLOCK)) {
        perror("ker packet/control channel"); return 1;
    }
    struct sigaction action = {.sa_handler = stop_worker};
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    signal(SIGPIPE, SIG_IGN);
    struct ker_worker_log log = {0};
    if (log_dir && ker_worker_log_open(&log, log_dir, (unsigned int)getpid(),
            log_level < 0 ? RTE_LOG_INFO : (uint32_t)log_level)) {
        perror("ker: open worker log"); return 1;
    }
    argv[split] = argv[0];
    if (rte_eal_init(argc - split, argv + split) < 0) {
        fprintf(stderr, "ker EAL: %s\n", rte_strerror(rte_errno));
        if (ker_worker_log_close(&log)) perror("ker: close worker log");
        return 1;
    }
    if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
        fprintf(stderr, "ker: secondary EAL processes are unsupported\n");
        if (ker_worker_log_close(&log)) perror("ker: close worker log");
        rte_eal_cleanup(); return 1;
    }
    if (log_level >= 0) {
        ker_worker_log_global_level((uint32_t)log_level);
        if (log_dir) ker_worker_log_level(log.type, (uint32_t)log_level);
    }
    if (log.file && ferror(log.file)) {
        fprintf(stderr, "ker: write worker log failed during EAL startup\n");
        if (ker_worker_log_close(&log)) perror("ker: close worker log");
        rte_eal_cleanup(); return 1;
    }
    uint16_t port = UINT16_MAX;
    bool started = false, configured = false;
    struct rte_mempool *pool = NULL;
    struct rte_mbuf *pending_tx = NULL, *rx[BURST] = {0};
    uint16_t rx_count = 0, rx_index = 0;
    struct ker_pcap tx_capture = {0}, rx_capture = {0};
    uint64_t transmitted = 0, received = 0, tx_dropped = 0, rx_dropped = 0, tx_retries = 0, rx_retries = 0;
    uint64_t transmitted_bytes = 0, received_bytes = 0, tx_multiseg = 0, rx_multiseg = 0;
    uint64_t rx_startup_discarded = 0, idle_waits = 0, idle_timeouts = 0;
    unsigned char tx_bytes[sizeof(struct ker_packet_header) + WIRE_MAX], rx_bytes[WIRE_MAX];
    struct ker_worker_tx batch = {0};
    uint64_t tx_flushes = 0, tx_timer_flushes = 0, tx_full_flushes = 0, tx_drain_flushes = 0;
    size_t tx_length = 0;
    int status = 1, tx_capture_status, rx_capture_status;
    bool draining = false;
    uint64_t stop_requests = 0;
    bool control_eof = false;
    int64_t drain_started = 0, drain_progress = 0;
    if (rte_eth_dev_get_port_by_name(port_name, &port)) {
        fprintf(stderr, "ker: unknown ethdev %s\n", port_name); goto cleanup;
    }
    struct rte_eth_conf conf = {0}; /* No checksum, VLAN, LRO, or TSO offloads. */
    bool scatter = !strcmp(mbuf_mode, "scatter");
    if (scatter) {
        struct rte_eth_dev_info info;
        int result = rte_eth_dev_info_get(port, &info);
        if (result || !(info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) ||
            !(info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) {
            fprintf(stderr, "ker: ethdev cannot support scatter RX and multi-segment TX\n");
            goto cleanup;
        }
        uint32_t rx_overhead = ker_worker_rx_eth_overhead(&info);
        uint64_t required_rx_segments = ker_worker_rx_required_segments((uint32_t)mtu,
            rx_overhead);
        uint16_t rx_segment_limit = info.rx_desc_lim.nb_mtu_seg_max;
        if (!ker_worker_rx_limits_support(required_rx_segments, rx_segment_limit)) {
            fprintf(stderr, "ker: scatter MTU %d requires %llu RX segments with %u-byte device overhead, ethdev rx_desc_lim.nb_mtu_seg_max=%u\n",
                mtu, (unsigned long long)required_rx_segments, rx_overhead,
                rx_segment_limit);
            goto cleanup;
        }
        uint16_t required_segments = ker_worker_scatter_required_segments((uint32_t)mtu);
        if (!ker_worker_scatter_limits_support(required_segments,
                info.tx_desc_lim.nb_seg_max, info.tx_desc_lim.nb_mtu_seg_max)) {
            fprintf(stderr, "ker: scatter MTU %d with VLAN header requires %u TX segments, ethdev limits are nb_seg_max=%u nb_mtu_seg_max=%u\n",
                mtu, required_segments, info.tx_desc_lim.nb_seg_max,
                info.tx_desc_lim.nb_mtu_seg_max);
            goto cleanup;
        }
        conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_SCATTER;
        conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    }
    if (rte_eth_dev_configure(port, 1, 1, &conf)) goto device_error;
    configured = true;
    if (rte_eth_dev_set_mtu(port, (uint16_t)mtu)) goto device_error;
    uint16_t rx_desc = 256, tx_desc = 256;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc)) goto device_error;
    /* Match F-Stack numa_on: lcore-local allocations, or explicit socket 0. */
    unsigned int allocation_socket = numa ? rte_socket_id() : 0;
    pool = rte_pktmbuf_pool_create("ker_native_packets", 4095, 0, 0,
        (uint16_t)(scatter ? RTE_MBUF_DEFAULT_BUF_SIZE : RTE_MAX(RTE_MBUF_DEFAULT_BUF_SIZE, mtu + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN + RTE_PKTMBUF_HEADROOM)), allocation_socket);
    if (!pool) { fprintf(stderr, "ker packet pool: %s\n", rte_strerror(rte_errno)); goto cleanup; }
    if (rte_eth_rx_queue_setup(port, 0, rx_desc, allocation_socket, NULL, pool) ||
        rte_eth_tx_queue_setup(port, 0, tx_desc, allocation_socket, NULL) ||
        rte_eth_dev_start(port)) goto device_error;
    started = true;
    if (promiscuous >= 0) {
        int result = promiscuous ? rte_eth_promiscuous_enable(port) : rte_eth_promiscuous_disable(port);
        if (result) {
            fprintf(stderr, "ker: ethdev cannot configure promiscuous mode: %s\n", rte_strerror(-result));
            goto cleanup;
        }
        result = rte_eth_promiscuous_get(port);
        if (result != promiscuous) {
            fprintf(stderr, "ker: ethdev did not apply promiscuous mode (requested %d, observed %d)\n",
                promiscuous, result);
            goto cleanup;
        }
    }
    if (promiscuous == 0) {
        /* Device start precedes the explicit mode switch and can queue frames
         * while the PMD is promiscuous. Do not expose that backlog after READY. */
        struct ker_worker_rx_queue queue = {.port = port, .queue = 0};
        int result = ker_worker_rx_drain(worker_rx_burst, worker_rx_free,
            &queue, rx_desc, &rx_startup_discarded);
        rx_dropped += rx_startup_discarded;
        if (result) {
            fprintf(stderr, "ker: ethdev RX queue could not be proven empty after the %u-packet startup budget: %s\n",
                rx_desc, rte_strerror(-result));
            goto cleanup;
        }
    }
    int promiscuous_state = rte_eth_promiscuous_get(port);
    /* Membership filtering belongs to Linux. Until its receive-mode updates
     * cross the packet channel, opt in to PMD all-multicast reception. */
    if (all_multicast) {
        int result = rte_eth_allmulticast_enable(port);
        if (result) {
            fprintf(stderr, "ker: ethdev cannot enable --all-multicast: %s\n", rte_strerror(-result));
            goto cleanup;
        }
        if (rte_eth_allmulticast_get(port) != 1) {
            fprintf(stderr, "ker: ethdev did not enable --all-multicast\n");
            goto cleanup;
        }
    }
    if (pcap_dir && (ker_pcap_open(&tx_capture, pcap_dir, "ker-tx", pcap_snaplen,
            pcap_maximum, pcap_nsec) || ker_pcap_open(&rx_capture, pcap_dir,
            "ker-rx", pcap_snaplen, pcap_maximum, pcap_nsec))) {
        perror("ker: open packet capture"); goto cleanup;
    }
    struct rte_ether_addr mac;
    if (rte_eth_macaddr_get(port, &mac)) goto device_error;
    if (log_dir && ker_worker_log(RTE_LOG_INFO, log.type, "ker.io ready port=%s\n", port_name) < 0) {
        perror("ker: write worker log"); goto cleanup;
    }
    struct rte_eth_link link = {0};
    int link_status = rte_eth_link_get_nowait(port, &link);
    printf("KER_IO_READY {\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"mtu\":%u,"
        "\"mbuf_mode\":\"%s\",\"port_id\":%u,\"port_count\":%u,\"socket_id\":%d,"
        "\"process_type\":\"primary\",\"numa\":%s,\"lcore_socket_id\":%u,\"allocation_socket_id\":%u,\"pool_socket_id\":%d,\"memory_bytes\":%llu,\"hugepages\":%s,\"memory_channels\":%u,\"lcore_count\":%u,\"main_lcore\":%u,\"main_cpu\":%d,\"link_up\":%s,\"promiscuous\":%s,\"idle_sleep_us\":%d,\"tx_delay_us\":%d}\n",
        mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2], mac.addr_bytes[3],
        mac.addr_bytes[4], mac.addr_bytes[5], (unsigned int)mtu, mbuf_mode, port, rte_eth_dev_count_avail(),
        rte_eth_dev_socket_id(port), numa ? "true" : "false", rte_socket_id(), allocation_socket, pool->socket_id, (unsigned long long)rte_eal_get_physmem_size(),
        rte_eal_has_hugepages() ? "true" : "false", rte_memory_get_nchannel(), rte_lcore_count(), rte_get_main_lcore(), sched_getcpu(), link_status ? "null" : (link.link_status ? "true" : "false"),
        promiscuous_state < 0 ? "null" : (promiscuous_state ? "true" : "false"), idle_sleep_us, tx_delay_us);
    fflush(stdout);
    status = 0;
    while (!stopping) {
        char commands[256];
        ssize_t control;
        size_t control_budget = 4096;
        do {
            size_t read_size = control_budget < sizeof(commands) ? control_budget : sizeof(commands);
            control = read(control_fd, commands, read_size);
            if (control > 0) {
                stop_requests += (uint64_t)control;
                control_budget -= (size_t)control;
            }
        } while (control > 0 && control_budget);
        if (control < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { status = 1; break; }
        if (control == 0) control_eof = true;
        if ((control == 0 || stop_requests) && !draining) {
            draining = true;
            if (ker_worker_now_ns(&drain_started)) goto clock_error;
            drain_progress = drain_started;
        }
        bool progress = false;
        int reclaimed = rte_eth_tx_done_cleanup(port, 0, 0);
        if (reclaimed < 0 && reclaimed != -ENOTSUP) { status = 1; break; }
        for (unsigned int budget = 0; budget < BURST && batch.count < KER_WORKER_TX_CAPACITY && !batch.retrying; ++budget) {
            if (!pending_tx) {
                if (!tx_length) {
                    ssize_t count = recv(packet_fd, tx_bytes, sizeof(tx_bytes), MSG_DONTWAIT | MSG_TRUNC);
                    if (count < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) status = 1;
                        break;
                    }
                    if (count < (ssize_t)(sizeof(struct ker_packet_header) + RTE_ETHER_HDR_LEN) ||
                        count > (ssize_t)(sizeof(struct ker_packet_header) + mtu + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN)) { tx_dropped++; continue; }
                    struct ker_packet_header header;
                    memcpy(&header, tx_bytes, sizeof(header));
                    if (header.flags || header.gso_type || header.header_length || header.gso_size ||
                        header.checksum_start || header.checksum_offset) {
                        fprintf(stderr, "ker: native device requested unsupported TX offload\n");
                        status = 1; break;
                    }
                    tx_length = (size_t)count - sizeof(header);
                    if (!frame_size_supported(tx_bytes + sizeof(header), tx_length, mtu)) {
                        tx_length = 0; tx_dropped++; continue;
                    }
                }
                pending_tx = ker_worker_mbuf_from_bytes(pool, tx_bytes + sizeof(struct ker_packet_header), tx_length);
                if (!pending_tx) { tx_retries++; break; }
                /* Capture once before PMD ownership transfer, not on retries. */
                if (pcap_dir) {
                    struct timespec timestamp;
                    if (clock_gettime(CLOCK_REALTIME, &timestamp) ||
                        ker_pcap_write(&tx_capture, pending_tx, &timestamp)) {
                        perror("ker: TX packet capture"); status = 1; break;
                    }
                }
            }
            int64_t queued_at = 0;
            if (tx_delay_us && !batch.count && ker_worker_now_ns(&queued_at)) goto clock_error;
            if (!ker_worker_tx_append(&batch, pending_tx, queued_at)) { status = 1; break; }
            pending_tx = NULL;
            tx_length = 0;
            progress = true;
        }
        if (status) break;
        int64_t tx_now = 0;
        if (batch.count && tx_delay_us && ker_worker_now_ns(&tx_now)) goto clock_error;
        if (batch.count && (draining || !ker_worker_tx_wait_us(&batch, tx_delay_us, tx_now))) {
            tx_flushes++;
            if (draining) tx_drain_flushes++;
            if (batch.count == KER_WORKER_TX_CAPACITY) tx_full_flushes++;
            else if (!draining && !batch.retrying && tx_delay_us) tx_timer_flushes++;
            struct ker_worker_tx_result sent = ker_worker_tx_flush(&batch, tx_burst, &port);
            transmitted += sent.packets;
            transmitted_bytes += sent.bytes;
            tx_multiseg += sent.multiseg;
            if (batch.count) tx_retries++;
            if (sent.packets) progress = true;
        }
        if (draining) {
            while (rx_index < rx_count) rte_pktmbuf_free(rx[rx_index++]);
            int64_t now;
            if (ker_worker_now_ns(&now)) goto clock_error;
            if (progress) drain_progress = now;
            if (!pending_tx && !tx_length && !batch.count && now - drain_progress >= INT64_C(5000000)) break;
            if (now - drain_started >= INT64_C(500000000)) { status = 1; break; }
            if (!progress) usleep(1000);
            continue;
        }
        if (rx_index == rx_count) {
            rx_count = rte_eth_rx_burst(port, 0, rx, BURST);
            rx_index = 0;
            /* Each received frame is captured once, even if channel delivery
             * later retries or metadata validation rejects it. */
            if (pcap_dir) for (uint16_t i = 0; i < rx_count; ++i) {
                struct timespec timestamp;
                if (clock_gettime(CLOCK_REALTIME, &timestamp) ||
                    ker_pcap_write(&rx_capture, rx[i], &timestamp)) {
                    perror("ker: RX packet capture"); status = 1; break;
                }
            }
            if (status) break;
        }
        while (rx_index < rx_count) {
            struct rte_mbuf *packet = rx[rx_index];
            uint32_t length = packet->pkt_len;
            const void *bytes = NULL;
            if (length >= RTE_ETHER_HDR_LEN && length <= (uint32_t)mtu + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN && metadata_supported(packet))
                bytes = rte_pktmbuf_read(packet, 0, length, rx_bytes);
            if (bytes && frame_size_supported(bytes, length, mtu)) {
                struct ker_packet_header header = {0};
                struct iovec vectors[] = {{&header, sizeof(header)}, {(void *)bytes, length}};
                struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
                ssize_t count = sendmsg(packet_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                    rx_retries++; break; /* Retain the complete FIFO suffix. */
                }
                if (count < 0 && (errno == ECONNREFUSED || errno == EPIPE || errno == ENOTCONN)) {
                    draining = true;
                    if (ker_worker_now_ns(&drain_started)) goto clock_error;
                    drain_progress = drain_started;
                    break;
                }
                if (count != (ssize_t)(length + sizeof(header))) { status = 1; break; }
                if (packet->nb_segs > 1) rx_multiseg++;
                received++;
                received_bytes += length;
            } else rx_dropped++;
            rte_pktmbuf_free(packet);
            rx[rx_index++] = NULL;
            progress = true;
        }
        if (status) break;
        if (!progress) {
            short packet_events;
            int wait_us;
            ker_worker_wait_plan(idle_sleep_us,
                pending_tx != NULL || tx_length != 0 || batch.retrying, rx_index < rx_count,
                &packet_events, &wait_us);
            if (batch.count && !batch.retrying) {
                if (ker_worker_now_ns(&tx_now)) goto clock_error;
                int remaining_us = ker_worker_tx_wait_us(&batch, tx_delay_us, tx_now);
                if (wait_us > remaining_us) wait_us = remaining_us;
            }
            struct pollfd fds[] = {{control_fd, POLLIN, 0}, {packet_fd, packet_events, 0}};
            /* Ethernet PMD RX has no channel readiness notification. Idle
             * channel TX and control wake ppoll; retained work uses bounded
             * retries and RX suffixes watch channel writability. Linux owns
             * protocol timers. */
            struct timespec timeout = {.tv_nsec = (long)wait_us * 1000};
            idle_waits++;
            int result = ppoll(fds, 2, &timeout, NULL);
            if (!result) idle_timeouts++;
            else if (result < 0 && errno != EINTR) { perror("ker: idle wait"); status = 1; break; }
        }
    }
    goto cleanup;
clock_error:
    perror("ker: worker monotonic clock");
    status = 1;
    goto cleanup;
device_error:
    fprintf(stderr, "ker: ethdev initialization failed for %s\n", port_name);
cleanup:
    tx_capture_status = ker_pcap_close(&tx_capture);
    rx_capture_status = ker_pcap_close(&rx_capture);
    if (tx_capture_status || rx_capture_status) { perror("ker: close packet capture"); status = 1; }
    if (pending_tx) rte_pktmbuf_free(pending_tx);
    ker_worker_tx_discard(&batch);
    while (rx_index < rx_count) rte_pktmbuf_free(rx[rx_index++]);
    if (started && rte_eth_dev_stop(port)) status = 1;
    if (configured && rte_eth_dev_close(port)) status = 1;
    unsigned int outstanding = pool ? rte_mempool_in_use_count(pool) : 0;
    if (outstanding) {
        fprintf(stderr, "ker: %u packet buffers still owned after ethdev shutdown\n", outstanding);
        status = 1;
    } else if (pool) rte_mempool_free(pool);
    printf("KER_IO_DONE {\"tx\":%llu,\"rx\":%llu,\"dropped\":%llu,\"tx_retries\":%llu,"
        "\"rx_retries\":%llu,\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"tx_dropped\":%llu,\"rx_dropped\":%llu,\"outstanding\":%u,"
        "\"stop_requests\":%llu,\"control_eof\":%s,\"tx_multiseg\":%llu,\"rx_multiseg\":%llu,\"rx_startup_discarded\":%llu,\"idle_waits\":%llu,\"idle_timeouts\":%llu,\"tx_flushes\":%llu,\"tx_timer_flushes\":%llu,\"tx_full_flushes\":%llu,\"tx_drain_flushes\":%llu}\n", (unsigned long long)transmitted,
        (unsigned long long)received, (unsigned long long)(tx_dropped + rx_dropped),
        (unsigned long long)tx_retries, (unsigned long long)rx_retries,
        (unsigned long long)transmitted_bytes, (unsigned long long)received_bytes,
        (unsigned long long)tx_dropped, (unsigned long long)rx_dropped, outstanding,
        (unsigned long long)stop_requests, control_eof ? "true" : "false",
        (unsigned long long)tx_multiseg, (unsigned long long)rx_multiseg,
        (unsigned long long)rx_startup_discarded, (unsigned long long)idle_waits,
        (unsigned long long)idle_timeouts, (unsigned long long)tx_flushes,
        (unsigned long long)tx_timer_flushes, (unsigned long long)tx_full_flushes,
        (unsigned long long)tx_drain_flushes);
    fflush(stdout);
    if (log_dir && ker_worker_log(RTE_LOG_INFO, log.type, "ker.io stopped status=%d\n", status) < 0) status = 1;
    if (ker_worker_log_close(&log)) { perror("ker: close worker log"); status = 1; }
    if (rte_eal_cleanup()) status = 1;
    close(packet_fd);
    close(control_fd);
    return status;
}
