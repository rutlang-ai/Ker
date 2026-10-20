#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
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
#include <rte_log.h>

/* This process transports Ethernet frames only. All socket/TCP behavior runs
 * in the separate imported Linux instance in the application process. */
#define BURST 32
#define MTU 1500
#define WIRE_MAX (MTU + RTE_ETHER_HDR_LEN)
static volatile sig_atomic_t stopping;
static void stop_worker(int signal_number) { (void)signal_number; stopping = 1; }
static int64_t now_ns(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}
static int number(const char *text)
{
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || *end || value < 0 || value > INT32_MAX) return -1;
    return (int)value;
}
static bool metadata_supported(const struct rte_mbuf *packet)
{
    const uint64_t changed = RTE_MBUF_F_RX_VLAN_STRIPPED | RTE_MBUF_F_RX_QINQ_STRIPPED |
        RTE_MBUF_F_RX_LRO | RTE_MBUF_F_RX_SEC_OFFLOAD | RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED;
    return !(packet->ol_flags & changed) &&
        (packet->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK) != RTE_MBUF_F_RX_IP_CKSUM_NONE &&
        (packet->ol_flags & RTE_MBUF_F_RX_L4_CKSUM_MASK) != RTE_MBUF_F_RX_L4_CKSUM_NONE;
}

int main(int argc, char **argv)
{
    int packet_fd = -1, control_fd = -1, split = 0;
    bool all_multicast = false, pcap_nsec = false, log_level_set = false;
    const char *pcap_dir = NULL, *log_dir = NULL;
    int log_level = -1;
    int pcap_snaplen = 65535, pcap_maximum = 16 * 1024 * 1024;
    const char *port_name = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) { split = i; break; }
        if (!strcmp(argv[i], "--all-multicast")) { all_multicast = true; continue; }
        if (!strcmp(argv[i], "--pcap-nsec")) { pcap_nsec = true; continue; }
        if (i + 1 >= argc) break;
        if (!strcmp(argv[i], "--packet-fd")) packet_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--control-fd")) control_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--port")) port_name = argv[++i];
        else if (!strcmp(argv[i], "--log-dir")) log_dir = argv[++i];
        else if (!strcmp(argv[i], "--log-level")) { log_level = number(argv[++i]); log_level_set = true; }
        else if (!strcmp(argv[i], "--pcap-dir")) pcap_dir = argv[++i];
        else if (!strcmp(argv[i], "--pcap-snaplen")) pcap_snaplen = number(argv[++i]);
        else if (!strcmp(argv[i], "--pcap-max-bytes")) pcap_maximum = number(argv[++i]);
        else break;
    }
    if (packet_fd < 0 || control_fd < 0 || !port_name || !split || pcap_snaplen <= 0 || pcap_maximum <= 0 ||
        (log_level_set && (log_level < (int)RTE_LOG_EMERG || log_level > (int)RTE_LOG_DEBUG))) {
        fprintf(stderr, "usage: ker-io-worker --packet-fd N --control-fd N --port NAME [--all-multicast] [--log-dir DIR] [--log-level 1..8] [--pcap-dir DIR] [--pcap-snaplen N] [--pcap-max-bytes N] [--pcap-nsec] -- EAL_ARGS\n");
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
    uint64_t transmitted = 0, received = 0, dropped = 0, tx_retries = 0, rx_retries = 0;
    unsigned char tx_bytes[sizeof(struct ker_packet_header) + WIRE_MAX], rx_bytes[WIRE_MAX];
    size_t tx_length = 0;
    int status = 1, tx_capture_status, rx_capture_status;
    bool draining = false;
    int64_t drain_started = 0, drain_progress = 0;
    if (rte_eth_dev_get_port_by_name(port_name, &port)) {
        fprintf(stderr, "ker: unknown ethdev %s\n", port_name); goto cleanup;
    }
    struct rte_eth_conf conf = {0}; /* No checksum, VLAN, LRO, or TSO offloads. */
    if (rte_eth_dev_configure(port, 1, 1, &conf)) goto device_error;
    configured = true;
    if (rte_eth_dev_set_mtu(port, MTU)) goto device_error;
    uint16_t rx_desc = 256, tx_desc = 256;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc)) goto device_error;
    pool = rte_pktmbuf_pool_create("ker_native_packets", 4095, 0, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) { fprintf(stderr, "ker packet pool: %s\n", rte_strerror(rte_errno)); goto cleanup; }
    if (rte_eth_rx_queue_setup(port, 0, rx_desc, rte_socket_id(), NULL, pool) ||
        rte_eth_tx_queue_setup(port, 0, tx_desc, rte_socket_id(), NULL) ||
        rte_eth_dev_start(port)) goto device_error;
    started = true;
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
        "\"port_id\":%u,\"port_count\":%u,\"socket_id\":%d,"
        "\"process_type\":\"primary\",\"link_up\":%s}\n",
        mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2], mac.addr_bytes[3],
        mac.addr_bytes[4], mac.addr_bytes[5], MTU, port, rte_eth_dev_count_avail(),
        rte_eth_dev_socket_id(port), link_status ? "null" : (link.link_status ? "true" : "false"));
    fflush(stdout);
    status = 0;
    while (!stopping) {
        char command;
        ssize_t control = read(control_fd, &command, 1);
        if ((!control || control > 0) && !draining) {
            draining = true;
            drain_started = drain_progress = now_ns();
        }
        if (control < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { status = 1; break; }
        bool progress = false;
        int reclaimed = rte_eth_tx_done_cleanup(port, 0, 0);
        if (reclaimed < 0 && reclaimed != -ENOTSUP) { status = 1; break; }
        for (unsigned int budget = 0; budget < BURST; ++budget) {
            if (!pending_tx) {
                if (!tx_length) {
                    ssize_t count = recv(packet_fd, tx_bytes, sizeof(tx_bytes), MSG_DONTWAIT | MSG_TRUNC);
                    if (count < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) status = 1;
                        break;
                    }
                    if (count < (ssize_t)(sizeof(struct ker_packet_header) + RTE_ETHER_HDR_LEN) ||
                        count > (ssize_t)sizeof(tx_bytes)) { dropped++; continue; }
                    struct ker_packet_header header;
                    memcpy(&header, tx_bytes, sizeof(header));
                    if (header.flags || header.gso_type || header.header_length || header.gso_size ||
                        header.checksum_start || header.checksum_offset) {
                        fprintf(stderr, "ker: native device requested unsupported TX offload\n");
                        status = 1; break;
                    }
                    tx_length = (size_t)count - sizeof(header);
                }
                pending_tx = rte_pktmbuf_alloc(pool);
                if (!pending_tx) { tx_retries++; break; }
                void *bytes = rte_pktmbuf_append(pending_tx, tx_length);
                if (!bytes) { status = 1; break; }
                memcpy(bytes, tx_bytes + sizeof(struct ker_packet_header), tx_length);
                /* Capture once before PMD ownership transfer, not on retries. */
                if (pcap_dir) {
                    struct timespec timestamp;
                    if (clock_gettime(CLOCK_REALTIME, &timestamp) ||
                        ker_pcap_write(&tx_capture, pending_tx, &timestamp)) {
                        perror("ker: TX packet capture"); status = 1; break;
                    }
                }
            }
            if (rte_eth_tx_burst(port, 0, &pending_tx, 1) != 1) { tx_retries++; break; }
            pending_tx = NULL; /* PMD owns accepted mbufs, including deferred frees. */
            tx_length = 0;
            transmitted++;
            progress = true;
        }
        if (status) break;
        if (draining) {
            while (rx_index < rx_count) rte_pktmbuf_free(rx[rx_index++]);
            if (progress) drain_progress = now_ns();
            int64_t now = now_ns();
            if (!pending_tx && !tx_length && now - drain_progress >= INT64_C(5000000)) break;
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
            if (length >= RTE_ETHER_HDR_LEN && length <= WIRE_MAX && metadata_supported(packet))
                bytes = rte_pktmbuf_read(packet, 0, length, rx_bytes);
            if (bytes) {
                struct ker_packet_header header = {0};
                struct iovec vectors[] = {{&header, sizeof(header)}, {(void *)bytes, length}};
                struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
                ssize_t count = sendmsg(packet_fd, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                    rx_retries++; break; /* Retain the complete FIFO suffix. */
                }
                if (count < 0 && (errno == ECONNREFUSED || errno == EPIPE || errno == ENOTCONN)) {
                    draining = true;
                    drain_started = drain_progress = now_ns();
                    break;
                }
                if (count != (ssize_t)(length + sizeof(header))) { status = 1; break; }
                received++;
            } else dropped++;
            rte_pktmbuf_free(packet);
            rx[rx_index++] = NULL;
            progress = true;
        }
        if (status) break;
        if (!progress) {
            struct pollfd fds[] = {{control_fd, POLLIN, 0}, {packet_fd, POLLIN, 0}};
            (void)poll(fds, 2, 1); /* Bounded idle wait; protocol timers live in Linux. */
        }
    }
    goto cleanup;
device_error:
    fprintf(stderr, "ker: ethdev initialization failed for %s\n", port_name);
cleanup:
    tx_capture_status = ker_pcap_close(&tx_capture);
    rx_capture_status = ker_pcap_close(&rx_capture);
    if (tx_capture_status || rx_capture_status) { perror("ker: close packet capture"); status = 1; }
    if (pending_tx) rte_pktmbuf_free(pending_tx);
    while (rx_index < rx_count) rte_pktmbuf_free(rx[rx_index++]);
    if (started && rte_eth_dev_stop(port)) status = 1;
    if (configured && rte_eth_dev_close(port)) status = 1;
    unsigned int outstanding = pool ? rte_mempool_in_use_count(pool) : 0;
    if (outstanding) {
        fprintf(stderr, "ker: %u packet buffers still owned after ethdev shutdown\n", outstanding);
        status = 1;
    } else if (pool) rte_mempool_free(pool);
    printf("KER_IO_DONE {\"tx\":%llu,\"rx\":%llu,\"dropped\":%llu,\"tx_retries\":%llu,"
        "\"rx_retries\":%llu,\"outstanding\":%u}\n", (unsigned long long)transmitted,
        (unsigned long long)received, (unsigned long long)dropped,
        (unsigned long long)tx_retries, (unsigned long long)rx_retries, outstanding);
    fflush(stdout);
    if (log_dir && ker_worker_log(RTE_LOG_INFO, log.type, "ker.io stopped status=%d\n", status) < 0) status = 1;
    if (ker_worker_log_close(&log)) { perror("ker: close worker log"); status = 1; }
    if (rte_eal_cleanup()) status = 1;
    close(packet_fd);
    close(control_fd);
    return status;
}
