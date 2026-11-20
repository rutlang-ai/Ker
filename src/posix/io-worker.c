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
#include "worker-exception.h"
#include "worker-offload.h"
#include "worker-scatter.h"
#include <rte_log.h>
#include <rte_lcore.h>

/* This process transports Ethernet frames only. All socket/TCP behavior runs
 * in the separate imported Linux instance in the application process. */
#define BURST 32
#define WIRE_MAX (KER_NATIVE_MAX_MTU + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN)
static volatile sig_atomic_t stopping;
static void stop_worker(int signal_number) { (void)signal_number; stopping = 1; }
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

static int scatter_mtu_supported(uint16_t port, int mtu)
{
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result || !(info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) ||
        !(info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)) {
        fprintf(stderr, "ker: ethdev cannot support scatter RX and multi-segment TX\n");
        return -EOPNOTSUPP;
    }
    uint32_t rx_overhead = ker_worker_rx_eth_overhead(&info);
    uint64_t required_rx_segments = ker_worker_rx_required_segments((uint32_t)mtu,
        rx_overhead);
    uint16_t rx_segment_limit = info.rx_desc_lim.nb_mtu_seg_max;
    if (!ker_worker_rx_limits_support(required_rx_segments, rx_segment_limit)) {
        fprintf(stderr, "ker: scatter MTU %d requires %llu RX segments with %u-byte device overhead, ethdev rx_desc_lim.nb_mtu_seg_max=%u\n",
            mtu, (unsigned long long)required_rx_segments, rx_overhead,
            rx_segment_limit);
        return -EOPNOTSUPP;
    }
    uint16_t required_segments = ker_worker_scatter_required_segments((uint32_t)mtu);
    if (!ker_worker_scatter_limits_support(required_segments,
            info.tx_desc_lim.nb_seg_max, info.tx_desc_lim.nb_mtu_seg_max)) {
        fprintf(stderr, "ker: scatter MTU %d with VLAN header requires %u TX segments, ethdev limits are nb_seg_max=%u nb_mtu_seg_max=%u\n",
            mtu, required_segments, info.tx_desc_lim.nb_seg_max,
            info.tx_desc_lim.nb_mtu_seg_max);
        return -EOPNOTSUPP;
    }
    return 0;
}

static int start_with_mtu(uint16_t port, int mtu, uint16_t descriptors,
    struct rte_mempool *pool, bool *started)
{
    int result = rte_eth_dev_set_mtu(port, (uint16_t)mtu);
    if (!result)
        result = rte_eth_rx_queue_setup(port, 0, descriptors, rte_socket_id(), NULL, pool);
    if (!result) {
        *started = true;
        result = rte_eth_dev_start(port);
    }
    return result;
}

/* Only the worker owns the ethdev and queue descriptors. A failed restart
 * must restore the old device configuration before we reply to Linux. */
static int change_worker_mtu(uint16_t port, int requested, int previous,
    uint16_t descriptors, struct rte_mempool *pool, bool *started, int *status,
    struct ker_worker_exception *exception)
{
    if (rte_eth_dev_stop(port))
        return -1;
    *started = false;

    *status = start_with_mtu(port, requested, descriptors, pool, started);
    if (!*status && exception->pending) {
        unsigned tap_mtu = (unsigned)requested;
        *status = ker_worker_exception_mtu(exception, &tap_mtu, true);
    }
    if (*status) {
        if (rte_eth_dev_stop(port))
            return -1;
        *started = false;
        if (start_with_mtu(port, previous, descriptors, pool, started))
            return -1;
        unsigned tap_mtu = (unsigned)previous;
        if (exception->pending && ker_worker_exception_mtu(exception, &tap_mtu, true))
            return -1;
    }

    /* A failed readback still leaves a started PMD for cleanup to stop. */
    uint16_t actual;
    return rte_eth_dev_get_mtu(port, &actual) ||
        actual != (*status ? previous : requested) ? -1 : 0;
}

static int handle_mtu(int fd, uint16_t port, int maximum, bool scatter, bool busy,
    uint16_t descriptors, struct rte_mempool *pool, bool *started,
    int *mtu, uint64_t *changes, struct ker_worker_exception *exception)
{
    struct ker_mtu_message message;
    ssize_t count = recv(fd, &message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
        return 0;
    if (count == 0)
        return 1;
    if (count != sizeof(message) || message.magic != KER_MTU_MAGIC || message.status ||
        message.previous != *mtu)
        return -1;

    uint16_t actual;
    if (rte_eth_dev_get_mtu(port, &actual) || actual != *mtu)
        return -1;
    if (exception->pending) {
        unsigned tap_mtu = 0;
        if (ker_worker_exception_mtu(exception, &tap_mtu, false) || tap_mtu != (unsigned)*mtu)
            return -1;
        int pending = ker_worker_exception_mtu_busy(exception);
        if (pending < 0)
            return -1;
        busy |= pending != 0;
    }
    int requested = message.mtu;
    if (requested < KER_NATIVE_MIN_MTU || requested > maximum)
        message.status = -EINVAL;
    else if (requested != *mtu) {
        if (busy)
            message.status = -EBUSY;
        else if (scatter)
            message.status = scatter_mtu_supported(port, requested);
        if (!message.status) {
            if (change_worker_mtu(port, requested, *mtu, descriptors, pool, started, &message.status, exception))
                return -1;
            if (!message.status) {
                *mtu = requested;
                ++*changes;
            }
        }
    }

    message.mtu = *mtu;
    do {
        count = send(fd, &message, sizeof(message), MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (count < 0 && errno == EINTR);
    return count == sizeof(message) ? 0 : -1;
}

int main(int argc, char **argv)
{
    int packet_fd = -1, control_fd = -1, mtu_fd = -1, split = 0;
    bool all_multicast = false, pcap_nsec = false, log_level_set = false;
    const char *pcap_dir = NULL, *log_dir = NULL, *exception_iface = NULL;
    int exception_type = 0, exception_queue = 256, exception_rate = 0;
    int exception_console_rate = 0, exception_general_rate = 0;
    const char *exception_mode = "ethertype", *exception_policy = "accept";
    const char *exception_tcp = NULL, *exception_udp = NULL;
    struct ker_exception_filter exception_filter;
    int log_level = -1, mtu = KER_NATIVE_DEFAULT_MTU, maximum_mtu = 0;
    int tx_offloads = 0;
    int pcap_snaplen = 65535, pcap_maximum = 16 * 1024 * 1024;
    const char *port_name = NULL, *mbuf_mode = "large";
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) { split = i; break; }
        if (!strcmp(argv[i], "--all-multicast")) { all_multicast = true; continue; }
        if (!strcmp(argv[i], "--pcap-nsec")) { pcap_nsec = true; continue; }
        if (i + 1 >= argc) break;
        if (!strcmp(argv[i], "--packet-fd")) packet_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--control-fd")) control_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--port")) port_name = argv[++i];
        else if (!strcmp(argv[i], "--mbuf-mode")) mbuf_mode = argv[++i];
        else if (!strcmp(argv[i], "--tx-offloads")) tx_offloads = number(argv[++i]);
        else if (!strcmp(argv[i], "--mtu")) mtu = number(argv[++i]);
        else if (!strcmp(argv[i], "--mtu-fd")) {
            mtu_fd = number(argv[++i]);
            if (mtu_fd < 0) return 2;
        }
        else if (!strcmp(argv[i], "--max-mtu")) maximum_mtu = number(argv[++i]);
        else if (!strcmp(argv[i], "--exception-mode")) exception_mode = argv[++i];
        else if (!strcmp(argv[i], "--exception-policy")) exception_policy = argv[++i];
        else if (!strcmp(argv[i], "--exception-tcp-ports")) exception_tcp = argv[++i];
        else if (!strcmp(argv[i], "--exception-udp-ports")) exception_udp = argv[++i];
        else if (!strcmp(argv[i], "--exception-iface")) exception_iface = argv[++i];
        else if (!strcmp(argv[i], "--exception-type")) exception_type = number(argv[++i]);
        else if (!strcmp(argv[i], "--exception-queue")) exception_queue = number(argv[++i]);
        else if (!strcmp(argv[i], "--exception-console-rate")) exception_console_rate = number(argv[++i]);
        else if (!strcmp(argv[i], "--exception-general-rate")) exception_general_rate = number(argv[++i]);
        else if (!strcmp(argv[i], "--exception-rate")) exception_rate = number(argv[++i]);
        else if (!strcmp(argv[i], "--log-dir")) log_dir = argv[++i];
        else if (!strcmp(argv[i], "--log-level")) { log_level = number(argv[++i]); log_level_set = true; }
        else if (!strcmp(argv[i], "--pcap-dir")) pcap_dir = argv[++i];
        else if (!strcmp(argv[i], "--pcap-snaplen")) pcap_snaplen = number(argv[++i]);
        else if (!strcmp(argv[i], "--pcap-max-bytes")) pcap_maximum = number(argv[++i]);
        else break;
    }
    if ((mtu_fd >= 0) != (maximum_mtu != 0)) {
        fprintf(stderr, "ker: --mtu-fd and --max-mtu must be supplied together\n");
        return 2;
    }
    if (!maximum_mtu) maximum_mtu = mtu;
    if (tx_offloads < 0 || tx_offloads > 2 || maximum_mtu < mtu || maximum_mtu > KER_NATIVE_MAX_MTU ||
        (strcmp(mbuf_mode, "large") && strcmp(mbuf_mode, "scatter")) || mtu < KER_NATIVE_MIN_MTU || mtu > KER_NATIVE_MAX_MTU || packet_fd < 0 || control_fd < 0 || !port_name || !split || pcap_snaplen <= 0 || pcap_maximum <= 0 ||
        (log_level_set && (log_level < (int)RTE_LOG_EMERG || log_level > (int)RTE_LOG_DEBUG))) {
        fprintf(stderr, "usage: ker-io-worker --packet-fd N --control-fd N --port NAME [--mtu 1280..9000] [--mtu-fd N --max-mtu 1280..9000] [--mbuf-mode large|scatter] [--all-multicast] [--log-dir DIR] [--log-level 1..8] [--pcap-dir DIR] [--pcap-snaplen N] [--pcap-max-bytes N] [--pcap-nsec] -- EAL_ARGS\n");
        return 2;
    }
    bool port_filter = !strcmp(exception_mode, "ports");
    if ((!port_filter && strcmp(exception_mode, "ethertype")) ||
        (strcmp(exception_policy, "accept") && strcmp(exception_policy, "reject")) ||
        (port_filter && (exception_type || !exception_iface || ker_exception_filter_init(&exception_filter, exception_tcp, exception_udp))) ||
        (!port_filter && (exception_tcp || exception_udp || strcmp(exception_policy, "accept"))) ||
        (exception_iface && ((!port_filter && (exception_type < 1536 || exception_type > UINT16_MAX)) ||
        exception_queue < 4 || exception_queue > 65536 || (exception_queue & (exception_queue - 1)) || exception_rate < 0 || exception_console_rate < 0 || exception_general_rate < 0)) ||
        (!exception_iface && (exception_type || exception_rate || exception_console_rate || exception_general_rate || exception_queue != 256))) {
        fprintf(stderr, "ker: invalid host exception TAP options\n");
        return 2;
    }
    if (fcntl(packet_fd, F_SETFL, O_NONBLOCK) || fcntl(control_fd, F_SETFL, O_NONBLOCK)) {
        perror("ker packet/control channel"); return 1;
    }
    if (mtu_fd >= 0) {
        int type;
        socklen_t length = sizeof(type);
        if (getsockopt(mtu_fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_SEQPACKET ||
            fcntl(mtu_fd, F_SETFD, FD_CLOEXEC) < 0) {
            fprintf(stderr, "ker: invalid MTU control socket\n");
            return 2;
        }
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
    bool rx_shared[BURST] = {0};
    uint64_t wire_rx = 0, rx_shutdown_discarded = 0;
    struct ker_worker_exception exception = {.fd = -1};
    struct ker_pcap tx_capture = {0}, rx_capture = {0};
    uint64_t transmitted = 0, received = 0, tx_dropped = 0, rx_dropped = 0, tx_retries = 0, rx_retries = 0;
    uint64_t transmitted_bytes = 0, received_bytes = 0, tx_multiseg = 0, rx_multiseg = 0;
    struct ker_packet_header tx_header = {0};
    struct ker_worker_offload offload = {0};
    uint64_t tx_tcp_checksum = 0, tx_udp_checksum = 0, tx_ip_checksum = 0;
    uint64_t tx_tso4 = 0, tx_tso6 = 0, tx_checksum_fallback = 0;
    unsigned char tx_bytes[sizeof(struct ker_packet_header) + KER_NATIVE_MAX_GSO], rx_bytes[WIRE_MAX];
    size_t tx_length = 0;
    int status = 1, tx_capture_status, rx_capture_status;
    bool draining = false;
    uint64_t stop_requests = 0, mtu_changes = 0;
    bool control_eof = false;
    int64_t drain_started = 0, drain_progress = 0;
    if (rte_eth_dev_get_port_by_name(port_name, &port)) {
        fprintf(stderr, "ker: unknown ethdev %s\n", port_name); goto cleanup;
    }
    struct rte_eth_conf conf = {0}; /* No checksum, VLAN, LRO, or TSO offloads. */
    bool scatter = !strcmp(mbuf_mode, "scatter");
    if (scatter) {
        if (scatter_mtu_supported(port, mtu)) goto cleanup;
        conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_SCATTER;
        conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    }
    if (ker_worker_offload_prepare(port, tx_offloads, &conf, &offload)) {
        fprintf(stderr, "ker: requested TX checksum/TSO offloads exceed the selected PMD capabilities\n");
        goto cleanup;
    }
    uint16_t buffer_size = (uint16_t)(scatter ? RTE_MBUF_DEFAULT_BUF_SIZE :
        RTE_MAX(RTE_MBUF_DEFAULT_BUF_SIZE, maximum_mtu + RTE_ETHER_HDR_LEN +
            RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN + RTE_PKTMBUF_HEADROOM));
    unsigned usable = buffer_size - RTE_PKTMBUF_HEADROOM;
    unsigned gso_segments = (KER_NATIVE_MAX_GSO + usable - 1) / usable;
    if (tx_offloads == 2 && offload.segment_limit && gso_segments > offload.segment_limit) {
        fprintf(stderr, "ker: selected packet storage exceeds the PMD's GSO descriptor limit\n");
        goto cleanup;
    }
    if (rte_eth_dev_configure(port, 1, 1, &conf)) goto device_error;
    configured = true;
    if (tx_offloads) {
        struct rte_eth_conf observed;
        if (rte_eth_dev_conf_get(port, &observed) ||
            (observed.txmode.offloads & offload.flags) != offload.flags) {
            fprintf(stderr, "ker: PMD TX offload configuration readback differs\n");
            goto cleanup;
        }
    }
    if (rte_eth_dev_set_mtu(port, (uint16_t)mtu)) goto device_error;
    uint16_t rx_desc = 256, tx_desc = 256;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc)) goto device_error;
    pool = rte_pktmbuf_pool_create("ker_native_packets", 4095, 0, 0,
        buffer_size, rte_socket_id());
    if (!pool) { fprintf(stderr, "ker packet pool: %s\n", rte_strerror(rte_errno)); goto cleanup; }
    /* Original TAP creates its GSO context when TX opens the shared fd. */
    if (offload.tap && tx_offloads == 2) {
        if (rte_eth_tx_queue_setup(port, 0, tx_desc, rte_socket_id(), NULL) ||
            rte_eth_rx_queue_setup(port, 0, rx_desc, rte_socket_id(), NULL, pool))
            goto device_error;
    } else if (rte_eth_rx_queue_setup(port, 0, rx_desc, rte_socket_id(), NULL, pool) ||
        rte_eth_tx_queue_setup(port, 0, tx_desc, rte_socket_id(), NULL)) {
        goto device_error;
    }
    if (rte_eth_dev_start(port)) goto device_error;
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
    if (exception_iface) {
        int result = ker_worker_exception_open(&exception, exception_iface, pool, &mac, (unsigned)mtu,
            (uint16_t)(port_filter ? RTE_ETHER_TYPE_IPV4 : exception_type), (unsigned)exception_queue,
            (uint32_t)exception_rate, (uint32_t)exception_console_rate, (uint32_t)exception_general_rate);
        if (result) {
            fprintf(stderr, "ker: host exception TAP startup failed: %s\n", strerror(-result));
            goto cleanup;
        }
        if (port_filter) {
            exception.port_mode = true;
            exception.reject = !strcmp(exception_policy, "reject");
            exception.filter = exception_filter;
        }
    }
    if (log_dir && ker_worker_log(RTE_LOG_INFO, log.type, "ker.io ready port=%s\n", port_name) < 0) {
        perror("ker: write worker log"); goto cleanup;
    }
    struct rte_eth_link link = {0};
    int link_status = rte_eth_link_get_nowait(port, &link);
    printf("KER_IO_READY {\"tx_offload_mode\":%d,\"tx_offload_features\":%u,\"tx_offload_flags\":%llu,\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"mtu\":%u,"
        "\"mbuf_mode\":\"%s\",\"port_id\":%u,\"port_count\":%u,\"socket_id\":%d,"
        "\"process_type\":\"primary\",\"lcore_count\":%u,\"main_lcore\":%u,\"main_cpu\":%d,\"link_up\":%s}\n",
        tx_offloads, offload.features, (unsigned long long)offload.flags,
        mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2], mac.addr_bytes[3],
        mac.addr_bytes[4], mac.addr_bytes[5], (unsigned int)mtu, mbuf_mode, port, rte_eth_dev_count_avail(),
        rte_eth_dev_socket_id(port), rte_lcore_count(), rte_get_main_lcore(), sched_getcpu(), link_status ? "null" : (link.link_status ? "true" : "false"));
    fflush(stdout);
    status = 0;
    bool exception_first = false;
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
        if (mtu_fd >= 0 && !draining) {
            int result = handle_mtu(mtu_fd, port, maximum_mtu, scatter,
                pending_tx || tx_length || rx_index < rx_count, rx_desc, pool,
                &started, &mtu, &mtu_changes, &exception);
            if (result < 0) {
                fprintf(stderr, "ker: MTU device transaction failed\n");
                status = 1;
                break;
            }
            if (result > 0) {
                close(mtu_fd);
                mtu_fd = -1;
            }
        }
        bool progress = false;
        /* Alternate which traffic source gets its TX opportunity first. */
        if (exception_first && exception.pending && !draining) {
            int64_t now;
            if (ker_worker_now_ns(&now)) goto clock_error;
            int result = ker_worker_exception_poll(&exception, port, (unsigned)mtu, now, pcap_dir ? &tx_capture : NULL, &progress);
            if (result) { fprintf(stderr, "ker: host exception TAP forwarding failed: %s\n", strerror(-result)); status = 1; break; }
        }
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
                    if (count < (ssize_t)(sizeof(tx_header) + RTE_ETHER_HDR_LEN) ||
                        count > (ssize_t)sizeof(tx_bytes)) { tx_dropped++; continue; }
                    memcpy(&tx_header, tx_bytes, sizeof(tx_header));
                    tx_length = (size_t)count - sizeof(tx_header);
                    if (!tx_header.gso_type &&
                        !frame_size_supported(tx_bytes + sizeof(tx_header), tx_length, mtu)) {
                        tx_length = 0;
                        tx_dropped++;
                        continue;
                    }
                }
                pending_tx = ker_worker_mbuf_from_bytes(pool, tx_bytes + sizeof(tx_header), tx_length);
                if (!pending_tx) { tx_retries++; break; }
                struct ker_worker_offload_result translated;
                int result = ker_worker_offload_apply(&offload, &tx_header, pending_tx,
                    (unsigned)mtu, &translated);
                if (result || (pending_tx->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK &&
                    rte_eth_tx_prepare(port, 0, &pending_tx, 1) != 1)) {
                    fprintf(stderr, "ker: invalid or unsupported native TX offload metadata (%d)\n", result);
                    status = 1;
                    break;
                }
                tx_tcp_checksum += translated.tcp;
                tx_udp_checksum += translated.udp;
                tx_ip_checksum += translated.ip;
                tx_tso4 += translated.tso4;
                tx_tso6 += translated.tso6;
                tx_checksum_fallback += translated.fallback;
                /* Capture once before PMD ownership transfer, not on retries. */
                if (pcap_dir) {
                    struct timespec timestamp;
                    if (clock_gettime(CLOCK_REALTIME, &timestamp) ||
                        ker_pcap_write(&tx_capture, pending_tx, &timestamp)) {
                        perror("ker: TX packet capture"); status = 1; break;
                    }
                }
            }
            bool tx_is_multiseg = pending_tx->nb_segs > 1;
            bool tx_uses_offload = pending_tx->ol_flags & RTE_MBUF_F_TX_OFFLOAD_MASK;
            if (rte_eth_tx_burst(port, 0, &pending_tx, 1) != 1) {
                tx_retries++;
                if (offload.tap && tx_uses_offload) {
                    fprintf(stderr, "ker: TAP rejected offload TX; cannot retry a possibly modified mbuf\n");
                    status = 1;
                }
                break;
            }
            if (tx_is_multiseg) tx_multiseg++;
            pending_tx = NULL; /* PMD owns accepted mbufs, including deferred frees. */
            transmitted_bytes += tx_length;
            tx_length = 0;
            transmitted++;
            progress = true;
        }
        if (status) break;
        /* On native-first turns, attempt its batch before admitting another
         * exception burst; the next turn gives exception traffic first use. */
        if (!exception_first && exception.pending && !draining) {
            int64_t now;
            if (ker_worker_now_ns(&now)) goto clock_error;
            int result = ker_worker_exception_poll(&exception, port, (unsigned)mtu, now, pcap_dir ? &tx_capture : NULL, &progress);
            if (result) { fprintf(stderr, "ker: host exception TAP forwarding failed: %s\n", strerror(-result)); status = 1; break; }
        }
        exception_first = !exception_first;
        if (draining) {
            rx_shutdown_discarded += rx_count - rx_index;
            while (rx_index < rx_count) rte_pktmbuf_free(rx[rx_index++]);
            int64_t now;
            if (ker_worker_now_ns(&now)) goto clock_error;
            if (progress) drain_progress = now;
            if (!pending_tx && !tx_length && now - drain_progress >= INT64_C(5000000)) break;
            if (now - drain_started >= INT64_C(500000000)) { status = 1; break; }
            if (!progress) usleep(1000);
            continue;
        }
        if (rx_index == rx_count) {
            rx_count = rte_eth_rx_burst(port, 0, rx, BURST);
            wire_rx += rx_count;
            rx_index = 0;
            memset(rx_shared, 0, sizeof(rx_shared));
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
                enum ker_exception_route route = ker_worker_exception_route(&exception, packet);
                if (route == KER_EXCEPTION_DROP) {
                    exception.fragment_dropped++; rx_dropped++;
                    rte_pktmbuf_free(rx[rx_index]); rx[rx_index++] = NULL; progress = true; continue;
                }
                if (route == KER_EXCEPTION_SHARED && !rx_shared[rx_index]) {
                    /* Exactly one deep copy even when native channel delivery
                     * retains this RX suffix under backpressure. */
                    struct rte_mbuf *copy = rte_pktmbuf_copy(packet, pool, 0, UINT32_MAX);
                    rx_shared[rx_index] = true;
                    if (copy) {
                        int result = ker_worker_exception_enqueue(&exception, &copy);
                        if (result && result != -ENOBUFS) { rte_pktmbuf_free(copy); status = 1; break; }
                        exception.shared_selected++;
                        if (ker_exception_arp(packet)) exception.shared_arp++;
                        if (!result && ker_exception_classify(&exception.filter, packet) == KER_EXCEPTION_ICMP_ERROR)
                            exception.shared_icmp_error++;
                    } else exception.shared_failed++;
                }
                if (route == KER_EXCEPTION_HOST) {
                    int result = ker_worker_exception_enqueue(&exception, &rx[rx_index]);
                    if (result && result != -ENOBUFS) { status = 1; break; }
                    rx_index++; progress = true; continue;
                }
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
            struct pollfd fds[] = {{control_fd, POLLIN, 0}, {packet_fd, POLLIN, 0}, {mtu_fd, POLLIN, 0}, {exception.fd, POLLIN, 0}};
            (void)poll(fds, sizeof(fds) / sizeof(fds[0]), 1); /* Bounded idle wait; protocol timers live in Linux. */
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
    rx_shutdown_discarded += rx_count - rx_index;
    while (rx_index < rx_count) rte_pktmbuf_free(rx[rx_index++]);
    if (ker_worker_exception_close(&exception)) status = 1;
    if (started && rte_eth_dev_stop(port)) status = 1;
    if (configured && rte_eth_dev_close(port)) status = 1;
    unsigned int outstanding = pool ? rte_mempool_in_use_count(pool) : 0;
    if (outstanding) {
        fprintf(stderr, "ker: %u packet buffers still owned after ethdev shutdown\n", outstanding);
        status = 1;
    } else if (pool) rte_mempool_free(pool);
    printf("KER_IO_DONE {\"exception_console_charged\":%llu,\"exception_general_charged\":%llu,"
        "\"exception_console_dropped\":%llu,\"exception_general_dropped\":%llu,",
        (unsigned long long)exception.console_charged, (unsigned long long)exception.general_charged,
        (unsigned long long)exception.console_dropped, (unsigned long long)exception.general_dropped);
    printf("\"exception_shared_arp\":%llu,\"exception_shared_selected\":%llu,\"exception_shared_icmp_error\":%llu,\"exception_shared_failed\":%llu,\"exception_fragment_dropped\":%llu,",
        (unsigned long long)exception.shared_arp, (unsigned long long)exception.shared_selected,
        (unsigned long long)exception.shared_icmp_error, (unsigned long long)exception.shared_failed,
        (unsigned long long)exception.fragment_dropped);
    printf("\"exception_selected\":%llu,\"exception_enqueued\":%llu,"
        "\"exception_to_host\":%llu,\"exception_to_host_dropped\":%llu,\"exception_host_received\":%llu,"
        "\"exception_from_host\":%llu,\"exception_wire_dropped\":%llu,\"exception_shutdown_dropped\":%llu,"
        "\"exception_rate_dropped\":%llu,\"exception_malformed\":%llu,\"wire_rx\":%llu,\"rx_shutdown_discarded\":%llu,",
        (unsigned long long)exception.selected, (unsigned long long)exception.enqueued,
        (unsigned long long)exception.to_host, (unsigned long long)exception.to_host_dropped,
        (unsigned long long)exception.host_received, (unsigned long long)exception.from_host,
        (unsigned long long)exception.wire_dropped, (unsigned long long)exception.shutdown_dropped,
        (unsigned long long)exception.rate_dropped, (unsigned long long)exception.malformed,
        (unsigned long long)wire_rx, (unsigned long long)rx_shutdown_discarded);
    printf("\"tx_tcp_checksum\":%llu,\"tx_udp_checksum\":%llu,\"tx_ip_checksum\":%llu,"
        "\"tx_tso4\":%llu,\"tx_tso6\":%llu,\"tx_checksum_fallback\":%llu,",
        (unsigned long long)tx_tcp_checksum, (unsigned long long)tx_udp_checksum,
        (unsigned long long)tx_ip_checksum, (unsigned long long)tx_tso4,
        (unsigned long long)tx_tso6, (unsigned long long)tx_checksum_fallback);
    printf("\"mtu_final\":%d,\"mtu_changes\":%llu,\"tx\":%llu,\"rx\":%llu,\"dropped\":%llu,\"tx_retries\":%llu,"
        "\"rx_retries\":%llu,\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"tx_dropped\":%llu,\"rx_dropped\":%llu,\"outstanding\":%u,"
        "\"stop_requests\":%llu,\"control_eof\":%s,\"tx_multiseg\":%llu,\"rx_multiseg\":%llu}\n", mtu, (unsigned long long)mtu_changes, (unsigned long long)transmitted,
        (unsigned long long)received, (unsigned long long)(tx_dropped + rx_dropped),
        (unsigned long long)tx_retries, (unsigned long long)rx_retries,
        (unsigned long long)transmitted_bytes, (unsigned long long)received_bytes,
        (unsigned long long)tx_dropped, (unsigned long long)rx_dropped, outstanding,
        (unsigned long long)stop_requests, control_eof ? "true" : "false",
        (unsigned long long)tx_multiseg, (unsigned long long)rx_multiseg);
    fflush(stdout);
    if (log_dir && ker_worker_log(RTE_LOG_INFO, log.type, "ker.io stopped status=%d\n", status) < 0) status = 1;
    if (ker_worker_log_close(&log)) { perror("ker: close worker log"); status = 1; }
    if (rte_eal_cleanup()) status = 1;
    close(packet_fd);
    close(control_fd);
    if (mtu_fd >= 0) close(mtu_fd);
    return status;
}
