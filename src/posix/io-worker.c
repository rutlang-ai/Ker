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
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include "packet-channel.h"
#include "bond-policy.h"
#include "pcap.h"
#include "worker-log.h"
#include "worker-clock.h"
#include "worker-mbuf.h"
#include "worker-wait.h"
#include "worker-tx.h"
#include "worker-rx-drain.h"
#include "worker-scatter.h"
#include "worker-rss.h"
#include "worker-offload.h"
#include "worker-receive-mode.h"
#include "worker-exception.h"
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_memory.h>

/* This process transports Ethernet frames only. All socket/TCP behavior runs
 * in the separate imported Linux instance in the application process. */
#define BURST 32
#define MAX_QUEUES 16
#define WIRE_MAX (KER_NATIVE_MAX_MTU + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN)
static volatile sig_atomic_t stopping;
static void stop_worker(int signal_number) { (void)signal_number; stopping = 1; }

static int memory_lowest_address(const struct rte_memseg_list *list,
        const struct rte_memseg *segment, void *opaque)
{
    (void)list;
    uintptr_t *lowest = opaque;
    uintptr_t address = (uintptr_t)segment->addr;
    if (address < *lowest) *lowest = address;
    return 0;
}

struct ker_worker_rx_queue {
    uint16_t port;
    uint16_t queue;
};

/* Typed virtio-user queue_size controls the actual RX and TX rings even when
 * rte_eth_dev_adjust_nb_rx_tx_desc leaves its requested counts unchanged. */
static uint16_t configured_vdev_ring_size(int argc, char **argv, const char *port)
{
    for (int i = 0; i < argc; ++i) {
        const char *device = NULL;
        if (!strcmp(argv[i], "--vdev") && i + 1 < argc) device = argv[++i];
        else if (!strncmp(argv[i], "--vdev=", 7)) device = argv[i] + 7;
        if (!device) continue;
        const char *options = strchr(device, ',');
        if (!options || (size_t)(options - device) != strlen(port) ||
            strncmp(device, port, (size_t)(options - device))) continue;
        for (const char *item = options + 1; *item;) {
            const char *end = strchr(item, ',');
            size_t length = end ? (size_t)(end - item) : strlen(item);
            if (length > sizeof("queue_size=") - 1 &&
                !strncmp(item, "queue_size=", sizeof("queue_size=") - 1)) {
                char value[16];
                size_t digits = length - (sizeof("queue_size=") - 1);
                if (digits >= sizeof(value)) return 0;
                memcpy(value, item + sizeof("queue_size=") - 1, digits);
                value[digits] = '\0';
                char *tail;
                unsigned long parsed = strtoul(value, &tail, 10);
                if (*tail || parsed > UINT16_MAX) return 0;
                return (uint16_t)parsed;
            }
            if (!end) break;
            item = end + 1;
        }
    }
    return 0;
}

static int configured_port_descriptors(uint16_t port, int argc, char **argv,
    uint16_t minimum_rx, uint16_t minimum_tx, uint32_t *rx, uint32_t *tx)
{
    char name[RTE_ETH_NAME_MAX_LEN];
    struct rte_eth_dev_info info = {0};
    uint16_t rx_desc = 256, tx_desc = 256;
    if (rte_eth_dev_get_name_by_port(port, name) ||
        rte_eth_dev_info_get(port, &info) ||
        rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc)) return -EIO;
    uint16_t ring = configured_vdev_ring_size(argc, argv, name);
    rx_desc = RTE_MAX(RTE_MAX(rx_desc, minimum_rx), ring);
    tx_desc = RTE_MAX(RTE_MAX(tx_desc, minimum_tx), ring);
    if ((info.rx_desc_lim.nb_max && rx_desc > info.rx_desc_lim.nb_max) ||
        (info.tx_desc_lim.nb_max && tx_desc > info.tx_desc_lim.nb_max)) return -ERANGE;
    *rx = rx_desc;
    *tx = tx_desc;
    return 0;
}

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
static int configure_mtu(uint16_t port, int mtu, uint16_t descriptors,
    unsigned int allocation_socket, struct rte_mempool *pool, uint16_t queues,
    struct ker_worker_rss *rss, bool *started)
{
    int result = rte_eth_dev_set_mtu(port, (uint16_t)mtu);
    for (uint16_t queue = 0; !result && queue < queues; queue++)
        result = rte_eth_rx_queue_setup(port, queue, descriptors, allocation_socket, NULL, pool);
    if (!result) {
        result = rte_eth_dev_start(port);
        if (!result) *started = true;
    }
    if (!result && rss->reta_size) result = ker_worker_rss_apply(port, queues, rss);
    return result;
}
/* Run on the worker thread, which exclusively owns the ethdev and queues. */
static int mtu_command(int fd, uint16_t port, bool scatter, int maximum, int *mtu,
    bool busy, bool fixed_mtu, uint64_t *changes, struct rte_mempool *pool,
    uint16_t descriptors, unsigned int allocation_socket, uint16_t queues,
    struct ker_worker_rss *rss, bool *started)
{
    struct ker_mtu_message message;
    ssize_t size = recv(fd, &message, sizeof(message), MSG_DONTWAIT | MSG_TRUNC);
    if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    if (size == 0) return 1; /* Application exited; stop pipe owns worker drain. */
    if (size != sizeof(message) || message.magic != KER_MTU_MAGIC) return -1;
    uint16_t actual;
    if (rte_eth_dev_get_mtu(port, &actual) || actual != *mtu) return -1;
    int requested = message.mtu;
    message.status = 0;
    if (message.operation == KER_MTU_SET) {
        if (requested < KER_NATIVE_MIN_MTU || requested > maximum) message.status = -EINVAL;
        else if (message.previous != *mtu) message.status = -ESTALE;
        else if (busy) message.status = -EBUSY;
        else if (scatter && scatter_mtu_supported(port, requested)) message.status = -EOPNOTSUPP;
        else if (fixed_mtu && requested != *mtu) message.status = -EOPNOTSUPP;
        else if (requested != *mtu) {
            /* RX capacities can be fixed at queue setup (notably TAP scatter).
             * Stop before rebuilding queues with the same owned pool. Network
             * traffic can be lost during this link reconfiguration. */
            if (rte_eth_dev_stop(port)) return -1;
            *started = false;
            message.status = configure_mtu(port, requested, descriptors, allocation_socket, pool, queues, rss, started);
            if (message.status) {
                /* Restore even if ethdev's cached MTU still says the old value:
                 * a PMD may fail after changing its underlying device. */
                if (rte_eth_dev_stop(port)) return -1;
                *started = false;
                if (configure_mtu(port, *mtu, descriptors, allocation_socket, pool, queues, rss, started)) return -1;
                if (rte_eth_dev_get_mtu(port, &actual) || actual != *mtu) return -1;
            } else {
                /* configure_mtu() has restarted the PMD. Cleanup owns the stop
                 * even if readback cannot prove which MTU the PMD applied. */
                *started = true;
                if (rte_eth_dev_get_mtu(port, &actual) || actual != requested) return -1;
                (*changes)++;
                *mtu = requested;
            }
        }
    } else if (message.operation != KER_MTU_GET) message.status = -EOPNOTSUPP;
    message.mtu = *mtu;
    size = send(fd, &message, sizeof(message), MSG_DONTWAIT | MSG_NOSIGNAL);
    return size == sizeof(message) ? 0 : -1;
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
    /* Build-matched capability query used by ker-run preflight; this path
     * returns before EAL initialization and reflects this worker's headers. */
    if (argc == 2 && !strcmp(argv[1], "--dpdk-limits")) {
        printf("{\"max_numa_nodes\":%d}\n", RTE_MAX_NUMA_NODES);
        return RTE_MAX_NUMA_NODES > 0 ? 0 : 1;
    }
    int packet_fd = -1, control_fd = -1, mtu_fd = -1, split = 0;
    bool rss_enabled = false;
    int queues = 1;
    bool numa = true, all_multicast = false, pcap_nsec = false, log_level_set = false;
    const char *pcap_dir = NULL, *log_dir = NULL, *exception_iface = NULL;
    int exception_type = 0, exception_queue = 256, exception_rate = 0;
    int idle_sleep_us = 1000, tx_delay_us = 0;
    int promiscuous = -1, tx_offloads = 0;
    int log_level = -1, mtu = KER_NATIVE_DEFAULT_MTU, maximum_mtu = 0;
    int pcap_snaplen = 65535, pcap_maximum = 16 * 1024 * 1024;
    const char *port_name = NULL, *mbuf_mode = "large", *bond_policy = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--")) { split = i; break; }
        if (!strcmp(argv[i], "--rss")) { rss_enabled = true; continue; }
        if (!strcmp(argv[i], "--numa")) { numa = true; continue; }
        if (!strcmp(argv[i], "--no-numa")) { numa = false; continue; }
        if (!strcmp(argv[i], "--promiscuous")) { promiscuous = 1; continue; }
        if (!strcmp(argv[i], "--no-promiscuous")) { promiscuous = 0; continue; }
        if (!strcmp(argv[i], "--all-multicast")) { all_multicast = true; continue; }
        if (!strcmp(argv[i], "--pcap-nsec")) { pcap_nsec = true; continue; }
        if (i + 1 >= argc) break;
        if (!strcmp(argv[i], "--exception-iface")) exception_iface = argv[++i];
        else if (!strcmp(argv[i], "--exception-type")) exception_type = number(argv[++i]);
        else if (!strcmp(argv[i], "--exception-queue")) exception_queue = number(argv[++i]);
        else if (!strcmp(argv[i], "--exception-rate")) exception_rate = number(argv[++i]);
        else if (!strcmp(argv[i], "--tx-delay-us")) tx_delay_us = number(argv[++i]);
        else if (!strcmp(argv[i], "--idle-sleep-us")) idle_sleep_us = number(argv[++i]);
        else if (!strcmp(argv[i], "--packet-fd")) packet_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--bond-policy")) bond_policy = argv[++i];
        else if (!strcmp(argv[i], "--tx-offloads")) tx_offloads = number(argv[++i]);
        else if (!strcmp(argv[i], "--queues")) queues = number(argv[++i]);
        else if (!strcmp(argv[i], "--mtu-fd")) mtu_fd = number(argv[++i]);
        else if (!strcmp(argv[i], "--max-mtu")) maximum_mtu = number(argv[++i]);
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
    if ((exception_iface && (exception_type < 1536 || exception_type > UINT16_MAX ||
        exception_queue < 4 || exception_queue > 65536 || (exception_queue & (exception_queue - 1)) || exception_rate < 0)) ||
        (!exception_iface && (exception_type || exception_rate || exception_queue != 256))) return 1;
    if (!maximum_mtu) maximum_mtu = mtu;
    if (maximum_mtu < mtu || maximum_mtu > KER_NATIVE_MAX_MTU) return 1;
    if (tx_offloads < 0 || tx_offloads > 2 || queues < 1 || queues > MAX_QUEUES || (rss_enabled && queues < 2) || tx_delay_us < 0 || tx_delay_us > 100 || idle_sleep_us < 0 || idle_sleep_us > 100000 || (strcmp(mbuf_mode, "large") && strcmp(mbuf_mode, "scatter")) || mtu < KER_NATIVE_MIN_MTU || mtu > KER_NATIVE_MAX_MTU || packet_fd < 0 || control_fd < 0 || !port_name || !split || pcap_snaplen <= 0 || pcap_maximum <= 0 ||
        (log_level_set && (log_level < (int)RTE_LOG_EMERG || log_level > (int)RTE_LOG_DEBUG))) {
        fprintf(stderr, "usage: ker-io-worker --packet-fd N --control-fd N --port NAME [--tx-offloads 0..2] [--rss] [--queues 1..16] [--mtu-fd N] [--max-mtu 1280..9000] [--mtu 1280..9000] [--mbuf-mode large|scatter] [--numa|--no-numa] [--all-multicast] [--idle-sleep-us 0..100000] [--tx-delay-us 0..100] [--promiscuous|--no-promiscuous] [--log-dir DIR] [--log-level 1..8] [--pcap-dir DIR] [--pcap-snaplen N] [--pcap-max-bytes N] [--pcap-nsec] -- EAL_ARGS\n");
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
    uint16_t configured_ring = configured_vdev_ring_size(argc - split - 1,
        argv + split + 1, port_name);
    if (rte_eal_init(argc - split, argv + split) < 0) {
        fprintf(stderr, "ker EAL: %s\n", rte_strerror(rte_errno));
        if (ker_worker_log_close(&log)) perror("ker: close worker log");
        return 1;
    }
    uint32_t eal_log_level = rte_log_get_global_level();
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
    uint16_t rx_count = 0, rx_index = 0, next_queue = 0;
    uint64_t rx_by_queue[MAX_QUEUES] = {0}, rx_rss_metadata = 0;
    struct ker_pcap tx_capture = {0}, rx_capture = {0};
    uint64_t transmitted = 0, received = 0, tx_dropped = 0, rx_dropped = 0, tx_retries = 0, rx_retries = 0;
    uint64_t transmitted_bytes = 0, received_bytes = 0, tx_multiseg = 0, rx_multiseg = 0;
    uint64_t rx_startup_discarded = 0, rx_shutdown_discarded = 0, idle_waits = 0, idle_timeouts = 0;
    struct ker_packet_header tx_header = {0};
    struct ker_worker_offload offload = {0};
    struct ker_worker_exception exception = {.fd = -1};
    struct ker_worker_receive_mode receive_mode = {.socket_fd = -1, .identity_fd = -1};
    bool receive_mode_restored = false;
    uint64_t tx_tcp_checksum = 0, tx_udp_checksum = 0, tx_ip_checksum = 0, tx_tso4 = 0, tx_tso6 = 0, tx_checksum_fallback = 0;
    unsigned char tx_bytes[sizeof(struct ker_packet_header) + KER_NATIVE_MAX_GSO], rx_bytes[WIRE_MAX];
    struct ker_worker_tx batch = {0};
    uint64_t tx_flushes = 0, tx_timer_flushes = 0, tx_full_flushes = 0, tx_drain_flushes = 0;
    size_t tx_length = 0;
    int status = 1, tx_capture_status, rx_capture_status;
    bool draining = false;
    uint64_t stop_requests = 0, mtu_changes = 0;
    bool control_eof = false;
    char bond_json[256] = "null";
    uint16_t bond_members[16];
    uint32_t bond_rx_budgets[16] = {0}, bond_tx_budgets[16] = {0};
    uint32_t bond_rx_drain_budget = 0;
    int bond_member_count = 0;
    int64_t drain_started = 0, drain_progress = 0;
    if (rte_eth_dev_get_port_by_name(port_name, &port)) {
        fprintf(stderr, "ker: unknown ethdev %s\n", port_name); goto cleanup;
    }
    struct rte_eth_conf conf = {0}; /* No checksum, VLAN, LRO, or TSO offloads. */
    bool scatter = !strcmp(mbuf_mode, "scatter");
    if (scatter && scatter_mtu_supported(port, mtu)) goto cleanup;
    if (scatter) {
        conf.rxmode.offloads = RTE_ETH_RX_OFFLOAD_SCATTER;
        conf.txmode.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS;
    }
    struct ker_worker_rss rss = {0};
    struct rte_eth_dev_info queue_info = {0};
    if (rte_eth_dev_info_get(port, &queue_info) || queues > queue_info.max_rx_queues || queues > queue_info.max_tx_queues) {
        fprintf(stderr, "ker: requested queue pairs exceed ethdev capacity\n"); goto cleanup;
    }
    if (rss_enabled && ker_worker_rss_prepare(port, (uint16_t)queues, &conf, &rss)) {
        fprintf(stderr, "ker: RSS requires IPv4/IPv6 TCP/UDP types, a readable key and a bounded RETA\n"); goto cleanup;
    }
    if (ker_worker_offload_prepare(port, tx_offloads, &conf, &offload)) {
        fprintf(stderr, "ker: requested TX checksum/TSO offloads exceed original PMD capabilities or current adapter qualification\n"); goto cleanup;
    }
    uint16_t buffer_size = (uint16_t)(scatter ? RTE_MBUF_DEFAULT_BUF_SIZE :
        RTE_MAX(RTE_MBUF_DEFAULT_BUF_SIZE, maximum_mtu + RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN + RTE_PKTMBUF_HEADROOM));
    unsigned gso_segments = (KER_NATIVE_MAX_GSO + buffer_size - RTE_PKTMBUF_HEADROOM - 1) /
        (buffer_size - RTE_PKTMBUF_HEADROOM);
    if (tx_offloads == 2 && offload.segment_limit && gso_segments > offload.segment_limit) {
        fprintf(stderr, "ker: selected packet storage exceeds PMD GSO descriptor capacity\n"); goto cleanup;
    }
    if (rte_eth_dev_configure(port, (uint16_t)queues, (uint16_t)queues, &conf)) goto device_error;
    configured = true;
    struct rte_eth_conf observed_conf;
    if (rte_eth_dev_conf_get(port, &observed_conf) ||
        (observed_conf.txmode.offloads & offload.flags) != offload.flags) {
        fprintf(stderr, "ker: ethdev TX offload configuration readback differs\n"); goto cleanup;
    }
    if (bond_policy) {
        int result = ker_bond_policy_apply(port, bond_policy);
        if (result) {
            fprintf(stderr, "ker: original bond policy API unavailable/failed (%d); use a worker with complete PMD API support\n", result);
            goto device_error;
        }
    }
    if (rte_eth_dev_set_mtu(port, (uint16_t)mtu)) goto device_error;
    uint16_t rx_desc = 256, tx_desc = 256;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc)) goto device_error;
    struct rte_eth_dev_info budget_info = {0};
    if (rte_eth_dev_info_get(port, &budget_info)) goto device_error;
    /* A typed virtio-user ring can exceed the PMD-adjusted defaults. Use its
     * selected config value for both directions; other devices use adjusted
     * descriptors. Check PMD limits before attempting queue setup. */
    uint16_t selected_rx_budget = RTE_MAX(rx_desc, configured_ring);
    uint16_t selected_tx_budget = RTE_MAX(tx_desc, configured_ring);
    uint32_t pool_rx_desc = selected_rx_budget, pool_tx_desc = selected_tx_budget;
    if ((budget_info.rx_desc_lim.nb_max && selected_rx_budget > budget_info.rx_desc_lim.nb_max) ||
        (budget_info.tx_desc_lim.nb_max && selected_tx_budget > budget_info.tx_desc_lim.nb_max)) {
        fprintf(stderr, "ker: configured descriptor budget RX=%u TX=%u exceeds ethdev limits RX=%u TX=%u\n",
            selected_rx_budget, selected_tx_budget, budget_info.rx_desc_lim.nb_max,
            budget_info.tx_desc_lim.nb_max);
        goto cleanup;
    }
    if (queues > 1 && ker_worker_mbuf_budget_add_queues(&pool_rx_desc,
            &pool_tx_desc, (uint32_t)queues - 1, selected_rx_budget,
            selected_tx_budget)) {
        fprintf(stderr, "ker: multi-queue descriptor pool budget overflow\n");
        goto cleanup;
    }
    if (bond_policy) {
        int count = ker_bond_members(port, bond_members, 16);
        if (count <= 0 || count > 16) {
            fprintf(stderr, "ker: cannot determine configured bond members for descriptor pool budget (%d)\n", count);
            goto cleanup;
        }
        bond_member_count = count;
        for (int i = 0; i < count; i++) {
            for (int prior = 0; prior < i; prior++) {
                if (bond_members[i] == bond_members[prior]) {
                    fprintf(stderr, "ker: duplicate bond member %u in descriptor pool budget\n", bond_members[i]);
                    goto cleanup;
                }
            }
            int member_result = configured_port_descriptors(bond_members[i],
                argc - split - 1, argv + split + 1, selected_rx_budget,
                selected_tx_budget, &bond_rx_budgets[i], &bond_tx_budgets[i]);
            int budget_result = member_result ? member_result :
                ker_worker_mbuf_budget_add_queues(&pool_rx_desc, &pool_tx_desc,
                    (uint32_t)queues, bond_rx_budgets[i], bond_tx_budgets[i]);
            if (!budget_result && bond_rx_budgets[i] > UINT32_MAX - bond_rx_drain_budget)
                budget_result = -EOVERFLOW;
            if (budget_result) {
                fprintf(stderr, "ker: cannot prove descriptor pool budget for bond member %u (%d)\n",
                    bond_members[i], budget_result);
                goto cleanup;
            }
            bond_rx_drain_budget += bond_rx_budgets[i];
        }
    }
    uint32_t pool_count;
    int pool_result = ker_worker_mbuf_pool_count(pool_rx_desc, pool_tx_desc, &pool_count);
    if (pool_result) {
        fprintf(stderr, "ker: RX/TX descriptor pool budget overflow (%u RX, %u TX)\n",
            pool_rx_desc, pool_tx_desc);
        goto cleanup;
    }
    /* Match F-Stack numa_on: lcore-local allocations, or explicit socket 0. */
    unsigned int allocation_socket = numa ? rte_socket_id() : 0;
    pool = rte_pktmbuf_pool_create("ker_native_packets", pool_count, 0, 0,
        buffer_size, allocation_socket);
    if (!pool) {
        fprintf(stderr, "ker: cannot allocate %u mbufs for %u RX descriptors, %u TX descriptors and worker refill/burst headroom: %s\n", pool_count, pool_rx_desc, pool_tx_desc, rte_strerror(rte_errno));
        goto cleanup;
    }
    for (uint16_t queue = 0; queue < queues; queue++) {
        /* Original TAP initializes its GSO context only when TX creates the
         * shared TAP fd. RX-first setup leaves the advertised TSO path empty.
         * Configure TX first for that path using original public APIs. */
        if (offload.tap && tx_offloads == 2) {
            if (rte_eth_tx_queue_setup(port, queue, tx_desc, allocation_socket, NULL) ||
                rte_eth_rx_queue_setup(port, queue, rx_desc, allocation_socket, NULL, pool)) goto device_error;
        } else if (rte_eth_rx_queue_setup(port, queue, rx_desc, allocation_socket, NULL, pool) ||
            rte_eth_tx_queue_setup(port, queue, tx_desc, allocation_socket, NULL)) goto device_error;
    }
    if (rte_eth_dev_start(port)) goto device_error;
    started = true;
    if (rss_enabled && ker_worker_rss_apply(port, (uint16_t)queues, &rss)) {
        fprintf(stderr, "ker: original RSS key/RETA API failed or readback differs\n"); goto cleanup;
    }
    for (int member = 0; member < bond_member_count; member++) {
        struct rte_eth_rxq_info member_rx = {0};
        struct rte_eth_txq_info member_tx = {0};
        int member_rx_status = rte_eth_rx_queue_info_get(bond_members[member], 0, &member_rx);
        int member_tx_status = rte_eth_tx_queue_info_get(bond_members[member], 0, &member_tx);
        /* Several original PMDs (including TAP) do not report member queue
         * geometry here. A successful bond start proves their queue setup
         * accepted the exact descriptor arguments budgeted above; when a PMD
         * does expose counts, still verify they fit the allocated share. */
        if ((member_rx_status && member_rx_status != -ENOTSUP) ||
            (member_tx_status && member_tx_status != -ENOTSUP) ||
            (member_rx.nb_desc && member_rx.nb_desc > bond_rx_budgets[member]) ||
            (member_tx.nb_desc && member_tx.nb_desc > bond_tx_budgets[member])) {
            fprintf(stderr, "ker: bond member %u queue geometry is unavailable or exceeds its mbuf budget (%u/%u, status %d/%d vs %u/%u)\n",
                bond_members[member], member_rx.nb_desc, member_tx.nb_desc,
                member_rx_status, member_tx_status,
                bond_rx_budgets[member], bond_tx_budgets[member]);
            goto cleanup;
        }
    }
    uint32_t rx_ring_capacity = bond_policy ? bond_rx_drain_budget : selected_rx_budget;
    struct rte_eth_rxq_info startup_rx_info = {0};
    if (!rte_eth_rx_queue_info_get(port, 0, &startup_rx_info) &&
        startup_rx_info.nb_desc) {
        if (!bond_policy && startup_rx_info.nb_desc > selected_rx_budget) {
            fprintf(stderr, "ker: RX ring capacity %u exceeds configured mbuf budget %u\n",
                startup_rx_info.nb_desc, selected_rx_budget);
            goto cleanup;
        }
        if (!bond_policy) rx_ring_capacity = startup_rx_info.nb_desc;
    }
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
        for (uint16_t index = 0; index < queues; index++) {
            struct ker_worker_rx_queue queue = {.port = port, .queue = index};
            uint64_t discarded = 0;
            int result = ker_worker_rx_drain(worker_rx_burst, worker_rx_free, &queue,
                rx_ring_capacity, &discarded);
            rx_startup_discarded += discarded;
            rx_dropped += discarded;
            if (result) {
                fprintf(stderr, "ker: ethdev RX queue %u could not be proven empty after the %u-packet startup budget: %s\n",
                    index, rx_ring_capacity, rte_strerror(-result));
                goto cleanup;
            }
        }
    }
    if (exception_iface) {
        struct rte_ether_addr exception_mac;
        if (rte_eth_macaddr_get(port, &exception_mac)) goto device_error;
        int result = ker_worker_exception_open(&exception, exception_iface, pool, &exception_mac, (unsigned)mtu,
            (uint16_t)exception_type, (unsigned)exception_queue, (uint32_t)exception_rate);
        if (result) { fprintf(stderr, "ker: host exception TAP startup failed: %s\n", strerror(-result)); goto cleanup; }
    }
    int promiscuous_state = rte_eth_promiscuous_get(port);
    /* Membership filtering belongs to Linux. Until its receive-mode updates
     * cross the packet channel, opt in to PMD all-multicast reception. */
    if (all_multicast) {
        int result = ker_worker_allmulticast_enable(port, &receive_mode);
        if (result) {
            fprintf(stderr, "ker: ethdev cannot enable --all-multicast: %s\n", rte_strerror(-result));
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
    uintptr_t memory_base = UINTPTR_MAX;
    if (rte_memseg_walk(memory_lowest_address, &memory_base) < 0 || memory_base == UINTPTR_MAX) {
        fprintf(stderr, "ker: cannot inspect EAL memory segments\n"); goto cleanup;
    }
    char initial_bond_json[256] = "null";
    if (bond_policy && ker_bond_snapshot(port, initial_bond_json, sizeof(initial_bond_json))) goto device_error;
    int link_status = rte_eth_link_get_nowait(port, &link);
    struct rte_eth_dev_info device_info = {0};
    struct rte_eth_rxq_info receive_info = {0};
    struct rte_eth_txq_info transmit_info = {0};
    int device_status = rte_eth_dev_info_get(port, &device_info);
    if (device_status) memset(&device_info, 0, sizeof(device_info));
    int receive_status = rte_eth_rx_queue_info_get(port, 0, &receive_info);
    if (receive_status) receive_info.nb_desc = 0;
    int transmit_status = rte_eth_tx_queue_info_get(port, 0, &transmit_info);
    if (transmit_status) transmit_info.nb_desc = 0;
    if ((receive_info.nb_desc && receive_info.nb_desc > selected_rx_budget) ||
        (transmit_info.nb_desc && transmit_info.nb_desc > selected_tx_budget)) {
        fprintf(stderr, "ker: ethdev configured RX/TX rings (%u/%u) exceed mbuf budget (%u/%u)\n",
            receive_info.nb_desc, transmit_info.nb_desc, selected_rx_budget, selected_tx_budget);
        goto cleanup;
    }
    char rss_json[384] = "null";
    if (rss_enabled) {
        char key[129];
        for (unsigned index = 0; index < rss.key_length; index++) snprintf(key + index * 2, 3, "%02x", rss.key[index]);
        snprintf(rss_json, sizeof(rss_json), "{\"types\":%llu,\"key\":\"%s\",\"reta_size\":%u,\"reta_mapping\":\"index_mod_queues\",\"verified\":true}", (unsigned long long)rss.types, key, rss.reta_size);
    }
    printf("KER_IO_READY {\"all_multicast_method\":\"%s\",\"tap_retry_safe\":%s,\"tx_offload_features\":%u,\"tx_offload_flags\":%llu,\"tx_offload_mode\":%d,\"tx_capture_stage\":\"before_offload\",\"rss\":%s,\"queues\":%d,\"data_tx_queue\":0,\"bond\":%s,\"driver\":\"%s\",\"max_rx_queues\":%u,\"max_tx_queues\":%u,\"rx_descriptors\":%u,\"tx_descriptors\":%u,\"pool_rx_descriptors\":%u,\"pool_tx_descriptors\":%u,\"mbuf_pool_count\":%u,\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"mtu\":%u,"
        "\"mbuf_mode\":\"%s\",\"port_id\":%u,\"port_count\":%u,\"socket_id\":%d,"
        "\"process_type\":\"primary\",\"numa\":%s,\"lcore_socket_id\":%u,\"allocation_socket_id\":%u,\"pool_socket_id\":%d,\"eal_log_level\":%u,\"log_level\":%u,\"memory_base\":\"0x%llx\",\"memory_bytes\":%llu,\"hugepages\":%s,\"memory_channels\":%u,\"lcore_count\":%u,\"main_lcore\":%u,\"main_cpu\":%d,\"link_up\":%s,\"promiscuous\":%s,\"idle_sleep_us\":%d,\"tx_delay_us\":%d}\n",
        receive_mode.method ? receive_mode.method : "off", offload.tap_retry_safe ? "true" : "false", offload.features, (unsigned long long)offload.flags, tx_offloads, rss_json, queues, initial_bond_json, device_info.driver_name ? device_info.driver_name : "unknown",
        device_info.max_rx_queues, device_info.max_tx_queues, receive_info.nb_desc, transmit_info.nb_desc,
        pool_rx_desc, pool_tx_desc, pool_count,
        mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2], mac.addr_bytes[3],
        mac.addr_bytes[4], mac.addr_bytes[5], (unsigned int)mtu, mbuf_mode, port, rte_eth_dev_count_avail(),
        rte_eth_dev_socket_id(port), numa ? "true" : "false", rte_socket_id(), allocation_socket, pool->socket_id, eal_log_level, rte_log_get_global_level(), (unsigned long long)memory_base, (unsigned long long)rte_eal_get_physmem_size(),
        rte_eal_has_hugepages() ? "true" : "false", rte_memory_get_nchannel(), rte_lcore_count(), rte_get_main_lcore(), sched_getcpu(), link_status ? "null" : (link.link_status ? "true" : "false"),
        promiscuous_state < 0 ? "null" : (promiscuous_state ? "true" : "false"), idle_sleep_us, tx_delay_us);
    fflush(stdout);
    status = 0;
    while (!stopping) {
        /* Original bonding PMD services LACP TX control rings from tx_burst,
         * including when callers currently have no application frames. */
        if (bond_policy) (void)rte_eth_tx_burst(port, 0, NULL, 0);
        if (mtu_fd >= 0) {
            int result = mtu_command(mtu_fd, port, scatter, maximum_mtu, &mtu,
                pending_tx != NULL || tx_length || batch.count || rx_index < rx_count, exception.pending != NULL, &mtu_changes,
                pool, rx_desc, allocation_socket, (uint16_t)queues, &rss, &started);
            if (result < 0) { fprintf(stderr, "ker: MTU device transaction failed\n"); status = 1; break; }
            if (result > 0) { close(mtu_fd); mtu_fd = -1; }
        }
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
        if (exception.pending && !draining) {
            int64_t now;
            if (ker_worker_now_ns(&now)) goto clock_error;
            int result = ker_worker_exception_poll(&exception, port, (unsigned)mtu, now, pcap_dir ? &tx_capture : NULL, &progress);
            if (result) { fprintf(stderr, "ker: host exception TAP forwarding failed: %s\n", strerror(-result)); status = 1; break; }
        }
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
                        count > (ssize_t)sizeof(tx_bytes)) { tx_dropped++; continue; }
                    memcpy(&tx_header, tx_bytes, sizeof(tx_header));
                    tx_length = (size_t)count - sizeof(tx_header);
                    if (!tx_header.gso_type && !frame_size_supported(tx_bytes + sizeof(tx_header), tx_length, mtu)) {
                        tx_length = 0; tx_dropped++; continue;
                    }
                }
                pending_tx = ker_worker_mbuf_from_bytes(pool, tx_bytes + sizeof(struct ker_packet_header), tx_length);
                if (!pending_tx) { tx_retries++; break; }
                struct ker_worker_offload_result translated;
                int offload_error = ker_worker_offload_apply(&offload, &tx_header, pending_tx, (unsigned)mtu, &translated);
                if (offload_error) {
                    fprintf(stderr, "ker: unsupported/malformed native TX metadata (%d) flags=%u gso=%u size=%u hdr=%u csum=%u+%u length=%zu\n",
                        offload_error, tx_header.flags, tx_header.gso_type, tx_header.gso_size,
                        tx_header.header_length, tx_header.checksum_start, tx_header.checksum_offset, tx_length);
                    status = 1; break;
                }
                if (tx_offloads && pending_tx->ol_flags && rte_eth_tx_prepare(port, 0, &pending_tx, 1) != 1) {
                    fprintf(stderr, "ker: original PMD rejected TX offload preparation: %s\n", rte_strerror(rte_errno));
                    status = 1; break;
                }
                tx_tcp_checksum += translated.tcp; tx_udp_checksum += translated.udp; tx_ip_checksum += translated.ip;
                tx_tso4 += translated.tso4; tx_tso6 += translated.tso6; tx_checksum_fallback += translated.fallback;
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
            /* Pinned TAP can mutate an unaccepted offload buffer (and lose
             * its prepended checksum header). Do not retry damaged metadata
             * or report a successful session. Cleanup diagnoses ownership. */
            if (batch.count && offload.tap && tx_offloads && sent.rejected_offload && !offload.tap_retry_safe) {
                fprintf(stderr, "ker: TAP rejected an offload buffer; retry is unsupported by the pinned PMD\n");
                status = 1; break;
            }
            if (sent.packets) progress = true;
        }
        if (draining) {
            rx_shutdown_discarded += rx_count - rx_index;
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
            for (int visited = 0; visited < queues; visited++) {
                uint16_t queue = next_queue;
                next_queue = (uint16_t)((next_queue + 1) % queues);
                rx_count = rte_eth_rx_burst(port, queue, rx, BURST);
                rx_by_queue[queue] += rx_count;
                for (uint16_t index = 0; index < rx_count; index++)
                    if (rx[index]->ol_flags & RTE_MBUF_F_RX_RSS_HASH) rx_rss_metadata++;
                if (rx_count) break;
            }
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
                if (ker_worker_exception_matches(&exception, packet)) {
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
            struct pollfd fds[] = {{control_fd, POLLIN, 0}, {packet_fd, packet_events, 0}, {mtu_fd, POLLIN, 0}, {exception.fd, POLLIN, 0}};
            /* Ethernet PMD RX has no channel readiness notification. Idle
             * channel TX and control wake ppoll; retained work uses bounded
             * retries and RX suffixes watch channel writability. Linux owns
             * protocol timers. */
            if (bond_policy && wait_us > 10000) wait_us = 10000;
            struct timespec timeout = {.tv_nsec = (long)wait_us * 1000};
            idle_waits++;
            int result = ppoll(fds, 4, &timeout, NULL);
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
    if (bond_policy && configured) {
        bond_member_count = ker_bond_members(port, bond_members, 16);
        if (bond_member_count < 0) { bond_member_count = 0; status = 1; }
    }
    if (bond_policy && started && ker_bond_snapshot(port, bond_json, sizeof(bond_json))) {
        fprintf(stderr, "ker: cannot read original bond state\n"); status = 1;
    }
    tx_capture_status = ker_pcap_close(&tx_capture);
    rx_capture_status = ker_pcap_close(&rx_capture);
    if (tx_capture_status || rx_capture_status) { perror("ker: close packet capture"); status = 1; }
    if (pending_tx) rte_pktmbuf_free(pending_tx);
    ker_worker_tx_discard(&batch);
    rx_shutdown_discarded += rx_count - rx_index;
    while (rx_index < rx_count) rte_pktmbuf_free(rx[rx_index++]);
    if (ker_worker_exception_close(&exception)) { fprintf(stderr, "ker: exception TAP cleanup failed\n"); status = 1; }
    bool had_host_receive_mode = receive_mode.socket_fd >= 0;
    if (ker_worker_receive_mode_restore(&receive_mode)) {
        fprintf(stderr, "ker: failed to restore kernel TAP receive mode\n"); status = 1;
    } else if (had_host_receive_mode) receive_mode_restored = true;
    if (started && rte_eth_dev_stop(port)) status = 1;
    if (configured && rte_eth_dev_close(port)) status = 1;
    /* Bond close detaches/stops members but does not release their queues.
     * Those queues can still own this worker's mempool buffers. */
    for (int member = 0; member < bond_member_count; member++)
        if (rte_eth_dev_close(bond_members[member])) status = 1;
    unsigned int outstanding = pool ? rte_mempool_in_use_count(pool) : 0;
    if (outstanding) {
        fprintf(stderr, "ker: %u packet buffers still owned after ethdev shutdown\n", outstanding);
        status = 1;
    } else if (pool) rte_mempool_free(pool);
    printf("KER_IO_DONE {\"exception_selected\":%llu,\"exception_enqueued\":%llu,"
        "\"exception_to_host\":%llu,\"exception_to_host_dropped\":%llu,\"exception_host_received\":%llu,"
        "\"exception_from_host\":%llu,\"exception_wire_dropped\":%llu,\"exception_shutdown_dropped\":%llu,"
        "\"exception_rate_dropped\":%llu,\"exception_malformed\":%llu,\"rx_by_queue\":[",
        (unsigned long long)exception.selected, (unsigned long long)exception.enqueued,
        (unsigned long long)exception.to_host, (unsigned long long)exception.to_host_dropped,
        (unsigned long long)exception.host_received, (unsigned long long)exception.from_host,
        (unsigned long long)exception.wire_dropped, (unsigned long long)exception.shutdown_dropped,
        (unsigned long long)exception.rate_dropped, (unsigned long long)exception.malformed);
    for (int queue = 0; queue < queues; queue++)
        printf("%s%llu", queue ? "," : "", (unsigned long long)rx_by_queue[queue]);
    printf("],\"host_receive_mode_restored\":%s,\"tx_tcp_checksum\":%llu,\"tx_udp_checksum\":%llu,\"tx_ip_checksum\":%llu,\"tx_tso4\":%llu,\"tx_tso6\":%llu,\"tx_checksum_fallback\":%llu,\"rx_rss_metadata\":%llu,\"bond\":%s,\"mtu_final\":%d,\"max_mtu\":%d,\"mtu_changes\":%llu,\"tx\":%llu,\"rx\":%llu,\"dropped\":%llu,\"tx_retries\":%llu,"
        "\"rx_retries\":%llu,\"tx_bytes\":%llu,\"rx_bytes\":%llu,\"tx_dropped\":%llu,\"rx_dropped\":%llu,\"outstanding\":%u,"
        "\"stop_requests\":%llu,\"control_eof\":%s,\"tx_multiseg\":%llu,\"rx_multiseg\":%llu,\"rx_startup_discarded\":%llu,\"rx_shutdown_discarded\":%llu,\"idle_waits\":%llu,\"idle_timeouts\":%llu,\"tx_flushes\":%llu,\"tx_timer_flushes\":%llu,\"tx_full_flushes\":%llu,\"tx_drain_flushes\":%llu}\n", receive_mode_restored ? "true" : "false", (unsigned long long)tx_tcp_checksum, (unsigned long long)tx_udp_checksum, (unsigned long long)tx_ip_checksum, (unsigned long long)tx_tso4, (unsigned long long)tx_tso6, (unsigned long long)tx_checksum_fallback, (unsigned long long)rx_rss_metadata, bond_json, mtu, maximum_mtu, (unsigned long long)mtu_changes, (unsigned long long)transmitted,
        (unsigned long long)received, (unsigned long long)(tx_dropped + rx_dropped),
        (unsigned long long)tx_retries, (unsigned long long)rx_retries,
        (unsigned long long)transmitted_bytes, (unsigned long long)received_bytes,
        (unsigned long long)tx_dropped, (unsigned long long)rx_dropped, outstanding,
        (unsigned long long)stop_requests, control_eof ? "true" : "false",
        (unsigned long long)tx_multiseg, (unsigned long long)rx_multiseg,
        (unsigned long long)rx_startup_discarded, (unsigned long long)rx_shutdown_discarded, (unsigned long long)idle_waits,
        (unsigned long long)idle_timeouts, (unsigned long long)tx_flushes,
        (unsigned long long)tx_timer_flushes, (unsigned long long)tx_full_flushes,
        (unsigned long long)tx_drain_flushes);
    fflush(stdout);
    if (log_dir && ker_worker_log(RTE_LOG_INFO, log.type, "ker.io stopped status=%d\n", status) < 0) status = 1;
    if (ker_worker_log_close(&log)) { perror("ker: close worker log"); status = 1; }
    if (rte_eal_cleanup()) status = 1;
    close(packet_fd);
    close(control_fd);
    if (mtu_fd >= 0) close(mtu_fd);
    return status;
}
