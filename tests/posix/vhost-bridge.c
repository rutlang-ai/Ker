/* Test-only Ethernet transport between original DPDK vhost and TAP PMDs. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int signal) { (void)signal; stopping = 1; }

static int startup_flood(uint16_t port, struct rte_mempool *pool, uint64_t count,
    uint64_t *sent, const char *ack)
{
    int64_t deadline = (int64_t)time(NULL) + 10;
    while (*sent < count && !stopping && (int64_t)time(NULL) < deadline) {
        struct rte_eth_link link = {0};
        if (rte_eth_link_get_nowait(port, &link) || !link.link_status) {
            usleep(100);
            continue;
        }
        struct rte_mbuf *packet = rte_pktmbuf_alloc(pool);
        if (!packet) return -1;
        unsigned char *frame = (unsigned char *)rte_pktmbuf_append(packet, 64);
        if (!frame) { rte_pktmbuf_free(packet); return -1; }
        memset(frame, 0, 64);
        memcpy(frame, "\x00\x11\x22\x33\x44\x55", 6);
        memcpy(frame + 6, "\x02\x00\x00\x00\x00\x01", 6);
        frame[12] = 0x88; frame[13] = 0xb5;
        if (rte_eth_tx_burst(port, 0, &packet, 1) == 1) (*sent)++;
        else {
            rte_pktmbuf_free(packet);
            usleep(100);
        }
    }
    if (*sent != count) return -1;
    if (ack && *ack) {
        int fd = open(ack, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) return -1;
        (void)write(fd, "accepted", 8);
        close(fd);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int consumed = rte_eal_init(argc, argv);
    if (consumed < 0) return 1;
    bool queue_one = false, alternate = false;
    unsigned next_queue = 0;
    for (int index = consumed + 1; index < argc; index++) {
        if (!strcmp(argv[index], "--queue-one")) queue_one = true;
        else if (!strcmp(argv[index], "--alternate-queues")) alternate = true;
        else return 1;
    }
    struct rte_mempool *pool = rte_pktmbuf_pool_create("vhost_peer", 4095, 0, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    uint16_t ports[2]; bool configured[2] = {0}, started[2] = {0};
    int result = 1;
    uint64_t forwarded[2] = {0}, dropped = 0;
    uint64_t startup_flood_sent = 0;
    const char *startup_flood_trigger = getenv("KER_TEST_VHOST_FLOOD_TRIGGER");
    const char *startup_flood_ack = getenv("KER_TEST_VHOST_FLOOD_ACK");
    if (!pool || rte_eth_dev_get_port_by_name("net_vhost0", &ports[0]) ||
        rte_eth_dev_get_port_by_name("net_tap0", &ports[1])) goto done;
    for (unsigned side = 0; side < 2; side++) {
        struct rte_eth_conf config = {0};
        uint16_t queues = side == 0 ? 2 : 1;
        if (rte_eth_dev_configure(ports[side], queues, queues, &config)) goto done;
        configured[side] = true;
        for (uint16_t queue = 0; queue < queues; queue++)
            if (rte_eth_rx_queue_setup(ports[side], queue, 512, rte_socket_id(), NULL, pool) ||
                rte_eth_tx_queue_setup(ports[side], queue, 512, rte_socket_id(), NULL)) goto done;
        if (rte_eth_dev_start(ports[side])) goto done;
        started[side] = true;
        if (rte_eth_promiscuous_enable(ports[side]) || rte_eth_allmulticast_enable(ports[side])) goto done;
    }
    signal(SIGTERM, stop); signal(SIGINT, stop);
    puts("READY"); fflush(stdout);
    while (!stopping) {
        bool progress = false;
        if (startup_flood_trigger && !access(startup_flood_trigger, F_OK)) {
            uint64_t target = 1800;
            if (startup_flood(ports[0], pool, target, &startup_flood_sent,
                    startup_flood_ack)) {
                fprintf(stderr, "startup vhost flood stopped at %llu/%llu frames\n",
                    (unsigned long long)startup_flood_sent, (unsigned long long)target);
                result = 1; break;
            }
            startup_flood_trigger = NULL;
        }
        for (unsigned side = 0; side < 2; side++) {
            uint16_t queues = side == 0 ? 2 : 1;
            for (uint16_t queue = 0; queue < queues; queue++) {
                struct rte_mbuf *packets[32];
                uint16_t count = rte_eth_rx_burst(ports[side], queue, packets, 32);
                if (!count) continue;
                progress = true;
                /* Explicit test injection, not a claim about hardware RSS. */
                uint16_t target = side == 1 && queue_one ? 1 : 0;
                if (side == 1 && alternate) { target = (uint16_t)next_queue; next_queue ^= 1; }
                uint16_t sent = rte_eth_tx_burst(ports[1 - side], target, packets, count);
                forwarded[side] += sent; dropped += count - sent;
                for (uint16_t index = sent; index < count; index++) rte_pktmbuf_free(packets[index]);
            }
        }
        if (!progress) usleep(100);
    }
    result = 0;
done:
    for (unsigned side = 0; side < 2; side++) {
        if (started[side] && rte_eth_dev_stop(ports[side])) result = 1;
        if (configured[side] && rte_eth_dev_close(ports[side])) result = 1;
    }
    unsigned outstanding = pool ? rte_mempool_in_use_count(pool) : 0;
    printf("BRIDGE {\"to_host\":%llu,\"to_native\":%llu,\"dropped\":%llu,\"startup_flood\":%llu,\"outstanding\":%u}\n",
        (unsigned long long)forwarded[0], (unsigned long long)forwarded[1],
        (unsigned long long)dropped, (unsigned long long)startup_flood_sent, outstanding);
    if (outstanding) result = 1;
    else if (pool) rte_mempool_free(pool);
    if (rte_eal_cleanup()) result = 1;
    return result;
}
