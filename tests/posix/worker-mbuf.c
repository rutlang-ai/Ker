#define _GNU_SOURCE
#include "worker-mbuf.h"
#include <errno.h>
#include <rte_eal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    cpu_set_t cpus;
    CHECK(!sched_getaffinity(0, sizeof(cpus), &cpus));
    int cpu = 0;
    while (cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &cpus)) cpu++;
    CHECK(cpu < CPU_SETSIZE);
    char cores[64];
    snprintf(cores, sizeof(cores), "--lcores=0@%d", cpu);
    char *args[] = {"worker-mbuf", cores, "--no-huge", "--no-pci", "--no-shconf", "--no-telemetry", "--iova-mode=va", "-m", "64"};
    CHECK(rte_eal_init(sizeof(args) / sizeof(args[0]), args) >= 0);
    struct rte_mempool *pool = rte_pktmbuf_pool_create("chain_test", 31, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(pool);
    unsigned char input[9014], output[9014];
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (unsigned char)(i * 13 + 7);
    const size_t lengths[] = {14, 2047, 2048, 2049, 4096, 9014};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        size_t length = lengths[i];
        struct rte_mbuf *packet = ker_worker_mbuf_from_bytes(pool, input, length);
        CHECK(packet && packet->pkt_len == length);
        CHECK(packet->nb_segs == (length + 2047) / 2048);
        const void *bytes = rte_pktmbuf_read(packet, 0, length, output);
        CHECK(bytes && !memcmp(bytes, input, length));
        CHECK(rte_mempool_avail_count(pool) == 31u - packet->nb_segs);
        rte_pktmbuf_free(packet);
        CHECK(rte_mempool_avail_count(pool) == 31);
    }
    struct rte_mbuf *held[28];
    for (size_t i = 0; i < 28; i++) CHECK((held[i] = rte_pktmbuf_alloc(pool)));
    CHECK(rte_mempool_avail_count(pool) == 3);
    errno = 0;
    CHECK(!ker_worker_mbuf_from_bytes(pool, input, sizeof(input)) && errno == ENOBUFS);
    CHECK(rte_mempool_avail_count(pool) == 3);
    for (size_t i = 0; i < 28; i++) rte_pktmbuf_free(held[i]);
    CHECK(rte_mempool_avail_count(pool) == 31);
    CHECK(!ker_worker_mbuf_from_bytes(pool, NULL, 14) && errno == EINVAL);
    CHECK(!ker_worker_mbuf_from_bytes(pool, input, 0) && errno == EINVAL);
    rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());
    puts("PASS: real DPDK mbuf chains, segment boundaries and allocation-failure reclamation");
    return 0;
}
