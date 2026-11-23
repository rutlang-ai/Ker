/* Actual DPDK ring namespace/data isolation. Primary-only, no packets or EAL secondaries. */
#define _GNU_SOURCE
#include "session-ring-names.h"
#include "check.h"
#include "eal.h"
#include <limits.h>
#include <rte_errno.h>
#include <rte_ring.h>
#include <string.h>

#define COUNT (KER_SESSION_SLOTS * KER_SESSION_GENERATIONS * KER_SESSION_PROCESSES * KER_SESSION_CHANNELS)
#define FLAGS (RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ)
struct token { unsigned coordinate, sequence; unsigned char bytes[16]; };
static struct rte_ring *rings[COUNT];
static char names[COUNT][RTE_RING_NAMESIZE];
static unsigned slots[COUNT];
static struct token tokens[COUNT][KER_SESSION_CAPACITY + 1];

static void build(void)
{
    unsigned index = 0;
    for (unsigned slot = 0; slot < KER_SESSION_SLOTS; ++slot)
        for (unsigned gen = 0; gen < KER_SESSION_GENERATIONS; ++gen)
            for (unsigned proc = 0; proc < KER_SESSION_PROCESSES; ++proc)
                for (unsigned channel = 0; channel < KER_SESSION_CHANNELS; ++channel) {
                    CHECK(ker_session_ring_name(names[index], sizeof(names[index]), slot, gen, proc, channel) == 0);
                    CHECK(strlen(names[index]) < RTE_RING_NAMESIZE);
                    for (unsigned previous = 0; previous < index; ++previous)
                        CHECK(strcmp(names[previous], names[index]) != 0);
                    rings[index] = rte_ring_create(names[index], KER_SESSION_CAPACITY, SOCKET_ID_ANY, FLAGS);
                    CHECK(rings[index] && rte_ring_lookup(names[index]) == rings[index]);
                    CHECK(rte_ring_get_capacity(rings[index]) == KER_SESSION_CAPACITY);
                    CHECK((rings[index]->flags & FLAGS) == FLAGS);
                    for (unsigned previous = 0; previous < index; ++previous)
                        CHECK(rings[previous] != rings[index]);
                    slots[index] = slot;
                    for (unsigned seq = 0; seq <= KER_SESSION_CAPACITY; ++seq) {
                        tokens[index][seq].coordinate = index;
                        tokens[index][seq].sequence = seq;
                        memset(tokens[index][seq].bytes, (int)((index * 17 + seq) & 255), 16);
                    }
                    ++index;
                }
    CHECK(index == COUNT && COUNT == 128);
}
static void namespace_contracts(void)
{
    CHECK(strcmp(names[0], "ker_s0_g0_p0_ctl") == 0);
    CHECK(strcmp(names[COUNT-1], "ker_s3_g1_p3_reply") == 0);
    for (unsigned i = 0; i < COUNT; ++i) {
        CHECK(!rte_ring_create(names[i], KER_SESSION_CAPACITY, SOCKET_ID_ANY, FLAGS));
        CHECK(rte_errno == EEXIST && rte_ring_lookup(names[i]) == rings[i]);
        CHECK(rte_ring_count(rings[i]) == 0);
        char buffer[RTE_RING_NAMESIZE + 2];
        memset(buffer, 0x5a, sizeof(buffer));
        size_t length = strlen(names[i]);
        unsigned gen = (i / (KER_SESSION_CHANNELS * KER_SESSION_PROCESSES)) % KER_SESSION_GENERATIONS;
        unsigned proc = (i / KER_SESSION_CHANNELS) % KER_SESSION_PROCESSES;
        unsigned channel = i % KER_SESSION_CHANNELS;
        CHECK(ker_session_ring_name(buffer+1, length+1, slots[i], gen, proc, channel) == 0);
        CHECK(strcmp(buffer+1, names[i]) == 0 && buffer[0] == 0x5a && buffer[length+2] == 0x5a);
        memset(buffer, 0x5a, sizeof(buffer));
        CHECK(ker_session_ring_name(buffer+1, length, slots[i], gen, proc, channel) == -ENAMETOOLONG);
        CHECK(buffer[0] == 0x5a && buffer[length+1] == 0x5a && buffer[length] == 0);
    }
    char unchanged[32]; memset(unchanged, 0x5a, sizeof(unchanged));
    for (unsigned field = 0; field < 4; ++field)
        for (unsigned extreme = 0; extreme < 2; ++extreme) {
            unsigned values[] = {0, 0, 0, 0};
            const unsigned limits[] = {KER_SESSION_SLOTS, KER_SESSION_GENERATIONS, KER_SESSION_PROCESSES, KER_SESSION_CHANNELS};
            values[field] = extreme ? UINT_MAX : limits[field];
            CHECK(ker_session_ring_name(unchanged, sizeof(unchanged), values[0], values[1], values[2], values[3]) == -EINVAL);
            for (unsigned k = 0; k < sizeof(unchanged); ++k) CHECK(unchanged[k] == 0x5a);
        }
    CHECK(ker_session_ring_name(NULL, 32, 0, 0, 0, 0) == -EINVAL);
    CHECK(ker_session_ring_name(unchanged, 0, 0, 0, 0, 0) == -ENAMETOOLONG);
    for (unsigned k = 0; k < sizeof(unchanged); ++k) CHECK(unchanged[k] == 0x5a);
}
static void isolation(void)
{
    for (unsigned i = 0; i < COUNT; ++i) {
        for (unsigned seq = 0; seq < KER_SESSION_CAPACITY; ++seq)
            CHECK(rte_ring_enqueue(rings[i], &tokens[i][seq]) == 0);
        CHECK(rte_ring_count(rings[i]) == KER_SESSION_CAPACITY && rte_ring_free_count(rings[i]) == 0);
        CHECK(rte_ring_enqueue(rings[i], &tokens[i][KER_SESSION_CAPACITY]) == -ENOBUFS);
    }
    for (unsigned seq = 0; seq < KER_SESSION_CAPACITY; ++seq)
        for (unsigned i = 0; i < COUNT; ++i) {
            struct token *result = NULL;
            CHECK(rte_ring_count(rings[i]) == KER_SESSION_CAPACITY-seq);
            CHECK(rte_ring_dequeue(rings[i], (void **)&result) == 0 && result == &tokens[i][seq]);
            CHECK(result->coordinate == i && result->sequence == seq);
            for (unsigned k = 0; k < sizeof(result->bytes); ++k)
                CHECK(result->bytes[k] == ((i * 17 + seq) & 255));
        }
    for (unsigned i = 0; i < COUNT; ++i) {
        void *result = NULL;
        CHECK(rte_ring_dequeue(rings[i], &result) == -ENOENT && result == NULL);
        CHECK(rte_ring_free_count(rings[i]) == KER_SESSION_CAPACITY);
        CHECK(tokens[i][KER_SESSION_CAPACITY].coordinate == i); /* Rejected token remains caller-owned. */
    }
}
static void recreate(void)
{
    for (unsigned i = 0; i < COUNT; ++i) CHECK(rte_ring_enqueue(rings[i], &tokens[i][0]) == 0);
    for (unsigned i = 0; i < COUNT; ++i) {
        if (slots[i] != 1 && slots[i] != 2) continue;
        void *result = NULL;
        CHECK(rte_ring_dequeue(rings[i], &result) == 0 && result == &tokens[i][0]);
        rte_ring_free(rings[i]); rings[i] = NULL;
        CHECK(rte_ring_lookup(names[i]) == NULL && rte_errno == ENOENT);
    }
    for (unsigned i = 0; i < COUNT; ++i) {
        if (slots[i] != 1 && slots[i] != 2) {
            CHECK(rte_ring_lookup(names[i]) == rings[i] && rte_ring_count(rings[i]) == 1);
            continue;
        }
        rings[i] = rte_ring_create(names[i], KER_SESSION_CAPACITY, SOCKET_ID_ANY, FLAGS);
        CHECK(rings[i] && rte_ring_lookup(names[i]) == rings[i] && rte_ring_empty(rings[i]));
        CHECK(rte_ring_enqueue(rings[i], &tokens[i][1]) == 0);
    }
    for (unsigned i = 0; i < COUNT; ++i) {
        void *result = NULL;
        CHECK(rte_ring_dequeue(rings[i], &result) == 0);
        CHECK(result == &tokens[i][slots[i] == 1 || slots[i] == 2 ? 1 : 0]);
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    CHECK(!strcmp(argv[1], "names") || !strcmp(argv[1], "isolation") || !strcmp(argv[1], "recreate"));
    ker_test_eal_init(); build();
    if (!strcmp(argv[1], "names")) namespace_contracts();
    else if (!strcmp(argv[1], "isolation")) isolation();
    else recreate();
    for (unsigned i = 0; i < COUNT; ++i) {
        CHECK(rte_ring_empty(rings[i]));
        rte_ring_free(rings[i]);
        CHECK(rte_ring_lookup(names[i]) == NULL && rte_errno == ENOENT);
    }
    CHECK(rte_eal_cleanup() == 0);
    printf("PASS: actual DPDK 128-ring namespace profile=%s, all rings freed\n", argv[1]);
    return 0;
}
