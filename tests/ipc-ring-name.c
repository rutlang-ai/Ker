#define _GNU_SOURCE
#include <ker/ipc.h>
#include "check.h"
#include <errno.h>
#include <string.h>
#include <rte_ring.h>

static void epoch_ring_names(void)
{
    static const uint32_t epochs[] = {0, KER_IPC_EPOCH_NONE, 1, 2, 3, 4};
    static const unsigned slots[] = {0, 0, 1, 2, 3, 1};
    for (size_t i = 0; i < sizeof(epochs) / sizeof(epochs[0]); ++i)
        CHECK(ker_ipc_epoch_slot(epochs[i]) == slots[i]);

    char name[RTE_RING_NAMESIZE];
    struct ker_ipc_address address = {.process = 1, .generation = 0, .epoch = 3};
    CHECK(ker_ipc_format_ring(name, sizeof(name), &address, 0, FF_UNKNOWN, 0) == 0);
    CHECK(strcmp(name, "ff_msg_ring_in_1") == 0);

    address.generation = 1;
    address.epoch = 0;
    CHECK(ker_ipc_format_ring(name, sizeof(name), &address, 0, FF_UNKNOWN, 1) == 0);
    CHECK(strcmp(name, "ff_msg_ring_in_1_g1") == 0);

    address.epoch = 1;
    CHECK(ker_ipc_format_ring(name, sizeof(name), &address, 0, FF_UNKNOWN, 1) == 0);
    CHECK(strcmp(name, "ff_msg_ring_in_1_e1_g1") == 0);

    address.process = 999;
    address.epoch = 3;
    CHECK(ker_ipc_format_ring(name, sizeof(name), &address, 1, FF_RELOAD, 1) == 0);
    CHECK(strcmp(name, "ff_msg_ring_out_999_10_e3_g1") == 0);
    CHECK(ker_ipc_format_ring(name, 8, &address, 1, FF_RELOAD, 1) == -1);
    CHECK(ker_ipc_format_ring(NULL, sizeof(name), &address, 0, FF_UNKNOWN, 1) == -EINVAL);
}


static void legacy_ring_names(void)
{
    static const uint32_t epochs[] = {0, 1, 2, 3, 4, KER_IPC_EPOCH_NONE};
    static const unsigned processes[] = {0, 1, 127, 999};
    char actual[RTE_RING_NAMESIZE], expected[RTE_RING_NAMESIZE];

    for (size_t i = 0; i < sizeof(epochs) / sizeof(epochs[0]); ++i) {
        for (size_t j = 0; j < sizeof(processes) / sizeof(processes[0]); ++j) {
            for (int generation = 0; generation < 2; ++generation) {
                unsigned process = processes[j];
                struct ker_ipc_address address = {
                    .process = process, .generation = generation, .epoch = epochs[i],
                };
                CHECK(ker_ipc_format_ring(actual, sizeof(actual), &address, 0, FF_UNKNOWN, 0) == 0);
                CHECK(snprintf(expected, sizeof(expected), "ff_msg_ring_in_%u", process) > 0);
                CHECK(strcmp(actual, expected) == 0);

                for (int type = FF_SYSCTL; type < FF_MSG_NUM; ++type) {
                    CHECK(ker_ipc_format_ring(actual, sizeof(actual), &address, 1, type, 0) == 0);
                    CHECK(snprintf(expected, sizeof(expected), "ff_msg_ring_out_%u_%d", process, type) > 0);
                    CHECK(strcmp(actual, expected) == 0);
                }
            }
        }
    }
}


static void expect_distinct_epochs(struct ker_ipc_address address, int output, enum FF_MSG_TYPE type)
{
    char first[RTE_RING_NAMESIZE], second[RTE_RING_NAMESIZE];
    address.epoch = 1;
    CHECK(ker_ipc_format_ring(first, sizeof(first), &address, output, type, 1) == 0);
    address.epoch = 2;
    CHECK(ker_ipc_format_ring(second, sizeof(second), &address, output, type, 1) == 0);
    CHECK(strcmp(first, second) != 0);
    CHECK(strstr(first, "_e1_") != NULL && strstr(second, "_e2_") != NULL);
    CHECK(strlen(first) <= 28 && strlen(second) <= 28);
}

static void cross_master_ring_names(void)
{
    static const unsigned processes[] = {0, 1, 7, 127};
    char zero[RTE_RING_NAMESIZE], unspecified[RTE_RING_NAMESIZE];

    for (size_t i = 0; i < sizeof(processes) / sizeof(processes[0]); ++i) {
        for (int generation = 0; generation < 2; ++generation) {
            struct ker_ipc_address address = {.process = processes[i], .generation = generation};
            expect_distinct_epochs(address, 0, FF_UNKNOWN);
            for (int type = FF_SYSCTL; type < FF_MSG_NUM; ++type)
                expect_distinct_epochs(address, 1, type);

            CHECK(ker_ipc_format_ring(zero, sizeof(zero), &address, 0, FF_UNKNOWN, 1) == 0);
            address.epoch = KER_IPC_EPOCH_NONE;
            CHECK(ker_ipc_format_ring(unspecified, sizeof(unspecified), &address, 0, FF_UNKNOWN, 1) == 0);
            CHECK(strcmp(zero, unspecified) == 0);
        }
    }
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (strcmp(argv[1], "epoch-ring-names") == 0)
        epoch_ring_names();
    else if (strcmp(argv[1], "legacy-ring-names") == 0)
        legacy_ring_names();
    else {
        CHECK(strcmp(argv[1], "cross-master-ring-names") == 0);
        cross_master_ring_names();
    }
    return 0;
}
