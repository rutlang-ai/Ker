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

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (strcmp(argv[1], "epoch-ring-names") == 0)
        epoch_ring_names();
    else {
        CHECK(strcmp(argv[1], "legacy-ring-names") == 0);
        legacy_ring_names();
    }
    return 0;
}
