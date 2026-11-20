#include <ker/ipc.h>
#include "check.h"
#include <errno.h>
#include <rte_ring.h>
#include <stdlib.h>
#include <string.h>

static const char *optional(const char *text)
{
    return strcmp(text, "-") == 0 ? NULL : text;
}

static long long number(const char *text)
{
    char *end;
    errno = 0;
    long long value = strtoll(text, &end, 10);
    CHECK(errno == 0 && end != text && *end == '\0');
    return value;
}

int main(int argc, char **argv)
{
    CHECK(argc == 8);
    CHECK(ker_ipc_select_or_exit(optional(argv[1]), optional(argv[2])) == number(argv[3]));
    struct ker_ipc_address address;
    CHECK(ker_ipc_address(&address) == 0);
    CHECK(address.process == number(argv[3]) && address.generation == number(argv[4]));
    CHECK(address.epoch == number(argv[5]));
    CHECK(ker_ipc_epoch_slot(address.epoch) == number(argv[7]));

    char ring[RTE_RING_NAMESIZE];
    memset(ring, 0x5a, sizeof(ring));
    int result = ker_ipc_ring_name(ring, sizeof(ring), 0, FF_UNKNOWN);
    const char *expected = optional(argv[6]);
    if (expected) {
        CHECK(result == 0 && strcmp(ring, expected) == 0);
    } else {
        CHECK(result == -EAGAIN);
        for (size_t index = 0; index < sizeof(ring); ++index)
            CHECK(ring[index] == 0x5a);
    }
    return 0;
}
