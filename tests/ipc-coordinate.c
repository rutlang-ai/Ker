#include <ker/ipc.h>
#include "check.h"
#include <errno.h>
#include <rte_ring.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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


static void malformed(void)
{
    static const struct {
        const char *process;
        const char *generation;
    } invalid[] = {
        {"1:0:3:4", NULL}, {"1:0:", NULL}, {"1:0:x", NULL}, {"1:x", NULL},
        {"x", NULL}, {NULL, "x"}, {"1:0:4294967295", NULL}, {"1:0:-1", NULL},
        {"4294967296", NULL}, {"1:4294967296", NULL}, {"65536", NULL},
    };

    for (size_t index = 0; index <= sizeof(invalid) / sizeof(invalid[0]); ++index) {
        CHECK(fflush(NULL) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            if (index == sizeof(invalid) / sizeof(invalid[0]))
                ker_ipc_epoch_or_exit(KER_IPC_EPOCH_NONE);
            else
                ker_ipc_select_or_exit(invalid[index].process, invalid[index].generation);
            _exit(99);
        }

        int status;
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);
    }
}

int main(int argc, char **argv)
{
    char *valid[] = {argv[0], "2:1:1", "-", "2", "1", "1", "ff_msg_ring_in_2_e1_g1", "1"};
    if (argc == 2 && strcmp(argv[1], "--malformed") == 0) {
        malformed();
        argc = sizeof(valid) / sizeof(valid[0]);
        argv = valid;
    }
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
