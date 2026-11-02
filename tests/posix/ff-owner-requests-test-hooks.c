#include "ff-owner-requests-diag.h"
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/capability.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>

int ker_ff_owner_requests_test_snapshot(uint32_t mark, uint64_t *count)
{
    if (!count) return -EINVAL;
    struct ker_ff_owner_requests_state state;
    int status = ker_ff_owner_requests_begin(&state, mark);
    if (status) return status;
    atomic_bool cancel = false;
    uint64_t result = 0;
    for (;;) {
        int progress = ker_ff_owner_requests_step(&state, &cancel, &result);
        if (progress < 0) {
            ker_ff_owner_requests_close(&state);
            return progress;
        }
        if (progress == 1) break;
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    }
    ker_ff_owner_requests_close(&state);
    *count = result;
    return 0;
}

int ker_ff_owner_requests_test_syncookies(int value)
{
    if (value != 0 && value != 2) return -EINVAL;
    return lkl_sysctl("net.ipv4.tcp_syncookies", value ? "2" : "0");
}

int ker_ff_owner_requests_test_fastopen(void)
{
    return lkl_sysctl("net.ipv4.tcp_fastopen", "3");
}
