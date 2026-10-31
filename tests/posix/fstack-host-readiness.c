#define _GNU_SOURCE
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include "check.h"
#include "host-readiness.h"
#include "host-readiness-native.h"
#define ff_host_epoll_create1 example_host_epoll_create1
#define ff_host_kqueue_ctl example_host_kqueue_ctl
#define ff_host_kqueue_poll example_host_kqueue_poll
#define ff_host_close example_host_close
#define assert_true(x) CHECK(x)
#define assert_int_equal(a, b) CHECK((a) == (b))
#include "fstack-host-readiness-source.inc"
int main(void)
{
    example_require_native();
    for (unsigned i = 0; i < 5; ++i)
        test_ff_host_kqueue_ctl_add_idempotent(NULL);
    example_finish_native();
    puts("HOST_SOURCE_CASE test_ff_host_kqueue_ctl_add_idempotent");
    return 0;
}
