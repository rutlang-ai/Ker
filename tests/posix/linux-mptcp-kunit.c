#include <lkl_host.h>
#include "host-memory.h"
#include "host-thread.h"
#include "host-clock.h"
#include "host-timer.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Boot the actual test-profile kernel. KUnit and the unmodified MPTCP suites
 * execute at their original init-time position. No facade, replacement test,
 * or protocol implementation lives in this host harness. */
static void kernel_print(const char *bytes, int length)
{
    while (length > 0) {
        ssize_t result = write(STDOUT_FILENO, bytes, (size_t)length);
        if (result <= 0) _exit(10);
        bytes += result; length -= (int)result;
    }
}
int ker_native_host_usercopy_probe(void);
int main(int argc, char **argv)
{
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--disabled"))) return 2;
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_thread_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    ker_native_host_timer_init(&lkl_host_ops);
    if (ker_native_host_usercopy_probe()) return 6;
    lkl_host_ops.print = kernel_print;
    if (lkl_init(&lkl_host_ops)) return 3;
    int result = lkl_start_kernel("mem=64M loglevel=8 kunit.enable=%d kunit.filter_glob=mptcp-*", argc == 1);
    if (result) { fprintf(stderr, "native kernel boot failed: %d\n", result); return 4; }
    puts("KER_MPTCP_KUNIT_BOOTED"); fflush(stdout);
    result = (int)lkl_sys_halt();
    if (result) { fprintf(stderr, "native kernel halt failed: %d\n", result); return 5; }
    lkl_cleanup();
    puts("KER_MPTCP_KUNIT_HALTED");
    return 0;
}
