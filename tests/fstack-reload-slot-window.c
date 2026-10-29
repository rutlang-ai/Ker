/* Test-only role/mapping/fatal interception around the actual production TU.
 * No hook is compiled into or installed with ker::reload. */
#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_debug.h>
#include <setjmp.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "check.h"
static enum rte_proc_type_t p1_process_type;
static uint32_t p1_parent;
static struct rte_memzone mapping;
static jmp_buf fatal;
static unsigned fatal_count;
static int expecting_fatal;
static enum rte_proc_type_t test_role(void) { return p1_process_type; }
static const struct rte_memzone *test_lookup(const char *name)
{
    CHECK(!strcmp(name, "ff_reload_gendir")); return &mapping;
}
static void test_exit(int code, const char *format, ...) __attribute__((noreturn));
static void test_exit(int code, const char *format, ...)
{
    CHECK(expecting_fatal && code == EXIT_FAILURE);
    CHECK(strstr(format, "cannot register this") && strstr(format, "cross-master epoch isolation"));
    ++fatal_count; longjmp(fatal, 1);
}
#define rte_eal_process_type test_role
#define rte_memzone_lookup test_lookup
#define rte_exit test_exit
#include "../src/compat/reload.c"
#undef rte_exit
#undef rte_memzone_lookup
#undef rte_eal_process_type
static struct ff_reload_gendir *p1_dir;
#define __real_getppid getppid
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_memory_equal(a, b, size) CHECK(!memcmp((a), (b), (size)))
#define expect_assert_failure(call) do { \
    expecting_fatal = 1; \
    if (!setjmp(fatal)) { call; CHECK(0); } \
    expecting_fatal = 0; \
} while (0)
#define assert_true(value) CHECK(value)
#include "fstack-reload-slot-window-source.inc"
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    struct ff_reload_gendir directory = {0};
    p1_dir = &directory; mapping.addr = p1_dir; mapping.len = sizeof(*p1_dir);
    p1_dir->magic = FF_RELOAD_GENDIR_MAGIC; p1_dir->version = FF_RELOAD_GENDIR_VERSION;
    p1_dir->len = sizeof(*p1_dir); p1_dir->slot_max = FF_RELOAD_EPOCH_SLOT_MAX; p1_dir->gen_max = FF_RELOAD_GEN_MAX;
    struct ff_reload_state state = {0}; ff_reload_attach_state(&state);
    ff_global_cfg.dpdk.graceful_reload = 1;
    if (!strcmp(argv[1], "window")) {
        test_p2_slot_transient_window(NULL);
        CHECK(!fatal_count && g_dir == p1_dir);
        puts("PASS: original transient slot window, stale wait and exact slot");
    } else {
        CHECK(!strcmp(argv[1], "exhausted"));
        test_p2_slot_transient_exhausted(NULL);
        CHECK(fatal_count == 1 && !g_dir && !g_reload_gendir && !g_reload_dir_publish);
        puts("PASS: original transient slot budget exhaustion, refusal and exact slot");
    }
    return 0;
}
