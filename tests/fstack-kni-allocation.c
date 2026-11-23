#define _GNU_SOURCE
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include "eal.h"
#include "kni-bridge-internal.h"
static const char *p1_oom;
static unsigned p1_hotplug, fail_count;
static int intercept_fatal, expected_kni_fatal, bypass_fault, fatal_kind;
static jmp_buf fatal_jump;
extern void *__real_rte_zmalloc(const char *, size_t, unsigned);
extern int __real_rte_eal_hotplug_add(const char *, const char *, const char *);
extern void __real_rte_exit(int, const char *, ...) __attribute__((noreturn));
extern void __real___rte_panic(const char *, const char *, ...) __attribute__((noreturn));
void *__wrap_rte_zmalloc(const char *type, size_t size, unsigned align)
{
    if (p1_oom && type && !strcmp(type, p1_oom)) {
        if (bypass_fault) fputs("KNI_FAULT_BYPASS\n", stderr);
        else { ++fail_count; return NULL; }
    }
    return __real_rte_zmalloc(type, size, align);
}
int __wrap_rte_eal_hotplug_add(const char *bus, const char *name, const char *args)
{
    ++p1_hotplug; return __real_rte_eal_hotplug_add(bus, name, args);
}
void __wrap_rte_exit(int code, const char *format, ...)
{
    fatal_kind = 1;
    if (intercept_fatal && expected_kni_fatal) longjmp(fatal_jump, 1);
    char message[1024]; va_list args; va_start(args, format); vsnprintf(message, sizeof(message), format, args); va_end(args);
    fprintf(stderr, "REAL_KNI_EXIT stats_null=%d failed=%u hotplug=%u\n", kni_stat == NULL, fail_count, p1_hotplug);
    __real_rte_exit(code, "%s", message);
}
void __wrap___rte_panic(const char *function, const char *format, ...)
{
    fatal_kind = 2;
    if (intercept_fatal && expected_kni_fatal) longjmp(fatal_jump, 1);
    char message[1024]; va_list args; va_start(args, format); vsnprintf(message, sizeof(message), format, args); va_end(args);
    fprintf(stderr, "REAL_KNI_PANIC slot_null=%d failed=%u hotplug=%u\n", kni_stat && !kni_stat[0], fail_count, p1_hotplug);
    __real___rte_panic(function, "%s", message);
}
#define assert_null(x) CHECK((x) == NULL)
#define assert_non_null(x) CHECK((x) != NULL)
#define assert_int_equal(a,b) CHECK((a) == (b))
#define expect_assert_failure(expression) do { \
    expected_kni_fatal = 1; \
    if (!intercept_fatal || setjmp(fatal_jump) == 0) { (expression); expected_kni_fatal = 0; CHECK(expected_kni_fatal); } \
    expected_kni_fatal = 0; \
} while (0)
#include "fstack-kni-stats-oom-source.inc"
#include "fstack-kni-slot-oom-source.inc"
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    int slot = strstr(argv[1], "slot") != NULL;
    bypass_fault = !strcmp(argv[1], "bypass");
    intercept_fatal = strncmp(argv[1], "fatal-", 6) != 0;
    ker_test_eal_init();
    /* Use an actual ethdev with a MAC; each OOM precedes KNI hotplug. */
    CHECK(rte_eal_hotplug_add("vdev", "net_null0", "no-rx=1") == 0);
    for (unsigned i = 0; i < 5; ++i) {
        CHECK(example_kni_prepare() == 0);
        p1_oom = NULL; p1_hotplug = fail_count = 0; fatal_kind = 0;
        if (slot) test_p1_kni_slot_oom(NULL); else test_p1_kni_stats_oom(NULL);
        CHECK(fail_count == 1 && p1_hotplug == 0 && fatal_kind == (slot ? 2 : 1));
        p1_oom = NULL; CHECK(example_kni_reset() == 0);
    }
    CHECK(rte_eal_cleanup() == 0);
    printf("KNI_SOURCE_OOM %s cycles=5 failed_once=true hotplug=0\n", slot ? "slot" : "stats");
    return 0;
}
