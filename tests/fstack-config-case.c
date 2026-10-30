#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "check.h"
#include "fstack-config-policy.h"
#define FIXTURE_PATH(name) "fixtures/" name
int load_with_fixture(const char *path)
{
    char program[] = "config-inspect", option[] = "-c";
    char *argv[] = {program, option, (char *)path, NULL};
    return example_fstack_config_load(3, argv);
}
/* Exercise a bounded negative fixture through the retained parser without
 * disabling the production inspector's capacity preflight. */
extern int example_upstream_load_config(int argc, char *const argv[]);
int load_with_original_fixture(const char *path)
{
    char program[] = "config-inspect", option[] = "-c";
    char *argv[] = {program, option, (char *)path, NULL};

    example_fstack_config_unload();
    optind = 0;
    return example_upstream_load_config(3, argv);
}
#ifdef FSTACK_CONFIG_TEST_WRAP_STRSPLIT
static unsigned g_invalid_portlist_rte_strsplit_calls;
int __real_rte_strsplit(char *string, int stringlen, char **tokens,
                        int maxtokens, char delim);
int __wrap_rte_strsplit(char *string, int stringlen, char **tokens,
                        int maxtokens, char delim)
{
    if (strstr(string, "not_an_int") != NULL)
        g_invalid_portlist_rte_strsplit_calls++;
    return __real_rte_strsplit(string, stringlen, tokens, maxtokens, delim);
}
#endif
int load_with_proc(const char *path, const char *type, const char *id)
{
    char program[] = "config-inspect", conf[] = "-c", proc[] = "-t", index[] = "-p";
    char *argv[] = {program, conf, (char *)path, proc, (char *)type, index, (char *)id, NULL};
    return example_fstack_config_load(7, argv);
}
/* The fault boundary is linked only into these test executables. */
static int g_calloc_fail_after;
extern void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t count, size_t size)
{
    if (g_calloc_fail_after > 0 && --g_calloc_fail_after == 0) return NULL;
    return __real_calloc(count, size);
}
#define ff_global_cfg (*example_fstack_config_current())
#define ff_load_config example_fstack_config_load
#define assert_null(p) CHECK((p) == NULL)
#define assert_non_null(p) CHECK((p) != NULL)
#define assert_true(p) CHECK(p)
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_int_not_equal(a, b) CHECK((a) != (b))
#define assert_string_equal(a, b) CHECK(strcmp((a), (b)) == 0)
#define assert_string_not_equal(a, b) CHECK(strcmp((a), (b)) != 0)
#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)
#include STRINGIFY(SOURCE_INCLUDE)
#ifdef FSTACK_CONFIG_TEST_WRAP_STRSPLIT
static void verify_original_portlist_nonint_error_path(void)
{
    int rv;

    g_invalid_portlist_rte_strsplit_calls = 0;
    rv = load_with_original_fixture(FIXTURE_PATH("invalid_portlist_nonint.ini"));
    CHECK(rv == -1);
    CHECK(g_invalid_portlist_rte_strsplit_calls == 1);
    CHECK(example_fstack_config_current()->dpdk.nb_ports == 0);
    CHECK(example_fstack_config_current()->dpdk.bond_cfgs == NULL);
}
#endif
int main(void)
{
    for (unsigned i = 0; i < 5; ++i) {
        SOURCE_FUNCTION(NULL);
#ifdef FSTACK_CONFIG_TEST_WRAP_STRSPLIT
        verify_original_portlist_nonint_error_path();
#endif
        example_fstack_config_unload();
        CHECK(example_fstack_config_eal_argc() == 0);
    }
    return 0;
}
