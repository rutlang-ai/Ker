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
#ifdef FSTACK_CONFIG_TEST_WRAP_INI_HANDLER
typedef int (*test_ini_handler)(void *, const char *, const char *, const char *);
extern int __real_example_upstream_ini_parse(const char *, test_ini_handler, void *);
static int g_capture_original_ini_handler;
static unsigned g_rss_check_handler_calls;
static int g_rss_check_handler_result;

struct recording_ini_handler {
    test_ini_handler original;
    void *user;
};

static int record_original_ini_handler(void *opaque, const char *section,
                                       const char *name, const char *value)
{
    struct recording_ini_handler *recording = opaque;
    int result = recording->original(recording->user, section, name, value);

    if (strcmp(section, "rss_check") == 0 && strcmp(name, "enable") == 0) {
        g_rss_check_handler_calls++;
        g_rss_check_handler_result = result;
    }
    return result;
}

int __wrap_example_upstream_ini_parse(const char *filename,
                                      test_ini_handler handler, void *user)
{
    struct recording_ini_handler recording = {handler, user};

    if (!g_capture_original_ini_handler)
        return __real_example_upstream_ini_parse(filename, handler, user);
    return __real_example_upstream_ini_parse(filename,
                                              record_original_ini_handler,
                                              &recording);
}

static void verify_original_rss_handler_reached(void)
{
    int rv;

    /* The normal inspector rejects this plan and leaves the reset state. */
    rv = load_with_fixture(FIXTURE_PATH("invalid_rss_check_no_port.ini"));
    CHECK(rv != 0);
    CHECK(example_fstack_config_current()->log.dir == NULL);

    /* Bypass only inspector preflight; capture the real upstream callback. */
    g_rss_check_handler_calls = 0;
    g_rss_check_handler_result = -1;
    g_capture_original_ini_handler = 1;
    rv = load_with_original_fixture(FIXTURE_PATH("invalid_rss_check_no_port.ini"));
    g_capture_original_ini_handler = 0;
    CHECK(rv == -1);
    CHECK(g_rss_check_handler_calls == 1);
    CHECK(g_rss_check_handler_result == 0);
    CHECK(example_fstack_config_current()->dpdk.rss_check_cfgs == NULL);
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
#ifdef FSTACK_CONFIG_TEST_WRAP_INI_HANDLER
        verify_original_rss_handler_reached();
#endif
        example_fstack_config_unload();
        CHECK(example_fstack_config_eal_argc() == 0);
    }
    return 0;
}
