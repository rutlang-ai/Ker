#include "check.h"
#include "fstack-config-policy.h"
#include "ff_ini_parser.h"
#include <getopt.h>
#include <string.h>

extern int example_upstream_load_config(int argc, char *const args[]);
static unsigned calls;

#ifdef FSTACK_CONFIG_REJECT_LIST
#include <rte_string_fns.h>
int __real_rte_strsplit(char *input, int length, char **tokens, int count, char delim);
int __wrap_rte_strsplit(char *input, int length, char **tokens, int count, char delim)
{
    if (strcmp(input, "0,not_an_int,2") == 0 && delim == ',') calls++;
    return __real_rte_strsplit(input, length, tokens, count, delim);
}
#else
struct callback {
    ini_handler handler;
    void *user;
};
static int record(void *opaque, const char *section, const char *key, const char *value)
{
    struct callback *original = opaque;
    int result = original->handler(original->user, section, key, value);
    if (strcmp(section, FSTACK_CONFIG_REJECT_SECTION) == 0 &&
        strcmp(key, FSTACK_CONFIG_REJECT_KEY) == 0) {
        CHECK(result == 0);
        calls++;
    }
    return result;
}

int __real_example_upstream_ini_parse(const char *path, ini_handler handler, void *user);
int __wrap_example_upstream_ini_parse(const char *path, ini_handler handler, void *user)
{
    struct callback original = {handler, user};
    CHECK(strcmp(path, FSTACK_CONFIG_REJECTION_FIXTURE) == 0);
    return __real_example_upstream_ini_parse(path, record, &original);
}
#endif

int load_config_rejection_fixture(const char *path)
{
    /* Only replay the fixed, audited negative fixture directly against the
     * original parser so the inspector's preflight cannot mask the path. */
    CHECK(strcmp(path, FSTACK_CONFIG_REJECTION_FIXTURE) == 0);
    char program[] = "config-test", config[] = "-c";
    char *args[] = {program, config, (char *)path, NULL};
    example_fstack_config_unload();
    calls = 0;
    optind = 0;
    int result = example_upstream_load_config(3, args);
    CHECK(result == -1 && calls == 1);
    return result;
}
