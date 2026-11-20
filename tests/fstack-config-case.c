#include "check.h"
#include "fstack-config-policy.h"
#include <string.h>

#define FIXTURE_PATH(name) "fixtures/" name

int load_with_proc(const char *path, const char *type, const char *id)
{
    char program[] = "config-test", config[] = "-c", process[] = "-t", index[] = "-p";
    char *args[] = {program, config, (char *)path, process, (char *)type, index, (char *)id, NULL};
    return example_fstack_config_load(7, args);
}

int load_with_fixture(const char *path)
{
    char program[] = "config-test", config[] = "-c";
    char *args[] = {program, config, (char *)path, NULL};
    return example_fstack_config_load(3, args);
}

#define ff_global_cfg (*example_fstack_config_current())
#define ff_load_config example_fstack_config_load
#define assert_null(value) CHECK((value) == NULL)
#define assert_non_null(value) CHECK((value) != NULL)
#define assert_true(value) CHECK(value)
#define assert_int_equal(actual, expected) CHECK((actual) == (expected))
#define assert_int_not_equal(actual, unexpected) CHECK((actual) != (unexpected))
#define assert_string_equal(actual, expected) CHECK(strcmp((actual), (expected)) == 0)
#define assert_string_not_equal(actual, unexpected) CHECK(strcmp((actual), (unexpected)) != 0)
#define QUOTE_INNER(value) #value
#define QUOTE(value) QUOTE_INNER(value)
#ifdef FSTACK_CONFIG_VERIFY_REJECTION
int load_config_rejection_fixture(const char *path);
#define load_with_fixture load_config_rejection_fixture
#endif
#ifdef FSTACK_CONFIG_CHECK_ALLOCATION
extern int g_calloc_fail_after;
void verify_config_allocation(void);
#endif
#include QUOTE(SOURCE_INCLUDE)

int main(void)
{
    for (unsigned iteration = 0; iteration < 5; ++iteration) {
        SOURCE_FUNCTION(NULL);
#ifdef FSTACK_CONFIG_CHECK_ALLOCATION
        verify_config_allocation();
#endif
        example_fstack_config_unload();
        CHECK(example_fstack_config_eal_argc() == 0);
    }
    return 0;
}
