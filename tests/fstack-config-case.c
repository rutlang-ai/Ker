#include "check.h"
#include "fstack-config-policy.h"
#include <string.h>

#ifdef FSTACK_CONFIG_RELOAD_GENERATION
#include <ker/ipc.h>
#include "ff_reload.h"

static int reload_ring_name(char *buffer, unsigned size, const char *base,
    unsigned process, int type, int generation, int enabled)
{
    int output = strcmp(base, FF_MSG_RING_OUT) == 0;
    CHECK(output || strcmp(base, FF_MSG_RING_IN) == 0);
    CHECK(process <= UINT16_MAX);
    const struct ker_ipc_address address = {
        .process = process, .generation = generation, .epoch = 0,
    };
    return ker_ipc_format_ring(buffer, size, &address, output, (enum FF_MSG_TYPE)type, enabled);
}
#define ff_reload_msg_ring_name reload_ring_name
#endif

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
