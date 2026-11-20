#include "check.h"
#include "fstack-config-policy.h"
#include <errno.h>
#include <rte_config.h>

int g_calloc_fail_after;
static unsigned injections;

void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size)
{
    if (g_calloc_fail_after > 0 && --g_calloc_fail_after == 0) {
        CHECK(count == RTE_MAX_ETHPORTS && size == sizeof(struct FSTACK_CONFIG_ALLOCATED_TYPE));
        injections++;
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(count, size);
}

int load_with_fixture(const char *path);

void verify_config_allocation(void)
{
    CHECK(injections == 1 && g_calloc_fail_after == 0);
    CHECK(example_fstack_config_current()->dpdk.FSTACK_CONFIG_ALLOCATED_FIELD == NULL);
    injections = 0;
    CHECK(load_with_fixture("fixtures/" FSTACK_CONFIG_RECOVERY_FIXTURE) == 0);
    CHECK(example_fstack_config_current()->dpdk.FSTACK_CONFIG_ALLOCATED_FIELD != NULL);
}
