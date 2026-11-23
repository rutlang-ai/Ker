#include <string.h>
#include "check.h"
#include "fstack-config-policy.h"
#define FIXTURE_PATH(name) "fixtures/" name
static int load_with_fixture(const char *path)
{
    char program[] = "config-inspect", option[] = "-c";
    char *argv[] = {program, option, (char *)path, NULL};
    return example_fstack_config_load(3, argv);
}
#define ff_global_cfg (*example_fstack_config_current())
/* Exercise upstream cleanup itself: adapter memset must not hide a missing
 * free/null operation in the retained contract. */
extern void example_upstream_unload_config(void);
#define ff_unload_config example_upstream_unload_config
#define assert_null(p) CHECK((p) == NULL)
#define assert_non_null(p) CHECK((p) != NULL)
#include "fstack-config-unload-source.inc"
int main(void)
{
    /* Complete original assertions, then repeated real application loads.
     * No EAL startup, PMD or native networking is claimed by this test. */
    for (unsigned i = 0; i < 100; ++i) {
        test_ff_unload_config_zeroes_state(NULL);
        CHECK(example_fstack_config_eal_argc() == 0);
        CHECK(example_fstack_config_eal_arg(0) == NULL);
        CHECK(example_fstack_config_eal_arg(-1) == NULL);
    }
    return 0;
}
