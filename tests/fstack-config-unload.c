#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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
static void load_allow_list(int count, int expected_arguments)
{
    const char input[] = FIXTURE_PATH("valid_minimal.ini");
    FILE *fixture = fopen(input, "r");
    CHECK(fixture != NULL);
    char path[] = "/tmp/ker-fstack-config-plan-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    FILE *configuration = fdopen(fd, "w");
    CHECK(configuration != NULL);
    CHECK(fputs("[dpdk]\nallow=", configuration) >= 0);
    for (int i = 0; i < count; ++i)
        CHECK(fprintf(configuration, "%s0000:00:%02x.0", i ? "," : "", (unsigned)i) > 0);
    CHECK(fputc('\n', configuration) != EOF);

    char line[256];
    while (fgets(line, sizeof(line), fixture))
        CHECK(fputs(line, configuration) >= 0);
    CHECK(!ferror(fixture));
    CHECK(fclose(fixture) == 0 && fclose(configuration) == 0);

    int result = load_with_fixture(path);
    CHECK(unlink(path) == 0);
    CHECK((result == 0) == (expected_arguments > 0));
    CHECK(example_fstack_config_eal_argc() == expected_arguments);
    CHECK(example_fstack_config_eal_arg(expected_arguments) == NULL);
    example_fstack_config_unload();
}

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
    CHECK(load_with_fixture(FIXTURE_PATH("valid_minimal.ini")) == 0);
    int slots = DPDK_CONFIG_NUM - example_fstack_config_eal_argc();
    CHECK(slots > 0);
    load_allow_list(slots, DPDK_CONFIG_NUM);
    load_allow_list(slots + 1, 0);
    load_allow_list(slots, DPDK_CONFIG_NUM);
    return 0;
}
