#define _GNU_SOURCE
#include "check.h"
#include "flow-map-policy.h"
#include <ker/reload.h>
#include "ff_config.h"
#include "ff_reload.h"
#include <string.h>
extern struct ff_config example_flow_configuration;
static void attach(void *state)
{
    ker_reload_unbind_state();
    if (state) CHECK(!ker_reload_bind_state(state, sizeof(struct ff_reload_state), 1, 0));
}
#define ff_global_cfg example_flow_configuration
#define ff_reload_attach_state attach
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_true(a) CHECK(a)
#include "fstack-flow-map-source.inc"
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    if (!strcmp(argv[1], "basic")) test_ut_nr_23_flow_map(NULL);
    else if (!strcmp(argv[1], "single-phase")) test_a1_flow_map_single_phase(NULL);
    else if (!strcmp(argv[1], "admission")) test_a1_flow_map_admission_rule(NULL);
    else if (!strcmp(argv[1], "revoke")) test_a1_flow_map_revoke(NULL);
    else { CHECK(!strcmp(argv[1], "growth")); test_p3_flow_map_bounded_growth(NULL); }
    CHECK(!ff_flow_map_active());
    struct ker_reload_runtime view;
    CHECK(!ker_reload_runtime_view(&view)); CHECK(!view.attached);
    puts("PASS: complete original flow-map assertions; real reload state detached");
    return 0;
}
