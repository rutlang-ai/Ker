#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ker/reload.h>
#include <ker/ipc.h>
#include "fstack-config-policy.h"
#include "ff_reload.h"
#include "check.h"
#define FIXTURE_PATH(name) "fixtures/" name
static int load_with_proc(const char *path, const char *type, const char *id)
{
    char program[] = "generation-plan", conf[] = "-c", proc[] = "-t", index[] = "-p";
    char *argv[] = {program, conf, (char *)path, proc, (char *)type, index, (char *)id, NULL};
    return example_fstack_config_load(7, argv);
}
static void select_generation(int generation) { (void)ker_reload_worker_select(generation, 0); }
static void detach_state(void *state) { CHECK(!state); ker_reload_unbind_state(); }
static int ring_name(char *buffer, unsigned size, const char *base,
    unsigned process, int type, int generation, int enabled)
{
    int output = !strcmp(base, "ff_msg_ring_out_");
    CHECK(output || !strcmp(base, "ff_msg_ring_in_"));
    struct ker_ipc_address address = {process, generation, 0};
    return ker_ipc_format_ring(buffer, size, &address, output, (enum FF_MSG_TYPE)type, enabled);
}
#define ff_global_cfg (*example_fstack_config_current())
#define ff_reload_set_gen select_generation
#define ff_reload_gen ker_reload_selected_generation
#define ff_reload_attach_state detach_state
#define ff_reload_msg_ring_name ring_name
#define assert_int_equal(a, b) CHECK((a) == (b))
#define assert_string_equal(a, b) CHECK(strcmp((a), (b)) == 0)
#define assert_string_not_equal(a, b) CHECK(strcmp((a), (b)) != 0)
#include "fstack-generation-config-source.inc"
int main(void)
{
    size_t size = ker_reload_state_size();
    void *state = calloc(1, size); CHECK(state);
    CHECK(!ker_reload_state_init(state, size, 0));
    CHECK(!ker_reload_bind_state(state, size, 1, 0));
    test_ut_nr_12_generation_mapping(NULL);
    example_fstack_config_unload(); free(state);
    return 0;
}
