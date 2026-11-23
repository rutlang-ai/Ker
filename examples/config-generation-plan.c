/* Caller-side configuration/worker-role audit. No EAL, transport or reload
 * traffic is started. Original Linux protocol and CPU mapping stay untouched. */
#include <stdio.h>
#include <stdlib.h>
#include <ker/reload.h>
#include "fstack-config-policy.h"
int main(int argc, char **argv)
{
    if (argc < 3 || example_fstack_config_load(argc, argv)) {
        fprintf(stderr, "usage: %s -c legacy.ini [-t primary|secondary] [-p ID]\n", argv[0]);
        example_fstack_config_unload();
        return 1;
    }
    const struct ff_config *cfg = example_fstack_config_current();
    size_t size = ker_reload_state_size();
    void *state = calloc(1, size);
    if (!state || ker_reload_state_init(state, size, 0) ||
        ker_reload_bind_state(state, size, 1, 0)) {
        free(state); example_fstack_config_unload(); return 1;
    }
    int result = 0;
    for (int generation = 0; generation < 2; ++generation) {
        if (ker_reload_worker_select(generation, 0) ||
            ker_reload_selected_generation() != generation) { result = 1; break; }
        printf("Selected worker generation %d; configured process/lcore map:",
            ker_reload_selected_generation());
        for (int i = 0; i < cfg->dpdk.nb_procs; ++i) printf(" %d:%u", i, cfg->dpdk.proc_lcore[i]);
        puts("");
    }
    ker_reload_unbind_state(); free(state); example_fstack_config_unload();
    return result;
}
