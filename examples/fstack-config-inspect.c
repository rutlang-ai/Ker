#include <stdio.h>
#include "fstack-config-policy.h"
int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s -c FSTACK.ini [-t primary|secondary] [-p ID]\n", argv[0]);
        return 2;
    }
    int result = example_fstack_config_load(argc, argv);
    if (!result) {
        const struct ff_config *cfg = example_fstack_config_current();
        printf("Parsed legacy configuration: processes=%d, ports=%d\n",
               cfg->dpdk.nb_procs, cfg->dpdk.nb_ports);
        puts("Legacy EAL argument plan (not executed):");
        for (int i = 0; i < example_fstack_config_eal_argc(); ++i)
            printf("  %s\n", example_fstack_config_eal_arg(i));
        puts("Inspection only: FreeBSD, KNI, thread, RSS and reload settings "
             "require explicit runtime adaptation. No Ker runtime was configured.");
    }
    example_fstack_config_unload();
    return result ? 1 : 0;
}
