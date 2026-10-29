#include <getopt.h>
#include <string.h>
#include "fstack-config-policy.h"
extern struct ff_config example_upstream_global_cfg;
extern int example_upstream_load_config(int, char *const []);
extern void example_upstream_unload_config(void);
extern int example_upstream_dpdk_argc;
extern char *example_upstream_dpdk_argv[];
/* The parser only reads this default string; it does not call ff_log(). */
char example_upstream_log_filename_prefix[] = "./f-stack-";

void example_fstack_config_unload(void)
{
    example_upstream_unload_config();
    /* Scalars are not reset by upstream unload. A new application document
     * must not inherit flags from the previous one. */
    memset(&example_upstream_global_cfg, 0, sizeof(example_upstream_global_cfg));
}
int example_fstack_config_load(int argc, char *const argv[])
{
    example_fstack_config_unload();
    optind = 0;
    return example_upstream_load_config(argc, argv);
}
const struct ff_config *example_fstack_config_current(void)
{
    return &example_upstream_global_cfg;
}
int example_fstack_config_eal_argc(void)
{
    return example_upstream_dpdk_argc;
}
const char *example_fstack_config_eal_arg(int index)
{
    return index >= 0 && index < example_upstream_dpdk_argc
        ? example_upstream_dpdk_argv[index] : NULL;
}
