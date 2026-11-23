#ifndef EXAMPLE_FSTACK_CONFIG_POLICY_H
#define EXAMPLE_FSTACK_CONFIG_POLICY_H
#include <stdint.h>
#include "ff_config.h"
/* Single-threaded inspection only. Returned storage expires at load/unload.
 * A successful parse is not permission to apply a legacy setting to Ker. */
int example_fstack_config_load(int argc, char *const argv[]);
const struct ff_config *example_fstack_config_current(void);
void example_fstack_config_unload(void);
int example_fstack_config_eal_argc(void);
const char *example_fstack_config_eal_arg(int index);
#endif
