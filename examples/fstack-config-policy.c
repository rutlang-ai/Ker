#include <getopt.h>
#include <string.h>
#include "fstack-config-policy.h"
#include "ff_ini_parser.h"
extern struct ff_config example_upstream_global_cfg;
extern int example_upstream_load_config(int, char *const []);
extern void example_upstream_unload_config(void);
extern int example_upstream_dpdk_argc;
extern char *example_upstream_dpdk_argv[];
extern int example_parse_ini_document(const char *, ini_handler, void *);

/* Validate the fixed upstream argv capacity after the INI parser has applied
 * defaults and repeated keys, before ff_load_config assembles the EAL plan. */
int example_upstream_ini_parse(const char *path, ini_handler handler, void *user)
{
    int result = example_parse_ini_document(path, handler, user);
    if (result != 0)
        return result;

    const struct ff_config *cfg = user;
    size_t arguments = 1;
    arguments += cfg->dpdk.no_huge != 0;
    arguments += cfg->dpdk.proc_mask != NULL || (cfg->dpdk.thread_mode && cfg->dpdk.lcore_mask);
    arguments += cfg->dpdk.nb_channel != 0;
    arguments += cfg->dpdk.memory != 0;
    arguments += cfg->dpdk.log_level != 0;
    arguments += cfg->dpdk.proc_type != NULL || cfg->dpdk.thread_mode;
    arguments += cfg->dpdk.base_virtaddr != NULL;
    arguments += cfg->dpdk.file_prefix != NULL;

    if (cfg->dpdk.nb_vdev < 0 || cfg->dpdk.nb_vdev > DPDK_CONFIG_NUM ||
        cfg->dpdk.nb_bond < 0 || cfg->dpdk.nb_bond > DPDK_CONFIG_NUM)
        goto oversized;
    if (cfg->dpdk.nb_vdev)
        arguments += (size_t)cfg->dpdk.nb_vdev + 1 + (cfg->dpdk.file_prefix == NULL);
    arguments += 2 * (size_t)cfg->dpdk.nb_bond;

    const char *allow = cfg->dpdk.allow;
    while (allow && *allow) {
        allow += strspn(allow, ",");
        if (!*allow)
            break;
        size_t length = strcspn(allow, ",");
        if (length + sizeof("--allow=") > DPDK_CONFIG_MAXLEN)
            goto oversized;
        ++arguments;
        allow += length;
    }

    /* Upstream caps extra_eal_args separately. One slot stays null. */
    if (arguments <= DPDK_CONFIG_NUM)
        return 0;

oversized:
    fprintf(stderr, "F-Stack EAL plan exceeds the inspector argument capacity\n");
    return -3;
}

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
