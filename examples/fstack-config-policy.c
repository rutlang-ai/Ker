#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_config.h>

#include "ff_config.h"
#include "ff_ini_parser.h"
#include "fstack-config-policy.h"

extern struct ff_config example_upstream_global_cfg;
extern int example_upstream_load_config(int, char *const []);
extern void example_upstream_unload_config(void);
extern int example_upstream_dpdk_argc;
extern char *example_upstream_dpdk_argv[];
extern int example_upstream_ini_parse(const char *filename,
                                      ini_handler handler, void *user);
extern char *const example_upstream_short_options;
extern struct option example_upstream_long_options[];
/* The parser only reads this default string; it does not call ff_log(). */
char example_upstream_log_filename_prefix[] = "./f-stack-";

/*
 * The retained parser builds its EAL plan in fixed-size storage:
 * dpdk_argv[DPDK_CONFIG_NUM + 1], a DPDK_CONFIG_MAXLEN stack buffer per
 * argument, and caller-supplied arrays for port/lcore/vlan lists.  Upstream
 * checks none of these before writing, so a caller that inspects an arbitrary
 * legacy document must reject an oversized plan first.  The parser itself
 * stays byte-for-byte unchanged; this preflight only mirrors the small subset
 * of keys that contribute to those fixed-size destinations.
 */
struct vdev_plan {
    int has_path;
    int has_mac;
    size_t path_len;
    size_t mac_len;
    unsigned nb_queues;
    unsigned nb_cq;
    unsigned queue_size;
};

struct bond_plan {
    int has_slave;
    int has_primary;
    int has_mac;
    int has_xmit_policy;
    size_t slave_len;
    size_t primary_len;
    size_t mac_len;
    size_t xmit_policy_len;
    unsigned mode;
    unsigned socket_id;
    unsigned lsc_poll_period_ms;
    unsigned up_delay;
    unsigned down_delay;
};

struct config_plan {
    int no_huge;
    int channel;
    int memory;
    int log_level;
    int has_lcore_mask;
    size_t lcore_mask_len;
    int has_base_virtaddr;
    size_t base_virtaddr_len;
    int has_file_prefix;
    size_t file_prefix_len;
    size_t allow_count;
    size_t allow_max_len;
    size_t extra_count;
    size_t extra_max_len;
    int nb_vdev;
    int nb_bond;
    int has_port_list;
    int has_port_section;
    int has_owner_proc_id;
    int owner_proc_id;
    int primary_slim;
    int kni_enable;
    size_t vlan_filter_count;
    uint16_t vlan_filter_ids[DPDK_MAX_VLAN_FILTER];
    int vlan_attachments[RTE_MAX_ETHPORTS];
    int invalid;
    struct vdev_plan vdev[RTE_MAX_ETHPORTS];
    struct bond_plan bond[RTE_MAX_ETHPORTS];
};

static size_t decimal_digits(unsigned value)
{
    size_t digits = 1;

    while (value >= 10) {
        value /= 10;
        digits++;
    }
    return digits;
}

static int formatted_fits(size_t length)
{
    return length < (size_t)DPDK_CONFIG_MAXLEN;
}

static char *trim_spaces(char *text)
{
    size_t length;

    while (*text == ' ')
        text++;
    length = strlen(text);
    while (length > 0 && text[length - 1] == ' ') {
        text[--length] = '\0';
    }
    return text;
}

/* The retained __parse_config_list runs its range expansion with an int loop
 * variable and executes ++j after the last element, so endpoints outside int
 * range, or an upper endpoint of INT_MAX whose ++j overflows, make the
 * retained writes diverge from this preflight's count. */
static int range_endpoints_fit_int(long lower, long upper)
{
    return lower >= INT_MIN && lower <= INT_MAX &&
           upper >= INT_MIN && upper < INT_MAX;
}

/* Mirrors rte_strsplit(..., ',') plus __parse_config_list's range expansion. */
static size_t list_elements(const char *value)
{
    size_t length = strlen(value);
    size_t position = 0;
    size_t total = 0;
    unsigned tokens = 0;

    for (;;) {
        size_t start = position;
        size_t token_length;
        char token[4096];
        char *middle;

        while (position < length && value[position] != ',')
            position++;
        token_length = position - start;
        if (++tokens > 128 || token_length == 0)
            return SIZE_MAX;
        if (token_length >= sizeof(token))
            return SIZE_MAX;
        memcpy(token, value + start, token_length);
        token[token_length] = '\0';

        middle = strchr(token, '-');
        if (middle == NULL) {
            total++;
        } else {
            char *end;
            long lower;
            long upper;

            *middle = '\0';
            lower = strtol(trim_spaces(token), &end, 10);
            if (*end != '\0')
                return SIZE_MAX;
            upper = strtol(trim_spaces(middle + 1), &end, 10);
            if (*end != '\0')
                return SIZE_MAX;
            if (!range_endpoints_fit_int(lower, upper))
                return SIZE_MAX;
            if (upper >= lower)
                total += (size_t)(upper - lower) + 1;
        }
        if (total > (size_t)INT_MAX)
            return total;
        if (position >= length)
            break;
        position++;
        if (position >= length)
            break;
    }
    return total;
}

/* Mirrors __parse_config_list's value expansion and rejects any element
 * outside [0, max_value). Port ids index a RTE_MAX_ETHPORTS-sized allocation
 * in the retained parser, so their values must stay in range as well as their
 * count. */
static int list_values_in_range(const char *value, long max_value)
{
    size_t length = strlen(value);
    size_t position = 0;
    unsigned tokens = 0;

    for (;;) {
        size_t start = position;
        size_t token_length;
        char token[4096];
        char *middle;

        while (position < length && value[position] != ',')
            position++;
        token_length = position - start;
        if (++tokens > 128 || token_length == 0)
            return 0;
        if (token_length >= sizeof(token))
            return 0;
        memcpy(token, value + start, token_length);
        token[token_length] = '\0';

        middle = strchr(token, '-');
        if (middle == NULL) {
            char *end;
            long v = strtol(trim_spaces(token), &end, 10);

            if (*end != '\0' || v < 0 || v >= max_value)
                return 0;
        } else {
            char *end;
            long lower;
            long upper;

            *middle = '\0';
            lower = strtol(trim_spaces(token), &end, 10);
            if (*end != '\0')
                return 0;
            upper = strtol(trim_spaces(middle + 1), &end, 10);
            if (*end != '\0')
                return 0;
            if (lower < 0 || upper >= max_value)
                return 0;
        }
        if (position >= length)
            break;
        position++;
        if (position >= length)
            break;
    }
    return 1;
}

/* Mirrors __parse_config_list's expansion for vlan_filter, storing the ids so
 * a later [vlanN] section can be checked for membership before its portid is
 * counted. Caller has already bounded the element count. */
static void store_vlan_filter(struct config_plan *plan, const char *value)
{
    size_t length = strlen(value);
    size_t position = 0;
    size_t count = 0;
    unsigned tokens = 0;

    for (;;) {
        size_t start = position;
        size_t token_length;
        char token[4096];
        char *middle;

        while (position < length && value[position] != ',')
            position++;
        token_length = position - start;
        if (++tokens > 128 || token_length == 0)
            break;
        if (token_length >= sizeof(token))
            break;
        memcpy(token, value + start, token_length);
        token[token_length] = '\0';

        middle = strchr(token, '-');
        if (middle == NULL) {
            if (count < (size_t)DPDK_MAX_VLAN_FILTER)
                plan->vlan_filter_ids[count++] =
                    (uint16_t)strtol(trim_spaces(token), NULL, 10);
        } else {
            long lower;
            long upper;
            long v;

            *middle = '\0';
            lower = strtol(trim_spaces(token), NULL, 10);
            upper = strtol(trim_spaces(middle + 1), NULL, 10);
            for (v = lower; v <= upper && count < (size_t)DPDK_MAX_VLAN_FILTER; ++v)
                plan->vlan_filter_ids[count++] = (uint16_t)v;
        }
        if (position >= length)
            break;
        position++;
        if (position >= length)
            break;
    }
    plan->vlan_filter_count = count;
}

static int vlan_in_filter(const struct config_plan *plan, int vlanid)
{
    size_t i;

    for (i = 0; i < plan->vlan_filter_count; i++) {
        if (plan->vlan_filter_ids[i] == (uint16_t)vlanid)
            return 1;
    }
    return 0;
}

/* Counts the enabled cores in a hex lcore mask. parse_lcore_mask turns each
 * set bit into one entry of nb_procs, and port_cfg_handler copies nb_procs
 * entries into the DPDK_MAX_LCORE-sized lcore_list array, so a mask enabling
 * more than DPDK_MAX_LCORE cores would overflow that destination. */
static size_t lcore_mask_popcount(const char *value)
{
    size_t count = 0;

    while (*value == ' ' || *value == '\t')
        value++;
    if (value[0] == '0' && (value[1] == 'x' || value[1] == 'X'))
        value += 2;
    while (*value != '\0') {
        char c = *value++;
        unsigned val;

        if (c >= '0' && c <= '9')
            val = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            val = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            val = (unsigned)(c - 'A' + 10);
        else
            continue;
        count += (size_t)((val & 1) + ((val >> 1) & 1) +
                          ((val >> 2) & 1) + ((val >> 3) & 1));
    }
    return count;
}

/* Mirrors strtok_r(value, delimiters) used for allow/extra_eal_args. */
static void scan_tokens(const char *value, char delimiter, size_t *count,
                        size_t *max_length)
{
    const char *cursor = value;

    *count = 0;
    *max_length = 0;
    while (*cursor != '\0') {
        const char *start;
        size_t length;

        while (*cursor == delimiter)
            cursor++;
        if (*cursor == '\0')
            break;
        start = cursor;
        while (*cursor != '\0' && *cursor != delimiter)
            cursor++;
        length = (size_t)(cursor - start);
        (*count)++;
        if (length > *max_length)
            *max_length = length;
    }
}

static int plan_handler(void *user, const char *section, const char *name,
                        const char *value)
{
    struct config_plan *plan = user;

    if (strcmp(section, "dpdk") == 0) {
        if (strcmp(name, "no_huge") == 0) {
            plan->no_huge = atoi(value) != 0;
        } else if (strcmp(name, "channel") == 0) {
            plan->channel = atoi(value) != 0;
        } else if (strcmp(name, "memory") == 0) {
            plan->memory = atoi(value) != 0;
        } else if (strcmp(name, "log_level") == 0) {
            plan->log_level = atoi(value) != 0;
        } else if (strcmp(name, "lcore_mask") == 0) {
            plan->has_lcore_mask = 1;
            plan->lcore_mask_len = strlen(value);
            if (lcore_mask_popcount(value) > (size_t)DPDK_MAX_LCORE)
                plan->invalid = 1;
        } else if (strcmp(name, "base_virtaddr") == 0) {
            plan->has_base_virtaddr = 1;
            plan->base_virtaddr_len = strlen(value);
        } else if (strcmp(name, "file_prefix") == 0) {
            plan->has_file_prefix = 1;
            plan->file_prefix_len = strlen(value);
        } else if (strcmp(name, "allow") == 0) {
            scan_tokens(value, ',', &plan->allow_count, &plan->allow_max_len);
        } else if (strcmp(name, "extra_eal_args") == 0) {
            scan_tokens(value, ' ', &plan->extra_count, &plan->extra_max_len);
        } else if (strcmp(name, "nb_vdev") == 0) {
            plan->nb_vdev = atoi(value);
        } else if (strcmp(name, "nb_bond") == 0) {
            plan->nb_bond = atoi(value);
        } else if (strcmp(name, "primary_slim") == 0) {
            plan->primary_slim = atoi(value) != 0;
        } else if (strcmp(name, "port_list") == 0) {
            size_t elements = list_elements(value);

            if (elements == 0 || elements > (size_t)RTE_MAX_ETHPORTS ||
                !list_values_in_range(value, RTE_MAX_ETHPORTS))
                plan->invalid = 1;
            else
                plan->has_port_list = 1;
        } else if (strcmp(name, "vlan_filter") == 0) {
            size_t elements = list_elements(value);

            if (elements == 0 || elements > (size_t)DPDK_MAX_VLAN_FILTER)
                plan->invalid = 1;
            else
                store_vlan_filter(plan, value);
        }
        return 1;
    }

    if (strncmp(section, "vdev", 4) == 0) {
        struct vdev_plan *vdev;
        int id;

        if (sscanf(section, "vdev%d", &id) != 1)
            return 1;
        if (id < 0) {
            plan->invalid = 1;
            return 1;
        }
        if (id > plan->nb_vdev)
            return 1;
        if (id >= RTE_MAX_ETHPORTS) {
            plan->invalid = 1;
            return 1;
        }
        vdev = &plan->vdev[id];
        if (strcmp(name, "path") == 0) {
            vdev->has_path = 1;
            vdev->path_len = strlen(value);
        } else if (strcmp(name, "mac") == 0) {
            vdev->has_mac = 1;
            vdev->mac_len = strlen(value);
        } else if (strcmp(name, "queues") == 0) {
            vdev->nb_queues = (uint8_t)atoi(value);
        } else if (strcmp(name, "cq") == 0) {
            vdev->nb_cq = (uint8_t)atoi(value);
        } else if (strcmp(name, "queue_size") == 0) {
            vdev->queue_size = (uint16_t)atoi(value);
        }
        return 1;
    }

    if (strncmp(section, "bond", 4) == 0) {
        struct bond_plan *bond;
        int id;

        if (sscanf(section, "bond%d", &id) != 1)
            return 1;
        if (id < 0) {
            plan->invalid = 1;
            return 1;
        }
        if (id > plan->nb_bond)
            return 1;
        if (id >= RTE_MAX_ETHPORTS) {
            plan->invalid = 1;
            return 1;
        }
        bond = &plan->bond[id];
        if (strcmp(name, "slave") == 0) {
            bond->has_slave = 1;
            bond->slave_len = strlen(value);
        } else if (strcmp(name, "primary") == 0) {
            bond->has_primary = 1;
            bond->primary_len = strlen(value);
        } else if (strcmp(name, "mac") == 0) {
            bond->has_mac = 1;
            bond->mac_len = strlen(value);
        } else if (strcmp(name, "xmit_policy") == 0) {
            bond->has_xmit_policy = 1;
            bond->xmit_policy_len = strlen(value);
        } else if (strcmp(name, "mode") == 0) {
            bond->mode = (uint8_t)atoi(value);
        } else if (strcmp(name, "socket_id") == 0) {
            bond->socket_id = (uint8_t)atoi(value);
        } else if (strcmp(name, "lsc_poll_period_ms") == 0) {
            bond->lsc_poll_period_ms = (uint8_t)atoi(value);
        } else if (strcmp(name, "up_delay") == 0) {
            bond->up_delay = (uint16_t)atoi(value);
        } else if (strcmp(name, "down_delay") == 0) {
            bond->down_delay = (uint16_t)atoi(value);
        }
        return 1;
    }

    if (strncmp(section, "port", 4) == 0) {
        int id;

        if (sscanf(section, "port%d", &id) != 1)
            return 1;
        if (id < 0) {
            plan->invalid = 1;
            return 1;
        }
        plan->has_port_section = 1;
        if (strcmp(name, "lcore_list") == 0) {
            size_t elements = list_elements(value);

            if (elements == 0 || elements > (size_t)DPDK_MAX_LCORE)
                plan->invalid = 1;
        } else if (strcmp(name, "slave_port_list") == 0) {
            size_t elements = list_elements(value);

            if (elements == 0 || elements > (size_t)RTE_MAX_ETHPORTS)
                plan->invalid = 1;
        }
    }

    if (strncmp(section, "vlan", 4) == 0) {
        int vlanid;

        if (sscanf(section, "vlan%d", &vlanid) != 1)
            return 1;
        if (!vlan_in_filter(plan, vlanid))
            return 1;
        if (strcmp(name, "portid") == 0) {
            int portid = atoi(value);

            if (!plan->has_port_section) {
                /* port_cfgs is allocated by the first [portN] section; an
                 * attachment before then dereferences a null pointer. */
                plan->invalid = 1;
            } else if (portid < 0) {
                plan->invalid = 1;
            } else if (portid < RTE_MAX_ETHPORTS) {
                if (plan->vlan_attachments[portid] >= DPDK_MAX_VLAN_FILTER)
                    plan->invalid = 1;
                else
                    plan->vlan_attachments[portid]++;
            }
        }
    }

    if (strcmp(section, "kni") == 0) {
        if (strcmp(name, "owner_proc_id") == 0) {
            plan->has_owner_proc_id = 1;
            plan->owner_proc_id = atoi(value);
        } else if (strcmp(name, "enable") == 0) {
            plan->kni_enable = atoi(value) != 0;
        }
        return 1;
    }
    return 1;
}

static int plan_valid(const struct config_plan *plan)
{
    size_t arguments;
    int i;

    if (plan->invalid)
        return 0;
    if (plan->has_port_list && !plan->has_port_section)
        return 0;
    if (plan->has_owner_proc_id &&
        (plan->owner_proc_id < 0 || plan->owner_proc_id >= RTE_MAX_LCORE))
        return 0;
    if (!plan->has_lcore_mask && (plan->primary_slim || plan->kni_enable))
        return 0;
    if (plan->nb_vdev < 0 || plan->nb_vdev > RTE_MAX_ETHPORTS)
        return 0;
    if (plan->nb_bond < 0 || plan->nb_bond > RTE_MAX_ETHPORTS)
        return 0;
    if (plan->allow_count > (size_t)DPDK_CONFIG_NUM ||
        plan->extra_count > (size_t)DPDK_CONFIG_NUM)
        return 0;

    arguments = 1; /* program name */
    arguments += plan->no_huge ? 1 : 0;
    arguments += plan->has_lcore_mask ? 1 : 0;
    arguments += plan->channel ? 1 : 0;
    arguments += plan->memory ? 1 : 0;
    arguments += plan->log_level ? 1 : 0;
    arguments += 1; /* proc_type is always present after parsing */
    arguments += plan->has_base_virtaddr ? 1 : 0;
    arguments += plan->has_file_prefix ? 1 : 0;
    arguments += plan->allow_count;
    if (plan->nb_vdev != 0) {
        if (plan->nb_vdev > 0)
            arguments += (size_t)plan->nb_vdev;
        arguments += 1; /* --no-pci */
        if (!plan->has_file_prefix)
            arguments += 1;
    }
    if (plan->nb_bond > 0)
        arguments += 2 * (size_t)plan->nb_bond;
    arguments += plan->extra_count;
    if (arguments > (size_t)DPDK_CONFIG_NUM)
        return 0;

    if (plan->has_lcore_mask &&
        !formatted_fits(2 + plan->lcore_mask_len))
        return 0;
    if (plan->has_base_virtaddr &&
        !formatted_fits(16 + plan->base_virtaddr_len))
        return 0;
    if (plan->has_file_prefix &&
        !formatted_fits(24 + plan->file_prefix_len))
        return 0;
    if (plan->allow_count != 0 &&
        !formatted_fits(8 + plan->allow_max_len))
        return 0;

    for (i = 0; i < plan->nb_vdev; i++) {
        const struct vdev_plan *vdev = &plan->vdev[i];
        size_t length;

        if (!vdev->has_path)
            return 0;
        length = 24 + decimal_digits((unsigned)i) + vdev->path_len;
        if (vdev->nb_queues)
            length += 8 + decimal_digits(vdev->nb_queues);
        if (vdev->nb_cq)
            length += 4 + decimal_digits(vdev->nb_cq);
        if (vdev->queue_size)
            length += 12 + decimal_digits(vdev->queue_size);
        if (vdev->has_mac)
            length += 5 + vdev->mac_len;
        if (!formatted_fits(length))
            return 0;
    }

    for (i = 0; i < plan->nb_bond; i++) {
        const struct bond_plan *bond = &plan->bond[i];
        size_t length;

        if (!bond->has_slave)
            return 0;
        length = 24 + decimal_digits((unsigned)i) +
                 decimal_digits(bond->mode) + bond->slave_len;
        if (bond->has_primary)
            length += 9 + bond->primary_len;
        if (bond->socket_id)
            length += 11 + decimal_digits(bond->socket_id);
        if (bond->has_mac)
            length += 5 + bond->mac_len;
        if (bond->has_xmit_policy)
            length += 13 + bond->xmit_policy_len;
        if (bond->lsc_poll_period_ms)
            length += 20 + decimal_digits(bond->lsc_poll_period_ms);
        if (bond->up_delay)
            length += 10 + decimal_digits(bond->up_delay);
        if (bond->down_delay)
            length += 12 + decimal_digits(bond->down_delay);
        if (!formatted_fits(length))
            return 0;
    }

    return 1;
}

static const char *config_path_from_args(int argc, char *const argv[],
                                         int *args_invalid)
{
    const char *path = "config.ini";
    int option_index = 0;
    int c;

    /* Use the same option table as ff_parse_args so the preflight and the
     * retained parser select the same document, including getopt's `--`
     * handling, attached short-option values and unambiguous long options. */
    *args_invalid = 0;
    optind = 1;
    while ((c = getopt_long(argc, argv, example_upstream_short_options,
                            example_upstream_long_options,
                            &option_index)) != -1) {
        switch (c) {
        case 'c':
            path = optarg;
            break;
        case 'p': {
            long proc_id = strtol(optarg, NULL, 10);

            /* The retained parser narrows proc_id to uint16_t before its
             * range check, so a negative or over-large value survives and
             * later indexes proc_lcore[] out of bounds. */
            if (proc_id < 0 || proc_id >= RTE_MAX_LCORE)
                *args_invalid = 1;
            break;
        }
        default:
            break;
        }
    }
    return path;
}

static int config_plan_allows(const char *path)
{
    struct config_plan plan;

    memset(&plan, 0, sizeof(plan));
    /* A parse error must not bypass a partial plan that already reached an
     * oversized or out-of-range list: the retained parser would replay that
     * list and overflow before reporting the same error. plan_valid() accepts
     * an absent document or a within-capacity partial plan, so the retained
     * parser still reports its own open/parse failures. */
    example_upstream_ini_parse(path, plan_handler, &plan);
    return plan_valid(&plan);
}

void example_fstack_config_unload(void)
{
    example_upstream_unload_config();
    /* Scalars are not reset by upstream unload. A new application document
     * must not inherit flags from the previous one. */
    memset(&example_upstream_global_cfg, 0, sizeof(example_upstream_global_cfg));
}
int example_fstack_config_load(int argc, char *const argv[])
{
    const char *path;
    int args_invalid = 0;

    example_fstack_config_unload();
    path = config_path_from_args(argc, argv, &args_invalid);
    if (args_invalid || !config_plan_allows(path)) {
        fprintf(stderr, "configuration exceeds retained F-Stack parser "
                        "capacities; refusing to build an EAL argument plan\n");
        return -1;
    }
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
