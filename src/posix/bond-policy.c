#define _GNU_SOURCE
#include "bond-policy.h"
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#ifdef KER_NATIVE_STATIC_BOND
#include <rte_eth_bond_8023ad.h>
#endif

static void *symbol(const char *name)
{
    void *function = dlsym(RTLD_DEFAULT, name);
    if (function) return function;
    /* EAL loads PMDs with local symbol visibility. Resolve the already loaded
     * module without adding a mandatory dependency or probing a new driver. */
    void *module = dlopen("librte_net_bond.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!module) return NULL;
    function = dlsym(module, name);
    dlclose(module);
    return function;
}
int ker_bond_members(uint16_t port, uint16_t *ids, uint16_t capacity)
{
    int (*get)(uint16_t, uint16_t *, uint16_t) = symbol("rte_eth_bond_members_get");
    return get ? get(port, ids, capacity) : -EOPNOTSUPP;
}
int ker_bond_policy_apply(uint16_t port, const char *policy)
{
    unsigned poll, up, down; char extra;
    if (sscanf(policy, "%u,%u,%u%c", &poll, &up, &down, &extra) != 3 ||
        !poll || poll > INT_MAX || up > INT_MAX || down > INT_MAX) return -EINVAL;
    const char *setters[] = {"rte_eth_bond_link_monitoring_set", "rte_eth_bond_link_up_prop_delay_set", "rte_eth_bond_link_down_prop_delay_set"};
    const char *getters[] = {"rte_eth_bond_link_monitoring_get", "rte_eth_bond_link_up_prop_delay_get", "rte_eth_bond_link_down_prop_delay_get"};
    unsigned values[] = {poll, up, down};
    for (unsigned i = 0; i < 3; i++) {
        int (*set)(uint16_t, uint32_t) = symbol(setters[i]);
        int (*get)(uint16_t) = symbol(getters[i]);
        if (!set || !get) return -EOPNOTSUPP;
        int result = set(port, values[i]);
        if (result) return result;
        if (get(port) != (int)values[i]) return -EIO;
    }
    return 0;
}
int ker_bond_snapshot(uint16_t port, char *json, unsigned size)
{
    const char *names[] = {"rte_eth_bond_mode_get", "rte_eth_bond_primary_get", "rte_eth_bond_xmit_policy_get",
        "rte_eth_bond_link_monitoring_get", "rte_eth_bond_link_up_prop_delay_get", "rte_eth_bond_link_down_prop_delay_get"};
    int values[6];
    for (unsigned i = 0; i < 6; i++) {
        int (*get)(uint16_t) = symbol(names[i]);
        if (!get || (values[i] = get(port)) < 0) return -EIO;
    }
    int (*members)(uint16_t, uint16_t *, uint16_t) = symbol("rte_eth_bond_members_get");
    int (*active)(uint16_t, uint16_t *, uint16_t) = symbol("rte_eth_bond_active_members_get");
    uint16_t ids[16];
    int count = members ? members(port, ids, 16) : -1;
    int live = active ? active(port, ids, 16) : -1;
    if (count < 0 || live < 0) return -EIO;
    int distributing = -1;
#ifdef KER_NATIVE_STATIC_BOND
    if (values[0] == 4) {
        distributing = 0;
        int number = ker_bond_members(port, ids, 16);
        if (number < 0) return number;
        for (int i = 0; i < number; i++) {
            struct rte_eth_bond_8023ad_member_info info;
            if (rte_eth_bond_8023ad_member_info(port, ids[i], &info)) return -EIO;
            if ((info.actor_state & (STATE_COLLECTING | STATE_DISTRIBUTING)) ==
                (STATE_COLLECTING | STATE_DISTRIBUTING)) distributing++;
        }
    }
#endif
    int length = snprintf(json, size, "{\"mode\":%d,\"primary\":%d,\"xmit_policy\":%d,\"poll_ms\":%d,\"up_ms\":%d,\"down_ms\":%d,\"members\":%d,\"active\":%d,\"lacp_distributing\":%d}",
        values[0], values[1], values[2], values[3], values[4], values[5], count, live, distributing);
    return length > 0 && (unsigned)length < size ? 0 : -EOVERFLOW;
}
