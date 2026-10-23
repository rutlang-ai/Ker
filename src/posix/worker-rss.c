#include "worker-rss.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int ker_worker_rss_prepare(uint16_t port, uint16_t queues,
    struct rte_eth_conf *config, struct ker_worker_rss *state)
{
    struct rte_eth_dev_info info;
    int result = rte_eth_dev_info_get(port, &info);
    if (result) return result;
    const uint64_t types = RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP |
        RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP;
    if (queues < 2 || queues > info.max_rx_queues ||
        (info.flow_type_rss_offloads & types) != types ||
        info.hash_key_size < 40 || info.hash_key_size > sizeof(state->key) ||
        !info.reta_size || info.reta_size > 4096 ||
        (info.reta_size & (info.reta_size - 1))) return -EOPNOTSUPP;
    memset(state, 0, sizeof(*state));
    state->reta_size = info.reta_size;
    state->key_length = info.hash_key_size;
    state->types = types;
    config->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    config->rx_adv_conf.rss_conf.rss_hf = types;
    /* NULL preserves the original PMD's key and default hash algorithm. */
    return 0;
}

int ker_worker_rss_apply(uint16_t port, uint16_t queues,
    struct ker_worker_rss *state)
{
    if (!state->reta_size) return 0;
    if (queues < 2) return -EINVAL;
    struct rte_eth_rss_conf actual = {.rss_key = state->key,
        .rss_key_len = state->key_length};
    int result = rte_eth_dev_rss_hash_conf_get(port, &actual);
    if (result) return result;
    if (actual.rss_hf != state->types || actual.rss_key_len != state->key_length)
        return -EIO;
    unsigned groups = (state->reta_size + RTE_ETH_RETA_GROUP_SIZE - 1) / RTE_ETH_RETA_GROUP_SIZE;
    struct rte_eth_rss_reta_entry64 *table = calloc(groups, sizeof(*table));
    if (!table) return -ENOMEM;
    for (unsigned index = 0; index < state->reta_size; index++) {
        unsigned group = index / RTE_ETH_RETA_GROUP_SIZE;
        unsigned offset = index % RTE_ETH_RETA_GROUP_SIZE;
        table[group].mask |= UINT64_C(1) << offset;
        table[group].reta[offset] = index % queues;
    }
    result = rte_eth_dev_rss_reta_update(port, table, state->reta_size);
    if (!result) {
        for (unsigned group = 0; group < groups; group++)
            memset(table[group].reta, 0xff, sizeof(table[group].reta));
        result = rte_eth_dev_rss_reta_query(port, table, state->reta_size);
    }
    for (unsigned index = 0; !result && index < state->reta_size; index++)
        if (table[index / RTE_ETH_RETA_GROUP_SIZE].reta[index % RTE_ETH_RETA_GROUP_SIZE] != index % queues)
            result = -EIO;
    free(table);
    return result;
}
