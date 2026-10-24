/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef KER_WORKER_DEVICE_H
#define KER_WORKER_DEVICE_H

#include <errno.h>
#include <stdint.h>
#include <rte_dev.h>
#include <rte_devargs.h>
#include <rte_ethdev.h>
#include <rte_kvargs.h>

/* Derive a vdev's actual queue_size from the device retained by DPDK after
 * EAL initialization. EAL may rewrite its argv, so it is not a reliable source
 * for sizing the selected port or a bond member. */
static inline int ker_worker_vdev_queue_size(const struct rte_devargs *devargs,
    uint16_t *queue_size)
{
    if (!queue_size) return -EINVAL;
    *queue_size = 0;
    if (!devargs || !devargs->args || !*devargs->args) return 0;

    struct rte_kvargs *args = rte_kvargs_parse(devargs->args, NULL);
    if (!args) return -EINVAL;
    unsigned count = rte_kvargs_count(args, "queue_size");
    if (count > 1) {
        rte_kvargs_free(args);
        return -EINVAL;
    }
    if (count) {
        const char *text = rte_kvargs_get(args, "queue_size");
        uint32_t parsed = 0;
        if (!text || !*text) {
            rte_kvargs_free(args);
            return -EINVAL;
        }
        for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
            if (*p < '0' || *p > '9' ||
                parsed > (UINT16_MAX - (uint32_t)(*p - '0')) / 10) {
                rte_kvargs_free(args);
                return -EINVAL;
            }
            parsed = parsed * 10 + (uint32_t)(*p - '0');
        }
        if (!parsed) {
            rte_kvargs_free(args);
            return -EINVAL;
        }
        *queue_size = (uint16_t)parsed;
    }
    rte_kvargs_free(args);
    return 0;
}

/* Derive queue descriptor limits from the PMD plus its retained vdev args. */
static inline int ker_worker_configured_port_descriptors(uint16_t port,
    uint32_t minimum_rx, uint32_t minimum_tx, uint32_t *rx, uint32_t *tx)
{
    if (!rx || !tx || minimum_rx > UINT16_MAX || minimum_tx > UINT16_MAX)
        return -EINVAL;
    struct rte_eth_dev_info info = {0};
    uint16_t rx_desc = 256, tx_desc = 256, ring = 0;
    if (rte_eth_dev_info_get(port, &info) ||
        rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc)) return -EIO;
    const struct rte_devargs *devargs = info.device ? rte_dev_devargs(info.device) : NULL;
    int result = ker_worker_vdev_queue_size(devargs, &ring);
    if (result) return result;
    uint32_t configured_rx = RTE_MAX(RTE_MAX(rx_desc, minimum_rx), ring);
    uint32_t configured_tx = RTE_MAX(RTE_MAX(tx_desc, minimum_tx), ring);
    if ((info.rx_desc_lim.nb_max && configured_rx > info.rx_desc_lim.nb_max) ||
        (info.tx_desc_lim.nb_max && configured_tx > info.tx_desc_lim.nb_max)) return -ERANGE;
    *rx = configured_rx;
    *tx = configured_tx;
    return 0;
}

#endif
