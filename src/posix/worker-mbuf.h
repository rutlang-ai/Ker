/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef KER_WORKER_MBUF_H
#define KER_WORKER_MBUF_H
#include <rte_mbuf.h>
#include <stddef.h>
/* Copy one complete Ethernet frame into a pool-sized mbuf chain. On failure,
 * reclaim every allocated segment. The caller owns the returned chain. */
struct rte_mbuf *ker_worker_mbuf_from_bytes(struct rte_mempool *pool,
                                           const void *bytes, size_t length);
#endif
