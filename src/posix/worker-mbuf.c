/* SPDX-License-Identifier: BSD-3-Clause */
#include "worker-mbuf.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>

struct rte_mbuf *ker_worker_mbuf_from_bytes(struct rte_mempool *pool,
                                           const void *bytes, size_t length)
{
    if (!pool || !bytes || !length || length > UINT32_MAX) {
        errno = EINVAL;
        return NULL;
    }
    struct rte_mbuf *head = NULL;
    const unsigned char *input = bytes;
    while (length) {
        struct rte_mbuf *segment = rte_pktmbuf_alloc(pool);
        if (!segment) goto failure;
        size_t count = RTE_MIN(length, rte_pktmbuf_tailroom(segment));
        if (!count) { rte_pktmbuf_free(segment); goto failure; }
        void *output = rte_pktmbuf_append(segment, (uint16_t)count);
        if (!output) { rte_pktmbuf_free(segment); goto failure; }
        memcpy(output, input, count);
        if (!head) head = segment;
        else if (rte_pktmbuf_chain(head, segment)) {
            rte_pktmbuf_free(segment);
            goto failure;
        }
        input += count;
        length -= count;
    }
    return head;
failure:
    rte_pktmbuf_free(head);
    errno = ENOBUFS;
    return NULL;
}
