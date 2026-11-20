/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define MEMPOOL_CACHE_SIZE 256

#define MSG_RING_SIZE 32

#define FF_MBUF_GEN_MAX 2

#define FREE_RING_SIZE 4096

#define NB_SOCKETS 8

static inline unsigned
ff_shared_pool_cache_size(int graceful_reload, unsigned legacy_cache)
{
    return graceful_reload ? 0 : legacy_cache;
}

static inline int
ff_mbuf_gen_pool_name(char *buf, unsigned int buflen, int socketid, int gen)
{
    int n;

    if (gen < 0 || gen >= FF_MBUF_GEN_MAX)
        return -1;
    n = snprintf(buf, buflen, "mbuf_pool_%d_gen%d", socketid, gen);
    if (n < 0 || (unsigned int)n >= buflen)
        return -1;
    return 0;
}

struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

/* per-generation application-side mbuf pools (graceful_reload=1).
 * Pre-created at init; the active generation is selected by app_mbuf_gen
 * (constant 0 until reload generation switching lands). */
static struct rte_mempool *app_pktmbuf_pool[FF_MBUF_GEN_MAX][NB_SOCKETS];
static int app_mbuf_gen;

struct rte_mempool *
ff_app_mbuf_pool(unsigned socketid)
{
    if (!ff_global_cfg.dpdk.graceful_reload)
        return pktmbuf_pool[socketid];
    return app_pktmbuf_pool[app_mbuf_gen][socketid];
}

void
ff_app_mbuf_set_gen(int gen)
{
    if (gen < 0 || gen >= FF_MBUF_GEN_MAX)
        return;
    app_mbuf_gen = gen;
}
