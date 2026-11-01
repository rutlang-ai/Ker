static int
ff_rss_reta_log2(uint16_t reta_size)
{
    int log2 = 0;

    while ((reta_size >>= 1) != 0)
        log2++;

    return log2;
}

int
ff_rss_thash_build_key(uint16_t port_id, uint16_t reta_size)
{
    char name[64];
    int is_primary = (rte_eal_process_type() == RTE_PROC_PRIMARY);
    struct ff_rss_check_cfg *rcc = ff_global_cfg.dpdk.rss_check_cfgs;
    int thash_adjust = (rcc != NULL) ? rcc->thash_adjust : 1;
    uint8_t * const orig_rsskey = rsskey;
    const int orig_rsskey_len = rsskey_len;
    uint32_t reta_log2;
    struct rte_thash_ctx *ctx_v4 = NULL, *ctx_v6 = NULL;
    const uint8_t *key_v4 = NULL, *key_final = NULL;
    uint8_t key_v4_buf[64];

    rss_thash_ready[port_id] = 0;
    rss_thash6_ready[port_id] = 0;
    rss_reta_size[port_id] = reta_size;

    if (!thash_adjust || orig_rsskey == NULL || orig_rsskey_len == 0)
        return 0;
    if (reta_size < 2 || ff_rss_key_built)
        return 0;
    if ((size_t)orig_rsskey_len > sizeof(key_v4_buf))
        return 0;

    reta_log2 = ff_rss_reta_log2(reta_size);

    /* ---- v4 ctx ---- */
    snprintf(name, sizeof(name), "ff_rss_thash_%u", port_id);
    if (is_primary) {
        ctx_v4 = rte_thash_init_ctx(name, orig_rsskey_len, reta_log2,
            orig_rsskey, 0);
        if (ctx_v4 == NULL) {
            ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                "rte_thash_init_ctx(v4) failed for port %u, soft scan fallback\n",
                port_id);
            return 0;
        }
        if (rte_thash_add_helper(ctx_v4, "sport",
                FF_RSS_THASH_SPORT_HELPER_LEN,
                FF_RSS_THASH_V4_SPORT_OFF) != 0) {
            ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                "rte_thash_add_helper(v4) failed for port %u\n", port_id);
            rte_thash_free_ctx(ctx_v4);
            return 0;
        }
    } else {
        ctx_v4 = rte_thash_find_existing(name);
        if (ctx_v4 == NULL) {
            ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                "rte_thash_find_existing(v4) failed for port %u (secondary)\n",
                port_id);
            return 0;
        }
    }

    rss_thash_sport_h[port_id] = rte_thash_get_helper(ctx_v4, "sport");
    if (rss_thash_sport_h[port_id] == NULL) {
        if (is_primary)
            rte_thash_free_ctx(ctx_v4);
        return 0;
    }

    /* v4-rewritten key; v6 ctx is seeded from it (serial construction). */
    key_v4 = rte_thash_get_key(ctx_v4);
    if (key_v4 == NULL) {
        if (is_primary)
            rte_thash_free_ctx(ctx_v4);
        return 0;
    }
    memcpy(key_v4_buf, key_v4, orig_rsskey_len);

    rss_thash_ctx[port_id] = ctx_v4;
    rss_thash_ready[port_id] = 1;

    /* v6 ctx seeded by the v4-rewritten key. */
    snprintf(name, sizeof(name), "ff_rss_thash6_%u", port_id);
    if (is_primary) {
        ctx_v6 = rte_thash_init_ctx(name, orig_rsskey_len, reta_log2,
            key_v4_buf, 0);
        if (ctx_v6 == NULL)
            goto publish;
        if (rte_thash_add_helper(ctx_v6, "sport",
                FF_RSS_THASH_SPORT_HELPER_LEN,
                FF_RSS_THASH_V6_SPORT_OFF) != 0) {
            rte_thash_free_ctx(ctx_v6);
            ctx_v6 = NULL;
            goto publish;
        }
    } else {
        ctx_v6 = rte_thash_find_existing(name);
        if (ctx_v6 == NULL)
            goto publish;
    }

    rss_thash6_sport_h[port_id] = rte_thash_get_helper(ctx_v6, "sport");
    if (rss_thash6_sport_h[port_id] == NULL) {
        if (is_primary)
            rte_thash_free_ctx(ctx_v6);
        ctx_v6 = NULL;
        goto publish;
    }

    key_final = rte_thash_get_key(ctx_v6);
    if (key_final == NULL) {
        if (is_primary)
            rte_thash_free_ctx(ctx_v6);
        ctx_v6 = NULL;
        goto publish;
    }

    rss_thash6_ctx[port_id] = ctx_v6;
    rss_thash6_ready[port_id] = 1;

publish:
    {
        const uint8_t *pub_key = (rss_thash6_ready[port_id]
            ? key_final : key_v4_buf);
        uint8_t *new_rsskey = rte_malloc("ff_rsskey_synced",
            orig_rsskey_len, 0);

        if (new_rsskey == NULL) {
            ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                "rte_malloc(rsskey) failed for port %u, route② fallback\n",
                port_id);
            rss_thash_ready[port_id] = 0;
            rss_thash6_ready[port_id] = 0;
            return 0;
        }
        memcpy(new_rsskey, pub_key, orig_rsskey_len);

#ifdef FF_RSS_DIAG
        ff_rss_diag_dump_key("rsskey-published", port_id,
            new_rsskey, orig_rsskey_len);
        if (rss_thash_ctx[port_id] != NULL)
            ff_rss_diag_dump_key("ctx_v4-key", port_id,
                rte_thash_get_key(rss_thash_ctx[port_id]), orig_rsskey_len);
        if (rss_thash6_ready[port_id] && rss_thash6_ctx[port_id] != NULL)
            ff_rss_diag_dump_key("ctx_v6-key", port_id,
                rte_thash_get_key(rss_thash6_ctx[port_id]), orig_rsskey_len);
#endif

        /* Publish KEY_FINAL so the caller's dev_configure programs it into
         * the NIC, and ff_rss_check uses it too. orig_rsskey is static. */
        rsskey = new_rsskey;
        rsskey_len = orig_rsskey_len;
        ff_rss_key_built = 1;
        ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB,
            "ff_rss_thash_build_key: port %u key built (v6_ready=%d, proc=%s)\n",
            port_id, rss_thash6_ready[port_id],
            is_primary ? "primary" : "secondary");
    }

    return 0;
}

int
ff_rss_thash_ctx_init(void)
{
#ifdef FF_RSS_DIAG
    uint16_t port_id;

    if (rte_eal_process_type() != RTE_PROC_PRIMARY)
        return 0;

    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        struct rte_eth_rss_conf rb;
        uint8_t rb_key[64];
        uint16_t rsz = rss_reta_size[port_id];
        uint16_t nbq = ff_global_cfg.dpdk.port_cfgs[port_id].nb_lcores;

        if (!rss_thash_ready[port_id])
            continue;

        memset(&rb, 0, sizeof(rb));
        rb.rss_key = rb_key;
        rb.rss_key_len = sizeof(rb_key);
        if (rte_eth_dev_rss_hash_conf_get(port_id, &rb) == 0)
            ff_rss_diag_dump_key("NIC-readback", port_id,
                rb_key, (int)rb.rss_key_len);

        if (rsz >= 1 && nbq > 0) {
            int ngrp = (rsz + RTE_ETH_RETA_GROUP_SIZE - 1) /
                RTE_ETH_RETA_GROUP_SIZE;
            struct rte_eth_rss_reta_entry64 rc[ngrp];
            int g;

            memset(rc, 0, sizeof(rc));
            for (g = 0; g < ngrp; g++)
                rc[g].mask = ~0ULL;
            if (rte_eth_dev_rss_reta_query(port_id, rc, rsz) == 0) {
                int mismatch = 0, idx;
                for (idx = 0; idx < rsz; idx++) {
                    uint16_t v = rc[idx / RTE_ETH_RETA_GROUP_SIZE]
                        .reta[idx % RTE_ETH_RETA_GROUP_SIZE];
                    if (v != (idx % nbq))
                        mismatch++;
                }
                ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB,
                    "RETA port=%u size=%u nbq=%u "
                    "mismatch_vs_idx%%nbq=%d (0=assumption holds)\n",
                    port_id, rsz, nbq, mismatch);
            } else {
                ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                    "reta_query(port %u) failed/unavailable\n",
                    port_id);
            }
        }
    }
#endif

    return 0;
}

int
ff_rss_adjust_sport(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t dport, uint16_t *out_sport, uint16_t first, uint16_t last)
{
    struct lcore_conf *qconf = ff_cur_lcore_conf();
    struct ff_dpdk_if_context *ctx = ff_veth_softc_to_hostc(softc);
    uint16_t port_id, nb_queues, reta_size, queueid;
    uint32_t desired;
    uint8_t tuple[FF_RSS_THASH_V4_TUPLE_LEN];
    uint16_t sport;
    uint16_t base, block, nblocks;
    int tries, reta_log2;

    if (softc == NULL || out_sport == NULL)
        return -1;

    port_id = ctx->port_id;
    if (!rss_thash_ready[port_id] || rss_thash_ctx[port_id] == NULL)
        return -1;
    /* Soft-scan fallback when thash_adjust is disabled. */
    if (ff_global_cfg.dpdk.rss_check_cfgs &&
            !ff_global_cfg.dpdk.rss_check_cfgs->thash_adjust)
        return -1;

    nb_queues = qconf->nb_queue_list[port_id];
    if (nb_queues <= 1)
        return -1;

    reta_size = rss_reta_size[port_id];
    queueid = qconf->tx_queue_id[port_id];

    /*
     * rte_thash_adjust_tuple only rewrites the LOW reta_log2 bits of the
     * sport field (bit range [tuple_offset+tuple_len-reta_log2,
     * tuple_offset+tuple_len-1], see rte_thash.c). For the v4 sport helper
     * (tuple_offset=80=FF_RSS_THASH_V4_SPORT_OFF, tuple_len=16) with
     * reta_size=512 (reta_log2=9) it
     * controls the low 9 bits of the network-order sport, i.e. values
     * [0, reta_size). The HIGH bits are kept from the sport seed we provide.
     *
     * The previous code seeded sport=0, so the result was always in
     * [0, reta_size) (e.g. <512) -> reserved/well-known ports that are NOT
     * valid ephemeral ports -> connections failed even though the soft
     * recheck said the queue matched. Fix: seed sport with a reta_size-aligned
     * BASE inside the ephemeral range [first,last]; adjust then fills the low
     * reta_log2 bits, so the final port stays within [base, base+reta_size-1]
     * which lies inside [first,last] and still lands on the local queue.
     */
    reta_log2 = ff_rss_reta_log2(reta_size);

    if (first > last)
        return -1;
    /* Align the search window to reta_size blocks within [first,last]. */
    base = (uint16_t)(((uint32_t)first + reta_size - 1) & ~((uint32_t)reta_size - 1));
    if (base < first || (uint32_t)base + reta_size - 1 > last)
        return -1;                 /* range too small / unaligned -> soft scan */
    nblocks = (uint16_t)((last - base + 1) / reta_size);
    if (nblocks == 0)
        return -1;
    /* pick a random reta_size-aligned base block inside the ephemeral range */
    block = (uint16_t)(ff_arc4random() % nblocks);
    base = (uint16_t)(base + block * reta_size);
    (void)reta_log2;

    /*
     * desired_value picked from D(q) = { v in [0, reta_size) | v % Q == q }
     * so (hash & (reta_size-1)) % nb_queues == queueid holds. Rotate the
     * starting candidate to spread reta entries.
     */
    desired = queueid + (ff_arc4random() % ((reta_size + nb_queues - 1) / nb_queues)) * nb_queues;
    if (desired >= reta_size)
        desired = queueid;

    for (tries = 0; tries < (int)((reta_size + nb_queues - 1) / nb_queues); tries++) {
        uint16_t host_lport;

        if (desired >= reta_size)
            desired = queueid;

        /* Re-seed every iteration: high bits = aligned ephemeral base,
         * low reta_log2 bits = 0 (adjust_tuple fills them). Network order. */
        sport = htons(base);

        /*
         * Build the tuple in the REPLY (inbound) field order, because what we
         * really need is the REPLY (SYN-ACK) to land on the local queue. The
         * NIC hashes the reply as:
         *     srcIP = remote (saddr), dstIP = local (daddr),
         *     srcPort = 80 (dport),   dstPort = localPort  (what we solve for)
         * So the local port sits in the dstPort field at byte 10, which is
         * exactly where the v4 sport helper now points (offset = 80 bits).
         */
        memset(tuple, 0, sizeof(tuple));
        bcopy(&saddr, &tuple[0], sizeof(saddr));   /* remote IP  */
        bcopy(&daddr, &tuple[4], sizeof(daddr));   /* local  IP  */
        bcopy(&dport, &tuple[8], sizeof(dport));   /* remote port (80) */
        bcopy(&sport, &tuple[10], sizeof(sport));  /* local port seed -> solved */

        if (rte_thash_adjust_tuple(rss_thash_ctx[port_id],
                rss_thash_sport_h[port_id], tuple, sizeof(tuple),
                desired & (reta_size - 1), FF_RSS_THASH_ADJUST_ATTEMPTS,
                NULL, NULL) == 0) {
            int recheck = (ff_global_cfg.dpdk.rss_check_cfgs &&
                ff_global_cfg.dpdk.rss_check_cfgs->recheck);
            /* tuple[10..11] now holds the solved network-order local port. */
            bcopy(&tuple[10], &sport, sizeof(sport));
            host_lport = ntohs(sport);

            /* Guard: the adjusted port MUST stay inside the ephemeral range
             * [first,last]. With a reta_size-aligned base it always should,
             * but verify defensively (e.g. odd reta/range corner cases). */
            if (host_lport < first || host_lport > last) {
                desired += nb_queues;
                continue;
            }

            /*
             * Re-verify with the REPLY field order (this is the hash the NIC
             * applies to the inbound SYN-ACK). recheck calls ff_rss_check with
             * the reply tuple: (remote, local, srcPort=80, dstPort=localPort).
             */
            if (!recheck ||
                ff_rss_check(softc, saddr, daddr, dport, sport)) {
#ifdef FF_RSS_DIAG
                /* rev_queue is the REPLY's landing queue and MUST equal qid;
                 * fwd_* is the outbound direction (informational). */
                uint8_t rd[12];
                bcopy(&saddr, &rd[0], 4);   /* remote IP            */
                bcopy(&daddr, &rd[4], 4);   /* local  IP            */
                bcopy(&dport, &rd[8], 2);   /* 80 (reply src port)  */
                bcopy(&sport, &rd[10], 2);  /* localPort (reply dst)*/
                uint32_t rh = toeplitz_hash(rsskey_len, rsskey, sizeof(rd), rd);

                uint8_t fd[12];
                bcopy(&saddr, &fd[0], 4);
                bcopy(&daddr, &fd[4], 4);
                bcopy(&sport, &fd[8], 2);   /* outbound src = localPort */
                bcopy(&dport, &fd[10], 2);  /* outbound dst = 80        */
                uint32_t fh = toeplitz_hash(rsskey_len, rsskey, sizeof(fd), fd);

                ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB,
                    "adjust_sport ok proc=%s port=%u qid=%u nbq=%u "
                    "saddr=0x%08x daddr=0x%08x dport=%u lport=%u base=%u "
                    "rev_reta=%u rev_queue=%u fwd_reta=%u fwd_queue=%u\n",
                    rte_eal_process_type() == RTE_PROC_PRIMARY
                        ? "primary" : "secondary",
                    port_id, queueid, nb_queues,
                    ntohl(saddr), ntohl(daddr), ntohs(dport), host_lport, base,
                    rh & (reta_size - 1),
                    (rh & (reta_size - 1)) % nb_queues,
                    fh & (reta_size - 1),
                    (fh & (reta_size - 1)) % nb_queues);
#endif
                /* Return HOST-order local port; caller does htons() itself. */
                *out_sport = host_lport;
                return 0;
            }
        }

        desired += nb_queues;
    }

    return -1;
}

int
ff_rss_adjust_sport6(void *softc, const uint8_t *saddr6,
    const uint8_t *daddr6, uint16_t dport, uint16_t *out_sport,
    uint16_t first, uint16_t last)
{
    struct lcore_conf *qconf = ff_cur_lcore_conf();
    struct ff_dpdk_if_context *ctx = ff_veth_softc_to_hostc(softc);
    uint16_t port_id, nb_queues, reta_size, queueid;
    uint32_t desired;
    uint8_t tuple[FF_RSS_THASH_V6_TUPLE_LEN];
    uint16_t sport;
    uint16_t base, block, nblocks;
    int tries, reta_log2;

    if (softc == NULL || out_sport == NULL)
        return -1;

    port_id = ctx->port_id;
    if (!rss_thash6_ready[port_id] || rss_thash6_ctx[port_id] == NULL)
        return -1;
    /* Soft-scan fallback when thash_adjust is disabled. */
    if (ff_global_cfg.dpdk.rss_check_cfgs &&
            !ff_global_cfg.dpdk.rss_check_cfgs->thash_adjust)
        return -1;

    nb_queues = qconf->nb_queue_list[port_id];
    if (nb_queues <= 1)
        return -1;

    reta_size = rss_reta_size[port_id];
    queueid = qconf->tx_queue_id[port_id];

    /* Align search window to reta_size blocks inside [first,last] so the
     * adjusted low bits keep the result a valid ephemeral port (see v4). */
    reta_log2 = ff_rss_reta_log2(reta_size);
    if (first > last)
        return -1;
    base = (uint16_t)(((uint32_t)first + reta_size - 1) & ~((uint32_t)reta_size - 1));
    if (base < first || (uint32_t)base + reta_size - 1 > last)
        return -1;
    nblocks = (uint16_t)((last - base + 1) / reta_size);
    if (nblocks == 0)
        return -1;
    block = (uint16_t)(ff_arc4random() % nblocks);
    base = (uint16_t)(base + block * reta_size);
    (void)reta_log2;

    desired = queueid + (ff_arc4random() % ((reta_size + nb_queues - 1) / nb_queues)) * nb_queues;
    if (desired >= reta_size)
        desired = queueid;

    for (tries = 0; tries < (int)((reta_size + nb_queues - 1) / nb_queues); tries++) {
        if (desired >= reta_size)
            desired = queueid;

        sport = htons(base);

        /* Reply (SYN-ACK) field order: local port is the reply dstPort. */
        memset(tuple, 0, sizeof(tuple));
        bcopy(saddr6, &tuple[0], 16);   /* remote IP */
        bcopy(daddr6, &tuple[16], 16);  /* local  IP */
        bcopy(&dport, &tuple[32], sizeof(dport));  /* remote port (80) */
        bcopy(&sport, &tuple[34], sizeof(sport));  /* local port seed -> solved */

        if (rte_thash_adjust_tuple(rss_thash6_ctx[port_id],
                rss_thash6_sport_h[port_id], tuple, sizeof(tuple),
                desired & (reta_size - 1), FF_RSS_THASH_ADJUST_ATTEMPTS,
                NULL, NULL) == 0) {
            int recheck = (ff_global_cfg.dpdk.rss_check_cfgs &&
                ff_global_cfg.dpdk.rss_check_cfgs->recheck);
            uint16_t host_lport;

            bcopy(&tuple[34], &sport, sizeof(sport));
            host_lport = ntohs(sport);
            if (host_lport < first || host_lport > last) {
                desired += nb_queues;
                continue;
            }
            if (!recheck ||
                ff_rss_check6(softc, saddr6, daddr6, dport, sport)) {
                *out_sport = host_lport;
                return 0;
            }
        }

        desired += nb_queues;
    }

    return -1;
}
