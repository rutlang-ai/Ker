static uint32_t
toeplitz_hash(unsigned keylen, const uint8_t *key,
    unsigned datalen, const uint8_t *data)
{
    uint32_t hash = 0, v;
    u_int i, b;

    /* XXXRW: Perhaps an assertion about key length vs. data length? */

    v = (key[0]<<24) + (key[1]<<16) + (key[2] <<8) + key[3];
    for (i = 0; i < datalen; i++) {
        for (b = 0; b < 8; b++) {
            if (data[i] & (1<<(7-b)))
                hash ^= v;
            v <<= 1;
            if ((i + 4) < keylen &&
                (key[i+4] & (1<<(7-b))))
                v |= 1;
        }
    }
    return (hash);
}

int
ff_rss_tbl_init(void)
{
    uint32_t ori_idx, idx, ori_daddr_idx, daddr_idx;
    uint32_t daddr, saddr;
    uint16_t sport;
    int prev_dport, stat, i, j, k;
    void *sc;
    struct ff_dpdk_if_context ctx;

    memset(ff_rss_tbl, 0, sizeof(ff_rss_tbl));

    sc = ff_veth_get_softc(&ctx);
    if (sc == NULL) {
        ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB, "ff_veth_get_softc failed\n");
        return -1;
    }

    for (i = 0; i < ff_global_cfg.dpdk.rss_check_cfgs->nb_rss_tbl; i++) {
        struct ff_rss_tbl_cfg *rcc = &ff_global_cfg.dpdk.rss_check_cfgs->rss_tbl_cfgs[i];

        if (rcc->family == AF_INET6)
            continue;

        ctx.port_id = rcc->port_id;
        daddr = rcc->daddr;
        saddr = rcc->saddr;
        sport = rcc->sport;

        /* Use DIR D to avoid getting the same idx while FF_RSS_TBL_MAX_DIP_MASK is very small*/
        ori_idx = idx = ((saddr + (uint32_t)((uint8_t *)&saddr)[3]) ^ sport) & \
            FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
        ori_daddr_idx = daddr_idx = (daddr + (uint32_t)((uint8_t *)&daddr)[3]) & \
            FF_RSS_TBL_MAX_DIP_MASK;

        do {
            if (ff_rss_tbl[idx].saddr == INADDR_ANY ||
                    (ff_rss_tbl[idx].saddr == saddr &&
                    ff_rss_tbl[idx].sport == sport)) {
                break;
            }

            if (ff_rss_tbl[idx].saddr != saddr ||
                    ff_rss_tbl[idx].sport != sport) {
                idx++;
                idx &= FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
            }
        } while (idx != ori_idx);

        if (idx == ori_idx &&
                ((ff_rss_tbl[idx].saddr != INADDR_ANY) &&
                (ff_rss_tbl[idx].saddr != saddr ||
                ff_rss_tbl[idx].sport != sport))) {
            ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB, "There are too many 2-tuble(> %d) of saddrs(max %d) * sport(max %d),"
                " this 4-tuple rss_tbl config will be ignored,"
                 " idx %d, port_id %u, daddr "NIPQUAD_FMT", saddr "NIPQUAD_FMT", sport %u\n",
                 FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES, FF_RSS_TBL_MAX_SADDR, FF_RSS_TBL_MAX_SPORT,
                 i, ctx.port_id, NIPQUAD(daddr), NIPQUAD(saddr), ntohs(sport));
            goto IGNORE;
            //ff_veth_free_softc(sc);
            //return -1;
        }

        do {
            if (ff_rss_tbl[idx].dip_tbl[daddr_idx].daddr == INADDR_ANY) {
                break;
            }

            if (ff_rss_tbl[idx].dip_tbl[daddr_idx].daddr != daddr) {
                daddr_idx++;
                daddr_idx &= FF_RSS_TBL_MAX_DIP_MASK;
            } else {
                /* Dup 3-tuple */
                ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB, "Duplicate ff rss table 3-tuple,"
                    " this 4-tuple rss_tbl config will be ignored,"
                     " port_id %u, daddr "NIPQUAD_FMT", saddr "NIPQUAD_FMT", sport %u\n",
                     ctx.port_id, NIPQUAD(daddr), NIPQUAD(saddr), ntohs(sport));
                goto IGNORE;
            }
        } while (daddr_idx != ori_daddr_idx);

        if (daddr_idx == ori_daddr_idx && ff_rss_tbl[idx].dip_tbl[daddr_idx].daddr != INADDR_ANY) {
           ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB, "There are too many daddrs(> %d) with same saddr and sport,"
                " this 4-tuple rss_tbl config will be ignored,"
                 " idx %d, port_id %u, daddr "NIPQUAD_FMT", saddr "NIPQUAD_FMT", sport %u\n",
                 i, FF_RSS_TBL_MAX_DADDR, ctx.port_id,
                 NIPQUAD(daddr), NIPQUAD(saddr), ntohs(sport));
            goto IGNORE;
            //return -1; /* Not used now */
        }

        /* The idx of port start form 1, 0 used as the idx of last selected port */
        k = 1;
        prev_dport = -1;
        ff_rss_tbl[idx].dip_tbl[daddr_idx].dport[0] = k;
        ff_rss_tbl[idx].dip_tbl[daddr_idx].first_idx = k;
        for (j = 0; j < FF_RSS_TBL_MAX_DPORT; j++) {
            stat = ff_rss_check(sc, saddr, daddr, sport, htons(j));
            if (stat) {
                ff_rss_tbl[idx].dip_tbl[daddr_idx].num++;
                ff_rss_tbl[idx].dip_tbl[daddr_idx].dport[k++] = j;
                if (prev_dport == -1) {
                    ff_rss_tbl[idx].dip_tbl[daddr_idx].first = j;
                }
                prev_dport = j;
            }
        }
        /*
         * If num and k set 65536, it will be 0, otherwise will set portrange failed.
         * It only appears in a single process, has no impact.
         * And 65535 only used for comparative testing.
         */
        if (k == FF_RSS_TBL_MAX_DPORT + 1) {
            ff_rss_tbl[idx].dip_tbl[daddr_idx].num = k -2;
            ff_rss_tbl[idx].dip_tbl[daddr_idx].last_idx =  k - 2;
        } else
            ff_rss_tbl[idx].dip_tbl[daddr_idx].last_idx = k - 1;
        ff_rss_tbl[idx].dip_tbl[daddr_idx].last = prev_dport;
        ff_rss_tbl[idx].dip_tbl[daddr_idx].daddr = daddr;

        ff_rss_tbl[idx].saddr = saddr;
        ff_rss_tbl[idx].sport = sport;
        ff_rss_tbl[idx].num++;

        ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB, "Inited one ff_rss_tbl success, port_id %u, daddr "NIPQUAD_FMT
            ", saddr "NIPQUAD_FMT", sport %u,"
            " last idx %u, available lport num %u\n",
            ctx.port_id, NIPQUAD(daddr), NIPQUAD(saddr), ntohs(sport),
            ff_rss_tbl[idx].dip_tbl[daddr_idx].last_idx,
            ff_rss_tbl[idx].dip_tbl[daddr_idx].num);

IGNORE:
        // do nothing
        ;
    }

    ff_veth_free_softc(sc);

    return 0;

}

int
ff_rss_tbl_set_portrange(uint16_t first, uint16_t last)
{
    int i, j, k;

    if (first > last || !ff_global_cfg.dpdk.rss_check_cfgs ||
            ff_global_cfg.dpdk.rss_check_cfgs->enable == 0) {
        return -1;
    }

    for (i = 0; i < FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES; i++) {
        if (ff_rss_tbl[i].saddr == INADDR_ANY) {
            continue;
        }

        for(j = 0; j < FF_RSS_TBL_MAX_DADDR; j++) {
            if (ff_rss_tbl[i].dip_tbl[j].daddr == INADDR_ANY) {
                continue;
            }

            ff_rss_tbl[i].dip_tbl[j].first = first;
            ff_rss_tbl[i].dip_tbl[j].last = last;

            ff_rss_tbl[i].dip_tbl[j].first_idx = 0;
            for (k = 1; k <= ff_rss_tbl[i].dip_tbl[j].num; k++) {
                if (ff_rss_tbl[i].dip_tbl[j].first_idx == 0 &&
                        ff_rss_tbl[i].dip_tbl[j].dport[k] >= first) {
                    ff_rss_tbl[i].dip_tbl[j].first_idx = k;
                    if (ff_rss_tbl[i].dip_tbl[j].dport[ff_rss_tbl[i].dip_tbl[j].num] < last) {
                        /* ff_rss_tbl_init set last_idx as ff_rss_tbl[i].dip_tbl[j].num already. */
                        break;
                    }
                    if (first == last) {
                        ff_rss_tbl[i].dip_tbl[j].last_idx = k;
                        break;
                    }
                }
                if (ff_rss_tbl[i].dip_tbl[j].dport[k] == last) {
                    ff_rss_tbl[i].dip_tbl[j].last_idx = k;
                    break;
                }
                if (ff_rss_tbl[i].dip_tbl[j].dport[k] > last) {
                    ff_rss_tbl[i].dip_tbl[j].last_idx = k > 1 ? k -1 : k;
                    break;
                }
            }

            if (ff_rss_tbl[i].dip_tbl[j].first_idx == 0 ||
                    ff_rss_tbl[i].dip_tbl[j].last_idx < ff_rss_tbl[i].dip_tbl[j].first_idx) {
                ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB, "ff_rss_tbl_set_portrange failed, first %u, last %u\n",
                    first, last);
                return -1;
            }
        }
    }

    return 0;
}

int
ff_rss_tbl_get_portrange(uint32_t saddr, uint32_t daddr, uint16_t sport,
    uint16_t *rss_first, uint16_t *rss_last, uint16_t **rss_portrange)
{
    uint32_t ori_idx, idx, ori_daddr_idx, daddr_idx;
    int i;

    if (!ff_global_cfg.dpdk.rss_check_cfgs ||
            ff_global_cfg.dpdk.rss_check_cfgs->enable == 0) {
        return -1;
    }

    ori_idx = idx = ((saddr + (uint32_t)((uint8_t *)&saddr)[3]) ^ sport) & \
        FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
    do {
        /* If not inited, no need to continue find */
        if (ff_rss_tbl[idx].saddr == INADDR_ANY) {
            return -ENOENT;
        }

        if (ff_rss_tbl[idx].saddr == saddr && ff_rss_tbl[idx].sport == sport) {
            ori_daddr_idx = daddr_idx = (daddr + (uint32_t)((uint8_t *)&daddr)[3]) & \
                FF_RSS_TBL_MAX_DIP_MASK;
            do {
                if (ff_rss_tbl[idx].dip_tbl[daddr_idx].daddr == INADDR_ANY) {
                    return -ENOENT;
                }

                if (ff_rss_tbl[idx].dip_tbl[daddr_idx].daddr == daddr) {
                    *rss_first = ff_rss_tbl[idx].dip_tbl[daddr_idx].first_idx;
                    *rss_last = ff_rss_tbl[idx].dip_tbl[daddr_idx].last_idx;
                    *rss_portrange = &ff_rss_tbl[idx].dip_tbl[daddr_idx].dport[0];
                    return 0;
                }

                daddr_idx++;
                daddr_idx &= FF_RSS_TBL_MAX_DIP_MASK;
            } while (daddr_idx != ori_daddr_idx);

            if (daddr_idx == ori_daddr_idx) {
                return -ENOENT;
            }
        }

        idx++;
        idx &= FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
    } while (idx != ori_idx);

    if (idx == ori_idx) {
        return -ENOENT;
    }

    return -ENOENT;
}

int
ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
    uint16_t sport, uint16_t dport)
{
    struct lcore_conf *qconf = ff_cur_lcore_conf();
    struct ff_dpdk_if_context *ctx = ff_veth_softc_to_hostc(softc);
    uint16_t nb_queues = qconf->nb_queue_list[ctx->port_id];

    if (nb_queues <= 1) {
        return 1;
    }

    uint16_t reta_size = rss_reta_size[ctx->port_id];
    uint16_t queueid = qconf->tx_queue_id[ctx->port_id];

    uint8_t data[sizeof(saddr) + sizeof(daddr) + sizeof(sport) +
            sizeof(dport)];

    unsigned datalen = 0;

    bcopy(&saddr, &data[datalen], sizeof(saddr));
    datalen += sizeof(saddr);

    bcopy(&daddr, &data[datalen], sizeof(daddr));
    datalen += sizeof(daddr);

    bcopy(&sport, &data[datalen], sizeof(sport));
    datalen += sizeof(sport);

    bcopy(&dport, &data[datalen], sizeof(dport));
    datalen += sizeof(dport);

    uint32_t hash = 0;
    hash = toeplitz_hash(rsskey_len, rsskey, datalen, data);

    return ((hash & (reta_size - 1)) % nb_queues) == queueid;
}

static inline int
ff_in6_is_any(const uint8_t addr6[16])
{
    int i;

    for (i = 0; i < 16; i++)
        if (addr6[i] != 0)
            return 0;
    return 1;
}

static inline uint32_t
ff_in6_fold(const uint8_t addr6[16])
{
    uint32_t v = 0;
    int i;

    for (i = 0; i < 16; i++)
        v += (uint32_t)addr6[i] << ((i & 3) * 8);
    return v;
}

int
ff_rss_check6(void *softc, const uint8_t *saddr6, const uint8_t *daddr6,
    uint16_t sport, uint16_t dport)
{
    struct lcore_conf *qconf = ff_cur_lcore_conf();
    struct ff_dpdk_if_context *ctx = ff_veth_softc_to_hostc(softc);
    uint16_t nb_queues = qconf->nb_queue_list[ctx->port_id];

    if (nb_queues <= 1) {
        return 1;
    }

    uint16_t reta_size = rss_reta_size[ctx->port_id];
    uint16_t queueid = qconf->tx_queue_id[ctx->port_id];

    uint8_t data[16 + 16 + sizeof(sport) + sizeof(dport)];
    unsigned datalen = 0;

    bcopy(saddr6, &data[datalen], 16);
    datalen += 16;
    bcopy(daddr6, &data[datalen], 16);
    datalen += 16;
    bcopy(&sport, &data[datalen], sizeof(sport));
    datalen += sizeof(sport);
    bcopy(&dport, &data[datalen], sizeof(dport));
    datalen += sizeof(dport);

    uint32_t hash = toeplitz_hash(rsskey_len, rsskey, datalen, data);

    return ((hash & (reta_size - 1)) % nb_queues) == queueid;
}

int
ff_rss_tbl6_init(void)
{
    uint32_t ori_idx, idx, ori_daddr_idx, daddr_idx;
    uint8_t *daddr6, *saddr6;
    uint16_t sport;
    int prev_dport, stat, i, j, k;
    void *sc;
    struct ff_dpdk_if_context ctx;

    memset(ff_rss_tbl6, 0, sizeof(ff_rss_tbl6));

    sc = ff_veth_get_softc(&ctx);
    if (sc == NULL) {
        ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB, "ff_veth_get_softc failed\n");
        return -1;
    }

    for (i = 0; i < ff_global_cfg.dpdk.rss_check_cfgs->nb_rss_tbl; i++) {
        struct ff_rss_tbl_cfg *rcc = &ff_global_cfg.dpdk.rss_check_cfgs->rss_tbl_cfgs[i];

        if (rcc->family != AF_INET6)
            continue;

        ctx.port_id = rcc->port_id;
        daddr6 = rcc->daddr6;
        saddr6 = rcc->saddr6;
        sport = rcc->sport;

        ori_idx = idx = (ff_in6_fold(saddr6) ^ sport) &
            FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
        ori_daddr_idx = daddr_idx = ff_in6_fold(daddr6) & FF_RSS_TBL_MAX_DIP_MASK;

        do {
            if (ff_in6_is_any(ff_rss_tbl6[idx].saddr6) ||
                    (memcmp(ff_rss_tbl6[idx].saddr6, saddr6, 16) == 0 &&
                    ff_rss_tbl6[idx].sport == sport)) {
                break;
            }
            idx++;
            idx &= FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
        } while (idx != ori_idx);

        if (idx == ori_idx && !ff_in6_is_any(ff_rss_tbl6[idx].saddr6) &&
                (memcmp(ff_rss_tbl6[idx].saddr6, saddr6, 16) != 0 ||
                ff_rss_tbl6[idx].sport != sport)) {
            ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                "ff_rss_tbl6: too many v6 saddr*sport entries, ignore one cfg, port_id %u\n",
                ctx.port_id);
            goto IGNORE;
        }

        do {
            if (ff_in6_is_any(ff_rss_tbl6[idx].dip_tbl[daddr_idx].daddr6)) {
                break;
            }
            if (memcmp(ff_rss_tbl6[idx].dip_tbl[daddr_idx].daddr6, daddr6, 16) != 0) {
                daddr_idx++;
                daddr_idx &= FF_RSS_TBL_MAX_DIP_MASK;
            } else {
                ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                    "ff_rss_tbl6: duplicate v6 3-tuple, ignore one cfg, port_id %u\n",
                    ctx.port_id);
                goto IGNORE;
            }
        } while (daddr_idx != ori_daddr_idx);

        if (daddr_idx == ori_daddr_idx &&
                !ff_in6_is_any(ff_rss_tbl6[idx].dip_tbl[daddr_idx].daddr6)) {
            ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
                "ff_rss_tbl6: too many v6 daddrs, ignore one cfg, port_id %u\n",
                ctx.port_id);
            goto IGNORE;
        }

        k = 1;
        prev_dport = -1;
        ff_rss_tbl6[idx].dip_tbl[daddr_idx].dport[0] = k;
        ff_rss_tbl6[idx].dip_tbl[daddr_idx].first_idx = k;
        for (j = 0; j < FF_RSS_TBL_MAX_DPORT; j++) {
            stat = ff_rss_check6(sc, saddr6, daddr6, sport, htons(j));
            if (stat) {
                ff_rss_tbl6[idx].dip_tbl[daddr_idx].num++;
                ff_rss_tbl6[idx].dip_tbl[daddr_idx].dport[k++] = j;
                if (prev_dport == -1) {
                    ff_rss_tbl6[idx].dip_tbl[daddr_idx].first = j;
                }
                prev_dport = j;
            }
        }
        if (k == FF_RSS_TBL_MAX_DPORT + 1) {
            ff_rss_tbl6[idx].dip_tbl[daddr_idx].num = k - 2;
            ff_rss_tbl6[idx].dip_tbl[daddr_idx].last_idx = k - 2;
        } else
            ff_rss_tbl6[idx].dip_tbl[daddr_idx].last_idx = k - 1;
        ff_rss_tbl6[idx].dip_tbl[daddr_idx].last = prev_dport;
        bcopy(daddr6, ff_rss_tbl6[idx].dip_tbl[daddr_idx].daddr6, 16);

        bcopy(saddr6, ff_rss_tbl6[idx].saddr6, 16);
        ff_rss_tbl6[idx].sport = sport;
        ff_rss_tbl6[idx].num++;

IGNORE:
        ;
    }

    ff_veth_free_softc(sc);

    return 0;
}

int
ff_rss_tbl6_set_portrange(uint16_t first, uint16_t last)
{
    int i, j, k;

    if (first > last || !ff_global_cfg.dpdk.rss_check_cfgs ||
            ff_global_cfg.dpdk.rss_check_cfgs->enable == 0) {
        return -1;
    }

    for (i = 0; i < FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES; i++) {
        if (ff_in6_is_any(ff_rss_tbl6[i].saddr6)) {
            continue;
        }

        for (j = 0; j < FF_RSS_TBL_MAX_DADDR; j++) {
            if (ff_in6_is_any(ff_rss_tbl6[i].dip_tbl[j].daddr6)) {
                continue;
            }

            ff_rss_tbl6[i].dip_tbl[j].first = first;
            ff_rss_tbl6[i].dip_tbl[j].last = last;

            ff_rss_tbl6[i].dip_tbl[j].first_idx = 0;
            for (k = 1; k <= ff_rss_tbl6[i].dip_tbl[j].num; k++) {
                if (ff_rss_tbl6[i].dip_tbl[j].first_idx == 0 &&
                        ff_rss_tbl6[i].dip_tbl[j].dport[k] >= first) {
                    ff_rss_tbl6[i].dip_tbl[j].first_idx = k;
                    if (ff_rss_tbl6[i].dip_tbl[j].dport[ff_rss_tbl6[i].dip_tbl[j].num] < last) {
                        break;
                    }
                    if (first == last) {
                        ff_rss_tbl6[i].dip_tbl[j].last_idx = k;
                        break;
                    }
                }
                if (ff_rss_tbl6[i].dip_tbl[j].dport[k] == last) {
                    ff_rss_tbl6[i].dip_tbl[j].last_idx = k;
                    break;
                }
                if (ff_rss_tbl6[i].dip_tbl[j].dport[k] > last) {
                    ff_rss_tbl6[i].dip_tbl[j].last_idx = k > 1 ? k - 1 : k;
                    break;
                }
            }

            if (ff_rss_tbl6[i].dip_tbl[j].first_idx == 0 ||
                    ff_rss_tbl6[i].dip_tbl[j].last_idx < ff_rss_tbl6[i].dip_tbl[j].first_idx) {
                ff_log(FF_LOG_ERR, FF_LOGTYPE_FSTACK_LIB,
                    "ff_rss_tbl6_set_portrange failed, first %u, last %u\n", first, last);
                return -1;
            }
        }
    }

    return 0;
}

int
ff_rss_tbl6_get_portrange(const uint8_t *saddr6, const uint8_t *daddr6,
    uint16_t sport, uint16_t *rss_first, uint16_t *rss_last,
    uint16_t **rss_portrange)
{
    uint32_t ori_idx, idx, ori_daddr_idx, daddr_idx;

    if (!ff_global_cfg.dpdk.rss_check_cfgs ||
            ff_global_cfg.dpdk.rss_check_cfgs->enable == 0) {
        return -1;
    }

    ori_idx = idx = (ff_in6_fold(saddr6) ^ sport) &
        FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
    do {
        if (ff_in6_is_any(ff_rss_tbl6[idx].saddr6)) {
            return -ENOENT;
        }

        if (memcmp(ff_rss_tbl6[idx].saddr6, saddr6, 16) == 0 &&
                ff_rss_tbl6[idx].sport == sport) {
            ori_daddr_idx = daddr_idx = ff_in6_fold(daddr6) & FF_RSS_TBL_MAX_DIP_MASK;
            do {
                if (ff_in6_is_any(ff_rss_tbl6[idx].dip_tbl[daddr_idx].daddr6)) {
                    return -ENOENT;
                }

                if (memcmp(ff_rss_tbl6[idx].dip_tbl[daddr_idx].daddr6, daddr6, 16) == 0) {
                    *rss_first = ff_rss_tbl6[idx].dip_tbl[daddr_idx].first_idx;
                    *rss_last = ff_rss_tbl6[idx].dip_tbl[daddr_idx].last_idx;
                    *rss_portrange = &ff_rss_tbl6[idx].dip_tbl[daddr_idx].dport[0];
                    return 0;
                }

                daddr_idx++;
                daddr_idx &= FF_RSS_TBL_MAX_DIP_MASK;
            } while (daddr_idx != ori_daddr_idx);

            return -ENOENT;
        }

        idx++;
        idx &= FF_RSS_TBL_MAX_SADDR_SPORT_ENTRIES_MASK;
    } while (idx != ori_idx);

    return -ENOENT;
}
