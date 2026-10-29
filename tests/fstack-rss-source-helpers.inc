#define TEST_RSS_LAST    65535      /* FreeBSD default ipport_lastauto   */

#define TEST_RSS_FIRST   10000      /* FreeBSD default ipport_firstauto */

#define TEST_RSS_RETA     0          /* rss_reta_size[] BSS default => mask 0xFFFF */

#define TEST_RSS_QID      1          /* this "process" owns tx queue 1        */

#define TEST_RSS_NBQ      4          /* multi-queue so ff_rss_check is active */

#define TEST_RSS_PORT     0

static struct ff_rss_check_cfg g_rss_cfg;
static struct ff_dpdk_if_context g_test_ctx;

static const uint8_t test_rsskey_40[40] = {
    0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b,
    0x19, 0x83, 0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb,
    0xd9, 0x38, 0x9e, 0x6b, 0xd1, 0x03, 0x9c, 0x2c,
    0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d, 0x56, 0xd9,
    0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc
};

static const uint8_t test_saddr6[16] = {
    0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x01
};

static const uint8_t test_daddr6[16] = {
    0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x02
};

static uint32_t
test_toeplitz(unsigned keylen, const uint8_t *key,
              unsigned datalen, const uint8_t *data)
{
    uint32_t hash = 0, v;
    unsigned i, b;
    v = ((uint32_t)key[0] << 24) + ((uint32_t)key[1] << 16) +
        ((uint32_t)key[2] << 8) + key[3];
    for (i = 0; i < datalen; i++) {
        for (b = 0; b < 8; b++) {
            if (data[i] & (1 << (7 - b)))
                hash ^= v;
            v <<= 1;
            if ((i + 4) < keylen && (key[i + 4] & (1 << (7 - b))))
                v |= 1;
        }
    }
    return hash;
}

static int
test_expected_rss_check(uint32_t saddr, uint32_t daddr, uint16_t sport,
                        uint16_t dport, uint16_t nb_queues,
                        uint16_t reta_size, uint16_t queueid)
{
    uint8_t data[sizeof(saddr) + sizeof(daddr) + sizeof(sport) + sizeof(dport)];
    unsigned dl = 0;
    uint32_t hash;
    if (nb_queues <= 1)
        return 1;
    memcpy(&data[dl], &saddr, sizeof(saddr)); dl += sizeof(saddr);
    memcpy(&data[dl], &daddr, sizeof(daddr)); dl += sizeof(daddr);
    memcpy(&data[dl], &sport, sizeof(sport)); dl += sizeof(sport);
    memcpy(&data[dl], &dport, sizeof(dport)); dl += sizeof(dport);
    hash = test_toeplitz(sizeof(test_rsskey_40), test_rsskey_40, dl, data);
    return ((hash & (uint16_t)(reta_size - 1)) % nb_queues) == queueid;
}

static int
test_expected_rss_check6(const uint8_t saddr6[16], const uint8_t daddr6[16],
                         uint16_t sport, uint16_t dport, uint16_t nb_queues,
                         uint16_t reta_size, uint16_t queueid)
{
    uint8_t data[16 + 16 + sizeof(sport) + sizeof(dport)];
    unsigned dl = 0;
    uint32_t hash;
    if (nb_queues <= 1)
        return 1;
    memcpy(&data[dl], saddr6, 16); dl += 16;
    memcpy(&data[dl], daddr6, 16); dl += 16;
    memcpy(&data[dl], &sport, sizeof(sport)); dl += sizeof(sport);
    memcpy(&data[dl], &dport, sizeof(dport)); dl += sizeof(dport);
    hash = test_toeplitz(sizeof(test_rsskey_40), test_rsskey_40, dl, data);
    return ((hash & (uint16_t)(reta_size - 1)) % nb_queues) == queueid;
}

static int
test_rss_build_table(uint32_t saddr, uint32_t daddr, uint16_t sport)
{
    memset(&g_rss_cfg, 0, sizeof(g_rss_cfg));
    g_rss_cfg.enable = 1;
    g_rss_cfg.recheck = 1;   /* R-D 04-06: default recheck=1 to keep R-B/R-C hard assertions */
    g_rss_cfg.nb_rss_tbl = 1;
    g_rss_cfg.rss_tbl_cfgs[0].port_id = TEST_RSS_PORT;
    g_rss_cfg.rss_tbl_cfgs[0].saddr = saddr;
    g_rss_cfg.rss_tbl_cfgs[0].daddr = daddr;
    g_rss_cfg.rss_tbl_cfgs[0].sport = sport;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    lcore_conf[0].tx_queue_id[TEST_RSS_PORT]   = TEST_RSS_QID;

    return ff_rss_tbl_init();
}

static void *
test_rss_softc(uint16_t port_id)
{
    g_test_ctx.port_id = port_id;
    return ff_veth_get_softc(&g_test_ctx);   /* stores &g_test_ctx, returns sentinel */
}

static int
test_rss6_build_table(const uint8_t saddr6[16], const uint8_t daddr6[16],
                      uint16_t sport)
{
    memset(&g_rss_cfg, 0, sizeof(g_rss_cfg));
    g_rss_cfg.enable = 1;
    g_rss_cfg.recheck = 1;   /* R-D 04-06: default recheck=1 to keep R-B/R-C hard assertions */
    g_rss_cfg.nb_rss_tbl = 1;
    g_rss_cfg.rss_tbl_cfgs[0].port_id = TEST_RSS_PORT;
    g_rss_cfg.rss_tbl_cfgs[0].family  = AF_INET6;
    memcpy(g_rss_cfg.rss_tbl_cfgs[0].saddr6, saddr6, 16);
    memcpy(g_rss_cfg.rss_tbl_cfgs[0].daddr6, daddr6, 16);
    g_rss_cfg.rss_tbl_cfgs[0].sport = sport;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    lcore_conf[0].nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    lcore_conf[0].tx_queue_id[TEST_RSS_PORT]   = TEST_RSS_QID;

    return ff_rss_tbl6_init();
}
