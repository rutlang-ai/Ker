static void
fill_tcp_ack(uint8_t *p, uint32_t foreign, uint32_t local,
    uint16_t sport, uint16_t dport)
{
    memset(p, 0, 54);
    p[12] = 0x08; p[13] = 0x00;              /* ethertype IPv4 */
    /* IPv4 header at 14 */
    p[14] = 0x45;                            /* v4, IHL 5 */
    p[16] = 0; p[17] = 40;                   /* total length */
    p[20] = 0x40; p[21] = 0x00;              /* DF, no fragment */
    p[22] = 64;                              /* TTL */
    p[23] = 6;                               /* proto TCP */
    memcpy(p + 26, &foreign, 4);             /* ip src (foreign) */
    memcpy(p + 30, &local, 4);               /* ip dst (local) */
    /* TCP header at 34 */
    p[46] = 0x50;                            /* data offset 5 */
    p[47] = 0x10;                            /* ACK */
    memcpy(p + 34, &sport, 2);
    memcpy(p + 36, &dport, 2);
}

static struct rte_mbuf *
inj_mbuf(uint32_t foreign, uint32_t local, uint16_t sport, uint16_t dport)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_inj_pool);

    if (m == NULL)
        return NULL;
    fill_tcp_ack(rte_pktmbuf_mtod(m, uint8_t *), foreign, local, sport, dport);
    rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m) = 54;
    return m;
}

static void
flow_key_v4(ff_flow_key_t *k, uint32_t foreign, uint32_t local,
    uint16_t sport, uint16_t dport)
{
    memset(k, 0, sizeof(*k));
    k->af = FF_FLOW_MAP_V4;
    k->src[0] = foreign;                     /* foreign address first */
    k->dst[0] = local;
    k->sport = sport;
    k->dport = dport;
}
