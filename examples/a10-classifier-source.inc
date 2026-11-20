static int
it_flow_dispatcher(void *data, uint16_t *len, uint16_t queue_id,
    uint16_t nb_queues, struct ff_dispatcher_context context)
{
    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *ip, *tp;
    uint16_t et, l = *len;
    ff_flow_key_t k;

    (void)nb_queues; (void)context;
    /* mirror of ngx_ff_flow_map_dispatcher (C-NR-303): classify TCP flows
     * by flow_map; hit -> queue_id (ours, incl. syncache stage),
     * miss -> FF_DISPATCH_PEER (old flow, forward to the drainer) */
    if (l < 14 + 20 + 20)
        return (int)queue_id;                    /* unparsable: local */
    et = (uint16_t)((p[12] << 8) | p[13]);
    if (et == 0x8100) {                          /* one VLAN layer */
        p += 4; l -= 4;
        et = (uint16_t)((p[12] << 8) | p[13]);
    }
    if (et != 0x0800)
        return (int)queue_id;                    /* ARP/NDP never classified */
    ip = p + 14;
    if ((ip[0] >> 4) != 4)
        return (int)queue_id;
    if ((((uint16_t)ip[6] << 8) | ip[7]) & 0x3fff)
        return (int)queue_id;                    /* fragment: local */
    if (ip[9] != 6)
        return (int)queue_id;                    /* TCP only */
    tp = ip + ((ip[0] & 0x0f) << 2);

    memset(&k, 0, sizeof(k));
    k.af = FF_FLOW_MAP_V4;
    memcpy(&k.src[0], ip + 12, 4);               /* foreign */
    memcpy(&k.dst[0], ip + 16, 4);               /* local */
    memcpy(&k.sport, tp, 2);
    memcpy(&k.dport, tp + 2, 2);

    if (ff_flow_map_lookup(&k))
        return (int)queue_id;
    return FF_DISPATCH_PEER;
}
