int
ff_dpdk_if_send(struct ff_dpdk_if_context *ctx, void *m,
    int total)
{
    /* evaluated before the FF_USE_PAGE_ARRAY branch. A
     * parked generation must not stage into tx_mbufs — page-array pages
     * and the shared table are not a hand-off-able representation, so a
     * parked sender always takes the pktmbuf conversion below and hands
     * the result to this generation's drain_tx ring (the bsd mbuf itself
     * cannot cross a process boundary, hence divert only after the
     * conversion). */
    const int no_hw = ff_no_hw_mode_nosync();

    if (unlikely(ctx == NULL)) {
        ff_traffic.tx_dropped++;
        if (m != NULL) {
            ff_mbuf_free(m);
        }
        return -1;
    }
#ifdef FF_USE_PAGE_ARRAY
    if (!no_hw) {
        struct lcore_conf *qconf = ff_cur_lcore_conf();
        int    len = 0;

        len = ff_if_send_onepkt(ctx, m,total);
        if (unlikely(len == MAX_PKT_BURST)) {
            send_burst(qconf, MAX_PKT_BURST, ctx->port_id);
            len = 0;
        }
        qconf->tx_mbufs[ctx->port_id].len = len;
        return 0;
    }
#endif
    struct rte_mempool *mbuf_pool = ff_app_mbuf_pool(ff_cur_lcore_conf()->socket_id);
    struct rte_mbuf *head = rte_pktmbuf_alloc(mbuf_pool);
    if (head == NULL) {
        ff_traffic.tx_dropped++;
        ff_mbuf_free(m);
        return -1;
    }

    head->pkt_len = total;
    head->nb_segs = 0;

    int off = 0;
    struct rte_mbuf *cur = head, *prev = NULL;
    while(total > 0) {
        if (cur == NULL) {
            cur = rte_pktmbuf_alloc(mbuf_pool);
            if (cur == NULL) {
                ff_traffic.tx_dropped += head->nb_segs + 1;
                rte_pktmbuf_free(head);
                ff_mbuf_free(m);
                return -1;
            }
        }

        if (prev != NULL) {
            prev->next = cur;
        }
        head->nb_segs++;

        prev = cur;
        void *data = rte_pktmbuf_mtod(cur, void*);
        int cap = rte_pktmbuf_tailroom(cur);
        int len = total > cap ? cap : total;
        int ret = ff_mbuf_copydata(m, data, off, len);
        if (ret < 0) {
            ff_traffic.tx_dropped += head->nb_segs;
            rte_pktmbuf_free(head);
            ff_mbuf_free(m);
            return -1;
        }


        cur->data_len = len;
        off += len;
        total -= len;
        cur = NULL;
    }

    struct ff_tx_offload offload = {0};
    ff_mbuf_tx_offload(m, &offload);

    void *data = rte_pktmbuf_mtod(head, void*);

    if (ctx->hw_features.tx_csum_ip && offload.ip_csum) {
        /* ipv6 not supported yet */
        struct rte_ipv4_hdr *iph;
        int iph_len;
        iph = (struct rte_ipv4_hdr *)(data + RTE_ETHER_HDR_LEN);
        iph_len = (iph->version_ihl & 0x0f) << 2;

        head->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
        head->l2_len = RTE_ETHER_HDR_LEN;
        head->l3_len = iph_len;
    }

    if (ctx->hw_features.tx_csum_l4) {
        struct rte_ipv4_hdr *iph;
        int iph_len;
        iph = (struct rte_ipv4_hdr *)(data + RTE_ETHER_HDR_LEN);
        iph_len = (iph->version_ihl & 0x0f) << 2;

        if (iph->version == 4) {
            head->ol_flags |= RTE_MBUF_F_TX_IPV4;
        } else {
            head->ol_flags |= RTE_MBUF_F_TX_IPV6;
        }

        if (offload.tcp_csum) {
            head->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
            head->l2_len = RTE_ETHER_HDR_LEN;
            head->l3_len = iph_len;
        }

        /*
         *  TCP segmentation offload.
         *
         *  - set the PKT_TX_TCP_SEG flag in mbuf->ol_flags (this flag
         *    implies PKT_TX_TCP_CKSUM)
         *  - set the flag PKT_TX_IPV4 or PKT_TX_IPV6
         *  - if it's IPv4, set the PKT_TX_IP_CKSUM flag and
         *    write the IP checksum to 0 in the packet
         *  - fill the mbuf offload information: l2_len,
         *    l3_len, l4_len, tso_segsz
         *  - calculate the pseudo header checksum without taking ip_len
         *    in account, and set it in the TCP header. Refer to
         *    rte_ipv4_phdr_cksum() and rte_ipv6_phdr_cksum() that can be
         *    used as helpers.
         */
        if (offload.tso_seg_size) {
            struct rte_tcp_hdr *tcph;
            int tcph_len;

            if (iph->version == 4) {
                tcph = (struct rte_tcp_hdr *)((char *)iph + iph_len);
                tcph_len = (tcph->data_off & 0xf0) >> 2;
                head->ol_flags |= RTE_MBUF_F_TX_IPV4;
                if (ctx->hw_features.tx_csum_ip) {
                    head->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
                }
                tcph->cksum = rte_ipv4_phdr_cksum(iph, RTE_MBUF_F_TX_TCP_SEG);
                head->l3_len = iph_len;
            } else {
                struct rte_ipv6_hdr *ip6h = (struct rte_ipv6_hdr *)iph;
                int ip6_len = sizeof(struct rte_ipv6_hdr);
                tcph = (struct rte_tcp_hdr *)((char *)ip6h + ip6_len);
                tcph_len = (tcph->data_off & 0xf0) >> 2;
                head->ol_flags |= RTE_MBUF_F_TX_IPV6;
                tcph->cksum = rte_ipv6_phdr_cksum(ip6h, RTE_MBUF_F_TX_TCP_SEG);
                head->l3_len = ip6_len;
            }

            head->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
            head->l2_len = RTE_ETHER_HDR_LEN;
            head->l4_len = tcph_len;
            head->tso_segsz = offload.tso_seg_size;
        }

        if (offload.udp_csum) {
            head->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
            head->l2_len = RTE_ETHER_HDR_LEN;
            head->l3_len = iph_len;
        }
    }

    ff_mbuf_free(m);

    if (unlikely(no_hw)) {
        /* parked — the peer generation transmits this packet. */
        struct lcore_conf *qconf = ff_cur_lcore_conf();
        ff_divert_tx_mbuf(ctx->port_id,
            qconf->tx_queue_id[ctx->port_id], head);
        return 0;
    }

    return send_single_packet(head, ctx->port_id);
}
