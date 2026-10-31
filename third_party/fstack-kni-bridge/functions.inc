int
ff_kni_is_owner_thread(void)
{
    if (ff_global_cfg.dpdk.thread_mode)
        return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
    return rte_eal_process_type() == RTE_PROC_PRIMARY;
}

int
ff_kni_is_runtime_owner(void)
{
    if (ff_global_cfg.dpdk.thread_mode)
        return rte_lcore_id() == ff_global_cfg.dpdk.proc_lcore[0];
    if (!ff_global_cfg.dpdk.primary_slim)
        return rte_eal_process_type() == RTE_PROC_PRIMARY;
    if (ff_global_cfg.dpdk.proc_id != ff_global_cfg.kni.owner_proc_id)
        return 0;
    /* under graceful_reload two generations share the same
     * proc_id, so the owner check must also match the generation: only the
     * active generation owns KNI runtime (the master flips the active gen
     * at T5). Without an attached reload state (non-nginx apps) the legacy
     * proc_id-only comparison is kept.
     * across masters the generation alone is ambiguous (both start at
     * gen 0 in their own anonymous block), so the check goes through the
     * generation directory's single (epoch, gen) KNI owner word — two
     * processes must never both rte_eth_tx_burst the same TX queue. */
    if (ff_global_cfg.dpdk.graceful_reload && ff_reload_state_attached())
        return ff_reload_kni_owner_match();
    return 1;
}

static int
kni_needs_stats(void)
{
    return ff_kni_is_owner_thread() ||
        (!ff_global_cfg.dpdk.thread_mode && ff_global_cfg.dpdk.primary_slim &&
         ff_global_cfg.dpdk.proc_id == ff_global_cfg.kni.owner_proc_id);
}

static void
set_bitmap(uint16_t port, unsigned char *bitmap)
{
    port = htons(port);
    unsigned char *p = bitmap + port/8;
    *p = set_bit(*p, port % 8);
}

static void
kni_set_bitmap(const char *p, unsigned char *port_bitmap)
{
    int i;
    const char *head, *tail, *tail_num;
    if(!p)
        return;

    head = p;
    while (1) {
        tail = strstr(head, ",");
        tail_num = strstr(head, "-");
        if(tail_num && (!tail || tail_num < tail - 1)) {
            for(i = atoi(head); i <= atoi(tail_num + 1); ++i) {
                set_bitmap(i, port_bitmap);
            }
        } else {
            set_bitmap(atoi(head), port_bitmap);
        }

        if(!tail)
            break;

        head = tail + 1;
    }
}

static int
kni_process_tx(uint16_t port_id, __rte_unused uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    /* read packet from kni ring(phy port) and transmit to kni */
    uint16_t nb_tx, nb_to_tx, nb_kni_tx = 0;
    nb_tx = rte_ring_dequeue_burst(kni_rp[port_id], (void **)pkts_burst, count, NULL);

    /*
     * The total ratelimit forwarded to the kernel, may a few more packets being sent, but it doesn’t matter,
     * If there are too many processes, there is also the possibility that the control packet will be ratelimited.
     */
    if (ff_global_cfg.kni.kernel_packets_ratelimit) {
        if (likely(kni_rate_limt.kernel_packets < (uint64_t)ff_global_cfg.kni.kernel_packets_ratelimit)) {
            nb_to_tx = nb_tx;
        } else {
            nb_to_tx = 0;
        }
        kni_rate_limt.kernel_packets += nb_tx;
    } else {
        nb_to_tx = nb_tx;
    }

    nb_kni_tx = rte_eth_tx_burst(kni_stat[port_id]->port_id, 0, pkts_burst, nb_to_tx);

    if(nb_kni_tx < nb_tx) {
        uint16_t i;
        for(i = nb_kni_tx; i < nb_tx; ++i)
            rte_pktmbuf_free(pkts_burst[i]);

        kni_stat[port_id]->rx_dropped += (nb_tx - nb_kni_tx);
    }

    kni_stat[port_id]->rx_packets += nb_kni_tx;
    return 0;
}

static int
kni_process_rx(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    uint16_t nb_kni_rx = 0, nb_rx;

    nb_kni_rx = rte_eth_rx_burst(kni_stat[port_id]->port_id, 0, pkts_burst, count);

    if (nb_kni_rx > 0) {
        if (ff_global_cfg.dpdk.primary_slim &&
            rte_eal_process_type() == RTE_PROC_PRIMARY) {
            /* Redirect to inject ring to avoid race between primary and
             * owner_proc_id secondary both calling rte_eth_tx_burst on
             * the same physical port TX queue 0. */
            unsigned enq = rte_ring_enqueue_burst(kni_inject_rp[port_id],
                (void **)pkts_burst, nb_kni_rx, NULL);
            if (enq < nb_kni_rx) {
                uint16_t i;
                for (i = enq; i < nb_kni_rx; ++i)
                    rte_pktmbuf_free(pkts_burst[i]);
                kni_stat[port_id]->tx_dropped += (nb_kni_rx - enq);
            }
            kni_stat[port_id]->tx_packets += enq;
            return 0;
        }

        nb_rx = rte_eth_tx_burst(port_id, queue_id, pkts_burst, nb_kni_rx);
        if (nb_rx < nb_kni_rx) {
            uint16_t i;
            for(i = nb_rx; i < nb_kni_rx; ++i)
                rte_pktmbuf_free(pkts_burst[i]);

            kni_stat[port_id]->tx_dropped += (nb_kni_rx - nb_rx);
        }

        kni_stat[port_id]->tx_packets += nb_rx;
    }
    return 0;
}

void
ff_kni_init(uint16_t nb_ports, const char *tcp_ports, const char *udp_ports)
{
    if (kni_needs_stats()) {
        kni_stat = rte_zmalloc("kni:stat",
            sizeof(struct kni_interface_stats *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
        if (kni_stat == NULL)
            rte_exit(EXIT_FAILURE, "rte_zmalloc(1 (struct netio_kni_stat *)) "
                "failed\n");
    }

    uint16_t lcoreid = rte_lcore_id();
    char name_buf[RTE_RING_NAMESIZE];
    snprintf(name_buf, RTE_RING_NAMESIZE, "kni::ring_%d", lcoreid);
    kni_rp = rte_zmalloc(name_buf,
            sizeof(struct rte_ring *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
    if (kni_rp == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (struct rte_ring*)) "
                "failed\n", name_buf);
    }

    snprintf(name_buf, RTE_RING_NAMESIZE, "kni::inject_ring_%d", lcoreid);
    kni_inject_rp = rte_zmalloc(name_buf,
            sizeof(struct rte_ring *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
    if (kni_inject_rp == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (kni_inject_rp)) "
                "failed\n", name_buf);
    }

    snprintf(name_buf, RTE_RING_NAMESIZE, "kni:tcp_port_bitmap_%d", lcoreid);
    tcp_port_bitmap = rte_zmalloc("kni:tcp_port_bitmap", 8192,
        RTE_CACHE_LINE_SIZE);
    if (tcp_port_bitmap == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (tcp_port_bitmap)) "
                "failed\n", name_buf);
    }

    snprintf(name_buf, RTE_RING_NAMESIZE, "kni:udp_port_bitmap_%d", lcoreid);
    udp_port_bitmap = rte_zmalloc("kni:udp_port_bitmap", 8192,
        RTE_CACHE_LINE_SIZE);
    if (udp_port_bitmap == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (udp_port_bitmap)) "
                "failed\n",name_buf);
    }

    memset(tcp_port_bitmap, 0, 8192);
    memset(udp_port_bitmap, 0, 8192);

    kni_set_bitmap(tcp_ports, tcp_port_bitmap);
    kni_set_bitmap(udp_ports, udp_port_bitmap);
}

void
ff_kni_alloc(uint16_t port_id, unsigned socket_id, int port_idx,
    unsigned ring_queue_size)
{
    if (kni_needs_stats()) {
        struct rte_ether_addr addr = {{0}};
        int ret;

        kni_stat[port_id] = (struct kni_interface_stats*)rte_zmalloc(
            "kni:stat_lcore",
            sizeof(struct kni_interface_stats),
            RTE_CACHE_LINE_SIZE);

        if (kni_stat[port_id] == NULL) {
            rte_panic("rte_zmalloc kni_interface_stats failed\n");
        }

        kni_stat[port_id]->rx_packets = 0;
        kni_stat[port_id]->rx_dropped = 0;
        kni_stat[port_id]->tx_packets = 0;
        kni_stat[port_id]->tx_dropped = 0;

        /* Get the interface default mac address. A future owner reads it
         * and stores the virtio port id below so kni_process_tx() can
         * burst to the right port once this generation is activated. */
        rte_eth_macaddr_get(port_id,
                (struct rte_ether_addr *)&addr);
        printf("ff_kni_alloc get Port %u MAC:"RTE_ETHER_ADDR_PRT_FMT"\n",
            (unsigned)port_id, RTE_ETHER_ADDR_BYTES(&addr));

        /*
         * to add virtio port for exception path(KNI),
         * see https://doc.dpdk.org/guides/howto/virtio_user_as_exception_path.html#virtio-user-as-exception-path
         */
        char port_name[32];
        char port_args[256];

        /* set the name and arguments */
        snprintf(port_name, sizeof(port_name), "virtio_user%u", port_id);
        snprintf(port_args, sizeof(port_args),
            "path=/dev/vhost-net,queues=1,queue_size=%u,iface=veth%d,mac=" RTE_ETHER_ADDR_PRT_FMT,
            ring_queue_size, port_id, RTE_ETHER_ADDR_BYTES(&addr));
        printf("ff_kni_alloc to rte_eal_hotplug_add virtio user port, portname:%s, portargs:%s\n",
            port_name, port_args);

        /* add the vdev for virtio_user */
        if (ff_kni_is_owner_thread() &&
            rte_eal_hotplug_add("vdev", port_name, port_args) < 0) {
            rte_exit(EXIT_FAILURE, "ff_kni_alloc cannot create virtio user paired port for port %u\n", port_id);
        }

        kni_stat[port_id]->port_id = port_idx + nb_dev_ports;
    }

    char ring_name[RTE_KNI_NAMESIZE];
    snprintf((char*)ring_name, RTE_KNI_NAMESIZE, "kni_ring_%u", port_id);

    if (ff_kni_is_owner_thread()) {
        kni_rp[port_id] = rte_ring_create(ring_name, ring_queue_size,
            socket_id, RING_F_SC_DEQ);

        if (rte_ring_lookup(ring_name) != kni_rp[port_id])
            rte_panic("lookup kni ring failed!\n");
    } else {
        kni_rp[port_id] = rte_ring_lookup(ring_name);
    }

    if (kni_rp[port_id] == NULL)
        rte_panic("create kni ring failed!\n");

    printf("create kni ring success, %u ring entries are now free!\n",
        rte_ring_free_count(kni_rp[port_id]));

    char inject_ring_name[RTE_KNI_NAMESIZE];
    snprintf((char*)inject_ring_name, RTE_KNI_NAMESIZE, "kni_inject_%u", port_id);

    if (ff_kni_is_owner_thread()) {
        kni_inject_rp[port_id] = rte_ring_create(inject_ring_name, ring_queue_size,
            socket_id, RING_F_SC_DEQ);

        if (rte_ring_lookup(inject_ring_name) != kni_inject_rp[port_id])
            rte_panic("lookup kni inject ring failed!\n");
    } else {
        kni_inject_rp[port_id] = rte_ring_lookup(inject_ring_name);
    }

    if (kni_inject_rp[port_id] == NULL)
        rte_panic("create kni inject ring failed!\n");
}

void
ff_kni_process(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    kni_process_tx(port_id, queue_id, pkts_burst, count);
    kni_process_rx(port_id, queue_id, pkts_burst, count);
}

int
ff_kni_enqueue(enum FilterReturn filter, uint16_t port_id, struct rte_mbuf *pkt)
{
    if (filter >= FILTER_ARP) {
        if (ff_global_cfg.kni.console_packets_ratelimit) {
            kni_rate_limt.console_packets++;
            if (kni_rate_limt.console_packets > (uint64_t)ff_global_cfg.kni.console_packets_ratelimit) {
                goto error;
            }
        }
    } else {
        if (ff_global_cfg.kni.general_packets_ratelimit) {
            kni_rate_limt.gerneal_packets++;
            if (kni_rate_limt.gerneal_packets > (uint64_t)ff_global_cfg.kni.general_packets_ratelimit) {
                goto error;
            }
        }
    }

    int ret = rte_ring_enqueue(kni_rp[port_id], pkt);
    if (ret < 0) {
        goto error;
    }

    return 0;

error:
    if (ff_kni_is_owner_thread() || ff_kni_is_runtime_owner()) {
        kni_stat[port_id]->rx_dropped++;
    }
    rte_pktmbuf_free(pkt);

    return -1;
}
