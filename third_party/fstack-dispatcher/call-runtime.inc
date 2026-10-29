            if (packet_dispatcher) {
                cur_tsc = rte_rdtsc();
                ret = (*packet_dispatcher)(data, &len, queue_id, nb_queues);
                usr_cb_tsc += rte_rdtsc() - cur_tsc;
            } else if (packet_dispatcher_with_context) {
                struct ff_dispatcher_context ctx;
                if (rtem->ol_flags & RTE_MBUF_F_RX_VLAN_STRIPPED) {
                    ctx.vlan.stripped = 1;
                    ctx.vlan.vlan_tci = rte_cpu_to_be_16(rtem->vlan_tci);
                } else {
                   ctx.vlan.stripped = 0;
                   ctx.vlan.vlan_tci = 0;
                }
                cur_tsc = rte_rdtsc();
                ret = (*packet_dispatcher_with_context)(data, &len, queue_id, nb_queues, ctx);
                usr_cb_tsc += rte_rdtsc() - cur_tsc;
            }
