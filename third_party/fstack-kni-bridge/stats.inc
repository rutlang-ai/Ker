struct kni_interface_stats {
    /* port id of dev or virtio_user */
    uint16_t port_id;

    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;

    /* number of pkts received from NIC, but failed to send to KNI or kni_ring */
    uint64_t rx_dropped;

    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;

    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;
};
