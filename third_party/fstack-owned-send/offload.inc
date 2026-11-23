struct ff_tx_offload {
    uint8_t ip_csum;
    uint8_t tcp_csum;
    uint8_t udp_csum;
    uint8_t sctp_csum;
    uint16_t tso_seg_size;
};
