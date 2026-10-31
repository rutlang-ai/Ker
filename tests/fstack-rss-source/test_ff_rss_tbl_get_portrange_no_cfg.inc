static void
test_ff_rss_tbl_get_portrange_no_cfg(void **state)
{
    (void)state;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
    uint16_t first = 0, last = 0;
    uint16_t *portrange = NULL;
    int rv = ff_rss_tbl_get_portrange(0x01020304, 0x05060708, htons(80),
                                      &first, &last, &portrange);
    assert_int_equal(rv, -1);
}
