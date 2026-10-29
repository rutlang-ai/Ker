static void
test_ff_rss_tbl_get_portrange_smoke(void **state)
{
    (void)state;
    struct ff_rss_check_cfg dummy = { .enable = 1 };
    ff_global_cfg.dpdk.rss_check_cfgs = &dummy;
    uint16_t first = 0, last = 0;
    uint16_t *portrange = NULL;
    int rv = ff_rss_tbl_get_portrange(0xDEADBEEF, 0xCAFEBABE, htons(80),
                                      &first, &last, &portrange);
    /* Just verify the function ran without crashing. The return value
     * depends on the global ff_rss_tbl state which we don't control here. */
    (void)rv;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}
