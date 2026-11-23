static void
test_ff_load_config_all_sections(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_all_sections.ini"));
    (void)rv;
    /* dpdk fields */
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_int_equal(ff_global_cfg.dpdk.nb_channel,  4);
    assert_int_equal(ff_global_cfg.dpdk.memory,      128);
    assert_int_equal(ff_global_cfg.dpdk.tso,         0);
    assert_int_equal(ff_global_cfg.dpdk.lro,         0);
    assert_int_equal(ff_global_cfg.dpdk.symmetric_rss, 1);
    assert_int_equal(ff_global_cfg.dpdk.idle_sleep, 20);
    /* kni section parsed */
    assert_int_equal(ff_global_cfg.kni.enable, 1);
    assert_non_null(ff_global_cfg.kni.method);
    /* pcap section parsed (timestamp_precision = 0 default still 0; but
     * snap_len/save_path should be populated) */
    assert_non_null(ff_global_cfg.pcap.save_path);
    /* freebsd boot/sysctl sections allocate cfg pointers */
    /* ff_freebsd_cfg *boot is populated by freebsd_conf_handler when [freebsd.boot]
     * lines arrive; non-NULL after parse. */
    assert_non_null(ff_global_cfg.freebsd.boot);
    assert_non_null(ff_global_cfg.freebsd.sysctl);
}
