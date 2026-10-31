static void
test_ut_nr_20_queue_mapping_config(void **state)
{
    (void)state;
    int rv;
    uint16_t portid;

    /* legal: graceful topology, N stays N */
    rv = load_with_proc(FIXTURE_PATH("valid_graceful_reload.ini"),
                        "secondary", "0");
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 3);       /* NOT 6 */
    portid = ff_global_cfg.dpdk.portid_list[0];
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[portid].nb_lcores, 2);
                                                            /* NOT 4 */
    /* default heartbeat timeout when the key is absent */
    assert_int_equal(ff_global_cfg.dpdk.reload_heartbeat_timeout_ms, 1000);

    /* explicit heartbeat timeout parses */
    rv = load_with_proc(FIXTURE_PATH("valid_greload_hb_timeout.ini"),
                        "secondary", "0");
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.reload_heartbeat_timeout_ms, 250);

    /* below-floor heartbeat timeout is rejected */
    rv = load_with_fixture(FIXTURE_PATH("invalid_greload_hb_small.ini"));
    assert_int_equal(rv, -1);

    /* negative heartbeat timeout is remapped to the default, never a huge
     * unsigned value that would silently disable stall detection (P3-1) */
    rv = load_with_fixture(FIXTURE_PATH("valid_greload_hb_negative.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.reload_heartbeat_timeout_ms, 1000);

    /* illegal graceful topology still rejected (fixture from M1) */
    rv = load_with_fixture(FIXTURE_PATH("invalid_greload_no_slim.ini"));
    assert_int_equal(rv, -1);

    /* graceful_reload=0: zero regression, defaults intact */
    rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_full.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.graceful_reload, 0);
    assert_int_equal(ff_global_cfg.dpdk.reload_heartbeat_timeout_ms, 1000);
}
