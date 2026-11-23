static void
test_ut_nr_12_generation_mapping(void **state)
{
    (void)state;
    char n1[64], n2[64];
    uint16_t lcore_before[3];
    int i, rv;

    /* (a) gen isolation on names */
    assert_int_equal(ff_reload_msg_ring_name(n1, sizeof(n1),
        "ff_msg_ring_in_", 1, -1, 0, 1), 0);
    assert_int_equal(ff_reload_msg_ring_name(n2, sizeof(n2),
        "ff_msg_ring_in_", 1, -1, 1, 1), 0);
    assert_string_equal(n1, "ff_msg_ring_in_1_g0");
    assert_string_equal(n2, "ff_msg_ring_in_1_g1");
    assert_string_not_equal(n1, n2);

    assert_int_equal(ff_reload_msg_ring_name(n1, sizeof(n1),
        "ff_msg_ring_in_", 0, -1, 0, 1), 0);
    assert_int_equal(ff_reload_msg_ring_name(n2, sizeof(n2),
        "ff_msg_ring_in_", 1, -1, 0, 1), 0);
    assert_string_not_equal(n1, n2);

    /* out-ring with msg_type keeps the "<base><proc>_<type>" legacy shape */
    assert_int_equal(ff_reload_msg_ring_name(n1, sizeof(n1),
        "ff_msg_ring_out_", 1, 3, 0, 1), 0);
    assert_string_equal(n1, "ff_msg_ring_out_1_3_g0");

    /* (b) graceful=0 names are byte-identical to the pre-change layout */
    assert_int_equal(ff_reload_msg_ring_name(n1, sizeof(n1),
        "ff_msg_ring_in_", 1, -1, 0, 0), 0);
    assert_string_equal(n1, "ff_msg_ring_in_1");
    assert_int_equal(ff_reload_msg_ring_name(n1, sizeof(n1),
        "ff_msg_ring_out_", 1, 3, 0, 0), 0);
    assert_string_equal(n1, "ff_msg_ring_out_1_3");

    /* truncation is an error */
    assert_int_equal(ff_reload_msg_ring_name(n1, 8,
        "ff_msg_ring_in_", 1, -1, 0, 1), -1);

    /* (c) generation switching never touches the proc_id mapping */
    rv = load_with_proc(FIXTURE_PATH("valid_graceful_reload.ini"),
                        "secondary", "1");
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 3);
    for (i = 0; i < 3; i++) {
        lcore_before[i] = ff_global_cfg.dpdk.proc_lcore[i];
    }

    ff_reload_set_gen(0);
    assert_int_equal(ff_reload_gen(), 0);
    for (i = 0; i < 3; i++) {
        assert_int_equal(ff_global_cfg.dpdk.proc_lcore[i], lcore_before[i]);
    }
    ff_reload_set_gen(1);
    assert_int_equal(ff_reload_gen(), 1);
    for (i = 0; i < 3; i++) {
        assert_int_equal(ff_global_cfg.dpdk.proc_lcore[i], lcore_before[i]);
    }

    /* out-of-range generation is ignored */
    ff_reload_set_gen(FF_RELOAD_GEN_MAX);
    assert_int_equal(ff_reload_gen(), 1);
    ff_reload_set_gen(-1);
    assert_int_equal(ff_reload_gen(), 1);

    assert_int_equal(FF_RELOAD_GEN_MAX, 2);
    ff_reload_attach_state(NULL);
}
