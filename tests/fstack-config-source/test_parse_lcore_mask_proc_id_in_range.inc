static void
test_parse_lcore_mask_proc_id_in_range(void **state)
{
    (void)state;
    /* lcore_mask=0x3 -> 2 procs; proc_id=1 is valid (last). */
    int rv = load_with_proc(FIXTURE_PATH("valid_lcore_blank_multibit.ini"),
                            "primary", "1");
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.proc_id, 1);
    assert_non_null(ff_global_cfg.dpdk.proc_mask);
}
