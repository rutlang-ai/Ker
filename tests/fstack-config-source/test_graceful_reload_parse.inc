static void
test_graceful_reload_parse(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("valid_graceful_reload.ini"),
                            "secondary", "0");
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.graceful_reload, 1);
    assert_int_equal(ff_global_cfg.dpdk.primary_slim, 1);
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 3);
}
