static void
test_ff_load_config_freebsd_boot_multi_entries(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_freebsd_boot.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.freebsd.hz, 200);
    /* Walk the boot/sysctl chains; at least 1 entry should be present. */
    int nboot = 0;
    for (struct ff_freebsd_cfg *p = ff_global_cfg.freebsd.boot; p; p = p->next) {
        nboot++;
    }
    int nsysctl = 0;
    for (struct ff_freebsd_cfg *p = ff_global_cfg.freebsd.sysctl; p; p = p->next) {
        nsysctl++;
    }
    /* boot has panicstr (string-typed), sysctl has 5 entries above. */
    assert_true(nboot >= 1);
    assert_int_equal(nsysctl, 5);
}
