static void
test_ff_check_config_kni_method_reject_ok(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_kni_method_reject.ini"));
    assert_int_equal(rv, 0);
    assert_string_equal(ff_global_cfg.kni.method, "reject");
}
