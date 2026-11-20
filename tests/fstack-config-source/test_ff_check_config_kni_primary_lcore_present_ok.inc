static void
test_ff_check_config_kni_primary_lcore_present_ok(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("valid_kni_primary_lcore_ok.ini"),
                            "primary", "0");
    assert_int_equal(rv, 0);
}
