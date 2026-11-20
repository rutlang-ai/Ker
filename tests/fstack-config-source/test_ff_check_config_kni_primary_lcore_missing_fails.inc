static void
test_ff_check_config_kni_primary_lcore_missing_fails(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("invalid_kni_primary_lcore_missing.ini"),
                            "primary", "0");
    assert_int_equal(rv, -1);
}
