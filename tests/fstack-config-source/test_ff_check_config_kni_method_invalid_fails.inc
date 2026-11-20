static void
test_ff_check_config_kni_method_invalid_fails(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_kni_method_bad.ini"));
    assert_int_equal(rv, -1);
}
