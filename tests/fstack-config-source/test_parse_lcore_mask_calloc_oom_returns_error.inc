static void
test_parse_lcore_mask_calloc_oom_returns_error(void **state)
{
    (void)state;
    g_calloc_fail_after = 1;     /* fail the 1st calloc (proc_lcore) */
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    g_calloc_fail_after = 0;     /* disarm */
    assert_int_equal(rv, -1);
}
