static void
test_vdev_cfgs_calloc_oom_returns_error(void **state)
{
    (void)state;
    g_calloc_fail_after = 3;
    int rv = load_with_fixture(FIXTURE_PATH("valid_vdev.ini"));
    g_calloc_fail_after = 0;
    assert_int_equal(rv, -1);
}
