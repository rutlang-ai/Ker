static void
test_greload_thread_mode_mutex(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_greload_thread_mode.ini"));
    assert_int_equal(rv, -1);
}
