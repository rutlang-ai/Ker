static void
test_graceful_reload_requires_slim(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_greload_no_slim.ini"));
    assert_int_equal(rv, -1);
}
