static void
test_ff_load_config_thread_mode_secondary_conflict(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("valid_thread_mode.ini"),
                            "secondary", "0");
    assert_int_equal(rv, -1);
}
