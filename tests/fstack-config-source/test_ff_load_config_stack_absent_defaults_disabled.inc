static void
test_ff_load_config_stack_absent_defaults_disabled(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.stack.kernel_coexist, 0);
}
