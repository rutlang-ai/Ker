static void
test_ff_load_config_stack_coexist_enabled(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_stack_kernel.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.stack.kernel_coexist, 1);
}
