static void
test_ff_load_config_stack_garbage_defaults_disabled(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_stack_garbage.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.stack.kernel_coexist, 0);
}
