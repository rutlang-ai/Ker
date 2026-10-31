static void
test_ff_dpdk_if_send_copydata_fail(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    g_copydata_fail = 1;
    void *ctx = ff_test_register(0);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, 128);
    assert_int_equal(rv, -1);
    ff_dpdk_deregister_if(ctx);
}
