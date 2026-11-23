static void
test_ff_dpdk_if_send_null_ctx_with_mbuf(void **state)
{
    (void)state;
    /* Non-NULL m: the guard must call ff_mbuf_free(m) before returning -1.
     * Our local stub ff_mbuf_free is a no-op, so we just verify the call
     * doesn't crash and the return is -1. */
    int dummy_mbuf = 0xCAFE;
    int rv = ff_dpdk_if_send(NULL, &dummy_mbuf, 100);
    assert_int_equal(rv, -1);
}
