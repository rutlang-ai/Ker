static int
fake_dispatcher(void *data, uint16_t *len, uint16_t queue_id, uint16_t nb_queues)
{
    (void)data; (void)len; (void)queue_id; (void)nb_queues;
    return 0;
}

static int
fake_dispatcher_ctx(void *data, uint16_t *len, uint16_t queue_id,
                    uint16_t nb_queues, struct ff_dispatcher_context ctx)
{
    (void)data; (void)len; (void)queue_id; (void)nb_queues; (void)ctx;
    return 0;
}

static void
test_ff_regist_packet_dispatcher_smoke(void **state)
{
    (void)state;
    ff_regist_packet_dispatcher(fake_dispatcher);
    ff_regist_packet_dispatcher(NULL);
}

static void
test_ff_regist_packet_dispatcher_context_smoke(void **state)
{
    (void)state;
    ff_regist_packet_dispatcher_context(fake_dispatcher_ctx);
    ff_regist_packet_dispatcher_context(NULL);
}

static void
test_ut_nr_24_unregist_dispatcher(void **state)
{
    (void)state;

    ff_unregist_packet_dispatcher();
    ff_unregist_packet_dispatcher();
    ff_unregist_packet_dispatcher_context();
    ff_unregist_packet_dispatcher_context();

    /* re-register / unregister round-trip must not wedge the pointers */
    ff_regist_packet_dispatcher(NULL);
    ff_regist_packet_dispatcher_context(NULL);
    ff_unregist_packet_dispatcher();
    ff_unregist_packet_dispatcher_context();
}
