static void
test_p1_kni_slot_oom(void **state)
{
    (void)state;
    ff_kni_init(1, NULL, NULL);
    assert_non_null(kni_stat);
    p1_oom = "kni:stat_lcore";
    expect_assert_failure(ff_kni_alloc(0, 0, 0, 16));
    assert_null(kni_stat[0]);
    assert_int_equal(p1_hotplug, 0);
}
