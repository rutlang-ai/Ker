static void
test_p1_kni_stats_oom(void **state)
{
    (void)state;
    p1_oom = "kni:stat";
    expect_assert_failure(ff_kni_init(1, NULL, NULL));
    assert_null(kni_stat);
}
