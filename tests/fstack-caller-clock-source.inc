static void
test_ut_nr_17_hardclock_interval(void **state)
{
    (void)state;
    /* hz=100 on a 1 GHz TSC: 10 ms -> 10,000,000 ticks */
    assert_int_equal(ff_hardclock_interval_tsc(1000000000ULL, 100),
                     10000000ULL);
    /* hz=1000 on 2.5 GHz: 1 ms -> 2,500,000 ticks */
    assert_int_equal(ff_hardclock_interval_tsc(2500000000ULL, 1000),
                     2500000ULL);
    /* ceil term: 2.999999 GHz -> 3000 ticks/us, hz=100 -> 30,000,000 */
    assert_int_equal(ff_hardclock_interval_tsc(2999999000ULL, 100),
                     30000000ULL);
    /* legacy-formula equivalence across hz decades (US_PER_S % hz == 0) */
    for (unsigned hz = 1; hz <= 1000000; hz *= 10) {
        uint64_t timer_hz = 2600000000ULL;
        uint64_t legacy =
            (timer_hz + US_PER_S - 1) / US_PER_S * (US_PER_S / hz);
        assert_int_equal(ff_hardclock_interval_tsc(timer_hz, hz), legacy);
    }
    /* degenerate hz: 0 and > US_PER_S yield 0 (caller rte_exit()s) */
    assert_int_equal(ff_hardclock_interval_tsc(1000000000ULL, 0), 0);
    assert_int_equal(ff_hardclock_interval_tsc(1000000000ULL, US_PER_S + 1), 0);
}
