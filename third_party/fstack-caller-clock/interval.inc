uint64_t
ff_hardclock_interval_tsc(uint64_t timer_hz, unsigned int bsd_hz)
{
    uint64_t intrs;

    if (bsd_hz == 0 || bsd_hz > US_PER_S)
        return 0;
    intrs = US_PER_S / bsd_hz;
    return (timer_hz + US_PER_S - 1) / US_PER_S * intrs;
}
