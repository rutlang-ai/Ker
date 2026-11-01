extern int __real_ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
                               uint16_t sport, uint16_t dport);
extern int __real_ff_rss_check6(void *softc, const uint8_t *saddr6,
                                const uint8_t *daddr6, uint16_t sport,
                                uint16_t dport);

static uint64_t g_ff_rss_check_calls;
static uint64_t g_ff_rss_check6_calls;

int
__wrap_ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
                    uint16_t sport, uint16_t dport)
{
    g_ff_rss_check_calls++;
    return __real_ff_rss_check(softc, saddr, daddr, sport, dport);
}

int
__wrap_ff_rss_check6(void *softc, const uint8_t *saddr6, const uint8_t *daddr6,
                     uint16_t sport, uint16_t dport)
{
    g_ff_rss_check6_calls++;
    return __real_ff_rss_check6(softc, saddr6, daddr6, sport, dport);
}
