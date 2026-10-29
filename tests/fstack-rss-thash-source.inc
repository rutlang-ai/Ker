static const uint8_t test_rsskey_40[40] = {
    0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b,
    0x19, 0x83, 0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb,
    0xd9, 0x38, 0x9e, 0x6b, 0xd1, 0x03, 0x9c, 0x2c,
    0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d, 0x56, 0xd9,
    0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc
};

/* Equivalent Toeplitz hash — byte-for-byte aligned with the lib's static
 * toeplitz_hash (ff_dpdk_if.c:2548-2568). */
static uint32_t
test_toeplitz(unsigned keylen, const uint8_t *key,
              unsigned datalen, const uint8_t *data)
{
    uint32_t hash = 0, v;
    unsigned i, b;
    v = ((uint32_t)key[0] << 24) + ((uint32_t)key[1] << 16) +
        ((uint32_t)key[2] << 8) + key[3];
    for (i = 0; i < datalen; i++) {
        for (b = 0; b < 8; b++) {
            if (data[i] & (1 << (7 - b)))
                hash ^= v;
            v <<= 1;
            if ((i + 4) < keylen && (key[i + 4] & (1 << (7 - b))))
                v |= 1;
        }
    }
    return hash;
}

/* Independent replica of ff_rss_check()'s verdict for v4 (ff_dpdk_if.c:2851).
 * data layout = saddr(4)|daddr(4)|sport(2)|dport(2) (network-order values as
 * stored, matching the lib's bcopy of the raw 32/16-bit quantities). */
static int
test_expected_rss_check(uint32_t saddr, uint32_t daddr, uint16_t sport,
                        uint16_t dport, uint16_t nb_queues,
                        uint16_t reta_size, uint16_t queueid)
{
    uint8_t data[sizeof(saddr) + sizeof(daddr) + sizeof(sport) + sizeof(dport)];
    unsigned dl = 0;
    uint32_t hash;
    if (nb_queues <= 1)
        return 1;
    memcpy(&data[dl], &saddr, sizeof(saddr)); dl += sizeof(saddr);
    memcpy(&data[dl], &daddr, sizeof(daddr)); dl += sizeof(daddr);
    memcpy(&data[dl], &sport, sizeof(sport)); dl += sizeof(sport);
    memcpy(&data[dl], &dport, sizeof(dport)); dl += sizeof(dport);
    hash = test_toeplitz(sizeof(test_rsskey_40), test_rsskey_40, dl, data);
    return ((hash & (uint16_t)(reta_size - 1)) % nb_queues) == queueid;
}

/* Independent replica of ff_rss_check6()'s verdict for v6 (ff_dpdk_if.c:3117).
 * data layout = saddr6(16)|daddr6(16)|sport(2)|dport(2) = 36B, host byte order,
 * same toeplitz/key/reta口径 as v4. */
static int
test_expected_rss_check6(const uint8_t saddr6[16], const uint8_t daddr6[16],
                         uint16_t sport, uint16_t dport, uint16_t nb_queues,
                         uint16_t reta_size, uint16_t queueid)
{
    uint8_t data[16 + 16 + sizeof(sport) + sizeof(dport)];
    unsigned dl = 0;
    uint32_t hash;
    if (nb_queues <= 1)
        return 1;
    memcpy(&data[dl], saddr6, 16); dl += 16;
    memcpy(&data[dl], daddr6, 16); dl += 16;
    memcpy(&data[dl], &sport, sizeof(sport)); dl += sizeof(sport);
    memcpy(&data[dl], &dport, sizeof(dport)); dl += sizeof(dport);
    hash = test_toeplitz(sizeof(test_rsskey_40), test_rsskey_40, dl, data);
    return ((hash & (uint16_t)(reta_size - 1)) % nb_queues) == queueid;
}


#define EQUIV_N        200
#define EQUIV_NBQ      4
#define EQUIV_QID      1

/* M4 Batch C (thash flaky hardening): the test tuples are already
 * srandom()-fixed, but rte_thash_add_helper() seeds its LFSR/polynomial
 * from rte_rand() and overwrites the helper's bit range of the hash key
 * with that m-sequence — and rte_eal_init() seeds rte_rand from the
 * TSC, so the key rewrite (hence the adjusted sports and the measured
 * landing rates) differed per process run. That was the observed flaky
 * failure (reta=128 full-loop landing ~100/200 instead of 200/200).
 * Re-seeding the DPDK PRNG right before every ctx creation makes the
 * key rewrite and the whole equivalence run reproducible; assertions
 * keep their original strength (100% full-loop landing). */
#define EQUIV_THASH_SEED  0x5EEDBEEFu

static int
equiv_log2(uint16_t v)
{
    int l = 0;
    while ((v >>= 1) != 0) l++;
    return l;
}


static void
run_equiv_for_reta(const char *ctx_name, uint16_t reta_size,
                   int *adj_ok, int *single_hit, int *final_ok,
                   double *avg_tries)
{
    struct rte_thash_ctx *ctx;
    struct rte_thash_subtuple_helper *h;
    int i, ok = 0, hit = 0, fok = 0;
    long tries_total = 0;
    const uint16_t nbq = EQUIV_NBQ, qid = EQUIV_QID;
    const uint32_t span = (reta_size + nbq - 1) / nbq;

    rte_srand(EQUIV_THASH_SEED ^ reta_size);   /* reproducible key m-seq */
    ctx = rte_thash_init_ctx(ctx_name, sizeof(test_rsskey_40),
                             equiv_log2(reta_size), (uint8_t *)test_rsskey_40, 0);
    /* key_len is in BYTES (lib passes rsskey_len=40); reta_sz is log2. */
    assert_non_null(ctx);
    /* helper len/offset are in BITS (mirror lib: 16 @ 64; len >= reta_sz). */
    assert_int_equal(rte_thash_add_helper(ctx, "sport", 16, 64), 0);
    h = rte_thash_get_helper(ctx, "sport");
    assert_non_null(h);

    srandom(0xC0FFEE ^ reta_size);   /* deterministic, reproducible numbers */
    for (i = 0; i < EQUIV_N; i++) {
        uint32_t saddr = ((uint32_t)random() << 1) ^ (uint32_t)random();
        uint32_t daddr = ((uint32_t)random() << 1) ^ (uint32_t)random();
        uint16_t dport = htons((uint16_t)(1024 + (random() % 60000)));
        uint32_t desired = qid + ((uint32_t)random() % span) * nbq;
        int found = 0, first_cand = 1;
        uint32_t tr;
        if (desired >= reta_size) desired = qid;

        for (tr = 0; tr < span; tr++) {
            uint16_t sport = 0;
            uint8_t tuple[12];
            if (desired >= reta_size) desired = qid;
            memset(tuple, 0, sizeof(tuple));
            memcpy(&tuple[0], &saddr, 4);
            memcpy(&tuple[4], &daddr, 4);
            memcpy(&tuple[8], &sport, 2);     /* sport seed 0 @ byte 8 */
            memcpy(&tuple[10], &dport, 2);    /* dport @ byte 10        */
            tries_total++;

            if (rte_thash_adjust_tuple(ctx, h, tuple, sizeof(tuple),
                                       desired & (reta_size - 1), 16,
                                       NULL, NULL) == 0) {
                if (first_cand) ok++;        /* per-candidate adjust success */
                memcpy(&sport, &tuple[8], 2);
                /* Re-verify with the lib's soft Toeplitz (host-order tuple,
                 * same as ff_rss_check). */
                int landed = test_expected_rss_check(saddr, daddr, sport, dport,
                                                     nbq, reta_size, qid);
                if (first_cand && landed) hit++;  /* per-candidate equivalence */
                if (landed) {
                    /* zero false positives: self-consistency must hold. */
                    uint8_t d[12];
                    unsigned dl = 0;
                    memcpy(&d[dl], &saddr, 4); dl += 4;
                    memcpy(&d[dl], &daddr, 4); dl += 4;
                    memcpy(&d[dl], &sport, 2); dl += 2;
                    memcpy(&d[dl], &dport, 2); dl += 2;
                    uint32_t hh = test_toeplitz(sizeof(test_rsskey_40),
                                                test_rsskey_40, dl, d);
                    assert_int_equal(((hh & (reta_size - 1)) % nbq), qid);
                    found = 1;
                    break;                    /* full-loop: first landing wins */
                }
            }
            first_cand = 0;
            desired += nbq;
        }
        if (found) fok++;
    }

    rte_thash_free_ctx(ctx);
    *adj_ok = ok;
    *single_hit = hit;
    *final_ok = fok;
    *avg_tries = (double)tries_total / EQUIV_N;
}

static void
test_ff_rss_thash_equivalence_hitrate(void **state)
{
    (void)state;
    if (equiv_eal_init_once() < 0) {
        printf("\n[R-B 0.3 EQUIV] DPDK EAL init failed in unit env; skipping "
               "thash equivalence quantification.\n");
        skip();
        return;
    }

    int adj128 = 0, sh128 = 0, fok128 = 0, adj512 = 0, sh512 = 0, fok512 = 0;
    double avg128 = 0, avg512 = 0;
    run_equiv_for_reta("ff_equiv_128", 128, &adj128, &sh128, &fok128, &avg128);
    run_equiv_for_reta("ff_equiv_512", 512, &adj512, &sh512, &fok512, &avg512);

    printf("\n[R-B 0.3 EQUIV] N=%d nbq=%d qid=%d key=40B(default_rsskey)\n",
           EQUIV_N, EQUIV_NBQ, EQUIV_QID);
    printf("[R-B 0.3 EQUIV] reta=128: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj128, EQUIV_N, 100.0 * adj128 / EQUIV_N,
           sh128, EQUIV_N, 100.0 * sh128 / EQUIV_N,
           fok128, EQUIV_N, 100.0 * fok128 / EQUIV_N, avg128, (128 + EQUIV_NBQ - 1) / EQUIV_NBQ);
    printf("[R-B 0.3 EQUIV] reta=512: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj512, EQUIV_N, 100.0 * adj512 / EQUIV_N,
           sh512, EQUIV_N, 100.0 * sh512 / EQUIV_N,
           fok512, EQUIV_N, 100.0 * fok512 / EQUIV_N, avg512, (512 + EQUIV_NBQ - 1) / EQUIV_NBQ);

    /* Rates are DATA for the leader's go/no-go (07 §1.3, no hard threshold).
     * Hard quality gate: the full reverse-calc loop must reliably land on the
     * target queue (this is what ff_rss_adjust_sport guarantees via its forced
     * ff_rss_check re-verify); zero false positives is asserted inline above. */
    assert_true(adj128 > 0);
    assert_true(adj512 > 0);
    assert_int_equal(fok128, EQUIV_N);   /* full loop lands 100% (zero tolerance) */
    assert_int_equal(fok512, EQUIV_N);
}

static void
run_equiv6_for_reta(const char *ctx_name, uint16_t reta_size,
                    int *adj_ok, int *single_hit, int *final_ok,
                    double *avg_tries)
{
    struct rte_thash_ctx *ctx;
    struct rte_thash_subtuple_helper *h;
    int i, ok = 0, hit = 0, fok = 0;
    long tries_total = 0;
    const uint16_t nbq = EQUIV_NBQ, qid = EQUIV_QID;
    const uint32_t span = (reta_size + nbq - 1) / nbq;

    rte_srand(EQUIV_THASH_SEED ^ reta_size);   /* reproducible key m-seq */
    ctx = rte_thash_init_ctx(ctx_name, sizeof(test_rsskey_40),
                             equiv_log2(reta_size), (uint8_t *)test_rsskey_40, 0);
    assert_non_null(ctx);
    /* v6 helper: len 16 bits @ offset 256 bits (mirror lib FF_RSS_THASH_V6). */
    assert_int_equal(rte_thash_add_helper(ctx, "sport6", 16, 256), 0);
    h = rte_thash_get_helper(ctx, "sport6");
    assert_non_null(h);

    srandom(0xBADC0DE ^ reta_size);   /* deterministic, reproducible */
    for (i = 0; i < EQUIV_N; i++) {
        uint8_t saddr6[16], daddr6[16];
        for (int b = 0; b < 16; b++) { saddr6[b] = random() & 0xff; daddr6[b] = random() & 0xff; }
        uint16_t dport = htons((uint16_t)(1024 + (random() % 60000)));
        uint32_t desired = qid + ((uint32_t)random() % span) * nbq;
        int found = 0, first_cand = 1;
        uint32_t tr;
        if (desired >= reta_size) desired = qid;

        for (tr = 0; tr < span; tr++) {
            uint16_t sport = 0;
            uint8_t tuple[36];
            if (desired >= reta_size) desired = qid;
            memset(tuple, 0, sizeof(tuple));
            memcpy(&tuple[0], saddr6, 16);
            memcpy(&tuple[16], daddr6, 16);
            memcpy(&tuple[32], &sport, 2);    /* sport seed 0 @ byte 32 */
            memcpy(&tuple[34], &dport, 2);    /* dport @ byte 34        */
            tries_total++;

            if (rte_thash_adjust_tuple(ctx, h, tuple, sizeof(tuple),
                                       desired & (reta_size - 1), 16,
                                       NULL, NULL) == 0) {
                if (first_cand) ok++;
                memcpy(&sport, &tuple[32], 2);
                int landed = test_expected_rss_check6(saddr6, daddr6, sport, dport,
                                                      nbq, reta_size, qid);
                if (first_cand && landed) hit++;
                if (landed) {
                    /* zero false positive: independent recompute must agree. */
                    uint8_t d[36];
                    unsigned dl = 0;
                    memcpy(&d[dl], saddr6, 16); dl += 16;
                    memcpy(&d[dl], daddr6, 16); dl += 16;
                    memcpy(&d[dl], &sport, 2); dl += 2;
                    memcpy(&d[dl], &dport, 2); dl += 2;
                    uint32_t hh = test_toeplitz(sizeof(test_rsskey_40),
                                                test_rsskey_40, dl, d);
                    assert_int_equal(((hh & (reta_size - 1)) % nbq), qid);
                    found = 1;
                    break;
                }
            }
            first_cand = 0;
            desired += nbq;
        }
        if (found) fok++;
    }

    rte_thash_free_ctx(ctx);
    *adj_ok = ok;
    *single_hit = hit;
    *final_ok = fok;
    *avg_tries = (double)tries_total / EQUIV_N;
}

static void
test_ff_rss_thash6_equivalence_hitrate(void **state)
{
    (void)state;
    if (equiv_eal_init_once() < 0) {
        printf("\n[R-C 0.2 EQUIV6] DPDK EAL init failed in unit env; skipping.\n");
        skip();
        return;
    }

    int adj128 = 0, sh128 = 0, fok128 = 0, adj512 = 0, sh512 = 0, fok512 = 0;
    double avg128 = 0, avg512 = 0;
    run_equiv6_for_reta("ff_equiv6_128", 128, &adj128, &sh128, &fok128, &avg128);
    run_equiv6_for_reta("ff_equiv6_512", 512, &adj512, &sh512, &fok512, &avg512);

    printf("\n[R-C 0.2 EQUIV6] N=%d nbq=%d qid=%d key=40B v6-tuple=36B sport@256bit\n",
           EQUIV_N, EQUIV_NBQ, EQUIV_QID);
    printf("[R-C 0.2 EQUIV6] reta=128: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj128, EQUIV_N, 100.0 * adj128 / EQUIV_N,
           sh128, EQUIV_N, 100.0 * sh128 / EQUIV_N,
           fok128, EQUIV_N, 100.0 * fok128 / EQUIV_N, avg128, (128 + EQUIV_NBQ - 1) / EQUIV_NBQ);
    printf("[R-C 0.2 EQUIV6] reta=512: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj512, EQUIV_N, 100.0 * adj512 / EQUIV_N,
           sh512, EQUIV_N, 100.0 * sh512 / EQUIV_N,
           fok512, EQUIV_N, 100.0 * fok512 / EQUIV_N, avg512, (512 + EQUIV_NBQ - 1) / EQUIV_NBQ);

    assert_true(adj128 > 0);
    assert_true(adj512 > 0);
    assert_int_equal(fok128, EQUIV_N);   /* v6 full loop lands 100% (zero tolerance) */
    assert_int_equal(fok512, EQUIV_N);
}
