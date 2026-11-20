static void
test_ut_nr_23_flow_map(void **state)
{
    struct ff_reload_state st;
    ff_flow_key_t k, k2;

    (void)state;

    /* the FreeBSD side builds the same struct; a layout drift would silently
     * corrupt every key, so pin it. */
    assert_int_equal((int)sizeof(ff_flow_key_t), 40);

    memset(&k, 0, sizeof(k));
    k.af = FF_FLOW_MAP_V4;
    k.src[0] = 0x0a000001;
    k.dst[0] = 0x0a000002;
    k.sport = 0x1234;
    k.dport = 0x0050;

    /* graceful_reload=0: recording is a no-op and lookup always misses */
    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_reload_attach_state(NULL);
    ff_flow_map_close();
    assert_int_equal(ff_flow_map_active(), 0);
    assert_int_equal(ff_flow_map_insert(&k), -1);
    assert_int_equal(ff_flow_map_lookup(&k), 0);

    /* graceful_reload=1 but no shared block (non-nginx app): still off */
    ff_global_cfg.dpdk.graceful_reload = 1;
    assert_int_equal(ff_flow_map_insert(&k), -1);

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    ff_reload_attach_state(&st);

    /* window still closed: insert is a no-op */
    assert_int_equal(ff_flow_map_active(), 0);
    assert_int_equal(ff_flow_map_insert(&k), -1);

    ff_flow_map_open();
    assert_int_equal(ff_flow_map_active(), 1);
    assert_int_equal(ff_flow_map_lookup(&k), 0);
    assert_int_equal(ff_flow_map_insert(&k), 0);
    /* A1: the insert itself marks the flow as this generation, so the
     * third handshake ACK is classified without a second step */
    assert_int_equal(ff_flow_map_lookup(&k), 1);
    /* idempotent: a repeated four-tuple must not consume a second slot */
    assert_int_equal(ff_flow_map_insert(&k), 1);
    assert_int_equal(ff_flow_map_lookup(&k), 1);

    /* a different source port is a different flow, and does not disturb the
     * first one (no hash-collision damage) */
    memcpy(&k2, &k, sizeof(k2));
    k2.sport = 0x1235;
    assert_int_equal(ff_flow_map_lookup(&k2), 0);
    assert_int_equal(ff_flow_map_insert(&k2), 0);
    assert_int_equal(ff_flow_map_lookup(&k), 1);
    assert_int_equal(ff_flow_map_lookup(&k2), 1);

    /* v6 flows live in the same table and stay distinct from v4 */
    memcpy(&k2, &k, sizeof(k2));
    k2.af = FF_FLOW_MAP_V6;
    assert_int_equal(ff_flow_map_lookup(&k2), 0);

    /* close empties the table; open starts a fresh one (reversible) */
    ff_flow_map_close();
    assert_int_equal(ff_flow_map_active(), 0);
    assert_int_equal(ff_flow_map_lookup(&k), 0);
    ff_flow_map_open();
    assert_int_equal(ff_flow_map_lookup(&k), 0);
    assert_int_equal(ff_flow_map_insert(&k), 0);
    assert_int_equal(ff_flow_map_lookup(&k), 1);
    ff_flow_map_close();

    ff_reload_attach_state(NULL);
    ff_global_cfg.dpdk.graceful_reload = 0;
}

static void
test_a1_flow_map_single_phase(void **state)
{
    struct ff_reload_state st;
    ff_flow_key_t k, k2;

    (void)state;

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    ff_reload_attach_state(&st);
    ff_global_cfg.dpdk.graceful_reload = 1;

    memset(&k, 0, sizeof(k));
    k.af = FF_FLOW_MAP_V4;
    k.src[0] = 0x0a000001;
    k.dst[0] = 0x0a000002;
    k.sport = 0x2222;
    k.dport = 0x0050;

    ff_flow_map_open();
    assert_int_equal(ff_flow_map_insert(&k), 0);
    /* visible to the dispatcher right away (single phase) */
    assert_int_equal(ff_flow_map_lookup(&k), 1);
    /* a repeated SYN on the same four-tuple is admitted, not rejected */
    assert_int_equal(ff_flow_map_insert(&k), 1);
    assert_int_equal(ff_flow_map_lookup(&k), 1);

    /* a second flow does not disturb the first */
    memcpy(&k2, &k, sizeof(k2));
    k2.sport = 0x2223;
    assert_int_equal(ff_flow_map_lookup(&k2), 0);
    assert_int_equal(ff_flow_map_insert(&k2), 0);
    assert_int_equal(ff_flow_map_lookup(&k), 1);
    assert_int_equal(ff_flow_map_lookup(&k2), 1);

    /* close empties the table; open starts a fresh one (reversible) */
    ff_flow_map_close();
    assert_int_equal(ff_flow_map_lookup(&k), 0);

    ff_flow_map_open();
    ff_flow_map_close();
    ff_reload_attach_state(NULL);
    ff_global_cfg.dpdk.graceful_reload = 0;
}

static void
test_a1_flow_map_admission_rule(void **state)
{
    struct ff_reload_state st;
    ff_flow_key_t k, fill;
    uint32_t i;
    int refused = 0;

    (void)state;

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);

    memset(&k, 0, sizeof(k));
    k.af = FF_FLOW_MAP_V4;
    k.src[0] = 0x0d000001;
    k.dst[0] = 0x0d000002;
    k.sport = 0x3333;
    k.dport = 0x0050;

    /* no window: nothing is tracked, so nothing may be refused */
    ff_global_cfg.dpdk.graceful_reload = 0;
    ff_reload_attach_state(NULL);
    assert_int_equal(ff_flow_map_admit(&k, NULL), 1);

    /* graceful_reload=1 but no shared block (non-nginx app): ditto */
    ff_global_cfg.dpdk.graceful_reload = 1;
    assert_int_equal(ff_flow_map_admit(&k, NULL), 1);

    ff_reload_attach_state(&st);

    /* a live window with room: admitted and recorded */
    ff_flow_map_close();
    ff_flow_map_open();
    assert_int_equal(ff_flow_map_admit(&k, NULL), 1);
    assert_int_equal(ff_flow_map_lookup(&k), 1);
    /* a retransmitted SYN on the same four-tuple is admitted, not refused */
    assert_int_equal(ff_flow_map_admit(&k, NULL), 1);
    ff_flow_map_close();

    /* a saturated window: refused, and the refused tuple stays out */
    ff_flow_map_cap_set(64);
    ff_flow_map_open();
    for (i = 0; i < 20000; i++) {
        memset(&fill, 0, sizeof(fill));
        fill.af = FF_FLOW_MAP_V4;
        fill.src[0] = 0x0e000000u + i;
        fill.dst[0] = 0x0e000001;
        fill.sport = (uint16_t)(0x4000u + (uint16_t)(i & 0xffff));
        fill.dport = 0x0050;
        if (ff_flow_map_insert(&fill) < 0) {
            refused = 1;
            break;
        }
    }
    assert_int_equal(refused, 1);
    assert_int_equal(ff_flow_map_admit(&fill, NULL), 0);
    assert_int_equal(ff_flow_map_lookup(&fill), 0);

    ff_flow_map_close();
    ff_flow_map_cap_set(1u << 16);      /* restore the default for later TCs */
    ff_reload_attach_state(NULL);
    ff_global_cfg.dpdk.graceful_reload = 0;
}

static void
test_a1_flow_map_revoke(void **state)
{
    struct ff_reload_state st;
    ff_flow_key_t k[64], ghost;
    uint32_t i, n = 0;
    int created = 0;

    (void)state;

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);

    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_reload_attach_state(&st);

    ff_flow_map_cap_set(64);
    ff_flow_map_close();
    ff_flow_map_open();

    /* Fill a small table so plenty of entries share probe chains. */
    for (i = 0; i < 64; i++) {
        memset(&k[n], 0, sizeof(k[n]));
        k[n].af = FF_FLOW_MAP_V4;
        k[n].src[0] = 0x0f000000u + i;
        k[n].dst[0] = 0x0f000001;
        k[n].sport = (uint16_t)(0x5000u + (uint16_t)i);
        k[n].dport = 0x0050;
        if (ff_flow_map_admit(&k[n], &created) == 1 && created == 1)
            n++;
    }
    assert_true(n >= 32);

    for (i = 0; i < n; i++)
        assert_int_equal(ff_flow_map_lookup(&k[i]), 1);

    /* Revoking an entry must hide only that one. Done for every entry: with
     * the table half full, at least one slot has an entry that had to step
     * past it, and clearing that slot without pulling the others back would
     * hide it. */
    for (i = 0; i < n; i++) {
        uint32_t j;

        assert_int_equal(ff_flow_map_revoke(&k[i]), 1);
        assert_int_equal(ff_flow_map_lookup(&k[i]), 0);
        for (j = 0; j < n; j++) {
            if (j == i)
                continue;
            assert_int_equal(ff_flow_map_lookup(&k[j]), 1);
        }
        assert_int_equal(ff_flow_map_insert(&k[i]), 0);
    }

    /* A duplicate four-tuple is not "created", so an earlier SYN's record is
     * not revoked when a later SYN-ACK fails. */
    created = 1;
    assert_int_equal(ff_flow_map_admit(&k[0], &created), 1);
    assert_int_equal(created, 0);
    assert_int_equal(ff_flow_map_lookup(&k[0]), 1);

    /* Revoking something that is not there changes nothing. */
    memset(&ghost, 0, sizeof(ghost));
    ghost.af = FF_FLOW_MAP_V4;
    ghost.src[0] = 0x0fffffffu;
    ghost.dst[0] = 0x0f000001;
    ghost.sport = 0x7fff;
    ghost.dport = 0x0050;
    assert_int_equal(ff_flow_map_revoke(&ghost), 0);

    ff_flow_map_close();
    ff_flow_map_cap_set(1u << 16);
    ff_reload_attach_state(NULL);
    ff_global_cfg.dpdk.graceful_reload = 0;
}

static void
test_p3_flow_map_bounded_growth(void **state)
{
    struct ff_reload_state st;
    uint64_t full = 0, grown = 0, grow_fail = 0, full_before = 0;
    uint32_t cap = 0;
    int i;

    (void)state;

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    ff_reload_attach_state(&st);
    ff_global_cfg.dpdk.graceful_reload = 1;

    ff_flow_map_cap_set(64);
    ff_flow_map_open();

    /* fill until the expansion bound is reached */
    for (i = 0; i < 20000; i++) {
        ff_flow_key_t k;

        memset(&k, 0, sizeof(k));
        k.af = FF_FLOW_MAP_V4;
        k.src[0] = 0x0b000000u + (uint32_t)i;
        k.dst[0] = 0x0b000001;
        k.sport = (uint16_t)(0x2000u + (uint16_t)(i & 0xffff));
        k.dport = 0x0050;

        (void)ff_flow_map_insert(&k);

        ff_flow_map_stats2(NULL, NULL, &full, &grown, &grow_fail, NULL,
            &cap, NULL);
        if (grown >= 4)
            break;
    }

    assert_true(grown >= 1);
    assert_true(grown <= 4);
    assert_int_equal((int)cap, 64 << (int)grown);
    assert_int_equal((int)grow_fail, 0);

    /* past the bound the table reports full instead of growing forever */
    full_before = full;
    for (i = 0; i < 4096; i++) {
        ff_flow_key_t k;

        memset(&k, 0, sizeof(k));
        k.af = FF_FLOW_MAP_V4;
        k.src[0] = 0x0c000000u + (uint32_t)i;
        k.dst[0] = 0x0c000001;
        k.sport = (uint16_t)(0x3000u + (uint16_t)(i & 0xffff));
        k.dport = 0x0050;

        (void)ff_flow_map_insert(&k);
    }
    ff_flow_map_stats2(NULL, NULL, &full, &grown, &grow_fail, NULL, &cap,
        NULL);
    assert_int_equal((int)grown, 4);
    assert_int_equal((int)cap, 64 << 4);
    assert_true(full > full_before);

    /* the knob is bounded: a non power of two or an out-of-range value is
     * ignored, so the capacity can never drift */
    ff_flow_map_close();
    ff_flow_map_cap_set(100);
    ff_flow_map_open();
    ff_flow_map_stats2(NULL, NULL, NULL, NULL, NULL, NULL, &cap, NULL);
    assert_int_equal((int)cap, 64 << 4);

    ff_flow_map_close();
    ff_flow_map_cap_set(1u << 16);      /* restore the default for later TCs */
    ff_reload_attach_state(NULL);
    ff_global_cfg.dpdk.graceful_reload = 0;
}
