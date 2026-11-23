static int
fake_pcblddr(uint16_t family, void *dst_addr, uint16_t dst_port,
             void *src_addr)
{
    (void)family; (void)dst_addr; (void)dst_port; (void)src_addr;
    return 0;
}

static void
test_ff_regist_pcblddr_fun_smoke(void **state)
{
    (void)state;
    ff_regist_pcblddr_fun(fake_pcblddr);   /* must not crash */
    ff_regist_pcblddr_fun(NULL);           /* re-register NULL must not crash */
}

static void
test_ff_in_pcbladdr_no_callback(void **state)
{
    (void)state;
    /* Reset to NULL via the public setter */
    ff_regist_pcblddr_fun(NULL);

    int rv = ff_in_pcbladdr(AF_INET, NULL, 0, NULL);
    assert_int_equal(rv, 0);
}

static struct {
    int   invoked;
    uint16_t family_seen;
    void *faddr_seen;
    uint16_t fport_seen;
    void *laddr_seen;
    int   ret_value;
} g_pcblddr_capture;

static int
capturing_pcblddr(uint16_t family, void *faddr, uint16_t fport, void *laddr)
{
    g_pcblddr_capture.invoked++;
    g_pcblddr_capture.family_seen = family;
    g_pcblddr_capture.faddr_seen  = faddr;
    g_pcblddr_capture.fport_seen  = fport;
    g_pcblddr_capture.laddr_seen  = laddr;
    return g_pcblddr_capture.ret_value;
}

static void
test_ff_in_pcbladdr_af_inet_dispatches(void **state)
{
    (void)state;
    memset(&g_pcblddr_capture, 0, sizeof(g_pcblddr_capture));
    g_pcblddr_capture.ret_value = 7;          /* arbitrary marker */
    ff_regist_pcblddr_fun(capturing_pcblddr);

    int faddr = 0x12345678;
    int laddr = 0x9ABCDEF0;
    int rv = ff_in_pcbladdr(AF_INET, &faddr, 53, &laddr);

    assert_int_equal(rv, 7);                  /* return value transparently */
    assert_int_equal(g_pcblddr_capture.invoked, 1);
    assert_int_equal((int)g_pcblddr_capture.family_seen, AF_INET);
    assert_ptr_equal(g_pcblddr_capture.faddr_seen, &faddr);
    assert_int_equal((int)g_pcblddr_capture.fport_seen, 53);
    assert_ptr_equal(g_pcblddr_capture.laddr_seen, &laddr);

    ff_regist_pcblddr_fun(NULL);              /* clean up */
}

#define AF_INET6_FREEBSD_VAL    28      /* per ff_api.h L50 */

#define AF_INET6_LINUX_VAL      10      /* per ff_api.h L48 */

static void
test_ff_in_pcbladdr_af_inet6_freebsd_to_linux_remap(void **state)
{
    (void)state;
    memset(&g_pcblddr_capture, 0, sizeof(g_pcblddr_capture));
    g_pcblddr_capture.ret_value = 0;
    ff_regist_pcblddr_fun(capturing_pcblddr);

    int rv = ff_in_pcbladdr(AF_INET6_FREEBSD_VAL, NULL, 0, NULL);
    assert_int_equal(rv, 0);
    assert_int_equal(g_pcblddr_capture.invoked, 1);
    /* Family must be remapped to AF_INET6_LINUX before reaching callback */
    assert_int_equal((int)g_pcblddr_capture.family_seen, AF_INET6_LINUX_VAL);

    /* Reset capture and try unknown family -> EADDRNOTAVAIL (host=99 on Linux),
     * callback NOT called */
    memset(&g_pcblddr_capture, 0, sizeof(g_pcblddr_capture));
    rv = ff_in_pcbladdr(99 /* unknown */, NULL, 0, NULL);
    assert_int_equal(rv, EADDRNOTAVAIL);    /* POSIX, =99 on Linux */
    assert_int_equal(g_pcblddr_capture.invoked, 0);

    ff_regist_pcblddr_fun(NULL);
}
