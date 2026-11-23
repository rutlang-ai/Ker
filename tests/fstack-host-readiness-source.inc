static void
test_ff_host_kqueue_ctl_add_idempotent(void **state)
{
    (void)state;
    int epfd = ff_host_epoll_create1(0);
    assert_true(epfd >= 0);

    int ln = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(ln >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    assert_int_equal(bind(ln, (struct sockaddr *)&sa, sizeof(sa)), 0);
    assert_int_equal(listen(ln, 1), 0);
    socklen_t slen = sizeof(sa);
    assert_int_equal(getsockname(ln, (struct sockaddr *)&sa, &slen), 0);

    const int app_fd1 = 0x40000777;
    const int app_fd2 = 0x40000888;   /* second ADD re-maps app_fd via MOD */

    ff_host_kqueue_ctl(epfd, 0, ln, app_fd1, 0);
    /* repeat ADD on same hfd -> EEXIST -> MOD fallback (no error surfaced) */
    ff_host_kqueue_ctl(epfd, 0, ln, app_fd2, 0);

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(cli >= 0);
    assert_int_equal(connect(cli, (struct sockaddr *)&sa, sizeof(sa)), 0);

    int triples[3 * 8];
    int n = 0;
    for (int tries = 0; tries < 50 && n == 0; tries++) {
        n = ff_host_kqueue_poll(epfd, triples, 8);
        if (n == 0) {
            struct timespec slp = {0, 2 * 1000 * 1000};
            nanosleep(&slp, NULL);
        }
    }
    /* exactly one registration: the MOD-updated app_fd2 is reported once */
    assert_int_equal(n, 1);
    assert_int_equal(triples[0], app_fd2);
    assert_int_equal(triples[1], 0);

    int srv = accept(ln, NULL, NULL);
    assert_true(srv >= 0);
    ff_host_kqueue_ctl(epfd, 1, ln, app_fd2, 0);

    ff_host_close(srv);
    ff_host_close(cli);
    ff_host_close(ln);
    ff_host_close(epfd);
}
