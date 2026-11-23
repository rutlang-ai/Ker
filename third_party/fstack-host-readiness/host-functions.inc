int
ff_host_close(int fd)
{
    return close(fd);
}

int
ff_host_epoll_create1(int flags)
{
    return epoll_create1(flags);
}

void
ff_host_kqueue_ctl(int epfd, int del, int hfd, int app_fd, int want_write)
{
    struct epoll_event ev;

    ev.events = want_write ? EPOLLOUT : EPOLLIN;
    ev.data.fd = app_fd;
    if (del) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, hfd, &ev);
    } else if (epoll_ctl(epfd, EPOLL_CTL_ADD, hfd, &ev) < 0 &&
        errno == EEXIST) {
        epoll_ctl(epfd, EPOLL_CTL_MOD, hfd, &ev);
    }
}

int
ff_host_kqueue_poll(int epfd, int *triples, int maxevents)
{
    struct epoll_event evs[maxevents];
    int n, i;

    n = epoll_wait(epfd, evs, maxevents, 0);
    if (n <= 0)
        return 0;

    for (i = 0; i < n; i++) {
        triples[3 * i] = evs[i].data.fd;
        triples[3 * i + 1] = (evs[i].events & EPOLLOUT) ? 1 : 0;
        triples[3 * i + 2] = (evs[i].events & (EPOLLHUP | EPOLLERR)) ? 1 : 0;
    }
    return n;
}
