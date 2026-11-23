#include <errno.h>
#include <stdio.h>
#include <sys/epoll.h>
extern int __real_epoll_ctl(int, int, int, struct epoll_event *);
int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    if (op == EPOLL_CTL_MOD) {
        fputs("HOST_READINESS_MOD_FAULT\n", stderr);
        errno = EIO;
        return -1;
    }
    return __real_epoll_ctl(epfd, op, fd, event);
}
