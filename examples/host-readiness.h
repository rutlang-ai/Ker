#ifndef EXAMPLE_HOST_READINESS_H
#define EXAMPLE_HOST_READINESS_H
/* Caller-owned translation of readiness tags, not a Ker kqueue API. */
int example_host_close(int fd);
int example_host_epoll_create1(int flags);
void example_host_kqueue_ctl(int epfd, int del, int fd, int tag, int want_write);
int example_host_kqueue_poll(int epfd, int *triples, int maxevents);
#endif
