#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>
#include "host-readiness.h"
#define ff_host_close example_host_close
#define ff_host_epoll_create1 example_host_epoll_create1
#define ff_host_kqueue_ctl example_host_kqueue_ctl
#define ff_host_kqueue_poll example_host_kqueue_poll
#include "host-functions.inc"
