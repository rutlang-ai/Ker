#include <stdio.h>

#include "host-readiness.h"

int __real_example_host_kqueue_poll(int epfd, int *triples, int maxevents);

int __wrap_example_host_kqueue_poll(int epfd, int *triples, int maxevents)
{
    static unsigned polls;
    int result = __real_example_host_kqueue_poll(epfd, triples, maxevents);
    if (result >= 0 && ++polls == 10001) {
        puts("HIGH_RATE_POLL_10001");
        fflush(stdout);
    }
    return result;
}
