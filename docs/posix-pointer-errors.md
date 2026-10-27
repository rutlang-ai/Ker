# POSIX pointer error boundaries

`poll(NULL, count, ...)` and `ppoll(NULL, count, ...)` reject a nonzero count with `EFAULT` before pinning descriptors or reading readiness. The existing descriptor-count limit retains precedence; a zero count accepts NULL.

The native epoll scenario suite checks both calls while original Linux TCP data and a host pipe are readable, verifies both readiness states survive the error, drains the data and exercises the connection again. The same executable runs against the host baseline and the preloaded library. No imported Linux or DPDK source changes or migration count changes are required.
