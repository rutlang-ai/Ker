# POSIX pointer error boundaries

`poll(NULL, count, ...)` and `ppoll(NULL, count, ...)` reject a nonzero count with `EFAULT` before pinning descriptors or reading readiness. The existing descriptor-count limit retains precedence; a zero count accepts NULL.

The native epoll scenario suite checks both calls while original Linux TCP data and a host pipe are readable, verifies both readiness states survive the error, drains the data and exercises the connection again. The same executable runs against the host baseline and the preloaded library. No imported Linux or DPDK source changes or migration count changes are required.

`fstat`, `fstat64`, `__fxstat` and `__fxstat64` reject NULL output with `EFAULT` on a valid native descriptor. Native descriptor errors retain precedence, and host descriptors continue through the host syscall. The implementation is separated from libc's nonnull declaration so optimization cannot remove the check.

The same host/preload scenario exercises TCP, UDP and host-pipe descriptors through all four ABI entries, verifies invalid-descriptor `EBADF`, checks metadata after each fault and transfers TCP/pipe data afterward.
