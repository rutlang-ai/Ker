/* Test-only reproduction of original TAP's rejected-checksum-buffer ownership. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <rte_mbuf.h>
#include <sys/uio.h>
static _Thread_local bool armed;
static bool fired;
struct rte_mbuf *rte_pktmbuf_copy(const struct rte_mbuf *packet,
    struct rte_mempool *pool, uint32_t offset, uint32_t length)
{
    typedef struct rte_mbuf *(*copy_fn)(const struct rte_mbuf *, struct rte_mempool *, uint32_t, uint32_t);
    copy_fn original = (copy_fn)dlsym(RTLD_NEXT, "rte_pktmbuf_copy");
    if (!original) { errno = ENOSYS; return NULL; }
    struct rte_mbuf *copy = original(packet, pool, offset, length);
    if (copy && !fired && (packet->ol_flags & RTE_MBUF_F_TX_L4_MASK)) armed = true;
    return copy;
}
ssize_t writev(int fd, const struct iovec *vectors, int count)
{
    typedef ssize_t (*write_fn)(int, const struct iovec *, int);
    write_fn original = (write_fn)dlsym(RTLD_NEXT, "writev");
    if (armed && !fired) {
        armed = false; fired = true;
        fputs("INJECT: original TAP checksum writev EAGAIN after header copy\n", stderr);
        errno = EAGAIN;
        return -1;
    }
    return original(fd, vectors, count);
}
