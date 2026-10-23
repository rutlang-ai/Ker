/* Test-only fault injection after original TAP checksum copies and GSO. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_gso.h>
#include <sys/uio.h>
static _Thread_local bool armed, gso_active;
static bool fired, controlled;
static const char *fault;
static int skip;
static unsigned successful_writes;
bool ker_test_tap_fault_fired(void);
bool ker_test_tap_fault_fired(void) { return fired; }
void ker_test_tap_fault(const char *kind, int writes_before_failure);
void ker_test_tap_fault(const char *kind, int writes_before_failure)
{
    fault = kind; skip = writes_before_failure; successful_writes = 0; fired = armed = gso_active = false; controlled = true;
}
static const char *kind(void)
{
    return controlled ? fault : getenv("KER_TAP_FAULT");
}
struct rte_mbuf *rte_pktmbuf_copy(const struct rte_mbuf *packet,
    struct rte_mempool *pool, uint32_t offset, uint32_t length)
{
    typedef struct rte_mbuf *(*copy_fn)(const struct rte_mbuf *, struct rte_mempool *, uint32_t, uint32_t);
    copy_fn original = (copy_fn)dlsym(RTLD_NEXT, "rte_pktmbuf_copy");
    if (!original) { errno = ENOSYS; return NULL; }
    bool eligible = (packet->ol_flags & RTE_MBUF_F_TX_L4_MASK) &&
        (controlled || !getenv("KER_TAP_FAULT_TSO") || gso_active);
    if (eligible && !fired && kind() && !strcmp(kind(), "copy")) {
        fired = true; errno = ENOMEM;
        fputs("INJECT: TAP checksum copy ENOMEM\n", stderr);
        return NULL;
    }
    struct rte_mbuf *copy = original(packet, pool, offset, length);
    if (copy && !fired && eligible && (!kind() || !strcmp(kind(), "write"))) armed = true;
    return copy;
}
int rte_gso_segment(struct rte_mbuf *packet, const struct rte_gso_ctx *context,
    struct rte_mbuf **output, uint16_t count)
{
    typedef int (*gso_fn)(struct rte_mbuf *, const struct rte_gso_ctx *, struct rte_mbuf **, uint16_t);
    gso_fn original = (gso_fn)dlsym(RTLD_NEXT, "rte_gso_segment");
    if (!original) return -ENOSYS;
    int result = original(packet, context, output, count);
    gso_active = result > 1;
    if (!controlled && gso_active && !fired && getenv("KER_TAP_FAULT_TSO")) skip = 2;
    return result;
}
ssize_t writev(int fd, const struct iovec *vectors, int count)
{
    typedef ssize_t (*write_fn)(int, const struct iovec *, int);
    write_fn original = (write_fn)dlsym(RTLD_NEXT, "writev");
    if (!original) { errno = ENOSYS; return -1; }
    if (armed && !fired && skip == 0) {
        armed = false; fired = true;
        fprintf(stderr, "INJECT: original TAP checksum writev EAGAIN after header copy (after %u successful checksum writes)\n", successful_writes);
        errno = EAGAIN;
        return -1;
    }
    ssize_t written = original(fd, vectors, count);
    if (written > 0 && armed && !fired) { skip--; successful_writes++; }
    return written;
}
