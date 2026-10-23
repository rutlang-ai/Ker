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
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <sys/uio.h>
static _Thread_local bool armed, gso_active;
static bool fired, controlled;
static const char *fault;
static int skip;
static unsigned successful_writes;
static void *tap_driver_handle;
static bool tap_driver_checked;
static void *selected_tap_symbol(const char *name)
{
    if (!tap_driver_checked) {
        tap_driver_checked = true;
        uint16_t port;
        struct rte_eth_dev_info info = {0};
        if (!rte_eth_dev_get_port_by_name("net_tap0", &port) &&
            !rte_eth_dev_info_get(port, &info)) {
            Dl_info module;
            if (info.device && dladdr(rte_dev_driver(info.device), &module) && module.dli_fname)
                tap_driver_handle = dlopen(module.dli_fname, RTLD_NOW | RTLD_NOLOAD);
        }
    }
    return tap_driver_handle ? dlsym(tap_driver_handle, name) : NULL;
}
static void *next_or_tap_symbol(const char *name)
{
    void *symbol = dlsym(RTLD_NEXT, name);
    return symbol ? symbol : selected_tap_symbol(name);
}
bool ker_test_tap_fault_fired(void);
bool ker_test_tap_fault_fired(void) { return fired; }
void ker_test_tap_fault(const char *kind, int writes_before_failure);
void ker_test_tap_fault(const char *kind, int writes_before_failure)
{
    fault = kind; skip = writes_before_failure; successful_writes = 0; fired = gso_active = false;
    armed = kind && !strcmp(kind, "write"); controlled = true;
}
static const char *kind(void)
{
    return controlled ? fault : getenv("KER_TAP_FAULT");
}
struct rte_mbuf *rte_pktmbuf_copy(const struct rte_mbuf *packet,
    struct rte_mempool *pool, uint32_t offset, uint32_t length)
{
    typedef struct rte_mbuf *(*copy_fn)(const struct rte_mbuf *, struct rte_mempool *, uint32_t, uint32_t);
    copy_fn original = (copy_fn)next_or_tap_symbol("rte_pktmbuf_copy");
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
    gso_fn original = (gso_fn)next_or_tap_symbol("rte_gso_segment");
    if (!original) return -ENOSYS;
    int result = original(packet, context, output, count);
    gso_active = result > 1;
    if (gso_active && !fired && kind() && !strcmp(kind(), "write")) armed = true;
    if (!controlled && gso_active && !fired && getenv("KER_TAP_FAULT_TSO")) { skip = 2; armed = true; }
    return result;
}
ssize_t writev(int fd, const struct iovec *vectors, int count)
{
    typedef ssize_t (*write_fn)(int, const struct iovec *, int);
    write_fn original = (write_fn)next_or_tap_symbol("writev");
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
