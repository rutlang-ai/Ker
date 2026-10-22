/* Fault injection only: all successful operations still use the real PMD. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rte_eth_dev_set_mtu(uint16_t port, uint16_t mtu)
{
    static int injected;
    int (*real_set)(uint16_t, uint16_t) = dlsym(RTLD_NEXT, "rte_eth_dev_set_mtu");
    if (!real_set) abort();
    const char *mode = getenv("KER_TEST_MTU_FAILURE");
    if (injected && mode && !strcmp(mode, "rollback") && mtu == 1500) {
        fprintf(stderr, "INJECT: PMD rollback failure\n");
        return -EIO;
    }
    if (!injected && mode && mtu == 9000) {
        injected = 1;
        if (strcmp(mode, "before") && real_set(port, mtu)) abort();
        fprintf(stderr, "INJECT: MTU %s PMD set\n", mode);
        return -EIO;
    }
    return real_set(port, mtu);
}
