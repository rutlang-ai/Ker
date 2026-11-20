/* Fault injection after TAP has accepted the larger MTU. */
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
    if (!real_set)
        abort();
    const char *mode = getenv("KER_TEST_MTU_FAILURE");
    if (injected && mode && strcmp(mode, "fatal") == 0 && mtu == 1500) {
        fprintf(stderr, "INJECT: PMD rejected the rollback\n");
        return -EIO;
    }

    int result = real_set(port, mtu);
    if (!result && !injected && mode && mtu == 9000) {
        injected = 1;
        fprintf(stderr, "INJECT: PMD changed MTU before returning EIO\n");
        return -EIO;
    }
    return result;
}
