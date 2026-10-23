/* Fault injection only: all successful operations still use the real PMD. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int readback_injected;
static int device_stopped;
static int rollback_started;
static unsigned int start_generation;
static unsigned int stopped_generation;
static unsigned int fault_generation;

int rte_eth_dev_get_mtu(uint16_t port, uint16_t *mtu)
{
    int (*real_get)(uint16_t, uint16_t *) = dlsym(RTLD_NEXT, "rte_eth_dev_get_mtu");
    if (!real_get) abort();
    int result = real_get(port, mtu);
    const char *mode = getenv("KER_TEST_MTU_FAILURE");
    int rollback_fault = mode && (!strcmp(mode, "rollback-read-error") ||
        !strcmp(mode, "rollback-read-mismatch"));
    int target_mtu = rollback_fault ? 1500 : 9000;
    if (!result && !readback_injected && mode && fault_generation &&
        fault_generation == start_generation &&
        (!rollback_fault || rollback_started) && *mtu == target_mtu &&
        (!strcmp(mode, "read-error") || !strcmp(mode, "read-mismatch") || rollback_fault)) {
        readback_injected = 1;
        if (!strcmp(mode, "read-error") || !strcmp(mode, "rollback-read-error")) {
            fprintf(stderr, "INJECT: MTU readback error after PMD start generation=%u\n", start_generation);
            return -EIO;
        }
        *mtu = target_mtu - 1;
        fprintf(stderr, "INJECT: MTU readback mismatch after PMD start generation=%u\n", start_generation);
    }
    return result;
}

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
    if (!injected && mode && mtu == 9000 &&
        (!strcmp(mode, "before") || !strcmp(mode, "after") ||
         !strcmp(mode, "rollback") || !strcmp(mode, "rollback-read-error") ||
         !strcmp(mode, "rollback-read-mismatch"))) {
        injected = 1;
        if (strcmp(mode, "before") && strcmp(mode, "rollback-read-error") &&
            strcmp(mode, "rollback-read-mismatch") && real_set(port, mtu)) abort();
        if (mode && (!strcmp(mode, "rollback-read-error") ||
                     !strcmp(mode, "rollback-read-mismatch"))) rollback_started = 1;
        if (mode && (!strcmp(mode, "rollback-read-error") ||
                     !strcmp(mode, "rollback-read-mismatch"))) {
            fprintf(stderr, "INJECT: PMD requested MTU rejected before mutation\n");
            return -EIO;
        }
        fprintf(stderr, "INJECT: MTU %s PMD set\n", mode);
        return -EIO;
    }
    return real_set(port, mtu);
}

int rte_eth_dev_stop(uint16_t port)
{
    int (*real_stop)(uint16_t) = dlsym(RTLD_NEXT, "rte_eth_dev_stop");
    if (!real_stop) abort();
    int result = real_stop(port);
    if (!result) {
        device_stopped = 1;
        stopped_generation = start_generation;
        fprintf(stderr, "INJECT: actual PMD stop succeeded generation=%u\n", start_generation);
    }
    return result;
}

int rte_eth_dev_close(uint16_t port)
{
    int (*real_close)(uint16_t) = dlsym(RTLD_NEXT, "rte_eth_dev_close");
    if (!real_close) abort();
    fprintf(stderr, "INJECT: PMD close after stop=%d generation=%u stopped_generation=%u\n",
        device_stopped, start_generation, stopped_generation);
    return real_close(port);
}

int rte_eth_dev_start(uint16_t port)
{
    int (*real_start)(uint16_t) = dlsym(RTLD_NEXT, "rte_eth_dev_start");
    int (*real_get)(uint16_t, uint16_t *) = dlsym(RTLD_NEXT, "rte_eth_dev_get_mtu");
    if (!real_start || !real_get) abort();
    int result = real_start(port);
    if (!result) {
        uint16_t mtu = 0;
        if (real_get(port, &mtu)) abort();
        start_generation++;
        device_stopped = 0;
        const char *mode = getenv("KER_TEST_MTU_FAILURE");
        int rollback_fault = mode && (!strcmp(mode, "rollback-read-error") ||
            !strcmp(mode, "rollback-read-mismatch"));
        int target_mtu = rollback_fault ? 1500 : 9000;
        fault_generation = mode && mtu == target_mtu &&
            (!rollback_fault || rollback_started) ? start_generation : 0;
        fprintf(stderr, "INJECT: actual PMD start generation=%u mtu=%u fault_armed=%u\n",
            start_generation, mtu, fault_generation);
    }
    return result;
}
