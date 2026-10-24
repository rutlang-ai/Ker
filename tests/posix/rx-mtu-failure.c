/* Observe actual original EAL quiescence; successful calls use original PMD. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>

static bool resume_armed;

static void quiescent(const char *operation)
{
    unsigned core;
    RTE_LCORE_FOREACH_WORKER(core) {
        if (rte_eal_get_lcore_state(core)!=WAIT) {
            fprintf(stderr,"FAIL: %s while EAL lcore %u is running\n",operation,core);abort();
        }
    }
    fprintf(stderr,"QUIESCENT: %s\n",operation);
}
int rte_eth_dev_stop(uint16_t port)
{
    int (*original)(uint16_t)=dlsym(RTLD_NEXT,"rte_eth_dev_stop");
    if (!original) abort();
    quiescent("ethdev stop");return original(port);
}
int rte_eth_rx_queue_setup(uint16_t port,uint16_t queue,uint16_t count,unsigned socket,
    const struct rte_eth_rxconf *conf,struct rte_mempool *pool)
{
    int (*original)(uint16_t,uint16_t,uint16_t,unsigned,const struct rte_eth_rxconf *,struct rte_mempool *)=
        dlsym(RTLD_NEXT,"rte_eth_rx_queue_setup");
    if (!original) abort();
    quiescent("RX queue setup");return original(port,queue,count,socket,conf,pool);
}
int rte_eth_dev_set_mtu(uint16_t port,uint16_t mtu)
{
    static int injected;
    int (*original)(uint16_t,uint16_t)=dlsym(RTLD_NEXT,"rte_eth_dev_set_mtu");
    if (!original) abort();
    quiescent("MTU set");
    const char *mode=getenv("KER_RX_MTU_FAILURE");
    if (injected&&mode&&!strcmp(mode,"rollback")&&mtu==1500) {
        fprintf(stderr,"INJECT: remote RX rollback failure\n");return -EIO;
    }
    if (!injected&&mode&&*mode&&mtu==9000) {
        injected=1;
        if (strcmp(mode,"before")&&original(port,mtu)) abort();
        fprintf(stderr,"INJECT: remote RX MTU %s\n",mode);return -EIO;
    }
    int result=original(port,mtu);
    if (!result&&mtu==1400) resume_armed=true;
    return result;
}

int rte_eal_remote_launch(lcore_function_t *function,void *argument,unsigned core)
{
    int (*original)(lcore_function_t *,void *,unsigned)=dlsym(RTLD_NEXT,"rte_eal_remote_launch");
    if (!original) abort();
    const char *mode=getenv("KER_RX_MTU_FAILURE");
    if (resume_armed&&mode&&!strcmp(mode,"resume")) {
        fprintf(stderr,"INJECT: remote RX resume failure\n");return -EBUSY;
    }
    return original(function,argument,core);
}

/* Fail only the test-owned exception TAP setter. Successful writes/readback
 * remain original host ioctls, including the post-mutation failure case. */
int ioctl(int fd, unsigned long request, ...)
{
    int (*original)(int,unsigned long,...)=dlsym(RTLD_NEXT,"ioctl");
    if (!original) abort();
    va_list args;va_start(args,request);void *argument=va_arg(args,void *);va_end(args);
    const char *mode=getenv("KER_EXCEPTION_MTU_FAILURE");
    static bool injected;
    struct ifreq *iface=argument;
    if (mode&&request==SIOCSIFMTU&&iface&&!strcmp(iface->ifr_name,"coreexcept")) {
        if (injected&&!strcmp(mode,"rollback")&&iface->ifr_mtu==1500) {
            fprintf(stderr,"INJECT: exception TAP rollback failure\n");errno=EIO;return -1;
        }
        if (!injected&&iface->ifr_mtu==9000) {
            injected=true;
            if (strcmp(mode,"before")&&original(fd,request,argument)) abort();
            fprintf(stderr,"INJECT: exception TAP MTU %s\n",mode);errno=EIO;return -1;
        }
    }
    return original(fd,request,argument);
}
