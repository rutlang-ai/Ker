#define _GNU_SOURCE
#include "worker-rx-lcores.h"
#include "pcap.h"
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_pause.h>

int ker_worker_rx_lcores_plan(struct ker_worker_rx_lcores *rx, uint16_t port,
    uint16_t queues, const char *selection, bool require_main)
{
    if (!rx || !queues || queues > KER_RX_QUEUES) return -EINVAL;
    *rx = (struct ker_worker_rx_lcores){.port=port, .queues=queues,
        .main=rte_get_main_lcore(), .notify_fd=-1};
    atomic_init(&rx->stopping, false);
    atomic_init(&rx->error, 0);
    unsigned cores[KER_RX_QUEUES], count=0;
    if (!selection) cores[count++]=rx->main;
    else {
        const char *p=selection;
        do {
            if (*p<'0' || *p>'9' || count==queues) return -EINVAL;
            char *end; errno=0; unsigned long core=strtoul(p,&end,10);
            if (errno || core>=RTE_MAX_LCORE || (*end && *end!=',') || !rte_lcore_is_enabled((unsigned)core)) return -EINVAL;
            for (unsigned i=0;i<count;i++) if (cores[i]==core) return -EINVAL;
            cores[count++]=(unsigned)core;
            p=*end ? end+1 : end;
            if (*end && !*p) return -EINVAL;
        } while (*p);
    }
    bool found=false;
    for (unsigned i=0;i<count;i++) {
        found|=cores[i]==rx->main;
        rx->remote|=cores[i]!=rx->main;
        rx->poller[i]=(struct ker_rx_poller){.rx=rx,.lcore=cores[i]};
    }
    if (require_main && !found) return -EXDEV;
    rx->count=count;
    for (uint16_t q=0;q<queues;q++) rx->queue[q]=(struct ker_rx_poll_queue){.owner=cores[q%count],.observed=UINT_MAX,.cpu=-1};
    return 0;
}
static int poll_queues(void *opaque)
{
    struct ker_rx_poller *poller=opaque;
    struct ker_worker_rx_lcores *rx=poller->rx;
    unsigned core=rte_lcore_id();
    if (core!=poller->lcore) {atomic_store(&rx->error,-EXDEV);return -EXDEV;}
    for (uint16_t q=0;q<rx->queues;q++) if (rx->queue[q].owner==core) {
        rx->queue[q].observed=core;rx->queue[q].cpu=sched_getcpu();rx->queue[q].starts++;
    }
    while (!atomic_load_explicit(&rx->stopping,memory_order_acquire)) {
        bool progress=false;
        for (uint16_t q=0;q<rx->queues;q++) {
            struct ker_rx_poll_queue *queue=&rx->queue[q];
            if (queue->owner!=core) continue;
            if (queue->index==queue->count) {
                queue->polls++;
                queue->count=rte_eth_rx_burst(rx->port,q,queue->pending,KER_RX_BURST);
                queue->index=0;queue->polled+=queue->count;
            }
            unsigned remaining=queue->count-queue->index;
            if (!remaining) continue;
            unsigned accepted=rte_ring_enqueue_burst(queue->handoff,(void **)(queue->pending+queue->index),remaining,NULL);
            queue->index+=(uint16_t)accepted;
            if (accepted<remaining) queue->stalled++;
            if (accepted) {
                /* eventfd coalesces notifications. EAGAIN means a wake is
                 * already pending; main also checks every handoff ring. */
                uint64_t one=1;ssize_t result;
                do result=write(rx->notify_fd,&one,sizeof(one)); while (result<0 && errno==EINTR);
                if (result<0 && errno!=EAGAIN) {atomic_store(&rx->error,-errno);return -errno;}
                progress=true;
            }
        }
        if (!progress) rte_pause();
    }
    return 0;
}
int ker_worker_rx_lcores_start(struct ker_worker_rx_lcores *rx)
{
    if (!rx || !rx->count || rte_lcore_id()!=rx->main) return -EINVAL;
    if (rx->notify_fd>=0) return -EBUSY;
    for (unsigned i=0;i<rx->count;i++) if (rx->poller[i].launched) return -EBUSY;
    atomic_store_explicit(&rx->stopping,false,memory_order_release);
    atomic_store(&rx->error,0);
    for (uint16_t q=0;q<rx->queues;q++) if (rx->queue[q].owner==rx->main) rx->queue[q].starts++;
    if (!rx->remote) return 0;
    rx->notify_fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);
    if (rx->notify_fd<0) return -errno;
    for (uint16_t q=0;q<rx->queues;q++) if (rx->queue[q].owner!=rx->main) {
        char name[RTE_RING_NAMESIZE];snprintf(name,sizeof(name),"ker_rx_%u_%u",rx->port,q);
        rx->queue[q].handoff=rte_ring_create(name,KER_RX_HANDOFF_CAPACITY,rte_lcore_to_socket_id(rx->queue[q].owner),RING_F_SP_ENQ|RING_F_SC_DEQ);
        if (!rx->queue[q].handoff) return -rte_errno;
    }
    for (unsigned i=0;i<rx->count;i++) if (rx->poller[i].lcore!=rx->main) {
        int result=rte_eal_remote_launch(poll_queues,&rx->poller[i],rx->poller[i].lcore);
        if (result) return result;
        rx->poller[i].launched=true;
    }
    return 0;
}
uint16_t ker_worker_rx_lcores_burst(struct ker_worker_rx_lcores *rx, uint16_t q,
    struct rte_mbuf **packets, uint16_t capacity)
{
    struct ker_rx_poll_queue *queue=&rx->queue[q];
    if (queue->owner!=rx->main) return (uint16_t)rte_ring_dequeue_burst(queue->handoff,(void **)packets,capacity,NULL);
    queue->observed=rte_lcore_id();queue->cpu=sched_getcpu();queue->polls++;
    uint16_t count=rte_eth_rx_burst(rx->port,q,packets,capacity);queue->polled+=count;return count;
}
void ker_worker_rx_lcores_ack(struct ker_worker_rx_lcores *rx)
{
    if (rx->notify_fd<0) return;
    uint64_t value;
    while (read(rx->notify_fd,&value,sizeof(value))<0 && errno==EINTR) {}
}
static void discard_packet(struct rte_mbuf *packet, struct ker_pcap *capture, int *result)
{
    if (capture) {
        struct timespec timestamp;
        if (clock_gettime(CLOCK_REALTIME,&timestamp) || ker_pcap_write(capture,packet,&timestamp)) *result=-EIO;
    }
    rte_pktmbuf_free(packet);
}
static int retire(struct ker_worker_rx_lcores *rx, uint64_t *discarded, struct ker_pcap *capture, bool reconfigure)
{
    int result=0;*discarded=0;
    atomic_store_explicit(&rx->stopping,true,memory_order_release);
    for (unsigned i=0;i<rx->count;i++) if (rx->poller[i].launched) {
        if (rte_eal_wait_lcore(rx->poller[i].lcore)) result=-EIO;
        rx->poller[i].launched=false;
    }
    for (uint16_t q=0;q<rx->queues;q++) {
        struct ker_rx_poll_queue *queue=&rx->queue[q];
        struct rte_mbuf *packet;
        uint64_t *retired=reconfigure ? &queue->reconfigured : &queue->shutdown;
        /* Accepted ring entries precede the producer's retained FIFO suffix.
         * Main is the sole capture owner, including shutdown-only packets. */
        while (queue->handoff && !rte_ring_dequeue(queue->handoff,(void **)&packet)) {
            discard_packet(packet,capture,&result);(*retired)++;(*discarded)++;
        }
        while (queue->index<queue->count) {
            discard_packet(queue->pending[queue->index++],capture,&result);(*retired)++;(*discarded)++;
        }
        rte_ring_free(queue->handoff);queue->handoff=NULL;
    }
    if (rx->notify_fd>=0) {if (close(rx->notify_fd)) result=-errno;rx->notify_fd=-1;}
    return result;
}

int ker_worker_rx_lcores_stop(struct ker_worker_rx_lcores *rx, uint64_t *discarded, struct ker_pcap *capture)
{
    return retire(rx,discarded,capture,false);
}
int ker_worker_rx_lcores_pause(struct ker_worker_rx_lcores *rx, uint64_t *discarded, struct ker_pcap *capture)
{
    return retire(rx,discarded,capture,true);
}
