/* Real original EAL lcores, net_ring PMD, SP/SC rings and packet ownership. */
#define _GNU_SOURCE
#include "worker-rx-lcores.h"
#include "worker-mbuf.h"
#include "pcap.h"
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#include <rte_pause.h>
#define CHECK(x) do {if(!(x)){fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
static struct rte_mempool *pool;
#define JUMBO_FRAME_BYTES 9018
#define JUMBO_FRAME_COUNT (KER_RX_HANDOFF_CAPACITY - 1 + KER_RX_BURST)
static struct rte_mempool *jumbo_pool;
static struct rte_mbuf *packet(unsigned id)
{
    unsigned char bytes[1000];
    for(unsigned i=0;i<sizeof(bytes);i++)bytes[i]=(unsigned char)(id*13+i*17+(i>>8));
    memcpy(bytes,&id,sizeof(id));
    struct rte_mbuf *p=ker_worker_mbuf_from_bytes(pool,bytes,sizeof(bytes));CHECK(p&&p->nb_segs>1);return p;
}
static void verify(struct rte_mbuf *p,unsigned id)
{
    unsigned char storage[1000],expected[1000];
    const unsigned char *bytes=rte_pktmbuf_read(p,0,sizeof(storage),storage);CHECK(bytes&&p->pkt_len==sizeof(storage));
    for(unsigned i=0;i<sizeof(expected);i++)expected[i]=(unsigned char)(id*13+i*17+(i>>8));
    memcpy(expected,&id,sizeof(id));CHECK(!memcmp(bytes,expected,sizeof(expected)));rte_pktmbuf_free(p);
}
static struct rte_mbuf *jumbo_packet(unsigned id)
{
    unsigned char bytes[JUMBO_FRAME_BYTES];
    for (unsigned i = 0; i < sizeof(bytes); i++)
        bytes[i] = (unsigned char)(id * 19 + i * 23 + (i >> 8));
    memcpy(bytes, &id, sizeof(id));
    struct rte_mbuf *p = ker_worker_mbuf_from_bytes(jumbo_pool, bytes, sizeof(bytes));
    CHECK(p && p->nb_segs == 5 && p->pkt_len == sizeof(bytes));
    return p;
}
static void verify_jumbo(struct rte_mbuf *p, unsigned id)
{
    unsigned char storage[JUMBO_FRAME_BYTES], expected[JUMBO_FRAME_BYTES];
    const unsigned char *bytes = rte_pktmbuf_read(p, 0, sizeof(storage), storage);
    CHECK(bytes && p->pkt_len == sizeof(storage) && p->nb_segs == 5);
    for (unsigned i = 0; i < sizeof(expected); i++)
        expected[i] = (unsigned char)(id * 19 + i * 23 + (i >> 8));
    memcpy(expected, &id, sizeof(id));
    CHECK(!memcmp(bytes, expected, sizeof(expected)));
    rte_pktmbuf_free(p);
}
static uint64_t deadline(void){return rte_get_timer_cycles()+rte_get_timer_hz()*3;}
static void full(struct ker_worker_rx_lcores *rx)
{
    uint64_t end=deadline();
    while(rte_ring_count(rx->queue[1].handoff)!=KER_RX_HANDOFF_CAPACITY-1){CHECK(rte_get_timer_cycles()<end);rte_pause();}
}
int main(void)
{
    cpu_set_t cpus;CHECK(!sched_getaffinity(0,sizeof(cpus),&cpus));int cpu[2],found=0;
    for(int c=0;c<CPU_SETSIZE&&found<2;c++)if(CPU_ISSET(c,&cpus))cpu[found++]=c;
    if(found<2){puts("SKIP: two allowed CPUs required");return 77;}
    char cores[80];snprintf(cores,sizeof(cores),"--lcores=0@%d,1@%d",cpu[0],cpu[1]);
    char *args[]={"rx-lcores",cores,"--no-huge","--no-pci","--no-shconf","--no-telemetry","-m","64",NULL};
    CHECK(rte_eal_init(8,args)>=0);
    pool=rte_pktmbuf_pool_create("rx_core_pool",4095,0,0,512,SOCKET_ID_ANY);CHECK(pool);
    struct rte_ring *input[2],*output[2];
    for(unsigned q=0;q<2;q++){
        char name[32];snprintf(name,sizeof(name),"rx_input_%u",q);input[q]=rte_ring_create(name,2048,SOCKET_ID_ANY,0);
        snprintf(name,sizeof(name),"rx_output_%u",q);output[q]=rte_ring_create(name,16,SOCKET_ID_ANY,0);CHECK(input[q]&&output[q]);
    }
    int created=rte_eth_from_rings("lcore_wire",input,2,output,2,SOCKET_ID_ANY);CHECK(created>=0);uint16_t port=(uint16_t)created;
    struct rte_eth_conf config={0};CHECK(!rte_eth_dev_configure(port,2,2,&config));
    for(unsigned q=0;q<2;q++)CHECK(!rte_eth_rx_queue_setup(port,q,64,SOCKET_ID_ANY,NULL,pool)&&!rte_eth_tx_queue_setup(port,q,64,SOCKET_ID_ANY,NULL));
    CHECK(!rte_eth_dev_start(port));
    struct ker_worker_rx_lcores rx;
    CHECK(ker_worker_rx_lcores_plan(&rx,port,2,"1",true)==-EXDEV);
    CHECK(ker_worker_rx_lcores_plan(&rx,port,2,"2",false)==-EINVAL);
    CHECK(ker_worker_rx_lcores_plan(&rx,port,2,"0,0",false)==-EINVAL);
    CHECK(ker_worker_rx_lcores_plan(&rx,port,1,"0,1",false)==-EINVAL);
    CHECK(!ker_worker_rx_lcores_plan(&rx,port,2,"0,1",true));
    /* A real namespace collision tests partial-start cleanup without a fake
     * successful allocator. The colliding ring remains independently owned. */
    char collision_name[32];snprintf(collision_name,sizeof(collision_name),"ker_rx_%u_1",port);
    struct rte_ring *collision=rte_ring_create(collision_name,16,SOCKET_ID_ANY,0);CHECK(collision);
    CHECK(ker_worker_rx_lcores_start(&rx)==-EEXIST);uint64_t abandoned;
    CHECK(!ker_worker_rx_lcores_stop(&rx,&abandoned,NULL)&&!abandoned&&rx.notify_fd==-1);
    CHECK(rte_ring_lookup(collision_name)==collision);rte_ring_free(collision);
    CHECK(!ker_worker_rx_lcores_plan(&rx,port,2,"0,1",true)&&!ker_worker_rx_lcores_start(&rx));
    for(unsigned i=0;i<10;i++)CHECK(!rte_ring_enqueue(input[0],packet(i)));
    for(unsigned i=0;i<512;i++)CHECK(!rte_ring_enqueue(input[1],packet(1000+i)));
    full(&rx); /* Consumer deliberately absent until the bounded ring is full. */
    unsigned received=0;uint64_t end=deadline();
    while(received<512){
        struct rte_mbuf *packets[32];uint16_t count=ker_worker_rx_lcores_burst(&rx,1,packets,32);
        for(unsigned i=0;i<count;i++)verify(packets[i],1000+received++);
        CHECK(rte_get_timer_cycles()<end);if(!count)rte_pause();
    }
    struct rte_mbuf *packets[32];CHECK(ker_worker_rx_lcores_burst(&rx,0,packets,32)==10);
    for(unsigned i=0;i<10;i++)verify(packets[i],i);
    for(unsigned i=0;i<512;i++)CHECK(!rte_ring_enqueue(input[1],packet(2000+i)));
    char directory[]="/tmp/ker-rx-capture-XXXXXX";CHECK(mkdtemp(directory));
    struct ker_pcap capture={0};CHECK(!ker_pcap_open(&capture,directory,"shutdown",1500,1048576,false));
    full(&rx);CHECK(!ker_worker_rx_lcores_stop(&rx,&abandoned,&capture));CHECK(!ker_pcap_close(&capture));
    char path[128];snprintf(path,sizeof(path),"%s/shutdown-0.pcap",directory);
    FILE *file=fopen(path,"rb");CHECK(file&&!fseek(file,24,SEEK_SET));
    for(unsigned i=0;i<abandoned;i++){
        uint32_t header[4];unsigned char data[1000],expected[1000];unsigned id=2000+i;
        CHECK(fread(header,sizeof(header),1,file)==1&&header[0]>0&&header[1]<1000000&&header[2]==1000&&header[3]==1000);
        for(unsigned j=0;j<sizeof(expected);j++)expected[j]=(unsigned char)(id*13+j*17+(j>>8));
        memcpy(expected,&id,sizeof(id));CHECK(fread(data,sizeof(data),1,file)==1&&!memcmp(data,expected,sizeof(data)));
    }
    CHECK(fgetc(file)==EOF&&!fclose(file)&&!unlink(path)&&!rmdir(directory));
    CHECK(abandoned>=255&&abandoned<=287&&rx.queue[1].stalled>0&&rx.queue[1].shutdown==abandoned);
    CHECK(rx.queue[0].polled==10&&rx.queue[1].polled==512+abandoned);
    for(unsigned q=0;q<2;q++)CHECK(rx.queue[q].owner==q&&rx.queue[q].observed==q&&rx.queue[q].cpu==cpu[q]&&rx.queue[q].polls>0);
    CHECK(!ker_worker_rx_lcores_stop(&rx,&abandoned,NULL)&&!abandoned);
    for(unsigned q=0;q<2;q++){struct rte_mbuf *p;while(!rte_ring_dequeue(input[q],(void**)&p))rte_pktmbuf_free(p);}
    /* Exercise the real remote RX handoff with jumbo chains. The exact pool
     * includes five mbufs for each retained packet; the old one-mbuf reserve
     * cannot construct this full admitted burst. */
    uint32_t jumbo_segments = 0, jumbo_pool_count = 0, old_packet_bound = 0;
    CHECK(ker_worker_mbuf_frame_segments(9000,
        RTE_ETHER_HDR_LEN + RTE_VLAN_HLEN + RTE_ETHER_CRC_LEN,
        RTE_MBUF_DEFAULT_BUF_SIZE, &jumbo_segments) == 0 && jumbo_segments == 5);
    CHECK(ker_worker_mbuf_handoff_pool_count(0, 1,
        KER_RX_HANDOFF_CAPACITY + KER_RX_BURST, jumbo_segments,
        &jumbo_pool_count) == 0 && jumbo_pool_count == 1440);
    CHECK(ker_worker_mbuf_handoff_pool_count(0, 1,
        KER_RX_HANDOFF_CAPACITY + KER_RX_BURST, 1,
        &old_packet_bound) == 0 && old_packet_bound == 288);
    CHECK(old_packet_bound < JUMBO_FRAME_COUNT * jumbo_segments);
    jumbo_pool = rte_pktmbuf_pool_create("rx_jumbo_pool", jumbo_pool_count,
        0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
    CHECK(jumbo_pool);
    CHECK(!ker_worker_rx_lcores_plan(&rx,port,2,"0,1",true)&&!ker_worker_rx_lcores_start(&rx));
    for (unsigned i = 0; i < JUMBO_FRAME_COUNT; i++)
        CHECK(!rte_ring_enqueue(input[1], jumbo_packet(4000 + i)));
    full(&rx);
    CHECK(rte_mempool_in_use_count(jumbo_pool) ==
        JUMBO_FRAME_COUNT * jumbo_segments);
    CHECK(rte_mempool_avail_count(jumbo_pool) ==
        jumbo_pool_count - JUMBO_FRAME_COUNT * jumbo_segments);
    unsigned jumbo_received = 0; end = deadline();
    while (jumbo_received < JUMBO_FRAME_COUNT) {
        struct rte_mbuf *jumbo_packets[KER_RX_BURST];
        uint16_t count = ker_worker_rx_lcores_burst(&rx, 1, jumbo_packets, KER_RX_BURST);
        for (unsigned i = 0; i < count; i++)
            verify_jumbo(jumbo_packets[i], 4000 + jumbo_received++);
        CHECK(rte_get_timer_cycles() < end);
        if (!count) rte_pause();
    }
    CHECK(rx.queue[1].stalled > 0);
    CHECK(!ker_worker_rx_lcores_stop(&rx,&abandoned,NULL)&&!abandoned);
    CHECK(!rte_mempool_in_use_count(jumbo_pool) &&
        rte_mempool_avail_count(jumbo_pool) == jumbo_pool_count);
    rte_mempool_free(jumbo_pool); jumbo_pool = NULL;
    /* A real ENOSPC capture failure must report failure and still free every
     * queued/retained mbuf after joining its original EAL producer. */
    CHECK(!ker_worker_rx_lcores_plan(&rx,port,2,"0,1",true)&&!ker_worker_rx_lcores_start(&rx));
    for(unsigned i=0;i<32;i++)CHECK(!rte_ring_enqueue(input[1],packet(3000+i)));
    end=deadline();while(rte_ring_count(rx.queue[1].handoff)!=32){CHECK(rte_get_timer_cycles()<end);rte_pause();}
    char failure_directory[]="/tmp/ker-rx-full-XXXXXX";CHECK(mkdtemp(failure_directory));
    CHECK(!ker_pcap_open(&capture,failure_directory,"failure",1500,1048576,false)&&!fflush(capture.file));
    int full_fd=open("/dev/full",O_WRONLY);CHECK(full_fd>=0&&dup2(full_fd,fileno(capture.file))>=0&&!close(full_fd));
    CHECK(ker_worker_rx_lcores_stop(&rx,&abandoned,&capture)==-EIO&&abandoned==32);
    CHECK(ker_pcap_close(&capture)==-1&&!rte_mempool_in_use_count(pool));
    snprintf(path,sizeof(path),"%s/failure-0.pcap",failure_directory);CHECK(!unlink(path)&&!rmdir(failure_directory));
    CHECK(!rte_eth_dev_stop(port)&&!rte_eth_dev_close(port)&&!rte_mempool_in_use_count(pool));
    for(unsigned q=0;q<2;q++){rte_ring_free(input[q]);rte_ring_free(output[q]);}rte_mempool_free(pool);
    CHECK(!rte_eal_cleanup());puts("PASS: actual two-core RX ownership, bounded FIFO retry, partial startup and shutdown reclamation");return 0;
}
