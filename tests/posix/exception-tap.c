/* Real host Linux TAP/AF_PACKET plus original DPDK ring PMD ownership tests. */
#define _GNU_SOURCE
#include "worker-exception.h"
#include "worker-mbuf.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <sys/uio.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_eth_ring.h>
#include <rte_ethdev.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s errno=%d\n",__FILE__,__LINE__,#x,errno); exit(1); } } while(0)
static int target_fd = -1, write_budget = -1;
ssize_t __real_writev(int fd, const struct iovec *iov, int count);
ssize_t __wrap_writev(int fd, const struct iovec *iov, int count)
{
    if (fd == target_fd && write_budget >= 0) {
        if (!write_budget) { errno = EAGAIN; return -1; }
        write_budget--;
    }
    return __real_writev(fd, iov, count);
}
static struct rte_mempool *pool;
static struct rte_ring *tx;
static uint16_t port;
static struct ker_worker_exception bridge = {.fd = -1};
static int peer;
static const struct rte_ether_addr host_mac = {.addr_bytes={0x02,0x11,0x22,0x33,0x44,0x55}};
static void bytes(unsigned char *data, unsigned size, unsigned id)
{
    memset(data, 0xff, 6); memset(data + 6, 0x12, 6); data[12] = 0x88; data[13] = 0xb5;
    for (unsigned i = 14; i < size; i++) data[i] = (unsigned char)(id + i * 17);
}
static struct rte_mbuf *packet(unsigned id, unsigned size)
{
    unsigned char data[1500]; CHECK(size >= 14 && size <= sizeof(data)); bytes(data,size,id);
    struct rte_mbuf *p = ker_worker_mbuf_from_bytes(pool,data,size); CHECK(p); return p;
}
static void open_bridge(unsigned capacity, unsigned rate)
{
    CHECK(!rte_mempool_in_use_count(pool));
    CHECK(!ker_worker_exception_open(&bridge,"excepttest",pool,&host_mac,1500,0x88b5,capacity,rate));
    target_fd = bridge.fd;
    peer = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(0x88b5)); CHECK(peer >= 0);
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(0x88b5),
        .sll_ifindex = (int)if_nametoindex("excepttest")};
    CHECK(address.sll_ifindex && !bind(peer,(void*)&address,sizeof(address)));
}
static void close_bridge(void)
{
    CHECK(!close(peer)); CHECK(!ker_worker_exception_close(&bridge)); target_fd = -1;
    CHECK(!if_nametoindex("excepttest") && !rte_mempool_in_use_count(pool));
}
static void enqueue(unsigned count, unsigned start)
{
    for (unsigned i = 0; i < count; i++) {
        struct rte_mbuf *p = packet(start+i,64);
        CHECK(ker_worker_exception_matches(&bridge,p));
        CHECK(!ker_worker_exception_enqueue(&bridge,&p) && !p);
    }
}
static void host_receive(unsigned count, unsigned start, unsigned size)
{
    unsigned char expected[1500], actual[1600];
    for (unsigned i = 0; i < count; i++) {
        struct pollfd event = {peer,POLLIN,0}; CHECK(poll(&event,1,1000)==1);
        bytes(expected,size,start+i);
        CHECK(recv(peer,actual,sizeof(actual),0)==(ssize_t)size && !memcmp(actual,expected,size));
    }
    CHECK(recv(peer,actual,sizeof(actual),0)==-1 && errno==EAGAIN);
}
static void host_send(unsigned count, unsigned start, unsigned size)
{
    unsigned char data[1500];
    for (unsigned i=0;i<count;i++) { bytes(data,size,start+i); CHECK(send(peer,data,size,0)==(ssize_t)size); }
    struct pollfd event = {bridge.fd,POLLIN,0}; CHECK(poll(&event,1,1000)==1);
}
static void wire_receive(unsigned count, unsigned start, unsigned size)
{
    unsigned char expected[1500], storage[1500];
    for (unsigned i=0;i<count;i++) {
        struct rte_mbuf *p; CHECK(!rte_ring_dequeue(tx,(void**)&p));
        bytes(expected,size,start+i);
        const void *data = rte_pktmbuf_read(p,0,p->pkt_len,storage);
        CHECK(p->pkt_len==size && data && !memcmp(data,expected,size)); rte_pktmbuf_free(p);
    }
    CHECK(!rte_ring_count(tx));
}
static void step(int64_t now, unsigned mtu)
{
    bool progress=false; CHECK(!ker_worker_exception_poll(&bridge,port,mtu,now,NULL,&progress)); CHECK(progress);
}
int main(void)
{
    cpu_set_t cpus; CHECK(!sched_getaffinity(0,sizeof(cpus),&cpus)); int cpu=0; while(!CPU_ISSET(cpu,&cpus))cpu++;
    char cores[48]; snprintf(cores,sizeof(cores),"--lcores=0@%d",cpu);
    char *args[]={"exception-tap",cores,"--no-huge","--no-pci","--no-shconf","--no-telemetry","-m","64",NULL};
    CHECK(rte_eal_init(8,args)>=0);
    pool=rte_pktmbuf_pool_create("exception_test",1023,0,0,512,SOCKET_ID_ANY);CHECK(pool);
    struct rte_ring *rx=rte_ring_create("exception_rx",16,SOCKET_ID_ANY,0);
    tx=rte_ring_create("exception_tx",8,SOCKET_ID_ANY,0);CHECK(rx&&tx);
    int created=rte_eth_from_rings("exception_wire",&rx,1,&tx,1,SOCKET_ID_ANY);CHECK(created>=0);port=(uint16_t)created;
    struct rte_eth_conf config={0};CHECK(!rte_eth_dev_configure(port,1,1,&config));
    CHECK(!rte_eth_rx_queue_setup(port,0,16,SOCKET_ID_ANY,NULL,pool));
    CHECK(!rte_eth_tx_queue_setup(port,0,8,SOCKET_ID_ANY,NULL));CHECK(!rte_eth_dev_start(port));
    open_bridge(16,0);
    CHECK(rte_eal_process_type()==RTE_PROC_PRIMARY && bridge.pending && !rte_ring_count(bridge.pending));
    CHECK(!bridge.selected && !bridge.to_host && !bridge.to_host_dropped && !bridge.from_host);
    struct ifreq request = {0}; CHECK(!ioctl(bridge.fd,TUNGETIFF,&request));
    CHECK(!strcmp(request.ifr_name,"excepttest") && (request.ifr_flags & IFF_TAP) && !(request.ifr_flags & IFF_VNET_HDR));
    int control=socket(AF_INET,SOCK_DGRAM,0);CHECK(control>=0);
    CHECK(!ioctl(control,SIOCGIFHWADDR,&request)&&!memcmp(request.ifr_hwaddr.sa_data,host_mac.addr_bytes,6));
    CHECK(!ioctl(control,SIOCGIFMTU,&request)&&request.ifr_mtu==1500);
    CHECK(!ioctl(control,SIOCGIFFLAGS,&request)&&(request.ifr_flags&IFF_UP));CHECK(!close(control));
    puts("PASS: test_kni_alloc_primary_happy_path");
    enqueue(4,0);step(100,1500);host_receive(4,0,64);
    CHECK(bridge.to_host==4&&!bridge.to_host_dropped&&!rte_mempool_in_use_count(pool));
    puts("PASS: test_kni_process_tx_basic");
    enqueue(6,10);write_budget=2;step(200,1500);write_budget=-1;host_receive(2,10,64);
    CHECK(bridge.to_host==6&&bridge.to_host_dropped==4&&!rte_mempool_in_use_count(pool));
    puts("PASS: test_kni_process_tx_partial_drop");
    host_send(3,20,64);step(300,1500);wire_receive(3,20,64);
    CHECK(bridge.from_host==3&&!bridge.wire_dropped);puts("PASS: test_kni_process_rx_forward");
    unsigned fill=rte_ring_free_count(tx)-1;
    for(unsigned i=0;i<fill;i++)CHECK(!rte_ring_enqueue(tx,packet(30+i,64)));
    host_send(5,40,64);step(400,1500);CHECK(bridge.from_host==4&&bridge.wire_dropped==4);
    for(unsigned i=0;i<fill;i++){struct rte_mbuf*p;CHECK(!rte_ring_dequeue(tx,(void**)&p));rte_pktmbuf_free(p);}
    wire_receive(1,40,64);puts("PASS: test_kni_process_rx_partial_drop");
    struct rte_mbuf *unicast=packet(50,64);
    memcpy(rte_pktmbuf_mtod(unicast,void*),host_mac.addr_bytes,6);
    CHECK(!ker_worker_exception_enqueue(&bridge,&unicast)&&!unicast);step(450,1500);
    struct pollfd event={peer,POLLIN,0};CHECK(poll(&event,1,1000)==1);
    unsigned char data[1600];struct sockaddr_ll origin;socklen_t origin_size=sizeof(origin);
    CHECK(recvfrom(peer,data,sizeof(data),0,(void*)&origin,&origin_size)==64 && origin.sll_pkttype==PACKET_HOST &&
          !memcmp(data,host_mac.addr_bytes,6));
    /* Both real directions preserve a multi-segment mbuf's complete bytes. */
    struct rte_mbuf *large=packet(60,1300);CHECK(large->nb_segs>1);
    CHECK(!ker_worker_exception_enqueue(&bridge,&large)&&!large);step(500,1500);host_receive(1,60,1300);
    host_send(1,61,1300);step(600,1500);wire_receive(1,61,1300);
    host_send(1,62,1400);step(700,1280);CHECK(bridge.wire_dropped==5&&bridge.malformed==1);
    close_bridge();
    open_bridge(16,2);enqueue(5,70);step(100,1500);host_receive(5,70,64);
    CHECK(bridge.window_packets==5&&bridge.to_host==5);puts("PASS: test_kni_process_tx_kernel_ratelimit");
    enqueue(3,80);step(200,1500);host_receive(0,0,64);
    CHECK(bridge.rate_dropped==3&&bridge.to_host_dropped==3&&bridge.window_packets==8);
    puts("PASS: test_kni_process_tx_kernel_ratelimit_exceeded");
    enqueue(1,90);step(INT64_C(1000000100),1500);host_receive(1,90,64);
    CHECK(bridge.window_packets==1&&bridge.to_host==6);close_bridge();
    open_bridge(4,0);enqueue(3,100);
    struct rte_mbuf *dropped=packet(104,64);
    CHECK(ker_worker_exception_enqueue(&bridge,&dropped)==-ENOBUFS&&!dropped);
    CHECK(bridge.selected==4&&bridge.enqueued==3&&bridge.to_host_dropped==1);
    CHECK(rte_mempool_in_use_count(pool)==3);close_bridge();CHECK(bridge.shutdown_dropped==3);
    puts("PASS: test_kni_enqueue_full_ring_drops");
    CHECK(!rte_eth_dev_stop(port)&&!rte_eth_dev_close(port));
    CHECK(!rte_mempool_in_use_count(pool));rte_mempool_free(pool);rte_ring_free(tx);rte_ring_free(rx);
    CHECK(!rte_eal_cleanup());puts("PASS: real TAP deleted; all mbufs and rings reclaimed");return 0;
}
