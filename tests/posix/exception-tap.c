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
static void open_bridge_limits(unsigned capacity, unsigned rate, unsigned console, unsigned general)
{
    CHECK(!rte_mempool_in_use_count(pool));
    CHECK(!ker_worker_exception_open(&bridge,"excepttest",pool,&host_mac,1500,0x88b5,capacity,rate,console,general));
    target_fd = bridge.fd;
    peer = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(3)); CHECK(peer >= 0);
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(3),
        .sll_ifindex = (int)if_nametoindex("excepttest")};
    CHECK(address.sll_ifindex && !bind(peer,(void*)&address,sizeof(address)));
}
static void open_bridge(unsigned capacity, unsigned rate)
{
    open_bridge_limits(capacity, rate, 0, 0);
}
/* Raw frames cross a real TAP; a unicast experimental EtherType exercises the
 * ordinary class, while ARP and Ethernet multicast exercise console traffic. */
static void admission_bytes(unsigned char *data, unsigned id, unsigned kind)
{
    bytes(data,64,id);
    if (kind != 2) memcpy(data,host_mac.addr_bytes,6);
    if (kind == 1) { data[12]=0x08; data[13]=0x06; }
    if (kind == 3) {
        memset(data+14,0,20);data[12]=0x08;data[13]=0;data[14]=0x45;data[17]=50;data[23]=89;
    }
    if (kind == 4) {
        memset(data+14,0,48);data[12]=0x86;data[13]=0xdd;data[14]=0x60;data[19]=10;data[20]=58;data[54]=135;
    }
}
static void admission_enqueue(unsigned id, unsigned kind, int expected)
{
    unsigned char data[64]; admission_bytes(data,id,kind);
    struct rte_mbuf *p=ker_worker_mbuf_from_bytes(pool,data,sizeof(data)); CHECK(p);
    CHECK(ker_worker_exception_enqueue(&bridge,&p)==expected&&!p);
}
static void admission_receive(unsigned id, unsigned kind)
{
    unsigned char data[1600], expected[64]; admission_bytes(expected,id,kind);
    struct pollfd event={peer,POLLIN,0}; CHECK(poll(&event,1,1000)==1);
    CHECK(recv(peer,data,sizeof(data),0)==64&&!memcmp(data,expected,64));
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
    open_bridge_limits(16,0,0,0);
    admission_enqueue(110,1,0);admission_enqueue(111,0,0);
    CHECK(!bridge.console_packets&&!bridge.general_packets&&!bridge.console_charged&&!bridge.general_charged);
    step(100,1500);admission_receive(110,1);admission_receive(111,0);host_receive(0,0,64);
    CHECK(bridge.enqueued==2&&bridge.to_host==2);close_bridge();
    puts("PASS: test_ff_kni_enqueue_no_ratelimit");
    open_bridge_limits(16,0,2,0);
    admission_enqueue(120,1,0);admission_enqueue(121,2,0);
    admission_enqueue(122,1,-ENOBUFS);
    CHECK(bridge.console_packets==3&&bridge.console_charged==3&&bridge.console_dropped==1&&
          !bridge.general_packets&&bridge.enqueued==2&&bridge.to_host_dropped==1&&rte_mempool_in_use_count(pool)==2);
    step(100,1500);admission_receive(120,1);admission_receive(121,2);host_receive(0,0,64);
    CHECK(bridge.console_packets==3); /* Initial poll must not erase admissions. */
    admission_enqueue(123,2,-ENOBUFS);
    bool progress=false;CHECK(!ker_worker_exception_poll(&bridge,port,1500,INT64_C(1000000100),NULL,&progress));
    CHECK(!bridge.console_packets&&bridge.console_charged==4&&bridge.console_dropped==2);
    admission_enqueue(124,1,0);step(INT64_C(1000000200),1500);admission_receive(124,1);host_receive(0,0,64);
    CHECK(bridge.console_packets==1&&bridge.console_charged==5);close_bridge();
    puts("PASS: test_ff_kni_enqueue_console_ratelimit_over");
    open_bridge_limits(16,0,0,1);
    admission_enqueue(130,0,0);admission_enqueue(131,0,-ENOBUFS);
    admission_enqueue(132,1,0); /* Disabled console class does not charge. */
    CHECK(bridge.general_packets==2&&bridge.general_charged==2&&bridge.general_dropped==1&&
          !bridge.console_packets&&!bridge.console_charged&&bridge.to_host_dropped==1&&rte_mempool_in_use_count(pool)==2);
    step(100,1500);admission_receive(130,0);admission_receive(132,1);host_receive(0,0,64);close_bridge();
    puts("PASS: test_ff_kni_enqueue_general_ratelimit_over");
    open_bridge_limits(4,0,100,100);
    admission_enqueue(140,1,0);CHECK(bridge.console_packets==1&&!bridge.general_packets);
    admission_enqueue(141,0,0);CHECK(bridge.console_packets==1&&bridge.general_packets==1);
    admission_enqueue(142,2,0);admission_enqueue(143,0,-ENOBUFS); /* Full ring charges once. */
    CHECK(bridge.console_packets==2&&bridge.general_packets==2&&bridge.selected==4&&bridge.enqueued==3&&
          bridge.to_host_dropped==1&&!bridge.console_dropped&&!bridge.general_dropped&&rte_mempool_in_use_count(pool)==3);
    step(100,1500);admission_receive(140,1);admission_receive(141,0);admission_receive(142,2);host_receive(0,0,64);
    CHECK(ker_worker_exception_poll(&bridge,port,1500,99,NULL,&progress)==-EIO&&bridge.general_packets==2);
    admission_enqueue(144,0,0);close_bridge();CHECK(bridge.shutdown_dropped==1);
    /* Unicast OSPF and NDP must use console even without an L2 multicast bit. */
    open_bridge_limits(16,0,2,1);
    admission_enqueue(150,3,0);admission_enqueue(151,4,0);admission_enqueue(152,4,-ENOBUFS);
    CHECK(bridge.console_packets==3&&bridge.console_dropped==1&&!bridge.general_packets);
    step(100,1500);admission_receive(150,3);admission_receive(151,4);host_receive(0,0,64);close_bridge();
    puts("PASS: test_ff_kni_enqueue_filter_classification");
    CHECK(!rte_eth_dev_stop(port)&&!rte_eth_dev_close(port));
    CHECK(!rte_mempool_in_use_count(pool));rte_mempool_free(pool);rte_ring_free(tx);rte_ring_free(rx);
    CHECK(!rte_eal_cleanup());puts("PASS: real TAP deleted; all mbufs and rings reclaimed");return 0;
}
