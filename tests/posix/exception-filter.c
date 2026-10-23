#define _GNU_SOURCE
#include "worker-exception-filter.h"
#include "worker-mbuf.h"
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
static struct rte_mempool *pool;
static struct ker_exception_filter filter;
static bool enabled = true;
static unsigned char ip[256];
static enum ker_exception_class classify(unsigned length, unsigned type)
{
    unsigned char frame[270]={0};frame[12]=(unsigned char)(type>>8);frame[13]=(unsigned char)type;
    memcpy(frame+14,ip,length);
    struct rte_mbuf*p=ker_worker_mbuf_from_bytes(pool,frame,length+14);CHECK(p);
    enum ker_exception_class result=ker_exception_classify(enabled ? &filter : NULL,p);rte_pktmbuf_free(p);return result;
}
static void ipv4(unsigned protocol,unsigned port)
{
    memset(ip,0,sizeof(ip));ip[0]=0x45;ip[9]=(unsigned char)protocol;ip[22]=(unsigned char)(port>>8);ip[23]=(unsigned char)port;
}
static void ipv6(unsigned protocol,unsigned port)
{
    memset(ip,0,sizeof(ip));ip[0]=0x60;ip[6]=(unsigned char)protocol;ip[42]=(unsigned char)(port>>8);ip[43]=(unsigned char)port;
}
#define UNKNOWN(n) CHECK(classify(n,0x0800)==KER_EXCEPTION_UNKNOWN)
#define PASS(name) puts("FILTER_SOURCE_CASE " #name)
int main(void)
{
    CHECK(!ker_exception_arp(NULL));
    cpu_set_t cpus;CHECK(!sched_getaffinity(0,sizeof(cpus),&cpus));int cpu=0;while(!CPU_ISSET(cpu,&cpus))cpu++;
    char cores[48];snprintf(cores,sizeof(cores),"--lcores=0@%d",cpu);
    char*args[]={"filter",cores,"--no-huge","--no-pci","--no-shconf","--no-telemetry","-m","64",NULL};CHECK(rte_eal_init(8,args)>=0);
    pool=rte_pktmbuf_pool_create("filter_packets",1023,0,0,160,SOCKET_ID_ANY);CHECK(pool);
    CHECK(!ker_exception_filter_init(&filter,"80,443,8000-8002","53,5060"));PASS(test_ff_kni_init_tcp_udp_port_bitmaps);
    for(unsigned p=8000;p<=8002;p++){ipv4(6,p);CHECK(classify(40,0x0800)==KER_EXCEPTION_SERVICE);}
    ipv4(6,7999);UNKNOWN(40);ipv4(17,5060);CHECK(classify(28,0x0800)==KER_EXCEPTION_SERVICE);
    memset(ip,0,sizeof(ip));UNKNOWN(10);PASS(test_ff_kni_proto_filter_ipv4_short);
    CHECK(classify(28,0x0806)==KER_EXCEPTION_UNKNOWN);PASS(test_ff_kni_proto_filter_non_ip_frame);
    enabled=false;ipv4(6,80);UNKNOWN(64);PASS(test_ff_kni_proto_filter_ipv4_tcp_kni_disabled);
    ipv4(17,53);UNKNOWN(64);PASS(test_ff_kni_proto_filter_ipv4_udp_kni_disabled);enabled=true;
    ipv4(6,80);ip[0]=0x4f;UNKNOWN(24);PASS(test_ff_kni_proto_filter_ipv4_oversized_ihl);
    ipv4(4,0);UNKNOWN(24);
    /* The same actual original-DPDK tunnel path must recognize a complete
     * inner packet; blanket rejection of all IPIP would not qualify. */
    ip[20]=0x45;ip[29]=6;ip[42]=0;ip[43]=80;CHECK(classify(60,0x0800)==KER_EXCEPTION_SERVICE);
    ip[43]=81;UNKNOWN(60);PASS(test_ff_kni_proto_filter_ipv4_ipip_recurse);
    enabled=false;ipv4(89,0);CHECK(classify(20,0x0800)==KER_EXCEPTION_OSPF);PASS(test_ff_kni_proto_filter_ipv4_ospf_returns_ospf);enabled=true;
    ipv4(6,80);UNKNOWN(25);PASS(test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_short);
    ipv4(17,53);UNKNOWN(25);PASS(test_ff_kni_proto_filter_ipv4_udp_kni_enabled_short);
    ipv4(6,80);CHECK(classify(40,0x0800)==KER_EXCEPTION_SERVICE);PASS(test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_match_returns_kni);
    ipv4(6,8080);UNKNOWN(40);PASS(test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_miss_returns_unknown);
    ipv4(17,53);CHECK(classify(28,0x0800)==KER_EXCEPTION_SERVICE);PASS(test_ff_kni_proto_filter_ipv4_udp_kni_enabled_match_returns_kni);
    enabled=false;
    for(unsigned type=133;type<=137;type++){ipv6(58,0);ip[40]=(unsigned char)type;CHECK(classify(48,0x86dd)==KER_EXCEPTION_NDP);}
    ipv6(58,0);ip[40]=128;CHECK(classify(48,0x86dd)!=KER_EXCEPTION_NDP);
    ipv6(17,0);CHECK(classify(48,0x86dd)!=KER_EXCEPTION_NDP);
    ipv6(58,0);ip[40]=135;CHECK(classify(48,0x0800)!=KER_EXCEPTION_NDP&&classify(44,0x86dd)!=KER_EXCEPTION_NDP);
    PASS(test_p3_ndp_classification);enabled=true;
    ipv6(6,80);CHECK(classify(60,0x86dd)==KER_EXCEPTION_SERVICE);
    ipv6(17,53);CHECK(classify(48,0x86dd)==KER_EXCEPTION_SERVICE);
    /* Original DPDK handles extension offsets; short final headers reject. */
    ipv6(0,0);ip[40]=17;ip[41]=0;ip[50]=0;ip[51]=53;CHECK(classify(56,0x86dd)==KER_EXCEPTION_SERVICE);
    CHECK(classify(52,0x86dd)==KER_EXCEPTION_UNKNOWN);
    ipv4(17,53);ip[6]=0x20;CHECK(classify(28,0x0800)==KER_EXCEPTION_FRAGMENT);
    /* Error messages go to both original stacks; echoes/unknowns keep policy routing. */
    ipv4(1,0);ip[20]=3;ip[21]=4;CHECK(classify(28,0x0800)==KER_EXCEPTION_ICMP_ERROR);
    CHECK(classify(27,0x0800)==KER_EXCEPTION_UNKNOWN);
    ip[20]=8;CHECK(classify(28,0x0800)==KER_EXCEPTION_UNKNOWN);
    ip[20]=99;CHECK(classify(28,0x0800)==KER_EXCEPTION_UNKNOWN);
    ipv6(58,0);ip[40]=2;CHECK(classify(48,0x86dd)==KER_EXCEPTION_ICMP_ERROR);
    CHECK(classify(47,0x86dd)==KER_EXCEPTION_UNKNOWN);
    ip[40]=128;CHECK(classify(48,0x86dd)==KER_EXCEPTION_UNKNOWN);
    ip[40]=200;CHECK(classify(48,0x86dd)==KER_EXCEPTION_UNKNOWN);
    struct ker_exception_filter retained=filter;
    for(unsigned i=0;i<4;i++){const char*bad[]={"65536","80-1","80,","-1"};CHECK(ker_exception_filter_init(&filter,bad[i],NULL)==-EINVAL&&!memcmp(&filter,&retained,sizeof(filter)));}
    CHECK(ker_exception_filter_init(&filter,"80","bad")==-EINVAL&&!memcmp(&filter,&retained,sizeof(filter)));
    unsigned char mpls[40]={0};mpls[12]=0x88;mpls[13]=0x47;mpls[32]=8;mpls[33]=6;
    struct rte_mbuf *not_arp=ker_worker_mbuf_from_bytes(pool,mpls,sizeof(mpls));CHECK(not_arp&&!ker_exception_arp(not_arp));rte_pktmbuf_free(not_arp);
    CHECK(!ker_exception_filter_init(&filter,NULL,NULL));ipv4(6,80);UNKNOWN(40);PASS(test_ff_kni_init_null_port_lists);
    CHECK(!rte_mempool_in_use_count(pool));rte_mempool_free(pool);CHECK(!rte_eal_cleanup());return 0;
}
