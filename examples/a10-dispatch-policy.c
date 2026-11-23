#define _GNU_SOURCE
#include "a10-dispatch-policy.h"
#include <ker/peer-dispatcher.h>
#include <ker/reload.h>
#include <errno.h>
#include <string.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#define FF_DISPATCH_PEER KER_DISPATCH_PEER
#define ff_dispatcher_context ker_dispatcher_context
#include "a10-classifier-source.inc"
#undef ff_dispatcher_context
#undef FF_DISPATCH_PEER

int example_a10_classifier(void *data,uint16_t *length,uint16_t queue,
    uint16_t queues,struct ker_dispatcher_context context)
{
    /* Keep the original valid-fixture classifier unchanged. Bound its header
     * reads before calling it; unparsable inputs follow its local-input policy.
     * This profile supports a contiguous header and at most one inline VLAN. */
    if(!data || !length || *length<54)return queue;
    const uint8_t *p=data;
    unsigned offset=14;
    uint16_t type=(uint16_t)((p[12]<<8)|p[13]);
    if(type==0x8100){
        if(*length<58)return queue;
        type=(uint16_t)((p[16]<<8)|p[17]);offset=18;
    }
    if(type!=0x0800)return queue;
    unsigned ihl=(p[offset]&15u)*4u;
    if(ihl<20 || *length<offset+ihl+20)return queue;
    unsigned thl=(p[offset+ihl+12]>>4)*4u;
    if(thl<20 || *length<offset+ihl+thl)return queue;
    return it_flow_dispatcher(data,length,queue,queues,context);
}
int example_a10_parked_input(struct rte_ring *ring,unsigned budget,
    example_a10_input_fn input,void *argument)
{
    if(!ring || !budget || budget>32 || !input)return -EINVAL;
    struct ker_reload_runtime view;
    int result=ker_reload_runtime_view(&view);if(result)return result;
    if(!view.attached)return -ENOTCONN;
    if(view.rx_stopped)return -EAGAIN;
    if(ker_reload_rx_allowed())return 0;
    struct rte_mbuf *packets[32];
    unsigned count=rte_ring_dequeue_burst(ring,(void **)packets,budget,NULL);
    /* Software drain enters the chosen application input directly. Running
     * the classifier again would recirculate a miss back into the peer ring. */
    for(unsigned i=0;i<count;i++)input(packets[i],argument);
    return (int)count;
}
