/* SPDX-License-Identifier: BSD-3-Clause */
#define _POSIX_C_SOURCE 200809L
#include "session-peer-drain.h"

#include <assert.h>
#include <stdint.h>

struct scripted_dequeue {
    const int *results;
    unsigned count;
    unsigned calls;
    int repeated;
};

static int dequeue_script(void *opaque)
{
    struct scripted_dequeue *script=opaque;
    script->calls++;
    if(script->results) {
        unsigned index=script->calls-1;
        return index<script->count?script->results[index]:-EUCLEAN;
    }
    return script->repeated;
}

static struct timespec deadline_after(long milliseconds)
{
    struct timespec deadline;
    assert(clock_gettime(CLOCK_MONOTONIC,&deadline)==0);
    deadline.tv_sec+=milliseconds/1000;
    deadline.tv_nsec+=(milliseconds%1000)*1000000L;
    if(deadline.tv_nsec>=1000000000L) { deadline.tv_sec++; deadline.tv_nsec-=1000000000L; }
    return deadline;
}

int main(void)
{
    const int transient_then_packet[]={-EBUSY,-EBUSY,1,0};
    struct scripted_dequeue transient={.results=transient_then_packet,.count=4};
    struct timespec deadline=deadline_after(100);
    assert(ker_session_peer_dequeue_until(dequeue_script,&transient,&deadline)==1);
    assert(ker_session_peer_dequeue_until(dequeue_script,&transient,&deadline)==0);
    assert(transient.calls==4);

    struct scripted_dequeue empty={.results=(const int[]){0},.count=1};
    deadline=deadline_after(100);
    assert(ker_session_peer_dequeue_until(dequeue_script,&empty,&deadline)==0);
    assert(empty.calls==1);

    struct scripted_dequeue permanent_busy={.repeated=-EBUSY};
    deadline=deadline_after(5);
    assert(ker_session_peer_dequeue_until(dequeue_script,&permanent_busy,&deadline)==-ETIMEDOUT);
    assert(permanent_busy.calls>1);

    struct scripted_dequeue permanent_error={.results=(const int[]){-EPROTO},.count=1};
    deadline=deadline_after(100);
    assert(ker_session_peer_dequeue_until(dequeue_script,&permanent_error,&deadline)==-EPROTO);
    assert(permanent_error.calls==1);
    return 0;
}
