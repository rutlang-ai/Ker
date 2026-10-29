/* Application-side supervision using unchanged upstream nginx policy and Ker
 * runtime primitives. This translation unit is never linked into Ker libraries.
 * Workers must use the shared gate; the caller serializes control operations. */
#define _GNU_SOURCE
#include "reload-controller-policy.h"
#include <ker/reload.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
int example_reload_next(int state, int event) { return ngx_ff_reload_fsm_next(state,event); }
const char *example_reload_state_name(int state) { return ngx_ff_reload_fsm_state_name(state); }
static int dead(const struct example_reload_worker *worker)
{
    struct pollfd fd = {.fd=worker->pidfd,.events=POLLIN};
    int result; do result = poll(&fd,1,0); while (result < 0 && errno == EINTR);
    if (result < 0) return -errno;
    if (fd.revents & POLLNVAL) return -EBADF;
    return result && (fd.revents & POLLIN) ? 1 : 0;
}
static int gone(const struct example_reload_worker *workers,unsigned count)
{
    for (unsigned i=0;i<count;i++) { int result=dead(&workers[i]); if (result <= 0) return result; }
    return 1;
}
static int parked(const struct example_reload_worker *workers,unsigned count,uint32_t epoch)
{
    for (unsigned i=0;i<count;i++) {
        int result=dead(&workers[i]); if (result < 0) return result;
        if (!result && !ker_reload_parked(workers[i].slot,epoch)) return 0;
    }
    return 1;
}
static int require_proof(int proof) { return proof > 0 ? 0 : proof < 0 ? proof : -EAGAIN; }
static void close_workers(struct example_reload_worker *workers,unsigned count)
{
    for (unsigned i=0;i<count;i++) { close(workers[i].pidfd); workers[i].pidfd=-1; }
}
int example_reload_controller_init(struct example_reload_controller *c,const struct example_reload_ops *ops,void *context)
{
    if (!c || !ops || !ops->quiescent || !ops->drained || !ops->retire) return -EINVAL;
    memset(c,0,sizeof(*c)); c->state=NGX_FF_RELOAD_T0_IDLE; c->ops=*ops; c->context=context; return 0;
}
int example_reload_controller_add(struct example_reload_controller *c,unsigned slot,int pid,unsigned generation)
{
    if (!c || slot >= EXAMPLE_RELOAD_WORKERS || pid <= 0 || generation > 1) return -EINVAL;
    if (c->rollback) return -EBUSY;
    struct ker_reload_runtime v; int result=ker_reload_runtime_view(&v); if (result) return result;
    if (!v.attached) return -ENOTCONN;
    struct example_reload_worker *workers; unsigned *count;
    if (c->state == NGX_FF_RELOAD_T0_IDLE && generation == (unsigned)v.active_generation) {
        workers=c->old; count=&c->old_count;
    } else if (c->state == NGX_FF_RELOAD_T1_GNEW_SPAWN && generation == c->target) {
        workers=c->next; count=&c->next_count;
    } else return -EINVAL;
    if (*count == EXAMPLE_RELOAD_WORKERS) return -ENOSPC;
    for (unsigned group=0;group<2;group++) {
        const struct example_reload_worker *known=group ? c->next : c->old;
        unsigned n=group ? c->next_count : c->old_count;
        for (unsigned i=0;i<n;i++) if (known[i].slot == slot || known[i].pid == pid) return -EEXIST;
    }
    int fd=(int)syscall(SYS_pidfd_open,pid,0); if (fd < 0) return -errno;
    struct example_reload_worker worker={slot,pid,fd};
    result=dead(&worker); if (result) { close(fd); return result < 0 ? result : -ESRCH; }
    workers[(*count)++]=worker; return 0;
}
int example_reload_controller_release(struct example_reload_controller *c)
{
    if (!c || c->state != NGX_FF_RELOAD_T2_HANDOVER || c->rollback) return -EINVAL;
    if (c->released) return 0;
    int result=require_proof(parked(c->old,c->old_count,c->park)); if (result) return result;
    result=require_proof(c->ops.quiescent(c->context)); if (result) return result;
    result=ker_reload_rx_release((int)c->target);
    if (!result) c->released=1;
    return result;
}
int example_reload_controller_event(struct example_reload_controller *c,int event)
{
    if (!c) return -EINVAL;
    int next=example_reload_next(c->state,event), result;
    if (next == NGX_FF_RELOAD_T_MAX) return -EINVAL;
    if (c->rollback && next != NGX_FF_RELOAD_T_ERROR) return -EBUSY;
    struct ker_reload_runtime v;
    if ((result=ker_reload_runtime_view(&v))) return result;
    if (!v.attached) return -ENOTCONN;
    switch (next) {
    case NGX_FF_RELOAD_T1_GNEW_SPAWN:
        if (!c->old_count) return -EINVAL;
        if ((result=ker_reload_round_begin(&c->round,&c->target))) return result;
        break;
    case NGX_FF_RELOAD_T2_HANDOVER:
        if (!c->next_count) return -EAGAIN;
        for (unsigned i=0;i<c->next_count;i++) {
            result=dead(&c->next[i]); if (result) return result < 0 ? result : -ESRCH;
            if (!ker_reload_ready_matches(c->next[i].slot,c->next[i].pid,c->round)) return -EAGAIN;
        }
        if ((result=ker_reload_rx_mark(v.rx_owner,1))) return result;
        if ((result=ker_reload_park_arm(&c->park))) return result;
        c->released=0;
        break;
    case NGX_FF_RELOAD_T3_DRAIN:
        if (!c->released || v.rx_owner != (int)c->target || v.rx_stopped) return -EAGAIN;
        if ((result=require_proof(parked(c->old,c->old_count,c->park)))) return result;
        break;
    case NGX_FF_RELOAD_T4_DRAIN_DONE:
        if ((result=require_proof(c->ops.drained(c->context)))) return result;
        break;
    case NGX_FF_RELOAD_T5_GOLD_QUIT:
        if ((result=require_proof(c->ops.quiescent(c->context)))) return result;
        if ((result=c->ops.retire(c->context,c->old,c->old_count))) return result;
        break;
    case NGX_FF_RELOAD_T_ERROR:
        if (!c->rollback) {
            if ((result=ker_reload_rx_mark(v.rx_owner,1))) return result;
            if ((result=ker_reload_park_arm(&c->rollback))) return result;
        }
        if ((result=require_proof(parked(c->old,c->old_count,c->rollback)))) return result;
        if ((result=require_proof(parked(c->next,c->next_count,c->rollback)))) return result;
        if ((result=require_proof(c->ops.quiescent(c->context)))) return result;
        if ((result=c->ops.retire(c->context,c->next,c->next_count))) return result;
        if ((result=ker_reload_round_finish(0))) return result;
        c->rollback=0;
        break;
    case NGX_FF_RELOAD_T0_IDLE:
        if ((result=require_proof(c->ops.quiescent(c->context)))) return result;
        if (event == NGX_FF_RELOAD_EV_GOLD_EXITED) {
            if ((result=require_proof(gone(c->old,c->old_count)))) return result;
            if (v.rx_owner != (int)c->target || v.rx_stopped) return -EAGAIN;
            if ((result=ker_reload_round_finish(1))) return result;
            close_workers(c->old,c->old_count);
            memcpy(c->old,c->next,c->next_count*sizeof(c->old[0])); c->old_count=c->next_count; c->next_count=0;
        } else {
            if (v.reload_active || v.rx_owner != v.active_generation || v.rx_stopped) return -EAGAIN;
            if ((result=require_proof(gone(c->next,c->next_count)))) return result;
            close_workers(c->next,c->next_count); c->next_count=0;
        }
        break;
    default: return -EINVAL;
    }
    c->state=next; return 0;
}
int example_reload_controller_destroy(struct example_reload_controller *c)
{
    if (!c) return -EINVAL;
    int result=require_proof(gone(c->old,c->old_count)); if (result) return result;
    result=require_proof(gone(c->next,c->next_count)); if (result) return result;
    close_workers(c->old,c->old_count); close_workers(c->next,c->next_count); c->old_count=c->next_count=0; return 0;
}
