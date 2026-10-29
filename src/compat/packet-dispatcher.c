#include <ker/packet-dispatcher.h>
#include <errno.h>
#include <pthread.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
typedef ker_dispatcher_fn dispatch_func_t;
typedef ker_dispatcher_context_fn dispatch_func_context_t;
#define ff_dispatcher_context ker_dispatcher_context
#define ff_regist_packet_dispatcher ker_dispatcher_upstream_register
#define ff_regist_packet_dispatcher_context ker_dispatcher_upstream_register_context
#define ff_unregist_packet_dispatcher ker_dispatcher_upstream_unregister
#define ff_unregist_packet_dispatcher_context ker_dispatcher_upstream_unregister_context
#include "../../third_party/fstack-dispatcher/registration-runtime.inc"
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned long active;
static int replacing;
static _Thread_local unsigned depth;
static int change(int operation, ker_dispatcher_fn plain, ker_dispatcher_context_fn context)
{
    if (depth) return EDEADLK;
    int cancel_state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
    pthread_mutex_lock(&lock);
    while (replacing) pthread_cond_wait(&changed, &lock);
    replacing = 1;
    while (active) pthread_cond_wait(&changed, &lock);
    switch (operation) {
    case 0: ff_regist_packet_dispatcher(plain); break;
    case 1: ff_regist_packet_dispatcher_context(context); break;
    case 2: ff_unregist_packet_dispatcher(); break;
    case 3: ff_unregist_packet_dispatcher_context(); break;
    }
    replacing = 0;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
    pthread_setcancelstate(cancel_state, NULL);
    return 0;
}
int ker_packet_dispatcher_register(ker_dispatcher_fn callback) { return change(0, callback, NULL); }
int ker_packet_dispatcher_register_context(ker_dispatcher_context_fn callback) { return change(1, NULL, callback); }
int ker_packet_dispatcher_unregister(void) { return change(2, NULL, NULL); }
int ker_packet_dispatcher_unregister_context(void) { return change(3, NULL, NULL); }
static void leave(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&lock);
    --depth;
    if (!--active) pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
}
int ker_packet_dispatch(struct rte_mbuf *rtem, uint16_t *length,
    uint16_t queue_id, uint16_t nb_queues)
{
    if (!rtem || !length || !nb_queues || queue_id >= nb_queues) { errno = EINVAL; return -1; }
    int result, cancel_state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
    pthread_mutex_lock(&lock);
    while (replacing && !depth) pthread_cond_wait(&changed, &lock);
    ++active; ++depth;
    pthread_mutex_unlock(&lock);
    pthread_cleanup_push(leave, NULL);
    pthread_setcancelstate(cancel_state, NULL);
    int ret = queue_id;
    void *data = rte_pktmbuf_mtod(rtem, void *);
    uint16_t len = rte_pktmbuf_data_len(rtem);
    uint64_t cur_tsc, usr_cb_tsc = 0;
#include "../../third_party/fstack-dispatcher/call-runtime.inc"
    (void)usr_cb_tsc;
    *length = len;
    result = ret;
    pthread_cleanup_pop(1);
    return result;
}
