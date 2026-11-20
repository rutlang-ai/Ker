#include <ker/address-policy.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>

/* Only callback declarations/dispatch, not FreeBSD protocol processing. */
#define ff_in_pcbladdr ker_address_policy_upstream_select
#define ff_regist_pcblddr_fun ker_address_policy_upstream_register
#include "../../third_party/fstack-address-policy/address-runtime.inc"

static pthread_mutex_t policy_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t policy_changed = PTHREAD_COND_INITIALIZER;
static unsigned long policy_calls;
static int policy_replacing;
static _Thread_local unsigned policy_depth;

int ker_address_policy_register(ker_address_policy_fn callback)
{
    if (policy_depth) return EDEADLK;
    int cancel_state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
    pthread_mutex_lock(&policy_lock);
    while (policy_replacing) pthread_cond_wait(&policy_changed, &policy_lock);
    policy_replacing = 1;
    while (policy_calls) pthread_cond_wait(&policy_changed, &policy_lock);
    ff_regist_pcblddr_fun(callback);
    policy_replacing = 0;
    pthread_cond_broadcast(&policy_changed);
    pthread_mutex_unlock(&policy_lock);
    pthread_setcancelstate(cancel_state, NULL);
    return 0;
}

static void policy_leave(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&policy_lock);
    --policy_depth;
    if (!--policy_calls) pthread_cond_broadcast(&policy_changed);
    pthread_mutex_unlock(&policy_lock);
}

int ker_address_policy_select(uint16_t family, void *destination,
    uint16_t port, void *source)
{
    int result, cancel_state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
    pthread_mutex_lock(&policy_lock);
    /* A nested callback must be able to finish while a writer is waiting
     * for its outer call. It still sees the same original registration. */
    while (policy_replacing && !policy_depth)
        pthread_cond_wait(&policy_changed, &policy_lock);
    ++policy_calls;
    ++policy_depth;
    pthread_mutex_unlock(&policy_lock);
    pthread_cleanup_push(policy_leave, NULL);
    pthread_setcancelstate(cancel_state, NULL);
    result = ff_in_pcbladdr(family, destination, port, source);
    pthread_cleanup_pop(1);
    return result;
}
