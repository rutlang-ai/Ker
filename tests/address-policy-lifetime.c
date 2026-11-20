#define _GNU_SOURCE
#include <ker/address-policy.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <time.h>
#include "check.h"
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int entered, release_call, writer_started, writer_done;
static atomic_uint hits;
static _Thread_local int nested;
static void unlock(void *opaque) { CHECK(!pthread_mutex_unlock(opaque)); }
static int held(uint16_t family, void *destination, uint16_t port, void *source)
{
    (void)family; (void)destination; (void)port; (void)source;
    atomic_fetch_add(&hits, 1);
    CHECK(ker_address_policy_register(NULL) == EDEADLK);
    if (nested) return 19;
    CHECK(!pthread_mutex_lock(&lock));
    pthread_cleanup_push(unlock, &lock);
    entered = 1; CHECK(!pthread_cond_broadcast(&changed));
    while (!release_call) CHECK(!pthread_cond_wait(&changed, &lock));
    pthread_cleanup_pop(1);
    nested = 1;
    CHECK(ker_address_policy_select(2, NULL, 0, NULL) == 19);
    nested = 0;
    return 7;
}
static int replacement(uint16_t family, void *destination, uint16_t port, void *source)
{
    (void)family; (void)destination; (void)port; (void)source;
    return 23;
}
static void *invoke(void *unused)
{
    (void)unused;
    return (void *)(intptr_t)ker_address_policy_select(2, NULL, 0, NULL);
}
static void *replace(void *callback)
{
    CHECK(!pthread_mutex_lock(&lock));
    writer_started = 1; CHECK(!pthread_cond_broadcast(&changed));
    CHECK(!pthread_mutex_unlock(&lock));
    CHECK(!ker_address_policy_register(callback ? replacement : NULL));
    CHECK(!pthread_mutex_lock(&lock));
    writer_done = 1; CHECK(!pthread_cond_broadcast(&changed));
    CHECK(!pthread_mutex_unlock(&lock));
    return NULL;
}
static void barrier_case(int replace_callback)
{
    entered = release_call = writer_started = writer_done = 0;
    unsigned before = atomic_load(&hits);
    CHECK(!ker_address_policy_register(held));
    pthread_t reader, writer;
    CHECK(!pthread_create(&reader, NULL, invoke, NULL));
    CHECK(!pthread_mutex_lock(&lock));
    while (!entered) CHECK(!pthread_cond_wait(&changed, &lock));
    CHECK(!pthread_mutex_unlock(&lock));
    CHECK(!pthread_create(&writer, NULL, replace, (void *)(intptr_t)replace_callback));
    CHECK(!pthread_mutex_lock(&lock));
    while (!writer_started) CHECK(!pthread_cond_wait(&changed, &lock));
    struct timespec deadline; CHECK(!clock_gettime(CLOCK_REALTIME, &deadline));
    deadline.tv_nsec += 100000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_nsec -= 1000000000L; ++deadline.tv_sec; }
    while (!writer_done) {
        int result = pthread_cond_timedwait(&changed, &lock, &deadline);
        CHECK(result == 0 || result == ETIMEDOUT);
        if (result == ETIMEDOUT) break;
    }
    CHECK(!writer_done); /* previous callback must still own its registration */
    release_call = 1; CHECK(!pthread_cond_broadcast(&changed));
    CHECK(!pthread_mutex_unlock(&lock));
    void *result;
    CHECK(!pthread_join(reader, &result) && (intptr_t)result == 7);
    CHECK(!pthread_join(writer, &result) && result == NULL);
    CHECK(writer_done && atomic_load(&hits) == before+2);
    CHECK(ker_address_policy_select(2, NULL, 0, NULL) == (replace_callback ? 23 : 0));
    CHECK(atomic_load(&hits) == before+2);
}
int main(void)
{
    barrier_case(1); barrier_case(0);
    /* Deferred cancellation in a caller callback releases the registration
     * lease as well as the caller's own mutex. No leaked quiescence token. */
    entered = release_call = 0;
    CHECK(!ker_address_policy_register(held));
    pthread_t reader; CHECK(!pthread_create(&reader, NULL, invoke, NULL));
    CHECK(!pthread_mutex_lock(&lock));
    while (!entered) CHECK(!pthread_cond_wait(&changed, &lock));
    CHECK(!pthread_mutex_unlock(&lock));
    CHECK(!pthread_cancel(reader));
    void *result; CHECK(!pthread_join(reader, &result) && result == PTHREAD_CANCELED);
    CHECK(!ker_address_policy_register(NULL));
    CHECK(!ker_address_policy_select(2, NULL, 0, NULL));
    puts("PASS: replacement/unregister quiescence, nested calls, reentrant refusal and deferred cancellation");
    return 0;
}
