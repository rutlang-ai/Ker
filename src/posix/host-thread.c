// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "host-thread.h"
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdio.h>
#include <lkl_host.h>

/* Keep pthread start-argument ownership in Ker: the pinned host callback
 * leaks its wrapper if pthread_create fails. No Linux scheduler code changes. */
struct ker_thread_start { void (*routine)(void *); void *argument; };
static void *thread_start(void *opaque)
{
    struct ker_thread_start start = *(struct ker_thread_start *)opaque;
    free(opaque);
    start.routine(start.argument);
    return NULL;
}
static lkl_thread_t thread_create(void (*routine)(void *), void *argument)
{
    struct ker_thread_start *start = malloc(sizeof(*start));
    if (!start) return 0;
    *start = (struct ker_thread_start){.routine = routine, .argument = argument};
    pthread_t thread;
    int error = pthread_create(&thread, NULL, thread_start, start);
    if (error) {
        free(start);
        errno = error;
        return 0;
    }
    return (lkl_thread_t)thread;
}
/* The pinned POSIX host tsd_alloc dereferences its allocation before checking
 * failure. Keep the fix in Ker, using a private key representation and the
 * same pthread TLS semantics (including destructors) as the original table. */
struct ker_tls_key { pthread_key_t key; };
static struct lkl_tls_key *key_alloc(void (*destructor)(void *))
{
    struct ker_tls_key *key = malloc(sizeof(*key));
    if (!key) return NULL;
    int error = pthread_key_create(&key->key, destructor);
    if (error) {
        free(key);
        errno = error;
        return NULL;
    }
    return (struct lkl_tls_key *)key;
}
static void key_free(struct lkl_tls_key *opaque)
{
    struct ker_tls_key *key = (struct ker_tls_key *)opaque;
    pthread_key_delete(key->key);
    free(key);
}
static int key_set(struct lkl_tls_key *opaque, void *value)
{
    struct ker_tls_key *key = (struct ker_tls_key *)opaque;
    int error = pthread_setspecific(key->key, value);
    if (!error) return 0;
    errno = error;
    return -1;
}
static void *key_get(struct lkl_tls_key *opaque)
{
    struct ker_tls_key *key = (struct ker_tls_key *)opaque;
    return pthread_getspecific(key->key);
}
/* A failed wait/post cannot be reported by these void callbacks. Preserve
 * real POSIX semaphore semantics, retry interruptions, and stop on other errors. */
struct ker_sem { sem_t value; };
static void semaphore_check(int result)
{
    if (result) {
        perror("ker: host semaphore");
        abort();
    }
}
static struct lkl_sem *semaphore_alloc(int count)
{
    if (count < 0) { errno = EINVAL; return NULL; }
    struct ker_sem *sem = malloc(sizeof(*sem));
    if (!sem) return NULL;
    if (sem_init(&sem->value, 0, (unsigned int)count)) {
        int error = errno;
        free(sem);
        errno = error;
        return NULL;
    }
    return (struct lkl_sem *)sem;
}
static void semaphore_free(struct lkl_sem *opaque)
{
    struct ker_sem *sem = (struct ker_sem *)opaque;
    semaphore_check(sem_destroy(&sem->value));
    free(sem);
}
static void semaphore_up(struct lkl_sem *opaque)
{
    struct ker_sem *sem = (struct ker_sem *)opaque;
    semaphore_check(sem_post(&sem->value));
}
static void semaphore_down(struct lkl_sem *opaque)
{
    struct ker_sem *sem = (struct ker_sem *)opaque;
    int result;
    do { result = sem_wait(&sem->value); } while (result && errno == EINTR);
    semaphore_check(result);
}
/* The pinned host mutex allocator logs initialization errors but returns the
 * unusable object, and never destroys its attributes. Own the opaque mutex
 * representation here so every allocation failure has a complete unwind. */
struct ker_mutex { pthread_mutex_t value; };
static void mutex_check(int error)
{
    if (error) {
        errno = error;
        perror("ker: host mutex");
        abort(); /* These void callbacks cannot report synchronization failure. */
    }
}
static struct lkl_mutex *mutex_alloc(int recursive)
{
    struct ker_mutex *mutex = malloc(sizeof(*mutex));
    if (!mutex) return NULL;
    pthread_mutexattr_t attributes;
    int error = pthread_mutexattr_init(&attributes);
    if (error) goto fail;
    if (recursive)
        error = pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_RECURSIVE);
#ifdef DEBUG
    else
        error = pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_ERRORCHECK);
#endif
    int initialized = 0;
    if (!error) {
        error = pthread_mutex_init(&mutex->value, &attributes);
        initialized = !error;
    }
    int destroy_error = pthread_mutexattr_destroy(&attributes);
    if (!error) error = destroy_error;
    if (!error) return (struct lkl_mutex *)mutex;
    if (initialized) mutex_check(pthread_mutex_destroy(&mutex->value));
fail:
    free(mutex);
    errno = error;
    return NULL;
}
static void mutex_lock(struct lkl_mutex *opaque)
{
    struct ker_mutex *mutex = (struct ker_mutex *)opaque;
    mutex_check(pthread_mutex_lock(&mutex->value));
}
static void mutex_unlock(struct lkl_mutex *opaque)
{
    struct ker_mutex *mutex = (struct ker_mutex *)opaque;
    mutex_check(pthread_mutex_unlock(&mutex->value));
}
static void mutex_free(struct lkl_mutex *opaque)
{
    struct ker_mutex *mutex = (struct ker_mutex *)opaque;
    mutex_check(pthread_mutex_destroy(&mutex->value));
    free(mutex);
}
void ker_native_host_thread_init(struct lkl_host_operations *ops)
{
    ops->sem_alloc = semaphore_alloc;
    ops->sem_free = semaphore_free;
    ops->sem_up = semaphore_up;
    ops->sem_down = semaphore_down;
    ops->thread_create = thread_create;
    ops->mutex_alloc = mutex_alloc;
    ops->mutex_free = mutex_free;
    ops->mutex_lock = mutex_lock;
    ops->mutex_unlock = mutex_unlock;
    ops->tls_alloc = key_alloc;
    ops->tls_free = key_free;
    ops->tls_set = key_set;
    ops->tls_get = key_get;
}
