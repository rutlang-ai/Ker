// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "host-thread.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <lkl_host.h>

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
    ops->mutex_alloc = mutex_alloc;
    ops->mutex_free = mutex_free;
    ops->mutex_lock = mutex_lock;
    ops->mutex_unlock = mutex_unlock;
    ops->tls_alloc = key_alloc;
    ops->tls_free = key_free;
    ops->tls_set = key_set;
    ops->tls_get = key_get;
}
