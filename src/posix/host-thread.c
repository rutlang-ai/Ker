// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "host-thread.h"
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
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
void ker_native_host_thread_init(struct lkl_host_operations *ops)
{
    ops->tls_alloc = key_alloc;
    ops->tls_free = key_free;
    ops->tls_set = key_set;
    ops->tls_get = key_get;
}
