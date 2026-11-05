#define _GNU_SOURCE
#include "linux-selftest-runtime.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <pthread.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <stdatomic.h>
#include <time.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Original peers intentionally keep serving until process exit. Quiesce their
 * facade calls after upstream cleanup, before the in-process kernel is halted.
 * Timed select/poll slices below preserve their original wait/deadline while
 * allowing this exit barrier to stop admission without returning fake errors. */
static pthread_mutex_t io_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t io_changed = PTHREAD_COND_INITIALIZER;
static unsigned io_active;
static int io_closing;
static _Thread_local int io_finisher;
static void io_begin(void)
{
    pthread_mutex_lock(&io_lock);
    while (io_closing && !io_finisher) pthread_cond_wait(&io_changed, &io_lock);
    io_active++;
    pthread_mutex_unlock(&io_lock);
}
static void io_end(void)
{
    int error = errno;
    pthread_mutex_lock(&io_lock);
    io_active--;
    pthread_cond_broadcast(&io_changed);
    pthread_mutex_unlock(&io_lock);
    errno = error;
}
static void io_quiesce(void)
{
    pthread_mutex_lock(&io_lock);
    io_finisher = 1;
    io_closing = 1;
    while (io_active) pthread_cond_wait(&io_changed, &io_lock);
    pthread_mutex_unlock(&io_lock);
}

/* Test harness adaptation only. Protocol operations keep using the real
 * POSIX facade; namespace, administrative netlink and proc/tracefs setup
 * must refer to the same imported kernel as those sockets. */
static long call(unsigned op, unsigned long a, unsigned long b, unsigned long c,
                 unsigned long d, unsigned long e)
{
    long (*function)(unsigned, const unsigned long[6]) =
        dlsym(RTLD_DEFAULT, "ker_linux_selftest_call");
    if (!function) { errno = ENOSYS; return -1; }
    unsigned long args[6] = {a, b, c, d, e, 0};
    long result = function(op, args);
    if (result < 0) { errno = (int)-result; return -1; }
    return result;
}

static int native_path(const char *path)
{
    return !strncmp(path, "/proc/", 6) || !strncmp(path, "ksft-ftrace-", 12);
}

int __real_open(const char *, int, ...);
FILE *__real_fopen(const char *, const char *);
int __real_access(const char *, int);
char *__real_mkdtemp(char *);
int __real_rmdir(const char *);
int __real_socket(int, int, int);
ssize_t __real_send(int, const void *, size_t, int);
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

int __wrap_unshare(int flags)
{
    if (flags != CLONE_NEWNET) { errno = EOPNOTSUPP; return -1; }
    return (int)call(KER_TEST_UNSHARE, (unsigned long)flags, 0, 0, 0, 0);
}

int __wrap_setns(int fd, int flags)
{
    return (int)call(KER_TEST_SETNS, (unsigned long)fd, (unsigned long)flags, 0, 0, 0);
}

int __wrap_open(const char *path, int flags, ...)
{
    int mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap);
    }
    if (!native_path(path)) return __real_open(path, flags, mode);
    return (int)call(KER_TEST_OPEN, (unsigned long)path, (unsigned long)flags, (unsigned long)mode, 0, 0);
}

/* LKL calls are not host pthread cancellation points. Keep trace_pipe reads
 * nonblocking inside Linux and wait at a host cancellation point, so upstream's
 * pthread_cancel/join collector lifecycle remains valid. No trace is invented. */
static ssize_t trace_read(void *cookie, char *bytes, size_t length)
{
    int fd = *(int *)cookie;
    for (;;) {
        int previous;
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
        ssize_t result = read(fd, bytes, length);
        int error = errno;
        pthread_setcancelstate(previous, NULL);
        pthread_testcancel();
        if (result >= 0 || error != EAGAIN) { errno = error; return result; }
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
}

static int trace_close(void *cookie)
{
    int result = close(*(int *)cookie);
    free(cookie);
    return result;
}

FILE *__wrap_fopen(const char *path, const char *mode)
{
    if (!native_path(path)) return __real_fopen(path, mode);
    int flags;
    if (!strcmp(mode, "r")) flags = O_RDONLY;
    else if (!strcmp(mode, "r+")) flags = O_RDWR;
    else if (!strcmp(mode, "w")) flags = O_WRONLY | O_TRUNC;
    else if (!strcmp(mode, "a")) flags = O_WRONLY | O_APPEND;
    else { errno = EOPNOTSUPP; return NULL; }
    int trace_pipe = strstr(path, "/trace_pipe") != NULL;
    if (trace_pipe) flags |= O_NONBLOCK;
    int fd = (int)call(KER_TEST_OPEN, (unsigned long)path, (unsigned long)flags, 0, 0, 0);
    if (fd < 0) return NULL;
    FILE *file;
    if (trace_pipe) {
        int *cookie = malloc(sizeof(*cookie));
        if (!cookie) { close(fd); return NULL; }
        *cookie = fd;
        cookie_io_functions_t functions = {.read = trace_read, .close = trace_close};
        file = fopencookie(cookie, "r", functions);
        if (!file) free(cookie);
    } else file = fdopen(fd, mode);
    if (!file) { int error = errno; close(fd); errno = error; }
    return file;
}

int __wrap_access(const char *path, int mode)
{
    if (!native_path(path)) return __real_access(path, mode);
    return (int)call(KER_TEST_ACCESS, (unsigned long)path, (unsigned long)mode, 0, 0, 0);
}

char *__wrap_mkdtemp(char *path)
{
    if (!native_path(path)) return __real_mkdtemp(path);
    size_t length = strlen(path);
    if (length < 6 || strcmp(path + length - 6, "XXXXXX")) { errno = EINVAL; return NULL; }
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        unsigned char random[6];
        if (syscall(SYS_getrandom, random, sizeof(random), 0) != sizeof(random)) return NULL;
        for (unsigned i = 0; i < 6; i++) path[length - 6 + i] = "abcdefghijklmnopqrstuvwxyz0123456789"[random[i] % 36];
        if (!call(KER_TEST_MKDIR, (unsigned long)path, 0700, 0, 0, 0)) return path;
        if (errno != EEXIST) return NULL;
    }
    errno = EEXIST;
    return NULL;
}

int __wrap_rmdir(const char *path)
{
    if (!native_path(path)) return __real_rmdir(path);
    return (int)call(KER_TEST_RMDIR, (unsigned long)path, 0, 0, 0, 0);
}

int __wrap_mount(const char *source, const char *target, const char *type,
                 unsigned long flags, const void *data)
{
    if (strcmp(type, "tracefs") || !native_path(target)) { errno = EOPNOTSUPP; return -1; }
    return (int)call(KER_TEST_MOUNT, (unsigned long)source, (unsigned long)target,
                     (unsigned long)type, flags, (unsigned long)data);
}

int __wrap_umount(const char *target)
{
    if (!native_path(target)) { errno = EOPNOTSUPP; return -1; }
    return (int)call(KER_TEST_UMOUNT, (unsigned long)target, 0, 0, 0, 0);
}

int __wrap_socket(int domain, int type, int protocol)
{
    if (domain == AF_NETLINK)
        return (int)call(KER_TEST_NETLINK, (unsigned long)type, (unsigned long)protocol, 0, 0, 0);
    io_begin();
    int fd = __real_socket(domain, type, protocol);
    if (fd >= 0 && (domain == AF_INET || domain == AF_INET6)) {
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(fd) != 1) _exit(126);
    }
    io_end();
    return fd;
}

static int rewrite_links(void *bytes, int length);

static int rewrite_linkinfo(void *bytes, int length)
{
    int remaining = length;
    int veth = 0;
    for (struct rtattr *a = bytes; RTA_OK(a, remaining); a = RTA_NEXT(a, remaining))
        if ((a->rta_type & NLA_TYPE_MASK) == IFLA_INFO_KIND && RTA_PAYLOAD(a) >= 5 &&
            !memcmp(RTA_DATA(a), "veth\0", 5)) veth = 1;
    if (!veth) return 0;
    for (struct rtattr *a = bytes; RTA_OK(a, length); a = RTA_NEXT(a, length)) {
        if ((a->rta_type & NLA_TYPE_MASK) != IFLA_INFO_DATA) continue;
        int peers = RTA_PAYLOAD(a);
        for (struct rtattr *p = RTA_DATA(a); RTA_OK(p, peers); p = RTA_NEXT(p, peers)) {
            if ((p->rta_type & NLA_TYPE_MASK) != VETH_INFO_PEER) continue;
            if (RTA_PAYLOAD(p) < sizeof(struct ifinfomsg)) { errno = EINVAL; return -1; }
            if (rewrite_links((char *)RTA_DATA(p) + sizeof(struct ifinfomsg),
                              RTA_PAYLOAD(p) - (int)sizeof(struct ifinfomsg))) return -1;
        }
    }
    return 0;
}

static int rewrite_links(void *bytes, int length)
{
    for (struct rtattr *a = bytes; RTA_OK(a, length); a = RTA_NEXT(a, length)) {
        int type = a->rta_type & NLA_TYPE_MASK;
        if (type == IFLA_NET_NS_FD) {
            if (RTA_PAYLOAD(a) != sizeof(int)) { errno = EINVAL; return -1; }
            int fd;
            memcpy(&fd, RTA_DATA(a), sizeof(fd));
            long native = call(KER_TEST_FD_NUMBER, (unsigned long)fd, 0, 0, 0, 0);
            if (native < 0) return -1;
            fd = (int)native;
            memcpy(RTA_DATA(a), &fd, sizeof(fd));
        } else if (type == IFLA_LINKINFO && rewrite_linkinfo(RTA_DATA(a), RTA_PAYLOAD(a))) return -1;
    }
    return 0;
}

ssize_t __wrap_send(int fd, const void *bytes, size_t length, int flags)
{
    int domain = 0;
    socklen_t size = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &size) || domain != AF_NETLINK)
    {
        io_begin();
        ssize_t result = __real_send(fd, bytes, length, flags);
        io_end();
        return result;
    }
    if (length > 65536) { errno = EMSGSIZE; return -1; }
    void *copy = malloc(length);
    if (!copy) return -1;
    memcpy(copy, bytes, length);
    int remaining = (int)length;
    for (struct nlmsghdr *h = copy; NLMSG_OK(h, remaining); h = NLMSG_NEXT(h, remaining)) {
        if (h->nlmsg_type != RTM_NEWLINK) continue;
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg)) ||
            rewrite_links((char *)NLMSG_DATA(h) + sizeof(struct ifinfomsg),
                          h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)))) {
            int error = errno ? errno : EINVAL; free(copy); errno = error; return -1;
        }
    }
    io_begin();
    ssize_t result = __real_send(fd, copy, length, flags);
    io_end();
    int error = errno;
    free(copy);
    errno = error;
    return result;
}

struct thread_start { void *(*function)(void *); void *argument; int ns; };

static void *thread_start(void *opaque)
{
    struct thread_start value = *(struct thread_start *)opaque;
    free(opaque);
    if (__wrap_setns(value.ns, CLONE_NEWNET)) _exit(126);
    close(value.ns);
    return value.function(value.argument);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                          void *(*function)(void *), void *argument)
{
    struct thread_start *start = malloc(sizeof(*start));
    if (!start) return ENOMEM;
    int ns = (int)call(KER_TEST_OPEN, (unsigned long)"/proc/thread-self/ns/net", O_RDONLY, 0, 0, 0);
    if (ns < 0) { int error = errno; free(start); return error; }
    *start = (struct thread_start){function, argument, ns};
    int error = __real_pthread_create(thread, attributes, thread_start, start);
    if (error) { close(ns); free(start); }
    return error;
}

static atomic_ulong ao_options;
int __real_setsockopt(int, int, int, const void *, socklen_t);
int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t size)
{
    io_begin();
    int result = __real_setsockopt(fd, level, option, value, size);
    io_end();
    if (level == 6 && option >= 38 && option <= 42)
        atomic_fetch_add_explicit(&ao_options, 1, memory_order_relaxed);
    return result;
}

static void report_ao_options(void)
{
    char line[128];
    int size = snprintf(line, sizeof(line), "KER_TCP_AO_OPTIONS %lu\n", atomic_load(&ao_options));
    if (size > 0 && (size_t)size < sizeof(line)) (void)syscall(SYS_write, 2, line, (size_t)size);
}

/* Upstream aolib calls exit() from its ELF destructor. That recursive glibc
 * exit skips remaining ELF finalizers, including the facade's. Finish its real
 * lifecycle here after aolib's own cleanup, before forwarding the same status. */
static atomic_bool upstream_cleanup_finished;
static void cleanup_finished(void)
{
    atomic_store_explicit(&upstream_cleanup_finished, 1, memory_order_release);
}
void __real_test_add_destructor(void (*function)(void));
void __wrap_test_add_destructor(void (*function)(void))
{
    static int registered;
    if (!registered) {
        registered = 1;
        __real_test_add_destructor(cleanup_finished);
    }
    __real_test_add_destructor(function);
}

_Noreturn void __real_exit(int);
_Noreturn void __wrap_exit(int status)
{
    if (atomic_load_explicit(&upstream_cleanup_finished, memory_order_acquire)) {
        static atomic_flag claimed = ATOMIC_FLAG_INIT;
        if (atomic_flag_test_and_set_explicit(&claimed, memory_order_acq_rel)) {
            /* Another original peer may exit at the same time. Only the owner
             * may finalize; the process will terminate after that owner exits. */
            for (;;) { struct timespec delay = {1, 0}; nanosleep(&delay, NULL); }
        }
        io_quiesce();
        report_ao_options();
        if (call(KER_TEST_FINALIZE, 0, 0, 0, 0, 0)) status = 125;
    }
    __real_exit(status);
}

#define GUARDED(type, name, signature, arguments) \
    type __real_##name signature; \
    type __wrap_##name signature { io_begin(); type result = __real_##name arguments; io_end(); return result; }
GUARDED(ssize_t, recv, (int fd, void *bytes, size_t size, int flags), (fd, bytes, size, flags))
GUARDED(ssize_t, sendto, (int fd, const void *bytes, size_t size, int flags, const struct sockaddr *addr, socklen_t length), (fd, bytes, size, flags, addr, length))
GUARDED(int, accept, (int fd, struct sockaddr *addr, socklen_t *length), (fd, addr, length))
GUARDED(int, bind, (int fd, const struct sockaddr *addr, socklen_t length), (fd, addr, length))
GUARDED(int, connect, (int fd, const struct sockaddr *addr, socklen_t length), (fd, addr, length))
GUARDED(int, listen, (int fd, int backlog), (fd, backlog))
GUARDED(int, close, (int fd), (fd))
GUARDED(int, getsockopt, (int fd, int level, int option, void *value, socklen_t *size), (fd, level, option, value, size))

static long long monotonic_us(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000000 + now.tv_nsec / 1000;
}

int __real_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int __wrap_select(int count, fd_set *reads, fd_set *writes, fd_set *errors, struct timeval *timeout)
{
    fd_set initial[3], current[3];
    fd_set *sets[3] = {reads, writes, errors};
    for (int i = 0; i < 3; i++) if (sets[i]) initial[i] = *sets[i];
    long long deadline = timeout ? monotonic_us() + timeout->tv_sec * 1000000LL + timeout->tv_usec : -1;
    for (;;) {
        io_begin();
        long long left = deadline < 0 ? 50000 : deadline - monotonic_us();
        if (left < 0) left = 0;
        if (left > 50000) left = 50000;
        struct timeval slice = {.tv_sec = 0, .tv_usec = left};
        for (int i = 0; i < 3; i++) if (sets[i]) current[i] = initial[i];
        int result = __real_select(count, reads ? &current[0] : NULL, writes ? &current[1] : NULL,
                                   errors ? &current[2] : NULL, &slice);
        io_end();
        if (result || (deadline >= 0 && monotonic_us() >= deadline)) {
            /* A waiter ready during exit must park before original test code resumes. */
            io_begin(); io_end();
            for (int i = 0; i < 3; i++) if (sets[i]) *sets[i] = current[i];
            if (timeout) {
                left = deadline - monotonic_us();
                if (left < 0) left = 0;
                timeout->tv_sec = left / 1000000; timeout->tv_usec = left % 1000000;
            }
            return result;
        }
    }
}

int __real_poll(struct pollfd *, nfds_t, int);
int __wrap_poll(struct pollfd *fds, nfds_t count, int timeout)
{
    long long deadline = timeout < 0 ? -1 : monotonic_us() + timeout * 1000LL;
    for (;;) {
        io_begin();
        long long left = deadline < 0 ? 50 : (deadline - monotonic_us() + 999) / 1000;
        if (left < 0) left = 0;
        int result = __real_poll(fds, count, left > 50 ? 50 : (int)left);
        io_end();
        if (result || (deadline >= 0 && monotonic_us() >= deadline)) {
            io_begin(); io_end();
            return result;
        }
    }
}
