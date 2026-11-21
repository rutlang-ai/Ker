#define _GNU_SOURCE
#include "../../src/posix/fstack-socket-bridge.c"
#include "../../src/posix/lkl-overlay/arch/lkl/include/asm/ker-host-usercopy.h"
#include <assert.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>

struct ker_sb_preload_epoll_context_ref {
    void *context;
    ker_sb_preload_epoll_fd_close_fn fd_close;
    ker_sb_preload_epoll_context_destroy_fn destroy;
    uint64_t generation;
    size_t refs;
};
struct fake_epoll { int fd; int broker_fd; struct ker_sb_preload_epoll_context_ref *context; };
static struct fake_epoll epolls[128];
static size_t epoll_count;
static int managed[4096];
static int private_fds[4096];
static int interrupt_blocking_wait;
static int error_queue_fd=-1;
static int shutdown_state_fd=-1;
static uint32_t shutdown_state_flags;
static int old_snapshot_version_fd=-1;
static int retry_eagain_fd=-1, retry_eagain_remaining;
static int persistent_eagain_fd=-1, persistent_eagain_calls;
static int inject_queue=-1, inject_snapshot_fd=-1;
static struct kevent inject_change;
static struct ker_socket_client fake_client;
static pthread_once_t fake_lock_once=PTHREAD_ONCE_INIT;
static pthread_mutex_t fake_lock;
static _Thread_local unsigned fake_lock_depth;
static void fake_lock_init(void)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr,PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&fake_lock,&attr);
    pthread_mutexattr_destroy(&attr);
}

static struct fake_epoll *find_epoll(int fd)
{
    for (size_t i = 0; i < epoll_count; ++i)
        if (epolls[i].fd == fd) return &epolls[i];
    return NULL;
}
static void release_context(struct ker_sb_preload_epoll_context_ref *r)
{
    if (r && --r->refs == 0) { r->destroy(r->context); free(r); }
}
void ker_sb_preload_lock(void)
{
    pthread_once(&fake_lock_once,fake_lock_init);
    if (fake_lock_depth++==0) pthread_mutex_lock(&fake_lock);
}
void ker_sb_preload_unlock(void)
{
    assert(fake_lock_depth);
    if (--fake_lock_depth==0) pthread_mutex_unlock(&fake_lock);
}
int ker_sb_preload_runtime_ready(void) { return 1; }
int ker_sb_preload_epoll_create_locked(int flags)
{
    int fd = (int)syscall(SYS_epoll_create1, flags);
    if (fd >= 0) epolls[epoll_count++] = (struct fake_epoll){fd, fd, NULL};
    return fd;
}
int ker_sb_preload_duplicate_epoll_locked(int oldfd, int minimum, bool cloexec)
{
    struct fake_epoll *old = find_epoll(oldfd);
    if (!old) { errno = EBADF; return -1; }
    int fd = (int)syscall(SYS_fcntl, oldfd,
        cloexec ? F_DUPFD_CLOEXEC : F_DUPFD, minimum);
    if (fd < 0) return -1;
    struct fake_epoll *copy = &epolls[epoll_count++];
    *copy = (struct fake_epoll){fd, fd, old->context};
    if (copy->context) ++copy->context->refs;
    return fd;
}
int ker_sb_preload_track_private_fd_locked(int fd)
{
    if (fd>=0 && fd<(int)(sizeof(private_fds)/sizeof(private_fds[0])))
        private_fds[fd]=1;
    return 0;
}
void ker_sb_preload_untrack_private_fd_locked(int fd)
{
    if (fd>=0 && fd<(int)(sizeof(private_fds)/sizeof(private_fds[0])))
        private_fds[fd]=0;
}
int ker_sb_preload_epoll_context_install_locked(int fd, void *context,
    ker_sb_preload_epoll_fd_close_fn fd_close,
    ker_sb_preload_epoll_context_destroy_fn destroy)
{
    struct fake_epoll *e = find_epoll(fd);
    if (!e || e->context) { errno = EINVAL; return -1; }
    e->context = calloc(1, sizeof(*e->context));
    if (!e->context) return -1;
    *e->context = (struct ker_sb_preload_epoll_context_ref){context, fd_close,
        destroy, 1, 1};
    return 0;
}
int ker_sb_preload_epoll_context_acquire(int fd,
    struct ker_sb_preload_epoll_context_ref **reference, void **context,
    uint64_t *generation)
{
    ker_sb_preload_lock();
    struct fake_epoll *e = find_epoll(fd);
    if (!e || !e->context) {
        ker_sb_preload_unlock(); errno = EOPNOTSUPP; return -1;
    }
    ++e->context->refs;
    *reference = e->context; *context = e->context->context;
    *generation = e->context->generation;
    ker_sb_preload_unlock();
    return 0;
}
void ker_sb_preload_epoll_context_release(
    struct ker_sb_preload_epoll_context_ref *r)
{ ker_sb_preload_lock(); release_context(r); ker_sb_preload_unlock(); }
int ker_sb_preload_event_epoll_ctl_locked(int epfd, int op, int fd,
    struct epoll_event *event)
{
    if (fd>=0 && fd<(int)(sizeof(private_fds)/sizeof(private_fds[0])) &&
            private_fds[fd]) { errno=EOPNOTSUPP; return -1; }
    return (int)syscall(SYS_epoll_ctl, epfd, op, fd, event);
}
int ker_sb_preload_epoll_fd_locked(int fd, int *broker_fd)
{
    struct fake_epoll *e = find_epoll(fd);
    if (!e) return 0;
    int result = e->fd;
    if (broker_fd) *broker_fd = e->broker_fd;
    return result >= 0 ? 1 : 0;
}
int ker_sb_preload_network_fd_locked(int fd, int *cap)
{
    if (fd >= 0 && fd < (int)(sizeof(managed)/sizeof(managed[0])) && managed[fd]) {
        if (cap) *cap = fd;
        return 1;
    }
    return 0;
}
struct ker_socket_client *ker_sb_preload_client_locked(void) { return &fake_client; }
int ker_socket_client_epoll_ctl(struct ker_socket_client *client, int epfd,
    int operation, int cap, const struct epoll_event *event)
{
    (void)client;
    return (int)syscall(SYS_epoll_ctl, epfd, operation, cap, event);
}
int ker_sb_posix_epoll_wait(int epfd, struct epoll_event *events,
    int maximum, int timeout)
{
    if (timeout > 0 && interrupt_blocking_wait) { errno = EINTR; return -1; }
    return (int)syscall(SYS_epoll_wait, epfd, events, maximum, timeout);
}
int ker_sb_posix_getsockopt(int fd, int level, int option, void *value,
    socklen_t *length)
{ return getsockopt(fd, level, option, value, length); }
int ker_sb_preload_ff_event_snapshot(int fd,
    struct ker_socket_event_snapshot *snapshot)
{
    if (fd==retry_eagain_fd && retry_eagain_remaining>0) {
        --retry_eagain_remaining;
        errno=EAGAIN;
        return -1;
    }
    if (fd==persistent_eagain_fd) {
        ++persistent_eagain_calls;
        errno=EAGAIN;
        return -1;
    }
    struct pollfd p = {.fd=fd, .events=POLLIN|POLLOUT};
    if (poll(&p, 1, 0) < 0) return -1;
    *snapshot = (struct ker_socket_event_snapshot){
        .version=KER_SOCKET_EVENT_SNAPSHOT_VERSION,
        .size=sizeof(*snapshot),
        .validity=KER_SOCKET_EVENT_READ_AVAILABLE_VALID|
            KER_SOCKET_EVENT_WRITE_ACCOUNTING_VALID|KER_SOCKET_EVENT_HARD_ERROR_VALID,
        .family=AF_UNIX, .type=SOCK_STREAM, .protocol=0,
        .write_accounting_space=123456};
    if (fd==old_snapshot_version_fd) snapshot->version=1;
    if (fd==shutdown_state_fd) snapshot->flags|=shutdown_state_flags;
    if (p.revents & POLLIN) snapshot->events |= EPOLLIN;
    if (p.revents & POLLOUT) snapshot->events |= EPOLLOUT;
    if (p.revents & POLLHUP) snapshot->events |= EPOLLHUP;
    if (p.revents & POLLERR) snapshot->events |= EPOLLERR;
#ifdef POLLRDHUP
    if (p.revents & POLLRDHUP) snapshot->events |= EPOLLRDHUP;
#endif
    int available = 0, error = 0;
    socklen_t error_length = sizeof(error);
    if (ioctl(fd, FIONREAD, &available) < 0) return -1;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) < 0) return -1;
    snapshot->read_available = available;
    snapshot->pending_hard_error = error;
    if (fd==error_queue_fd) snapshot->flags|=KER_SOCKET_EVENT_ERROR_QUEUE_ONLY;
    if (fd==inject_snapshot_fd) {
        inject_snapshot_fd=-1;
        if (ff_kevent(inject_queue,&inject_change,1,NULL,0,NULL)<0) return -1;
    }
    return 0;
}
int ker_sb_preload_usercopy_in(void *local, const void *user, size_t length)
{
    if (ker_host_usercopy(local,user,length,0)) { errno=EFAULT; return -1; }
    return 0;
}
int ker_sb_preload_usercopy_out(void *user, const void *local, size_t length)
{
    if (ker_host_usercopy(user,local,length,1)) { errno=EFAULT; return -1; }
    return 0;
}
int ker_sb_preload_close_locked(int fd)
{
    ker_sb_preload_lock();
    struct fake_epoll *e = find_epoll(fd);
    if (e) {
        struct ker_sb_preload_epoll_context_ref *r = e->context;
        e->context = NULL;
        if (r) release_context(r);
        e->fd = -1;
    }
    int result=(int)syscall(SYS_close, fd);
    ker_sb_preload_unlock();
    return result;
}
int ker_sb_preload_event_fd_close_locked(int fd, int cap)
{
    ker_sb_preload_lock();
    for (size_t i = 0; i < epoll_count; ++i)
        if (epolls[i].context && epolls[i].context->fd_close(
                epolls[i].context->context, fd, cap)) {
            ker_sb_preload_unlock(); return -1;
        }
    ker_sb_preload_unlock();
    return 0;
}

static void check(bool ok, const char *message)
{
    if (!ok) { perror(message); fprintf(stderr, "FAIL: %s\n", message); exit(1); }
}
static void make_pair(int pair[2])
{
    check(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0, pair)==0,
        "socketpair");
    managed[pair[0]]=1;
}
static void close_pair(int pair[2])
{
    managed[pair[0]]=0; close(pair[0]); close(pair[1]);
}
struct wait_args { int queue; int result; };
static void *wait_with_reference(void *opaque)
{
    struct wait_args *args=opaque;
    struct timespec timeout={.tv_nsec=30000000};
    struct kevent result;
    args->result=ff_kevent(args->queue,NULL,0,&result,1,&timeout);
    return NULL;
}
int main(void)
{
    int queue=ff_kqueue(); check(queue>=0, "ff_kqueue");
    struct timespec zero={0};
    struct kevent results[4];
    size_t queue_refs=find_epoll(queue)->context->refs;
    errno=0;
    check(ff_kevent(queue,(const struct kevent *)(uintptr_t)1,1,NULL,0,NULL)==-1 &&
        errno==EFAULT,"bad changelist pointer fails safely");
    check(find_epoll(queue)->context->refs==queue_refs,
        "bad changelist does not leak context reference");
    errno=0;
    check(ff_kevent(queue,NULL,0,NULL,0,(const struct timespec *)(uintptr_t)1)==-1 &&
        errno==EFAULT,"bad timeout pointer fails safely");
    check(find_epoll(queue)->context->refs==queue_refs,
        "bad timeout does not leak context reference");
    struct wait_args concurrent_args={.queue=queue,.result=-2};
    pthread_t concurrent_waiter;
    check(pthread_create(&concurrent_waiter,NULL,wait_with_reference,
            &concurrent_args)==0,"start sole collector");
    usleep(3000);
    queue_refs=find_epoll(queue)->context->refs;
    errno=0;
    check(ff_kevent(queue,NULL,0,results,1,&zero)==-1 && errno==EBUSY,
        "concurrent collector fails boundedly with EBUSY");
    check(find_epoll(queue)->context->refs==queue_refs,
        "rejected concurrent collector releases context reference");
    check(pthread_join(concurrent_waiter,NULL)==0 && concurrent_args.result==0,
        "sole collector releases queue lock after finite wait");
    queue_refs=find_epoll(queue)->context->refs;
    errno=0;
    check(ff_kevent(queue,NULL,INT_MAX,NULL,0,NULL)==-1 && errno==EINVAL,
        "oversized changelist rejects before touching caller memory");
    check(find_epoll(queue)->context->refs==queue_refs,
        "oversized changelist does not leak context reference");

    int fault_pair[2]; make_pair(fault_pair);
    check(send(fault_pair[1],"p",1,0)==1,"seed faulting changelist target");
    long page_size=sysconf(_SC_PAGESIZE);
    check(page_size>0,"host page size");
    char *fault_pages=mmap(NULL,(size_t)page_size*2,PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    check(fault_pages!=MAP_FAILED,"map changelist fault pages");
    struct kevent *fault_list=(struct kevent *)(fault_pages+page_size-
        (long)sizeof(struct kevent));
    EV_SET(&fault_list[0],fault_pair[0],EVFILT_READ,EV_ADD,0,0,NULL);
    check(mprotect(fault_pages+page_size,(size_t)page_size,PROT_NONE)==0,
        "protect second changelist page");
    errno=0;
    check(ff_kevent(queue,fault_list,2,NULL,0,NULL)==-1 && errno==EFAULT,
        "partially unreadable changelist faults before any mutation");
    check(munmap(fault_pages,(size_t)page_size*2)==0,"unmap fault pages");
    check(ff_kevent(queue,NULL,0,results,4,&zero)==0,
        "valid prefix of faulting changelist was not installed");
    close_pair(fault_pair);

    struct kevent early_user_add, early_trigger;
    EV_SET(&early_user_add,0,EVFILT_USER,EV_ADD|EV_CLEAR,0,0,NULL);
    EV_SET(&early_trigger,0,EVFILT_USER,0,NOTE_TRIGGER,0,NULL);
    check(ff_kevent(queue,&early_user_add,1,NULL,0,NULL)==0 &&
        ff_kevent(queue,&early_trigger,1,NULL,0,NULL)==0,
        "prepare bad-output event");
    errno=0;
    check(ff_kevent(queue,NULL,0,(struct kevent *)(uintptr_t)1,1,
            &(struct timespec){0})==-1 && errno==EFAULT,
        "bad event output pointer fails safely after readiness");
    check(find_epoll(queue)->context->refs==queue_refs,
        "bad event output does not leak context reference");
    struct ff_kqueue_context *early_context=(struct ff_kqueue_context *)
        find_epoll(queue)->context->context;
    struct epoll_event rejected_private_event={.events=EPOLLIN};
    errno=0;
    check(ker_sb_preload_event_epoll_ctl_locked(early_context->user_epfd,
            EPOLL_CTL_ADD,early_context->users[0].event_fd,
            &rejected_private_event)==-1 && errno==EOPNOTSUPP,
        "generic epoll control still rejects internal private eventfd");

    int pair[2]; make_pair(pair);
    int read_tag=11, write_tag=22;
    struct kevent changes[2];
    EV_SET(&changes[0], pair[0], EVFILT_READ,
        EV_ADD|EV_ENABLE|EV_CLEAR|EV_ONESHOT, 0, 0, &read_tag);
    EV_SET(&changes[1], pair[0], EVFILT_WRITE,
        EV_ADD|EV_ENABLE|EV_CLEAR, 0, 0, &write_tag);
    check(send(pair[1], "x", 1, 0)==1, "seed read readiness");
    int count=ff_kevent(queue, changes, 2, results, 4, &zero);
    check(count==2, "independent read/write filters both reported");
    bool got_read=false, got_write=false;
    for (int i=0;i<count;i++) {
        if (results[i].filter==EVFILT_READ) {
            got_read=results[i].udata==&read_tag && results[i].data==1;
        } else if (results[i].filter==EVFILT_WRITE) {
            got_write=results[i].udata==&write_tag && results[i].data==123456;
        }
    }
    check(got_read && got_write, "filter userdata and Linux snapshot fields");
    check(ff_kevent(queue,NULL,0,results,4,&zero)==0,
        "oneshot read and clear write do not repeat without new edge");

    check(KER_SOCKET_EVENT_SNAPSHOT_VERSION==2u,
        "shutdown snapshot protocol requires version two");
    int stale_version_pair[2]; make_pair(stale_version_pair);
    int stale_version_tag=36;
    struct kevent stale_version_add;
    EV_SET(&stale_version_add,stale_version_pair[0],EVFILT_READ,
        EV_ADD|EV_CLEAR,0,0,&stale_version_tag);
    check(ff_kevent(queue,&stale_version_add,1,NULL,0,NULL)==0,
        "register old-version snapshot control");
    check(send(stale_version_pair[1],"v",1,0)==1,
        "seed old-version snapshot readiness");
    old_snapshot_version_fd=stale_version_pair[0];
    struct kevent stale_sentinel={.ident=0x5a5au,.udata=&stale_version_tag};
    results[0]=stale_sentinel;
    queue_refs=find_epoll(queue)->context->refs;
    errno=0;
    struct timespec stale_timeout={.tv_sec=1};
    count=ff_kevent(queue,NULL,0,results,1,&stale_timeout);
    int stale_error=errno;
    old_snapshot_version_fd=-1;
    check(count==-1 && stale_error==EPROTO,
        "version one shutdown snapshot fails closed under version two");
    check(results[0].ident==stale_sentinel.ident &&
        results[0].udata==stale_sentinel.udata,
        "rejected old snapshot fabricates no caller event");
    check(find_epoll(queue)->context->refs==queue_refs,
        "old snapshot version rejection releases context reference");
    close_pair(stale_version_pair);

    int half_close_pair[2]; make_pair(half_close_pair);
    struct kevent half_close_changes[2];
    EV_SET(&half_close_changes[0],half_close_pair[0],EVFILT_READ,
        EV_ADD|EV_CLEAR,0,0,NULL);
    EV_SET(&half_close_changes[1],half_close_pair[0],EVFILT_WRITE,
        EV_ADD|EV_CLEAR,0,0,NULL);
    check(shutdown(half_close_pair[1],SHUT_WR)==0,
        "peer half-close setup");
    shutdown_state_fd=half_close_pair[0];
    shutdown_state_flags=KER_SOCKET_EVENT_READ_SHUTDOWN;
    struct timespec half_close_timeout={.tv_sec=1};
    count=ff_kevent(queue,half_close_changes,2,results,4,&half_close_timeout);
    check(count>=1,"peer half-close readiness");
    bool read_eof=false, write_without_eof=false;
    for (int i=0;i<count;i++) {
        if (results[i].filter==EVFILT_READ)
            read_eof=(results[i].flags&EV_EOF)!=0;
        else if (results[i].filter==EVFILT_WRITE)
            write_without_eof=(results[i].flags&EV_EOF)==0;
    }
    check(read_eof && write_without_eof,
        "read half-close EOF preserves writable filter");
    EV_SET(&half_close_changes[0],half_close_pair[0],EVFILT_WRITE,
        EV_ADD|EV_CLEAR,0,0,NULL);
    shutdown_state_flags=KER_SOCKET_EVENT_WRITE_SHUTDOWN;
    check(shutdown(half_close_pair[0],SHUT_WR)==0,
        "local send shutdown setup");
    count=ff_kevent(queue,half_close_changes,1,results,4,&half_close_timeout);
    bool write_eof=false;
    for (int i=0;i<count;i++)
        if (results[i].filter==EVFILT_WRITE)
            write_eof=(results[i].flags&EV_EOF)!=0;
    check(count>=1 && write_eof,"local send shutdown emits write EOF");
    shutdown_state_fd=-1;
    shutdown_state_flags=0;
    close_pair(half_close_pair);

    struct kevent user_add, user_trigger;
    int initial_tag=31, trigger_tag=32;
    EV_SET(&user_add,0,EVFILT_USER,EV_ADD|EV_CLEAR,0,0,&initial_tag);
    EV_SET(&user_trigger,0,EVFILT_USER,0,NOTE_TRIGGER,0,&trigger_tag);
    struct kevent user_changes[3]={user_add,user_trigger,user_trigger};
    count=ff_kevent(queue,user_changes,3,results,1,&zero);
    check(count==1 && results[0].filter==EVFILT_USER &&
        results[0].ident==0 && results[0].udata==&trigger_tag,
        "eventfd-backed USER trigger and latest userdata");

    /* Duplicate kqueue descriptors retain one queue context and independent
     * descriptor lifetime. */
    int duplicate;
    ker_sb_preload_lock();
    duplicate=ker_sb_preload_duplicate_epoll_locked(queue,0,true);
    ker_sb_preload_unlock();
    check(duplicate>=0,"duplicate kqueue descriptor");
    check(ker_sb_preload_close_locked(queue)==0,"close original queue handle");
    check(ff_kevent(duplicate,NULL,0,results,4,&zero)==0,
        "duplicate retains adapter context");
    queue=duplicate;

    int interrupt_pair[2]; make_pair(interrupt_pair);
    struct kevent read_add;
    EV_SET(&read_add,interrupt_pair[0],EVFILT_READ,EV_ADD|EV_CLEAR,0,0,NULL);
    check(ff_kevent(queue,&read_add,1,NULL,0,NULL)==0,"register second read");
    interrupt_blocking_wait=1;
    struct timespec long_wait={.tv_sec=1};
    errno=0;
    check(ff_kevent(queue,NULL,0,results,4,&long_wait)==-1 && errno==EINTR,
        "interrupted composite wait propagates EINTR");
    interrupt_blocking_wait=0;

    struct kevent disable, enable;
    EV_SET(&disable,interrupt_pair[0],EVFILT_READ,EV_DISABLE,0,0,NULL);
    check(ff_kevent(queue,&disable,1,NULL,0,NULL)==0,"disable read filter");
    check(send(interrupt_pair[1],"d",1,0)==1,"seed disabled read filter");
    count=ff_kevent(queue,NULL,0,results,4,&zero);
    check(count==0,"disabled read filter is silent");
    EV_SET(&enable,interrupt_pair[0],EVFILT_READ,EV_ENABLE,0,0,NULL);
    check(ff_kevent(queue,&enable,1,NULL,0,NULL)==0,"reenable read filter");
    count=ff_kevent(queue,NULL,0,results,4,&zero);
    check(count==1 && results[0].filter==EVFILT_READ,
        "reenabled read filter observes native pending data");
    char drained;
    check(recv(interrupt_pair[0],&drained,1,0)==1,
        "consume read data before generation-only control");
    struct ff_kqueue_context *queue_context=(struct ff_kqueue_context *)
        find_epoll(queue)->context->context;
    struct ff_kqueue_watch *enabled_watch=ff_kqueue_watch_find(queue_context,
        interrupt_pair[0],EVFILT_READ);
    uint32_t enabled_generation=enabled_watch->generation;
    check(ff_kevent(queue,&disable,1,NULL,0,NULL)==0 &&
        ff_kevent(queue,&enable,1,NULL,0,NULL)==0 &&
        enabled_watch->generation!=enabled_generation,
        "re-enable rotates queued-readiness generation");

    int mod_pair[2]; make_pair(mod_pair);
    struct timespec before,after;
    int64_t elapsed;
    int old_mod_tag=41, new_mod_tag=42;
    struct kevent mod_add;
    EV_SET(&mod_add,mod_pair[0],EVFILT_READ,EV_ADD|EV_CLEAR,0,0,&old_mod_tag);
    check(ff_kevent(queue,&mod_add,1,NULL,0,NULL)==0,"register queued-MOD watch");
    inject_queue=queue;
    inject_snapshot_fd=mod_pair[0];
    EV_SET(&inject_change,mod_pair[0],EVFILT_READ,EV_ADD|EV_CLEAR,0,0,&new_mod_tag);
    struct timespec mod_timeout={.tv_nsec=30000000};
    check(send(mod_pair[1],"m",1,0)==1,"seed readiness before concurrent MOD");
    count=ff_kevent(queue,NULL,0,results,4,&mod_timeout);
    check(count==1 && results[0].filter==EVFILT_READ &&
        results[0].udata==&new_mod_tag,
        "readiness queued before concurrent MOD uses only new userdata");

    int retry_pair[2]; make_pair(retry_pair);
    int retry_tag=51;
    struct kevent retry_add;
    EV_SET(&retry_add,retry_pair[0],EVFILT_READ,EV_ADD|EV_CLEAR,0,0,&retry_tag);
    check(ff_kevent(queue,&retry_add,1,NULL,0,NULL)==0,"register retry-once watch");
    check(send(retry_pair[1],"e",1,0)==1,"seed retry-once readiness");
    retry_eagain_fd=retry_pair[0]; retry_eagain_remaining=1;
    struct timespec retry_timeout={.tv_sec=1};
    queue_refs=find_epoll(queue)->context->refs;
    count=ff_kevent(queue,NULL,0,results,4,&retry_timeout);
    retry_eagain_fd=-1;
    check(count==1 && results[0].filter==EVFILT_READ &&
        results[0].udata==&retry_tag && retry_eagain_remaining==0,
        "one EAGAIN preserves and retries the same readiness edge");
    check(find_epoll(queue)->context->refs==queue_refs,
        "single-EAGAIN retry releases its context reference");

    int persistent_pair[2]; make_pair(persistent_pair);
    int persistent_tag=52;
    struct kevent persistent_add;
    EV_SET(&persistent_add,persistent_pair[0],EVFILT_READ,EV_ADD|EV_CLEAR,0,0,
        &persistent_tag);
    check(ff_kevent(queue,&persistent_add,1,NULL,0,NULL)==0,
        "register persistent-EAGAIN watch");
    check(send(persistent_pair[1],"e",1,0)==1,"seed persistent-EAGAIN readiness");
    persistent_eagain_fd=persistent_pair[0]; persistent_eagain_calls=0;
    struct timespec persistent_timeout={.tv_nsec=6000000};
    queue_refs=find_epoll(queue)->context->refs;
    clock_gettime(CLOCK_MONOTONIC,&before);
    count=ff_kevent(queue,NULL,0,results,4,&persistent_timeout);
    clock_gettime(CLOCK_MONOTONIC,&after);
    elapsed=(after.tv_sec-before.tv_sec)*1000000000LL+
        after.tv_nsec-before.tv_nsec;
    check(count==0 && persistent_eagain_calls>=2 && persistent_eagain_calls<=12 &&
        elapsed>=5000000LL && elapsed<500000000LL,
        "persistent EAGAIN retries at bounded intervals until finite timeout");
    check(find_epoll(queue)->context->refs==queue_refs,
        "persistent EAGAIN deadline releases its context reference");
    persistent_eagain_fd=-1;
    count=ff_kevent(queue,NULL,0,results,4,&zero);
    check(count==1 && results[0].filter==EVFILT_READ &&
        results[0].udata==&persistent_tag,
        "readiness survives persistent transient failures for the next call");

    int partial_queue=ff_kqueue();
    check(partial_queue>=0,"create isolated partial-batch queue");
    struct ff_kqueue_context *partial_context=(struct ff_kqueue_context *)
        find_epoll(partial_queue)->context->context;
    int partial_read_pair[2], partial_write_pair[2];
    make_pair(partial_read_pair); make_pair(partial_write_pair);
    int partial_read_tag=61, partial_write_tag=62;
    struct kevent partial_changes[2];
    EV_SET(&partial_changes[0],partial_read_pair[0],EVFILT_READ,
        EV_ADD|EV_ONESHOT,0,0,&partial_read_tag);
    EV_SET(&partial_changes[1],partial_write_pair[0],EVFILT_WRITE,
        EV_ADD,0,0,&partial_write_tag);
    check(ff_kevent(partial_queue,partial_changes,2,NULL,0,NULL)==0,
        "register one-shot read plus write filters");
    check(send(partial_read_pair[1],"r",1,0)==1,
        "seed one-shot read before later-filter transient error");
    struct epoll_event read_ready;
    check(syscall(SYS_epoll_wait,partial_context->read_epfd,&read_ready,1,0)==1,
        "capture ready one-shot read token");
    persistent_eagain_fd=partial_write_pair[0]; persistent_eagain_calls=0;
    count=ff_kqueue_collect(partial_context,results,4,0,&read_ready);
    persistent_eagain_fd=-1;
    check(count==1 && results[0].filter==EVFILT_READ &&
        results[0].udata==&partial_read_tag,
        "earlier one-shot result is returned despite later-filter EAGAIN");
    check(partial_context->pending_ready && partial_context->pending_queue==1,
        "later write edge remains retained after partial event batch");
    count=ff_kevent(partial_queue,NULL,0,results,4,&zero);
    bool got_partial_write=false;
    for (int i=0;i<count;i++)
        if (results[i].filter==EVFILT_WRITE &&
                results[i].udata==&partial_write_tag) got_partial_write=true;
    check(count>=1 && got_partial_write,
        "retained later-filter event is returned by next kevent");
    struct kevent partial_write_delete;
    EV_SET(&partial_write_delete,partial_write_pair[0],EVFILT_WRITE,EV_DELETE,0,0,NULL);
    check(ff_kevent(partial_queue,&partial_write_delete,1,NULL,0,NULL)==0,
        "remove level-triggered partial-batch write watch");

    int fatal_read_pair[2], fatal_write_pair[2];
    make_pair(fatal_read_pair); make_pair(fatal_write_pair);
    int fatal_read_tag=63, fatal_write_tag=64;
    struct kevent fatal_changes[2];
    EV_SET(&fatal_changes[0],fatal_read_pair[0],EVFILT_READ,
        EV_ADD|EV_ONESHOT,0,0,&fatal_read_tag);
    EV_SET(&fatal_changes[1],fatal_write_pair[0],EVFILT_WRITE,
        EV_ADD,0,0,&fatal_write_tag);
    check(ff_kevent(partial_queue,fatal_changes,2,NULL,0,NULL)==0,
        "register one-shot plus explicit-error filters");
    check(send(fatal_read_pair[1],"r",1,0)==1,"seed earlier one-shot result");
    check(syscall(SYS_epoll_wait,partial_context->read_epfd,&read_ready,1,0)==1,
        "capture one-shot token before later explicit error");
    error_queue_fd=fatal_write_pair[0];
    count=ff_kqueue_collect(partial_context,results,4,0,&read_ready);
    error_queue_fd=-1;
    bool got_fatal_prefix=false;
    for (int i=0;i<count;i++)
        if (results[i].filter==EVFILT_READ &&
                results[i].udata==&fatal_read_tag) got_fatal_prefix=true;
    check(count>=1 && got_fatal_prefix,
        "earlier event is returned before later fatal filter status");
    errno=0;
    check(ff_kevent(partial_queue,NULL,0,results,4,&zero)==-1 && errno==EOPNOTSUPP,
        "later fatal status is surfaced on the following kevent");

    struct timespec measured={.tv_nsec=15000000};
    clock_gettime(CLOCK_MONOTONIC,&before);
    count=ff_kevent(queue,NULL,0,results,4,&measured);
    clock_gettime(CLOCK_MONOTONIC,&after);
    elapsed=(after.tv_sec-before.tv_sec)*1000000000LL+
        after.tv_nsec-before.tv_nsec;
    check(count==0 && elapsed>=12000000LL && elapsed<1000000000LL,
        "absolute finite timeout is bounded and not early");

    /* A real close callback removes the native epoll registrations before the
     * application fd can be reused. This harness exercises the FF bridge and
     * Linux epoll plumbing; snapshot transport is mocked, not LKL-provider proof. */
    int stale_fd=interrupt_pair[0];
    check(send(interrupt_pair[1],"z",1,0)==1,"seed close/reuse readiness");
    check(ker_sb_preload_event_fd_close_locked(stale_fd,stale_fd)==0,
        "close callback removes exact watched descriptor");
    managed[stale_fd]=0; close(stale_fd); close(interrupt_pair[1]);
    count=ff_kevent(queue,NULL,0,results,4,&zero);
    check(count==0,"stale closed-fd event is rejected");

    int reused_pair[2]; make_pair(reused_pair);
    check(reused_pair[0]==stale_fd,"host reused closed descriptor number");
    struct kevent reused_add;
    EV_SET(&reused_add,reused_pair[0],EVFILT_READ,EV_ADD,0,0,NULL);
    check(ff_kevent(queue,&reused_add,1,NULL,0,NULL)==0,
        "new socket generation can use reused fd number");
    check(send(reused_pair[1],"r",1,0)==1,"seed reused fd readiness");
    count=ff_kevent(queue,NULL,0,results,4,&zero);
    check(count==1 && results[0].ident==(uintptr_t)reused_pair[0],
        "reused fd reports only its new socket generation");
    error_queue_fd=reused_pair[0];
    check(send(reused_pair[1],"e",1,0)==1,"seed unsupported error-queue event");
    errno=0;
    count=ff_kevent(queue,NULL,0,results,4,&zero);
    check(count==-1 && errno==EOPNOTSUPP,
        "error-queue-only snapshot fails explicitly");
    error_queue_fd=-1;

    int bad;
    struct kevent unsupported;
    EV_SET(&unsupported,1,EVFILT_TIMER,EV_ADD,0,10,NULL);
    errno=0; bad=ff_kevent(queue,&unsupported,1,NULL,0,NULL);
    check(bad==-1 && errno==EOPNOTSUPP,"unimplemented filter fails before mutation");
    close_pair(pair);
    close_pair(mod_pair);
    close_pair(retry_pair);
    close_pair(persistent_pair);
    close_pair(partial_read_pair);
    close_pair(partial_write_pair);
    close_pair(fatal_read_pair);
    close_pair(fatal_write_pair);
    check(ker_sb_preload_close_locked(partial_queue)==0,
        "close isolated partial-batch queue");
    close_pair(reused_pair);
    struct wait_args args={.queue=queue,.result=-2};
    pthread_t waiter;
    check(pthread_create(&waiter,NULL,wait_with_reference,&args)==0,
        "start wait holding context reference");
    usleep(3000);
    check(ker_sb_preload_close_locked(queue)==0,"close queue during referenced wait");
    check(pthread_join(waiter,NULL)==0 && args.result==0,
        "in-flight wait safely releases final context reference");
    return 0;
}
