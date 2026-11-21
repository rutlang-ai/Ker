#define _GNU_SOURCE
#define KER_SOCKET_BROKER_PRELOAD_TESTING
#include "../../src/posix/socket-broker-preload-fd.c"
#include <assert.h>
#include <sys/eventfd.h>
#include <sys/wait.h>

void ker_sb_preload_owner_loop_fork_cleanup(void) {}

int ker_socket_client_open(struct ker_socket_client *client, const char *path)
{
    (void)client;
    (void)path;
    errno = ENOTCONN;
    return -1;
}

int ker_socket_client_epoll_ctl(struct ker_socket_client *client,
    int epoll_cap, int operation, int cap_fd, const struct epoll_event *event)
{
    (void)client;
    (void)epoll_cap;
    (void)operation;
    (void)cap_fd;
    (void)event;
    errno = ENOTCONN;
    return -1;
}

static int destroys;
static int closes;
static int close_context(void *context, int app_fd, int capability_fd)
{
    (void)context; (void)app_fd; (void)capability_fd;
    ++closes;
    return 0;
}
static void destroy_context(void *context)
{
    ++destroys;
    free(context);
}

int main(void)
{
    for (size_t i=0;i<PRELOAD_FD_SLOTS;i++) {
        network_fds[i]=(struct network_entry){.app_fd=-1,.private_fd=-1};
        epoll_fds[i]=(struct epoll_entry){.app_fd=-1,.broker_fd=-1};
    }
    for (size_t i=0;i<PRELOAD_PRIVATE_SLOTS;i++) private_fds[i]=-1;
    for (size_t i=0;i<PRELOAD_WAIT_SLOTS;i++)
        wait_pins[i]=(struct wait_pin_entry){.host_fd=-1,.broker_fd=-1};

    int app=(int)syscall(SYS_epoll_create1,EPOLL_CLOEXEC);
    int broker=(int)syscall(SYS_epoll_create1,EPOLL_CLOEXEC);
    assert(app>=0 && broker>=0);
    assert(ker_sb_preload_register_epoll_locked(app,broker)==0);
    close(broker);
    assert(ker_sb_preload_epoll_context_install_locked(app,calloc(1,1),
        close_context,destroy_context)==0);

    /* A private USER eventfd must stay rejected by generic broker routing,
     * while the kqueue adapter may attach its owned wakeup to host epoll. */
    int user_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    assert(user_eventfd >= 0);
    ker_sb_preload_lock();
    assert(ker_sb_preload_track_private_fd_locked(user_eventfd) == 0);
    int capability_fd = -1;
    errno = 0;
    assert(ker_sb_preload_network_fd_locked(user_eventfd, &capability_fd) == -1 &&
        errno == EOPNOTSUPP);
    struct epoll_event user_event = {.events = EPOLLIN};
    errno = 0;
    assert(ker_sb_preload_event_epoll_ctl_locked(app, EPOLL_CTL_ADD,
        user_eventfd, &user_event) == -1 && errno == EOPNOTSUPP);
    assert(syscall(SYS_epoll_ctl, app, EPOLL_CTL_ADD, user_eventfd,
        &user_event) == 0);
    ker_sb_preload_unlock();
    uint64_t one = 1;
    assert(write(user_eventfd, &one, sizeof(one)) == sizeof(one));
    struct epoll_event ready;
    assert(syscall(SYS_epoll_wait, app, &ready, 1, 1000) == 1);
    assert(ready.events & EPOLLIN);
    assert(syscall(SYS_epoll_ctl, app, EPOLL_CTL_DEL, user_eventfd, NULL) == 0);
    ker_sb_preload_lock();
    ker_sb_preload_untrack_private_fd_locked(user_eventfd);
    ker_sb_preload_unlock();
    close(user_eventfd);

    struct ker_sb_preload_epoll_context_ref *reference=NULL;
    void *context=NULL;
    uint64_t generation=0;
    assert(ker_sb_preload_epoll_context_acquire(app,&reference,&context,
        &generation)==0 && context && generation);
    ker_sb_preload_epoll_context_release(reference);

    assert(pthread_atfork(fork_prepare,fork_parent,fork_child)==0);
    pid_t child=fork();
    assert(child>=0);
    if (!child) _exit(destroys==1 ? 0 : 1);
    int status=0;
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) &&
        WEXITSTATUS(status)==0);
    assert(destroys==0);

    assert(ker_sb_preload_event_fd_close_locked(123,456)==0 && closes==1);
    ker_sb_preload_lock();
    ker_sb_preload_remove_epoll_locked(app);
    ker_sb_preload_unlock();
    assert(destroys==1);
    close(app);
    return 0;
}
