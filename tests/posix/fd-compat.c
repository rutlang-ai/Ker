#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static volatile sig_atomic_t signals;
static void on_signal(int signal_number) { (void)signal_number; signals++; }
struct epoll_waiter { int ep, ready, result; };
static pthread_mutex_t waiter_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t waiter_cond = PTHREAD_COND_INITIALIZER;
static int eventpoll_fds(int *fds, int capacity)
{
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    int count = 0;
    struct dirent *item;
    while ((item = readdir(directory))) {
        char *end;
        long fd = strtol(item->d_name, &end, 10);
        if (*end || fd < 0 || fd > 1048576) continue;
        char path[64], target[128];
        snprintf(path, sizeof(path), "/proc/self/fd/%ld", fd);
        ssize_t length = readlink(path, target, sizeof(target) - 1);
        if (length < 0) continue;
        target[length] = '\0';
        if (strcmp(target, "anon_inode:[eventpoll]") == 0) {
            CHECK(count < capacity);
            fds[count++] = (int)fd;
        }
    }
    CHECK(closedir(directory) == 0);
    return count;
}
static bool contains_fd(const int *fds, int count, int fd)
{
    for (int i = 0; i < count; ++i) if (fds[i] == fd) return true;
    return false;
}
static int added_eventpoll_fd(const int *before, int before_count,
    const int *after, int after_count)
{
    int found = -1, added = 0;
    for (int i = 0; i < after_count; ++i) if (!contains_fd(before, before_count, after[i])) {
        found = after[i]; ++added;
    }
    return added == 1 ? found : -1;
}
static void *wait_on_private_snapshot(void *argument)
{
    struct epoll_waiter *waiter = argument;
    pthread_mutex_lock(&waiter_mutex);
    waiter->ready = 1;
    pthread_cond_signal(&waiter_cond);
    pthread_mutex_unlock(&waiter_mutex);
    struct epoll_event event;
    waiter->result = epoll_wait(waiter->ep, &event, 1, 5000);
    return NULL;
}
struct close_replace_race { int ep, target, source, duplicate_result; pthread_barrier_t gate; };
static void *close_private_epoll(void *argument)
{
    struct close_replace_race *race = argument;
    int gate = pthread_barrier_wait(&race->gate);
    CHECK(gate == 0 || gate == PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(close(race->ep) == 0);
    return NULL;
}
static void *replace_private_epoll_fd(void *argument)
{
    struct close_replace_race *race = argument;
    int gate = pthread_barrier_wait(&race->gate);
    CHECK(gate == 0 || gate == PTHREAD_BARRIER_SERIAL_THREAD);
    race->duplicate_result = dup2(race->source, race->target);
    return NULL;
}

static void *descriptor_churn(void *unused)
{
    (void)unused;
    for (unsigned int i = 0; i < 64; ++i) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(fd >= 0);
        int other = fcntl(fd, F_DUPFD_CLOEXEC, 700);
        CHECK(other >= 700 && (fcntl(other, F_GETFD) & FD_CLOEXEC));
        CHECK(close(fd) == 0 && close(other) == 0);
    }
    return NULL;
}
int main(void)
{
    CHECK(syscall(SYS_socket, AF_INET, SOCK_STREAM, 0) == -1 && errno == EPERM);
    int files[600];
    for (unsigned int i = 0; i < 600; ++i) {
        files[i] = open("/dev/null", O_RDWR | O_CLOEXEC);
        CHECK(files[i] >= 0);
    }
    CHECK(files[599] > 512);
    char bytes[8] = {0};
    CHECK(write(files[599], bytes, sizeof(bytes)) == sizeof(bytes));
    CHECK(read(files[599], bytes, sizeof(bytes)) == 0);
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(listener > 512 && (fcntl(listener, F_GETFD) & FD_CLOEXEC));
    CHECK(fcntl(listener, F_SETFD, 0) == 0 && syscall(SYS_fcntl, listener, F_GETFD) == 0);
    CHECK(fcntl(listener, F_SETFD, FD_CLOEXEC) == 0 &&
        (syscall(SYS_fcntl, listener, F_GETFD) & FD_CLOEXEC));
    CHECK(fcntl(listener, F_SETFL, O_NONBLOCK | O_ASYNC) == -1 && errno == EOPNOTSUPP);
    int async = 1;
    CHECK(ioctl(listener, FIOASYNC, &async) == -1 && errno == EOPNOTSUPP);
    struct stat stat;
    CHECK(fstat(listener, &stat) == 0 && S_ISSOCK(stat.st_mode));
    int duplicate = dup(listener);
    CHECK(duplicate >= 0 && !(fcntl(duplicate, F_GETFD) & FD_CLOEXEC));
    CHECK(ioctl(listener, FIOCLEX) == 0 &&
        (fcntl(listener, F_GETFD) & FD_CLOEXEC) &&
        (syscall(SYS_fcntl, listener, F_GETFD) & FD_CLOEXEC));
    CHECK(!(fcntl(duplicate, F_GETFD) & FD_CLOEXEC));
    CHECK(ioctl(listener, FIONCLEX) == 0 &&
        !(fcntl(listener, F_GETFD) & FD_CLOEXEC) &&
        !(syscall(SYS_fcntl, listener, F_GETFD) & FD_CLOEXEC));
    CHECK(fcntl(duplicate, F_SETFL, 0) == 0 && !(fcntl(listener, F_GETFL) & O_NONBLOCK));
    CHECK(fcntl(listener, F_SETFL, O_NONBLOCK) == 0 && (fcntl(duplicate, F_GETFL) & O_NONBLOCK));
    /* Replacing a host file by a native descriptor and back must update both
     * domains atomically; fd values alone must never select the backend. */
    CHECK(dup2(listener, files[599]) == files[599]);
    CHECK(getsockname(files[599], (void *)&(struct sockaddr_in){0}, &(socklen_t){sizeof(struct sockaddr_in)}) == 0);
    CHECK(dup2(files[598], files[599]) == files[599]);
    CHECK(write(files[599], bytes, sizeof(bytes)) == sizeof(bytes));
    CHECK(close(duplicate) == 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 8) == 0);
    socklen_t length = sizeof(address);
    CHECK(getsockname(listener, (void *)&address, &length) == 0);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    CHECK(client >= 0);
    int connected = connect(client, (void *)&address, length);
    CHECK(!connected || errno == EINPROGRESS);
    struct pollfd wait = {listener, POLLIN, 0};
    CHECK(poll(&wait, 1, 2000) == 1);
    int accepted = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    CHECK(accepted >= 0);
    int pipefd[2];
    CHECK(pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) == 0);
    CHECK(write(pipefd[1], "H", 1) == 1);
    struct pollfd mixed[] = {{pipefd[0], POLLIN, 0}, {client, POLLOUT, 0}, {-1, POLLIN, 0}};
    CHECK(poll(mixed, 3, 2000) == 2 && (mixed[0].revents & POLLIN) &&
        (mixed[1].revents & POLLOUT) && !mixed[2].revents);
    int epoll_before[64], epoll_after[64];
    int epoll_before_count = eventpoll_fds(epoll_before, 64);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
    int epoll_after_count = eventpoll_fds(epoll_after, 64);
    int private_fd = added_eventpoll_fd(epoll_before, epoll_before_count,
        epoll_after, epoll_after_count);
    CHECK(private_fd >= 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x1122334455667788)};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &event) == 0);
    event.data.u64 = UINT64_C(0x8877665544332211);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, client, &event) == 0);
    CHECK(write(accepted, "N", 1) == 1);
    unsigned int seen = 0;
    for (unsigned int iteration = 0; iteration < 4 && seen != 3; ++iteration) {
        struct epoll_event ready[2];
        int count = epoll_wait(ep, ready, 2, 2000);
        CHECK(count > 0);
        for (int i = 0; i < count; ++i) {
            CHECK(ready[i].events & EPOLLIN);
            if (ready[i].data.u64 == UINT64_C(0x1122334455667788)) {
                CHECK(!(seen & 1) && read(pipefd[0], bytes, 1) == 1 && bytes[0] == 'H');
                seen |= 1;
            } else {
                CHECK(ready[i].data.u64 == UINT64_C(0x8877665544332211));
                CHECK(!(seen & 2) && read(client, bytes, 1) == 1 && bytes[0] == 'N');
                seen |= 2;
            }
        }
    }
    CHECK(seen == 3);
    event.events = EPOLLIN | EPOLLONESHOT;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, client, &event) == 0);
    CHECK(write(accepted, "AB", 2) == 2);
    CHECK(epoll_wait(ep, &event, 1, 2000) == 1 && read(client, bytes, 1) == 1);
    /* An in-flight host epoll snapshot is a protected fixed-destination target.
     * dup2 must fail without corrupting the shared epoll object. */
    event.events = EPOLLIN;
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, client, NULL) == 0);
    struct epoll_waiter waiter = {.ep = ep, .result = -2};
    epoll_before_count = eventpoll_fds(epoll_before, 64);
    pthread_t waiter_thread;
    CHECK(pthread_create(&waiter_thread, NULL, wait_on_private_snapshot, &waiter) == 0);
    pthread_mutex_lock(&waiter_mutex);
    while (!waiter.ready) pthread_cond_wait(&waiter_cond, &waiter_mutex);
    pthread_mutex_unlock(&waiter_mutex);
    int snapshot_fd = -1;
    for (unsigned int attempt = 0; attempt < 2000 && snapshot_fd < 0; ++attempt) {
        epoll_after_count = eventpoll_fds(epoll_after, 64);
        int candidate = added_eventpoll_fd(epoll_before, epoll_before_count,
            epoll_after, epoll_after_count);
        if (candidate >= 0) {
            errno = 0;
            if (dup2(listener, candidate) == -1 && errno == EBUSY) snapshot_fd = candidate;
            else CHECK(close(candidate) == 0); /* The wait snapshot advanced. */
        }
        if (snapshot_fd < 0) usleep(100);
    }
    CHECK(snapshot_fd >= 0);
    CHECK(write(pipefd[1], "W", 1) == 1);
    CHECK(pthread_join(waiter_thread, NULL) == 0 && waiter.result == 1);
    epoll_after_count = eventpoll_fds(epoll_after, 64);
    CHECK(!contains_fd(epoll_after, epoll_after_count, snapshot_fd));
    CHECK(read(pipefd[0], bytes, 1) == 1 && bytes[0] == 'W');
    CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, pipefd[0], NULL) == 0);
    /* Target the persistent private host epoll fd via each supported fixed
     * replacement API. The app fd takes that number while the owner relocates. */
    epoll_before_count = eventpoll_fds(epoll_before, 64);
    int public_dup2_fd = private_fd;
    CHECK(dup2(listener, private_fd) == private_fd);
    epoll_after_count = eventpoll_fds(epoll_after, 64);
    CHECK(!contains_fd(epoll_after, epoll_after_count, public_dup2_fd));
    private_fd = added_eventpoll_fd(epoll_before, epoll_before_count,
        epoll_after, epoll_after_count);
    CHECK(private_fd >= 0);
    event.events = EPOLLIN;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &event) == 0);
    CHECK(write(pipefd[1], "2", 1) == 1);
    CHECK(epoll_wait(ep, &event, 1, 2000) == 1);
    CHECK(read(pipefd[0], bytes, 1) == 1 && bytes[0] == '2');
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, pipefd[0], NULL) == 0);

    epoll_before_count = eventpoll_fds(epoll_before, 64);
    CHECK(dup3(listener, private_fd, O_CLOEXEC) == private_fd);
    CHECK(fcntl(private_fd, F_GETFD) & FD_CLOEXEC);
    int public_dup3_fd = private_fd;
    epoll_after_count = eventpoll_fds(epoll_after, 64);
    CHECK(!contains_fd(epoll_after, epoll_after_count, public_dup3_fd));
    private_fd = added_eventpoll_fd(epoll_before, epoll_before_count,
        epoll_after, epoll_after_count);
    CHECK(private_fd >= 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &event) == 0);
    CHECK(write(pipefd[1], "3", 1) == 1);
    CHECK(epoll_wait(ep, &event, 1, 2000) == 1);
    CHECK(read(pipefd[0], bytes, 1) == 1 && bytes[0] == '3');
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, pipefd[0], NULL) == 0);
    /* Race the final owner teardown against a fixed replacement of its host
     * fd. The caller's new destination must remain open after both finish. */
    for (unsigned int iteration = 0; iteration < 32; ++iteration) {
        epoll_before_count = eventpoll_fds(epoll_before, 64);
        int closing_ep = epoll_create1(EPOLL_CLOEXEC);
        CHECK(closing_ep >= 0);
        epoll_after_count = eventpoll_fds(epoll_after, 64);
        int target = added_eventpoll_fd(epoll_before, epoll_before_count,
            epoll_after, epoll_after_count);
        CHECK(target >= 0);
        struct close_replace_race race = {.ep = closing_ep, .target = target,
            .source = listener, .duplicate_result = -1};
        CHECK(pthread_barrier_init(&race.gate, NULL, 2) == 0);
        pthread_t close_thread, duplicate_thread;
        CHECK(pthread_create(&close_thread, NULL, close_private_epoll, &race) == 0);
        CHECK(pthread_create(&duplicate_thread, NULL, replace_private_epoll_fd, &race) == 0);
        CHECK(pthread_join(close_thread, NULL) == 0);
        CHECK(pthread_join(duplicate_thread, NULL) == 0);
        CHECK(pthread_barrier_destroy(&race.gate) == 0);
        CHECK(race.duplicate_result == target);
        CHECK(getsockname(target, (void *)&(struct sockaddr_in){0},
            &(socklen_t){sizeof(struct sockaddr_in)}) == 0);
        CHECK(close(target) == 0);
    }
    CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    event.events = EPOLLIN | EPOLLONESHOT;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, client, &event) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, client, &event) == 0);
    CHECK(epoll_wait(ep, &event, 1, 2000) == 1 && read(client, bytes, 1) == 1);
    /* Simulate an older host kernel while exercising the host-only epoll path. */
    int host_ep = (int)syscall(SYS_epoll_create1, EPOLL_CLOEXEC);
    CHECK(host_ep >= 0);
    struct epoll_event host_event = {.events = EPOLLIN, .data.u64 = 42};
    CHECK(syscall(SYS_epoll_ctl, host_ep, EPOLL_CTL_ADD, pipefd[0], &host_event) == 0);
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_epoll_pwait2, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    CHECK(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
    CHECK(write(pipefd[1], "F", 1) == 1);
    struct timespec short_wait = {0, 1000000};
    errno = 0;
    CHECK(epoll_pwait2(host_ep, &host_event, 1, &short_wait, NULL) == -1 && errno == ENOSYS);
    CHECK(epoll_wait(host_ep, &host_event, 1, 100) == 1 &&
        host_event.data.u64 == 42 && read(pipefd[0], bytes, 1) == 1 && bytes[0] == 'F');
    CHECK(write(pipefd[1], "G", 1) == 1);
    CHECK(epoll_pwait(host_ep, &host_event, 1, 100, NULL) == 1 &&
        host_event.data.u64 == 42 && read(pipefd[0], bytes, 1) == 1 && bytes[0] == 'G');
    CHECK(close(host_ep) == 0);
    CHECK(write(pipefd[1], "X", 1) == 1 && write(accepted, "Y", 1) == 1);
    CHECK(client < FD_SETSIZE && pipefd[0] < FD_SETSIZE);
    fd_set reads;
    FD_ZERO(&reads); FD_SET(client, &reads); FD_SET(pipefd[0], &reads);
    struct timeval timeout = {2, 0};
    int maximum = client > pipefd[0] ? client : pipefd[0];
    CHECK(select(maximum + 1, &reads, NULL, NULL, &timeout) == 2 &&
        FD_ISSET(client, &reads) && FD_ISSET(pipefd[0], &reads));
    CHECK(read(client, bytes, 1) == 1 && bytes[0] == 'Y');
    CHECK(read(pipefd[0], bytes, 1) == 1 && bytes[0] == 'X');
    /* A pending signal unblocked only during a mixed-domain wait must wake
     * atomically, and the caller's blocked mask must be restored afterward. */
    CHECK(signal(SIGUSR1, on_signal) != SIG_ERR);
    sigset_t blocked, original, during, restored;
    sigemptyset(&blocked); sigaddset(&blocked, SIGUSR1);
    CHECK(pthread_sigmask(SIG_BLOCK, &blocked, &original) == 0);
    during = original; sigdelset(&during, SIGUSR1);
    struct timespec delay = {2, 0};
    for (int api = 0; api < 4; ++api) {
        CHECK(raise(SIGUSR1) == 0);
        int result;
        if (api == 0) {
            struct pollfd waiting[2] = {{client, POLLIN, 0}, {pipefd[0], POLLIN, 0}};
            result = ppoll(waiting, 2, &delay, &during);
        } else if (api == 1) {
            FD_ZERO(&reads); FD_SET(client, &reads); FD_SET(pipefd[0], &reads);
            result = pselect(maximum + 1, &reads, NULL, NULL, &delay, &during);
        } else if (api == 2) result = epoll_pwait(ep, &event, 1, 2000, &during);
        else result = epoll_pwait2(ep, &event, 1, &delay, &during);
        CHECK(result == -1 && errno == EINTR && signals == api + 1);
        CHECK(pthread_sigmask(SIG_SETMASK, NULL, &restored) == 0 && sigismember(&restored, SIGUSR1));
    }
    CHECK(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    CHECK(close(ep) == 0 && close(client) == 0 && close(accepted) == 0 && close(listener) == 0);
    CHECK(close(public_dup2_fd) == 0 && close(public_dup3_fd) == 0);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    pthread_t threads[2];
    for (unsigned int i = 0; i < 2; ++i) CHECK(pthread_create(&threads[i], NULL, descriptor_churn, NULL) == 0);
    for (unsigned int i = 0; i < 2; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    for (unsigned int i = 0; i < 600; ++i) CHECK(close(files[i]) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) _exit(99); /* The runtime's atfork boundary must run first. */
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 125);
    puts("PASS: mixed high host/native fds, dup/fcntl, poll/select/epoll, oneshot, concurrent close");
    return 0;
}
