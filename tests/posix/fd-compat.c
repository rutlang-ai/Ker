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
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s: %m\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

static volatile sig_atomic_t signals;
static void on_signal(int signal_number) { (void)signal_number; signals++; }

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
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);
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
    CHECK(epoll_wait(ep, &event, 1, 0) == 0);
    event.events = EPOLLIN | EPOLLONESHOT;
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
