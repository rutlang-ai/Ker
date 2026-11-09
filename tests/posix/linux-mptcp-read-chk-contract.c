#define _GNU_SOURCE
#include "linux-mptcp-socket-proxy.c"
#include <assert.h>
#include <pthread.h>
#include <sys/wait.h>

struct read_peer { int fd; };

static void *reply_to_read(void *opaque)
{
    struct read_peer *peer = opaque;
    struct { struct ms_message header; unsigned char data[MS_MAX]; } request;
    ssize_t size = recv(peer->fd, &request, sizeof(request), 0);
    assert(size == (ssize_t)sizeof(request.header));
    assert(request.header.magic == MS_MAGIC && request.header.operation == MS_READ);
    assert(request.header.a == 5);
    struct { struct ms_message header; unsigned char data[MS_MAX]; } response = {
        .header = {.magic = MS_MAGIC, .operation = MS_READ, .length = 5, .result = 5},
        .data = {'h', 'e', 'l', 'l', 'o'}
    };
    size_t response_size = sizeof(response.header) + 5;
    assert(send(peer->fd, &response, response_size, 0) == (ssize_t)response_size);
    return NULL;
}

static void managed_checked_read_uses_adapter(void)
{
    int channel[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel) == 0);
    network_fds[channel[0]] = 1;
    struct read_peer peer = {.fd = channel[1]};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, reply_to_read, &peer) == 0);
    char buffer[5] = {0};
    ssize_t count = __wrap___read_chk(channel[0], buffer, sizeof(buffer), sizeof(buffer));
    if (count != 5) { fprintf(stderr, "managed checked read returned %zd errno=%d\n", count, errno); abort(); }
    assert(memcmp(buffer, "hello", sizeof(buffer)) == 0);
    assert(pthread_join(thread, NULL) == 0);
    network_fds[channel[0]] = 0;
    close(channel[0]); close(channel[1]);
}

static void ordinary_checked_read_uses_libc(void)
{
    int channel[2];
    assert(pipe(channel) == 0);
    assert(write(channel[1], "file", 4) == 4);
    close(channel[1]);
    char buffer[4] = {0};
    assert(__wrap___read_chk(channel[0], buffer, sizeof(buffer), sizeof(buffer)) == 4);
    assert(memcmp(buffer, "file", sizeof(buffer)) == 0);
    close(channel[0]);
}

static void oversized_managed_read_aborts_before_rpc(void)
{
    int channel[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, channel) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(channel[1]);
        network_fds[channel[0]] = 1;
        char buffer[1];
        (void)__wrap___read_chk(channel[0], buffer, 2, sizeof(buffer));
        _exit(0);
    }
    close(channel[0]);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    char unexpected_rpc;
    assert(recv(channel[1], &unexpected_rpc, sizeof(unexpected_rpc), MSG_DONTWAIT) == 0);
    close(channel[1]);
}

int main(void)
{
    managed_checked_read_uses_adapter();
    ordinary_checked_read_uses_libc();
    oversized_managed_read_aborts_before_rpc();
    puts("PASS: checked MPTCP reads preserve adapter and libc bounds semantics");
    return 0;
}
