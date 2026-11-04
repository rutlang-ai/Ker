#define _GNU_SOURCE
#include "nginx-owner-ready.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* A master/worker fixture using the production host transport. The Python peer
 * controls when the worker can send and keeps it alive through validation. */
int main(int argc, char **argv)
{
    assert(argc == 4);
    int endpoint = atoi(argv[1]), slot = atoi(argv[2]);
    const char *mode = argv[3];
    struct ker_nginx_owner_ready_sender sender = {0};
    assert(ker_nginx_owner_ready_sender_init(&sender, endpoint, getppid() + 1) == -EACCES);
    assert(!ker_nginx_owner_ready_sender_init(&sender, endpoint, getppid()));
    assert(ker_nginx_owner_ready_sender_init(&sender, endpoint, getppid()) == -EALREADY);
    assert(ker_nginx_owner_ready_sender_bind(&sender, slot, 0) == -EPERM);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        assert(ker_nginx_owner_ready_sender_bind(&sender, slot, 2) == -EINVAL);
        int invalid = open("/dev/null", O_WRONLY | O_CLOEXEC);
        assert(invalid >= 0);
        assert(ker_nginx_owner_ready_sender_bind(&sender, invalid, 0) == -ENOTSOCK);
        close(invalid);
        assert(!ker_nginx_owner_ready_sender_bind(&sender, slot, 1));
        assert(ker_nginx_owner_ready_sender_bind(&sender, slot, 1) == -EALREADY);
        pid_t descendant = fork();
        assert(descendant >= 0);
        if (!descendant) _exit(ker_nginx_owner_ready_sender_send(&sender) == -EXDEV ? 0 : 1);
        int status;
        assert(waitpid(descendant, &status, 0) == descendant && status == 0);
        printf("WORKER %ld\n", (long)getpid()); fflush(stdout);
        char byte;
        assert(read(STDIN_FILENO, &byte, 1) == 1);
        if (!strcmp(mode, "endpoint-reuse") || !strcmp(mode, "pidfd-reuse")) {
            int fd = !strcmp(mode, "endpoint-reuse") ? sender.fd : sender.peer_pidfd;
            invalid = open("/dev/null", O_WRONLY | O_CLOEXEC);
            assert(invalid >= 0 && dup2(invalid, fd) == fd);
            close(invalid);
            assert(ker_nginx_owner_ready_sender_send(&sender) == -ESTALE);
            ker_nginx_owner_ready_sender_close(&sender);
            assert(fcntl(fd, F_GETFD) >= 0); /* Never close a reused foreign fd. */
            close(fd);
        } else if (!strcmp(mode, "backpressure")) {
            char payload[64] = {0};
            while (send(endpoint, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL) >= 0) {}
            assert(errno == EAGAIN);
            assert(ker_nginx_owner_ready_sender_send(&sender) == -EAGAIN);
            sender.deadline_ns = 1;
            assert(ker_nginx_owner_ready_sender_send(&sender) == -ETIMEDOUT);
            ker_nginx_owner_ready_sender_close(&sender);
        } else if (!strcmp(mode, "dead-peer")) {
            assert(ker_nginx_owner_ready_sender_send(&sender) == -ECONNRESET);
            ker_nginx_owner_ready_sender_close(&sender);
        } else {
            assert(!ker_nginx_owner_ready_sender_send(&sender));
            assert(!ker_nginx_owner_ready_sender_send(&sender));
            printf("SENT\n"); fflush(stdout);
            assert(read(STDIN_FILENO, &byte, 1) == 1);
        }
        _exit(0);
    }
    ker_nginx_owner_ready_sender_close(&sender);
    int status;
    assert(waitpid(child, &status, 0) == child && status == 0);
    return 0;
}
