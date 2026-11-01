#define _GNU_SOURCE
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int ker_preload_constructor_probe_anchor(void)
{
    return 1;
}

__attribute__((constructor)) static void preload_constructor_probe(void)
{
    typedef int (*runtime_ready_fn)(void);
    runtime_ready_fn runtime_ready = (runtime_ready_fn)dlsym(RTLD_DEFAULT,
        "ker_sb_preload_runtime_ready");
    if (!runtime_ready || runtime_ready() != 0) _exit(121);
    static const char marker[] = "EARLY_CONSTRUCTOR_WRITE\n";
    if (write(STDERR_FILENO, marker, sizeof(marker) - 1) != (ssize_t)(sizeof(marker) - 1))
        _exit(122);

    int pipe_fds[2];
    if (syscall(SYS_pipe2, pipe_fds, O_CLOEXEC)) _exit(123);
    const char byte = 'C';
    char received = 0;
    if (write(pipe_fds[1], &byte, 1) != 1) _exit(124);
    if (read(pipe_fds[0], &received, 1) != 1 || received != byte) _exit(125);
    if (close(pipe_fds[0]) || close(pipe_fds[1])) _exit(126);

    errno = 0;
    if (socket(AF_INET, SOCK_STREAM, 0) != -1 || errno != ENOTCONN) _exit(131);
    errno = 0;
    if (epoll_create1(EPOLL_CLOEXEC) != -1 || errno != ENOTCONN) _exit(132);

    /* Descriptor zero used to match zero-filled, not-yet-initialized tables. */
    if (close(STDIN_FILENO)) _exit(127);
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd != STDIN_FILENO) _exit(128);
    if (read(STDIN_FILENO, &received, 1) != 0) _exit(129);
    if (close(STDIN_FILENO)) _exit(130);
}
