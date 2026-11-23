#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

extern int ker_preload_needed_proxy_anchor(void);

static void *required_symbol(void *handle, const char *name)
{
    void *symbol = dlsym(handle, name);
    if (!symbol) {
        fprintf(stderr, "missing preload symbol %s: %s\n", name, dlerror());
        exit(1);
    }
    return symbol;
}

int main(void)
{
    if (unsetenv("KER_SOCKET_BROKER_PATH") != 0) return 1;
    if (ker_preload_needed_proxy_anchor() != 1) return 2;

    void *preload = dlopen("libker-socket-preload.so", RTLD_NOW | RTLD_NOLOAD);
    if (!preload) {
        fprintf(stderr, "preload DSO was not loaded: %s\n", dlerror());
        return 3;
    }

    typedef ssize_t (*io_fn)(int, const void *, size_t);
    typedef ssize_t (*read_fn)(int, void *, size_t);
    typedef int (*close_fn)(int);
    typedef int (*socket_fn)(int, int, int);
    io_fn preload_write = (io_fn)required_symbol(preload, "write");
    read_fn preload_read = (read_fn)required_symbol(preload, "read");
    close_fn preload_close = (close_fn)required_symbol(preload, "close");
    socket_fn preload_socket = (socket_fn)required_symbol(preload, "socket");

    int pipe_fds[2];
    if (syscall(SYS_pipe2, pipe_fds, O_CLOEXEC) != 0) return 4;
    const char sent = 'L';
    char received = 0;
    if (preload_write(pipe_fds[1], &sent, 1) != 1) return 5;
    if (preload_read(pipe_fds[0], &received, 1) != 1 || received != sent) return 6;
    if (preload_close(pipe_fds[0]) != 0 || preload_close(pipe_fds[1]) != 0) return 7;

    errno = 0;
    if (preload_socket(AF_INET, SOCK_STREAM, 0) != -1 || errno != ENOTCONN) return 8;

    puts("PRELOAD_NEEDED_ORDER_OK");
    return 0;
}
