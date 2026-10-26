#define _GNU_SOURCE
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
extern ssize_t __read_chk(int, void *, size_t, size_t);
extern int __poll_chk(struct pollfd *, nfds_t, int, size_t);
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    /* Link the exact Ker checked-entry implementation into this host unit.
     * No fork is attempted inside a running imported kernel. */
    for (int kind = 0; kind < 2; ++kind) {
        pid_t child = fork(); CHECK(child >= 0);
        if (child == 0) {
            struct rlimit limit = {0, 0}; CHECK(setrlimit(RLIMIT_CORE, &limit) == 0);
            char bytes[8]; struct pollfd event = {-1, POLLIN, 0};
            if (kind == 0) {
                ssize_t (*volatile checked)(int, void *, size_t, size_t) = __read_chk;
                (void)checked(-1, bytes, 2, 1);
            } else {
                int (*volatile checked)(struct pollfd *, nfds_t, int, size_t) = __poll_chk;
                (void)checked(&event, 2, 0, sizeof(event));
            }
            _exit(90);
        }
        int status; CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
    puts("PASS: checked-entry buffer bounds abort before invalid-fd dispatch");
    return 0;
}
