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
extern int __ppoll_chk(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *, size_t);
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    struct rlimit limit = {0, 0}; CHECK(setrlimit(RLIMIT_CORE, &limit) == 0);
    /* Valid fortified callers must reach the unfortified public wrapper once,
     * not recursively enter these checked entry points. */
    struct pollfd event = {-1, POLLIN, 0}; struct timespec zero = {0, 0};
    volatile nfds_t one = 1;
    CHECK(poll(&event, one, 0) == 0);
    CHECK(ppoll(&event, one, &zero, NULL) == 0);
    /* Link the exact Ker checked-entry implementation into this host unit.
     * No fork is attempted inside a running imported kernel. */
    for (int kind = 0; kind < 5; ++kind) {
        pid_t child = fork(); CHECK(child >= 0);
        if (child == 0) {
            struct rlimit limit = {0, 0}; CHECK(setrlimit(RLIMIT_CORE, &limit) == 0);
            char bytes[8]; struct pollfd event = {-1, POLLIN, 0};
            if (kind == 0) {
                ssize_t (*volatile checked)(int, void *, size_t, size_t) = __read_chk;
                (void)checked(-1, bytes, 2, 1);
            } else if (kind == 1) {
                int (*volatile checked)(struct pollfd *, nfds_t, int, size_t) = __poll_chk;
                (void)checked(&event, 2, 0, sizeof(event));
            } else if (kind == 2) {
                int (*volatile checked)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *, size_t) = __ppoll_chk;
                (void)checked(&event, 2, &zero, NULL, sizeof(event));
            } else {
                volatile nfds_t oversized = 2;
                if (kind == 3) (void)poll(&event, oversized, 0);
                else (void)ppoll(&event, oversized, &zero, NULL);
            }
            _exit(90);
        }
        int status; CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
    }
    puts("PASS: optimized fortify poll routing and checked-entry buffer bounds");
    return 0;
}
