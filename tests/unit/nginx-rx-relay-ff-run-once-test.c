#define _GNU_SOURCE
#include "../../src/posix/fstack-nginx-runtime.c"

#include <sys/wait.h>

bool ker_sb_preload_ff_owner_is_current(void) { return true; }
int ker_sb_preload_owner_loop_enter(void) { return 0; }
void ker_sb_preload_owner_loop_leave(void) {}
int ker_sb_preload_owner_pump(void) { return 0; }
int ker_sb_posix_epoll_ctl(int epfd, int operation, int fd, struct epoll_event *event)
{
    (void)epfd; (void)operation; (void)fd; (void)event;
    return 0;
}

static int stop_first_run(void *context)
{
    (void)context;
    ff_stop_run();
    return 0;
}

int main(void)
{
    char trace[] = "/tmp/ker-rx-owner-ff-run-once-XXXXXX";
    int trace_fd = mkstemp(trace);
    if (trace_fd < 0) return 2;
    close(trace_fd);
    pid_t child = fork();
    if (child < 0) { unlink(trace); return 3; }
    if (!child) {
        if (setenv("KER_NGINX_RX_OWNER_RELAY_FD", "19", 1) ||
            setenv("KER_FSTACK_RUNTIME_TRACE", trace, 1)) _exit(40);
        runtime_initialized = 1;
        rx_owner_dispatcher = NULL; /* The first ff_run registers later in worker_ready. */
        rx_owner_dispatch_run_consumed = 0;
        ff_run(stop_first_run, NULL);
        if (!rx_owner_dispatch_run_consumed) _exit(41);
        ff_run(stop_first_run, NULL);
        _exit(42);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    FILE *file = fopen(trace, "re");
    char line[512] = {0};
    bool traced = file && fgets(line, sizeof(line), file) != NULL;
    if (file) fclose(file);
    unlink(trace);
    if (waited != child || !WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT ||
        !traced || !strstr(line, "ff_run RX owner relay rejected stale owner or reused run"))
        return 1;
    puts("FF_RUN_RELAY_ONCE first_run_consumes_without_callback=1 second_run=SIGABRT");
    return 0;
}
