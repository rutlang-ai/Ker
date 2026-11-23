#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static int hup_marker = -1;

static void stop_master(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static void observe_hup(int signal_number)
{
    static const char marker[] = "HUP\n";

    (void)signal_number;
    if (hup_marker >= 0) {
        (void)write(hup_marker, marker, sizeof(marker) - 1);
    }
}

int main(int argc, char **argv)
{
    int index;
    const char *prefix = ".";
    sigset_t quit_set, original_mask;
    struct sigaction action = {0};
    char gate_path[4096], waiting_path[4096], waiting_temp_path[4096];
    char release_path[4096];

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "-t") == 0) {
            return 0;
        }
        if (strcmp(argv[index], "-p") == 0 && index + 1 < argc) {
            prefix = argv[++index];
        }
    }
    {
        int gate_length = snprintf(gate_path, sizeof(gate_path),
            "%s/delay-signal-handlers", prefix);
        int waiting_length = snprintf(waiting_path, sizeof(waiting_path),
            "%s/signal-handler-waiting", prefix);
        int waiting_temp_length = snprintf(waiting_temp_path,
            sizeof(waiting_temp_path), "%s/signal-handler-waiting.tmp", prefix);
        int release_length = snprintf(release_path, sizeof(release_path),
            "%s/release-signal-handlers", prefix);
        if (gate_length < 0 || (size_t)gate_length >= sizeof(gate_path) ||
                waiting_length < 0 || (size_t)waiting_length >= sizeof(waiting_path) ||
                waiting_temp_length < 0 ||
                (size_t)waiting_temp_length >= sizeof(waiting_temp_path) ||
                release_length < 0 || (size_t)release_length >= sizeof(release_path))
            return 2;
        if (access(gate_path, F_OK) == 0) {
            int waiting_fd = open(waiting_temp_path,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            char pid_text[32];
            int pid_length;
            struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
            if (waiting_fd < 0)
                return 2;
            pid_length = snprintf(pid_text, sizeof(pid_text), "%ld\n",
                (long)getpid());
            if (pid_length <= 0 || (size_t)pid_length >= sizeof(pid_text) ||
                    write(waiting_fd, pid_text, (size_t)pid_length) != pid_length) {
                close(waiting_fd);
                return 2;
            }
            close(waiting_fd);
            if (rename(waiting_temp_path, waiting_path) != 0)
                return 2;
            while (access(release_path, F_OK) != 0)
                (void)nanosleep(&delay, NULL);
        }
    }
    sigemptyset(&quit_set);
    sigaddset(&quit_set, SIGQUIT);
    sigaddset(&quit_set, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &quit_set, &original_mask) != 0) {
        return 2;
    }
    action.sa_handler = stop_master;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGQUIT, &action, NULL) != 0) {
        return 2;
    }
    action.sa_handler = observe_hup;
    if (sigaction(SIGHUP, &action, NULL) != 0) {
        return 2;
    }
    {
        char marker_path[4096];
        int length = snprintf(marker_path, sizeof(marker_path),
            "%s/hup-observed", prefix);

        if (length < 0 || (size_t)length >= sizeof(marker_path)) {
            return 2;
        }
        hup_marker = open(marker_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
            0600);
        if (hup_marker < 0) {
            return 2;
        }
    }
    while (!stopping)
        (void)sigsuspend(&original_mask);
    if (sigprocmask(SIG_SETMASK, &original_mask, NULL) != 0)
        return 2;
    return 0;
}
