#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "-t") == 0) {
            return 0;
        }
        if (strcmp(argv[index], "-p") == 0 && index + 1 < argc) {
            prefix = argv[++index];
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
