#include <signal.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void stop_master(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

int main(int argc, char **argv)
{
    int index;

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "-t") == 0) {
            return 0;
        }
    }
    if (signal(SIGQUIT, stop_master) == SIG_ERR ||
        signal(SIGHUP, SIG_IGN) == SIG_ERR) {
        return 2;
    }
    while (!stopping) {
        pause();
    }
    return 0;
}
