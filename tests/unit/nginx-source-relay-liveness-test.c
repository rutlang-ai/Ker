#define KER_NGINX_RELAY_OBSERVATION_TESTING 1
#define _GNU_SOURCE
#include "../../src/posix/nginx-relay-observation.h"
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>
static volatile sig_atomic_t alarms;
static void alarm_handler(int sig) { (void)sig; ++alarms; }
int main(void)
{
    struct sigaction action = {.sa_handler = alarm_handler};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL)) return 1;
    int fd = syscall(SYS_pidfd_open, getpid(), 0);
    uint64_t now, end, checks = 0, start;
    if (fd < 0 || rx_owner_relay_monotonic_ns(&now)) return 2;
    end = now + UINT64_C(1000000000);
    struct itimerval timer = {.it_interval = {.tv_usec = 10}, .it_value = {.tv_usec = 10}};
    if (setitimer(ITIMER_REAL, &timer, NULL)) return 3;
    for (;;) {
        pid_t pid = 0;
        int ok = rx_owner_relay_pidfd_alive(fd, end);
        if (!ok) {
            if (rx_owner_relay_monotonic_ns(&now) || now < end || errno != ETIMEDOUT) return 4;
            break;
        }
        if (rx_owner_relay_pidfd_pid(fd, &pid, end) || pid != getpid() ||
                cycle_read_start_ticks_until(getpid(), &start, end)) {
            if (rx_owner_relay_monotonic_ns(&now) || now < end || errno != ETIMEDOUT) return 5;
            break;
        }
        ++checks;
    }
    setitimer(ITIMER_REAL, &(struct itimerval){0}, NULL);
    if (rx_owner_relay_pidfd_alive(fd, end) || !alarms || !checks) return 6;
    pid_t child = fork();
    if (child < 0) return 7;
    if (!child) { for (;;) pause(); }
    int dead = syscall(SYS_pidfd_open, child, 0);
    if (dead < 0 || kill(child, SIGKILL) || waitpid(child, NULL, 0) != child || rx_owner_relay_monotonic_ns(&now)) return 8;
    if (rx_owner_relay_pidfd_alive(dead, now + UINT64_C(1000000000))) return 9;
    printf("PASS checks=%llu alarms=%d poll_EINTR=%u finite_expiry=ETIMEDOUT dead_pidfd=rejected\n",
        (unsigned long long)checks, (int)alarms, rx_owner_relay_poll_interruptions);
    close(fd); close(dead);
    return 0;
}
