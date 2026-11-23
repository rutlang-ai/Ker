/* Test-only delay for filling a real RX ring during ethdev startup. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*promiscuous_disable_fn)(uint16_t port_id);

int rte_eth_promiscuous_disable(uint16_t port_id)
{
    const char *trigger = getenv("KER_TEST_VHOST_FLOOD_TRIGGER");
    const char *ack = getenv("KER_TEST_VHOST_FLOOD_ACK");
    const char *completed = getenv("KER_TEST_VHOST_FLOOD_COMPLETED");
    if (trigger && ack && *trigger && *ack) {
        int fd = open(trigger, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        if (fd < 0) return -1;
        (void)write(fd, "start", 5);
        close(fd);
        for (unsigned int attempt = 0; attempt < 15000; ++attempt) {
            if (!access(ack, F_OK)) {
                if (completed && *completed) {
                    fd = open(completed, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
                    if (fd >= 0) {
                        (void)write(fd, "ready", 5);
                        close(fd);
                    }
                }
                break;
            }
            usleep(1000);
            if (attempt == 14999) return -ETIMEDOUT;
        }
    }
    promiscuous_disable_fn next = (promiscuous_disable_fn)dlsym(RTLD_NEXT,
        "rte_eth_promiscuous_disable");
    if (!next) return -1;
    return next(port_id);
}
