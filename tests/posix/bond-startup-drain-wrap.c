/* Deterministic startup RX gate for the test-only static bond worker. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <rte_eth_bond.h>
#include <rte_ethdev.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __real_rte_eth_promiscuous_disable(uint16_t port_id);

static int signal_file(const char *path)
{
    if (!path || !*path) return 0;
    int fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int result = write(fd, "ready", 5) == 5 ? 0 : -1;
    close(fd);
    return result;
}

int __wrap_rte_eth_promiscuous_disable(uint16_t port_id)
{
    const char *trigger = getenv("KER_TEST_VHOST_FLOOD_TRIGGER");
    const char *ack = getenv("KER_TEST_VHOST_FLOOD_ACK");
    const char *completed = getenv("KER_TEST_VHOST_FLOOD_COMPLETED");
    char name[RTE_ETH_NAME_MAX_LEN] = {0};
    bool bond_port = !rte_eth_dev_get_name_by_port(port_id, name) &&
        !strncmp(name, "net_bonding", sizeof("net_bonding") - 1);
    if (bond_port && trigger && *trigger && ack && *ack) {
        int primary = -1;
        for (unsigned int attempt = 0; attempt < 10000; ++attempt) {
            primary = rte_eth_bond_primary_get(port_id);
            if (primary == 2) break;
            usleep(1000);
        }
        if (primary != 2) return -ETIMEDOUT;
        if (signal_file(trigger)) return -errno;
        for (unsigned int attempt = 0; attempt < 15000; ++attempt) {
            if (!access(ack, F_OK)) {
                if (signal_file(completed)) return -errno;
                break;
            }
            usleep(1000);
            if (attempt == 14999) return -ETIMEDOUT;
        }
    }
    return __real_rte_eth_promiscuous_disable(port_id);
}
