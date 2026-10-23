#ifndef KER_WORKER_RECEIVE_MODE_H
#define KER_WORKER_RECEIVE_MODE_H
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
struct ker_worker_receive_mode {
    int socket_fd; /* initialize to -1 */
    int identity_fd; /* protocol-zero AF_PACKET socket pins the Linux ifindex */
    unsigned ifindex;
    bool restore_allmulti;
    char interface[IFNAMSIZ];
    const char *method; /* pmd or host_tap after verified enable */
};
int ker_worker_allmulticast_enable(uint16_t port, struct ker_worker_receive_mode *state);
int ker_worker_receive_mode_restore(struct ker_worker_receive_mode *state);
#endif
