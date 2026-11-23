#ifndef KER_TCP_EVENT_SNAPSHOT_H
#define KER_TCP_EVENT_SNAPSHOT_H

#include <ker/socket-broker.h>

/* Private ker-posix entry point. `exported_fd` is pinned through the query;
 * its LKL descriptor is never returned to the caller. */
int ker_native_socket_event_snapshot(int exported_fd,
    struct ker_socket_event_snapshot *snapshot);

#endif
