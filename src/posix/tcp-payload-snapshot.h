#ifndef KER_TCP_PAYLOAD_SNAPSHOT_H
#define KER_TCP_PAYLOAD_SNAPSHOT_H

#include <ker/socket-broker.h>
#include <stdint.h>

/* Private ker-posix entry point. The caller supplies only broker-held mark
 * metadata; max_sockets is fixed here and never comes from the SDK. */
int ker_native_tcp_payload_snapshot(uint32_t mark,
    struct ker_socket_member_payload_snapshot *snapshot);
#ifdef KER_MEMBER_CENSUS_TEST_RUNTIME
int ker_native_tcp_payload_snapshot_test_limit(uint32_t mark, uint32_t max_sockets,
    struct ker_socket_member_payload_snapshot *snapshot);
#endif

#endif
