#ifndef KER_SOCKET_BROKER_READINESS_TEST_H
#define KER_SOCKET_BROKER_READINESS_TEST_H

struct ker_socket_broker_server;

/* Deterministic async VERIFY barrier for the uninstalled lifecycle fixture. */
int ker_socket_broker_server_readiness_test_set_verify_barrier(
    struct ker_socket_broker_server *server, int control_fd);

#endif
