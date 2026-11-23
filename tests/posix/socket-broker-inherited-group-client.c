#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 5) return 2;
    char *end = NULL;
    long capability_value = strtol(argv[2], &end, 10);
    if (!end || *end || capability_value < 0 || capability_value > INT32_MAX) return 2;
    int capability = (int)capability_value;
    long index_value = strtol(argv[3], &end, 10);
    if (!end || *end || index_value < 0 || index_value > 1) return 2;
    int descriptor_flags = fcntl(capability, F_GETFD);
    if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC)) return 3;
    int status_flags = fcntl(capability, F_GETFL);
    if (status_flags < 0 || (status_flags & O_ACCMODE) != O_WRONLY) return 3;

    struct ker_socket_client client;
    if (ker_socket_client_open(&client, argv[1])) {
        perror("open inherited group client");
        return 4;
    }
    enum ker_socket_broker_kind kind = 0;
    status_flags = -1;
    if (ker_socket_client_describe(&client, capability, &kind, &status_flags) ||
        status_flags != 0 ||
        (strcmp(argv[4], "group") && strcmp(argv[4], "census")) ||
        kind != (strcmp(argv[4], "census") ? KER_SOCKET_BROKER_REUSEPORT_GROUP :
            KER_SOCKET_BROKER_MEMBER_CENSUS)) {
        perror("describe inherited opaque capability");
        ker_socket_client_close(&client);
        return 5;
    }
    if (kind == KER_SOCKET_BROKER_REUSEPORT_GROUP) {
        if (ker_socket_client_reuseport_group_select(&client, capability,
                (unsigned)index_value)) {
            perror("select inherited group capability");
            ker_socket_client_close(&client);
            return 6;
        }
    } else {
        struct ker_socket_member_census_snapshot snapshot = {0};
        if (ker_socket_client_member_census_snapshot(&client, capability, &snapshot) ||
            snapshot.total != 1 ||
            snapshot.state_counts[KER_SOCKET_TCP_STATE_LISTEN] != 1 ||
            !snapshot.listener_cookie) {
            perror("snapshot inherited census capability");
            ker_socket_client_close(&client);
            return 7;
        }
    }
    ker_socket_client_close(&client);
    return 0;
}
