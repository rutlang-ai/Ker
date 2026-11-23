#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <errno.h>
#include <stdlib.h>

struct generation_controller {
    struct ker_socket_client client;
};

void *ker_test_generation_controller_open(const char *path)
{
    struct generation_controller *controller = calloc(1, sizeof(*controller));
    if (!controller) return NULL;
    if (ker_socket_client_open(&controller->client, path)) {
        int error = errno;
        free(controller);
        errno = error;
        return NULL;
    }
    return controller;
}

void ker_test_generation_controller_close(void *opaque)
{
    struct generation_controller *controller = opaque;
    if (!controller) return;
    ker_socket_client_close(&controller->client);
    free(controller);
}

int ker_test_generation_member(void *opaque, int group, unsigned index)
{
    struct generation_controller *controller = opaque;
    return ker_socket_client_reuseport_group_member(&controller->client, group, index);
}

int ker_test_generation_select(void *opaque, int group, unsigned index)
{
    struct generation_controller *controller = opaque;
    return ker_socket_client_reuseport_group_select(&controller->client, group, index);
}

int ker_test_generation_describe(void *opaque, int fd, int *kind, int *flags)
{
    struct generation_controller *controller = opaque;
    enum ker_socket_broker_kind broker_kind = 0;
    int result = ker_socket_client_describe(&controller->client, fd, &broker_kind, flags);
    if (!result) *kind = (int)broker_kind;
    return result;
}

int ker_test_generation_observe(void *opaque, int observer,
    struct ker_socket_tcp_observer_snapshot *snapshot)
{
    struct generation_controller *controller = opaque;
    return ker_socket_client_tcp_observer_snapshot(&controller->client, observer, snapshot);
}
