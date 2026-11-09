#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sock_filter accept_all[] = { BPF_STMT(BPF_RET | BPF_K, 0xffffffffU) };
    struct sock_fprog valid = { .len = 1, .filter = accept_all };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &valid, sizeof(valid))) {
        perror("valid SO_ATTACH_FILTER"); close(fd); return 2;
    }

    struct sock_filter jump_past_end[] = { BPF_STMT(BPF_JMP | BPF_JA, 1) };
    struct sock_fprog invalid = { .len = 1, .filter = jump_past_end };
    errno = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &invalid, sizeof(invalid)) != -1 || errno != EINVAL) {
        fprintf(stderr, "invalid native BPF returned success or errno %d, expected EINVAL\n", errno);
        close(fd); return 3;
    }

    const unsigned int native_limit_len = 4097;
    struct sock_filter *native_limit_filter = calloc(native_limit_len, sizeof(*native_limit_filter));
    if (!native_limit_filter) { perror("calloc native-limit BPF"); close(fd); return 4; }
    for (unsigned int i = 0; i < native_limit_len; i++)
        native_limit_filter[i] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, 0xffffffffU);
    struct sock_fprog native_limit = { .len = native_limit_len, .filter = native_limit_filter };
    errno = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &native_limit, sizeof(native_limit)) != -1 || errno != EINVAL) {
        fprintf(stderr, "over-limit native BPF returned success or errno %d, expected EINVAL\n", errno);
        free(native_limit_filter); close(fd); return 5;
    }
    free(native_limit_filter);

    struct sock_fprog null_program = { .len = 1, .filter = NULL };
    errno = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &null_program, sizeof(null_program)) != -1 || errno != EINVAL) {
        fprintf(stderr, "NULL BPF pointer returned success or errno %d, expected EINVAL\n", errno);
        close(fd); return 6;
    }

    const unsigned int oversized_len = 20000;
    struct sock_filter *oversized_filter = calloc(oversized_len, sizeof(*oversized_filter));
    if (!oversized_filter) { perror("calloc oversized BPF"); close(fd); return 7; }
    struct sock_fprog oversized = { .len = oversized_len, .filter = oversized_filter };
    errno = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &oversized, sizeof(oversized)) != -1 || errno != EINVAL) {
        fprintf(stderr, "oversized BPF returned success or errno %d, expected EINVAL\n", errno);
        free(oversized_filter); close(fd); return 8;
    }
    free(oversized_filter);

    close(fd);
    puts("BRIDGE_FILTER_CONTROL_PASS valid=0 invalid_native=EINVAL verifier_limit_native=EINVAL null_client=EINVAL oversized_rpc=EINVAL");
    return 0;
}
