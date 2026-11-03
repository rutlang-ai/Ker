/* Test-only coordinator. All TCP and cutover work remains in the broker. */
#define _GNU_SOURCE
#include <ker/socket-broker.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { perror(#x); return 1; } } while (0)

static uint64_t now_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec;
}

static int cutover_wait(struct ker_socket_client *client, int cap,
    uint32_t phase, int require_packet)
{
    uint64_t start = now_ns();
    struct ker_socket_group_cutover_status state;
    while (start && now_ns() - start < UINT64_C(10000000000)) {
        if (ker_socket_client_owner_group_cutover_poll(client, cap, &state)) return -1;
        if (state.phase == phase && (!require_packet || state.received_packets)) {
            printf("CUTOVER_STATE phase=%u received=%u accepted=%u\n",
                state.phase, state.received_packets, state.accepted_packets);
            fflush(stdout);
            return 0;
        }
        if (state.phase == KER_SOCKET_GROUP_CUTOVER_FAILED ||
            state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED) {
            errno = EPROTO; return -1;
        }
        struct timespec pause = {.tv_nsec = 1000000};
        (void)nanosleep(&pause, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

int main(int argc, char **argv)
{
    CHECK(argc == 3);
    char *end;
    long transfer = strtol(argv[2], &end, 10);
    CHECK(argv[2][0] && !*end && transfer >= 0 && transfer <= INT32_MAX);
    struct ker_socket_client client;
    CHECK(!ker_socket_client_open(&client, argv[1]));
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(4108)};
    CHECK(inet_pton(AF_INET, "198.18.0.2", &address.sin_addr) == 1);
    int plan = ker_socket_client_owner_group_staged_plan(&client, &address, 16,
        KER_SOCKET_BROKER_CONTROL | KER_SOCKET_BROKER_READ);
    CHECK(plan >= 0);
    int slots[] = {ker_socket_client_owner_group_slot(&client, plan, 0),
        ker_socket_client_owner_group_slot(&client, plan, 1)};
    CHECK(slots[0] >= 0 && slots[1] >= 0);
    char byte = 'N';
    union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(slots))]; } control = {0};
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(slots));
    memcpy(CMSG_DATA(header), slots, sizeof(slots));
    CHECK(sendmsg((int)transfer, &message, MSG_NOSIGNAL) == 1);
    close((int)transfer);
    int group = -1, census[2] = {-1, -1}, cutover = -1;
    char command[32];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "CONTROL\n")) {
            CHECK(group < 0);
            group = ker_socket_client_owner_group_control(&client, plan);
            CHECK(group >= 0);
        } else if (!strcmp(command, "CENSUS0\n") || !strcmp(command, "CENSUS1\n")) {
            unsigned index = command[6] - '0';
            CHECK(group >= 0 && census[index] < 0);
            census[index] = ker_socket_client_member_census_create(&client, group, index);
            struct ker_socket_member_census_snapshot state;
            CHECK(census[index] >= 0 && !ker_socket_client_member_census_snapshot(&client, census[index], &state));
            CHECK(state.listener_cookie && state.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1);
        } else if (!strcmp(command, "EARLY_RETIRE\n")) {
            CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "ALIAS_RETIRE\n")) {
            CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "WRONG_RETIRE\n")) {
            CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, slots[0]) == -1 && errno == ENOTSOCK);
        } else if (!strcmp(command, "RETIRE0\n")) {
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            int result;
            do {
                result = ker_socket_client_owner_group_retire_initial_listener(&client, plan);
                if (!result || errno != EAGAIN) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(!result);
            CHECK(!ker_socket_client_owner_group_retire_initial_listener(&client, plan));
        } else if (!strcmp(command, "STREAMS0\n")) {
            struct ker_socket_member_census_snapshot state;
            uint64_t deadline = now_ns() + UINT64_C(10000000000);
            do {
                CHECK(census[0] >= 0 && !ker_socket_client_member_census_snapshot(&client, census[0], &state));
                if (state.state_counts[KER_SOCKET_TCP_STATE_ESTABLISHED] >= 13) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(state.state_counts[KER_SOCKET_TCP_STATE_ESTABLISHED] >= 13);
            printf("SOURCE_STREAM_CENSUS established=%llu\n",
                (unsigned long long)state.state_counts[KER_SOCKET_TCP_STATE_ESTABLISHED]);
        } else if (!strcmp(command, "BEGIN\n")) {
            CHECK(cutover < 0);
            cutover = ker_socket_client_owner_group_cutover_begin(&client, plan);
            CHECK(cutover >= 0 && !cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_PREPARED, 0));
        } else if (!strcmp(command, "QUEUED\n")) {
            CHECK(cutover >= 0 && !cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_PREPARED, 1));
        } else if (!strcmp(command, "COMMIT\n")) {
            CHECK(!ker_socket_client_owner_group_cutover_commit(&client, cutover));
            CHECK(!cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_COMMITTED, 0));
        } else if (!strcmp(command, "ABORT\n")) {
            CHECK(!ker_socket_client_owner_group_cutover_abort(&client, cutover));
            CHECK(!cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_ABORTED, 0));
        } else if (!strcmp(command, "RELEASE\n")) {
            if (cutover >= 0) { close(cutover); cutover = -1; }
            if (group >= 0) { close(group); group = -1; }
            if (plan >= 0) { close(plan); plan = -1; }
            for (unsigned index = 0; index < 2; ++index) {
                if (slots[index] >= 0) { close(slots[index]); slots[index] = -1; }
            }
        } else if (!strcmp(command, "CLOSED0\n") || !strcmp(command, "CLOSED1\n")) {
            unsigned index = command[6] - '0';
            struct ker_socket_member_census_snapshot state;
            CHECK(census[index] >= 0);
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(!ker_socket_client_member_census_snapshot(&client, census[index], &state));
                if (!state.state_counts[KER_SOCKET_TCP_STATE_LISTEN]) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(!state.state_counts[KER_SOCKET_TCP_STATE_LISTEN]);
        } else if (!strcmp(command, "STOP\n")) break;
        else { errno = EINVAL; CHECK(0); }
        printf("OWNER_GROUP_OK %s", command); fflush(stdout);
    }
    if (cutover >= 0) close(cutover);
    for (unsigned index = 0; index < 2; ++index) {
        if (census[index] >= 0) close(census[index]);
        if (slots[index] >= 0) close(slots[index]);
    }
    if (group >= 0) close(group);
    if (plan >= 0) close(plan);
    ker_socket_client_close(&client);
    return 0;
}
