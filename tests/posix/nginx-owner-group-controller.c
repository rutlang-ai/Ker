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
    int previous_plan = -1, previous_group = -1, discarded_census = -1;
    int previous_aborted = 0, previous_abandoned = 0;
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
        } else if (!strcmp(command, "CENSUS_UNPUBLISHED\n")) {
            CHECK(group >= 0 && census[1] < 0);
            census[1] = ker_socket_client_member_census_create(&client, group, 1);
            struct ker_socket_member_census_snapshot state;
            CHECK(census[1] >= 0 && !ker_socket_client_member_census_snapshot(&client, census[1], &state));
            CHECK(!state.listener_cookie && !state.state_counts[KER_SOCKET_TCP_STATE_LISTEN]);
            CHECK(ker_socket_client_owner_group_cutover_begin(&client, plan) == -1 && errno == EAGAIN);
            CHECK(ker_socket_client_owner_group_abandon_plan(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "EARLY_NEXT\n")) {
            CHECK(ker_socket_client_owner_group_successor_plan(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "ABORT_NEXT\n")) {
            CHECK(ker_socket_client_owner_group_successor_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "WRONG_NEXT\n")) {
            CHECK(ker_socket_client_owner_group_successor_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
        } else if (!strcmp(command, "EARLY_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "COMMITTED_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "DEAD_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "WRONG_RETRY\n")) {
            CHECK(ker_socket_client_owner_group_retry_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
        } else if (!strcmp(command, "NEXT\n") || !strcmp(command, "RETRY\n") || !strcmp(command, "ABANDON\n") || !strcmp(command, "RECOVER\n")) {
            int recover = !strcmp(command, "RECOVER\n");
            int abandon = command[0] == 'A' || recover;
            int retry = command[0] == 'R' || abandon;
            int (*adopt)(struct ker_socket_client *, int) = recover ?
                ker_socket_client_owner_group_recover_dead_plan : abandon ?
                ker_socket_client_owner_group_abandon_plan : retry ?
                ker_socket_client_owner_group_retry_plan : ker_socket_client_owner_group_successor_plan;
            CHECK(previous_plan < 0 && previous_group < 0 && (abandon ? cutover < 0 : cutover >= 0));
            if (!abandon) {
                CHECK(adopt(&client, plan) == -1 && errno == EAGAIN);
                close(cutover); cutover = -1;
            }
            CHECK(ker_socket_client_owner_group_abandon_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, slots[1]) == -1 && errno == ENOTSOCK);
            uint64_t deadline = now_ns() + UINT64_C(10000000000);
            int next;
            do {
                next = adopt(&client, plan);
                if (next >= 0 || errno != EAGAIN) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(next >= 0);
            enum ker_socket_broker_kind kind;
            int flags = -1;
            CHECK(!ker_socket_client_describe(&client, next, &kind, &flags) &&
                kind == KER_SOCKET_BROKER_FF_OWNER_GROUP_PLAN && !flags);
            CHECK(adopt(&client, plan) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_slot(&client, next, 0) == -1 && errno == EALREADY);
            int next_group = ker_socket_client_owner_group_control(&client, next);
            CHECK(next_group >= 0);
            int next_census = ker_socket_client_member_census_create(&client, next_group, 0);
            struct ker_socket_member_census_snapshot before, after;
            CHECK(next_census >= 0 && !ker_socket_client_member_census_snapshot(&client, census[retry ? 0 : 1], &before));
            CHECK(!ker_socket_client_member_census_snapshot(&client, next_census, &after));
            CHECK(before.listener_cookie && before.listener_cookie == after.listener_cookie &&
                after.state_counts[KER_SOCKET_TCP_STATE_LISTEN] == 1);
            printf("SUCCESSOR_COOKIE preserved=%llu\n", (unsigned long long)after.listener_cookie);
            previous_aborted = retry; previous_abandoned = abandon;
            previous_plan = plan; plan = next;
            previous_group = group; group = next_group;
            for (unsigned index = 0; index < 2; ++index) {
                close(slots[index]); slots[index] = -1;
                if (retry && index == 1) {
                    if (discarded_census >= 0) close(discarded_census);
                    discarded_census = census[index];
                } else close(census[index]);
                census[index] = -1;
            }
            census[0] = next_census;
            if (retry) {
                if (!recover) CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EAGAIN);
            } else {
                slots[1] = ker_socket_client_owner_group_slot(&client, plan, 1);
                CHECK(slots[1] >= 0);
            }
            if (!retry) {
                CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EALREADY);
                memcpy(CMSG_DATA(header), &slots[1], sizeof(slots[1]));
                header->cmsg_len = CMSG_LEN(sizeof(slots[1]));
                message.msg_controllen = CMSG_SPACE(sizeof(slots[1]));
                CHECK(sendmsg((int)transfer, &message, MSG_NOSIGNAL) == 1);
            }
        } else if (!strcmp(command, "SELECT_HISTORY\n")) {
            CHECK(!ker_socket_client_reuseport_group_select(&client, group, 1));
            CHECK(!ker_socket_client_reuseport_group_select(&client, group, 0));
        } else if (!strcmp(command, "HISTORY_REFUSED\n")) {
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "RECOVER_BLOCKED\n")) {
            uint64_t deadline = now_ns() + UINT64_C(200000000);
            do {
                CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == EAGAIN);
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
        } else if (!strcmp(command, "RETRY_SLOT_BLOCKED\n")) {
            uint64_t deadline = now_ns() + UINT64_C(200000000);
            do {
                CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EAGAIN);
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
        } else if (!strcmp(command, "RETRY_SLOT\n")) {
            uint64_t deadline = now_ns() + UINT64_C(10000000000);
            do {
                slots[1] = ker_socket_client_owner_group_slot(&client, plan, 1);
                if (slots[1] >= 0 || errno != EAGAIN) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(slots[1] >= 0);
            CHECK(ker_socket_client_owner_group_slot(&client, plan, 1) == -1 && errno == EALREADY);
            memcpy(CMSG_DATA(header), &slots[1], sizeof(slots[1]));
            header->cmsg_len = CMSG_LEN(sizeof(slots[1]));
            message.msg_controllen = CMSG_SPACE(sizeof(slots[1]));
            CHECK(sendmsg((int)transfer, &message, MSG_NOSIGNAL) == 1);
        } else if (!strcmp(command, "CLOSED_REJECTED\n")) {
            struct ker_socket_member_census_snapshot state;
            CHECK(discarded_census >= 0 && !ker_socket_client_member_census_snapshot(&client, discarded_census, &state));
            CHECK(!state.state_counts[KER_SOCKET_TCP_STATE_LISTEN]);
        } else if (!strcmp(command, "OLD_CAPS\n")) {
            CHECK(previous_plan >= 0 && previous_group >= 0);
            CHECK(ker_socket_client_owner_group_cutover_begin(&client, previous_plan) == -1 && errno == (previous_abandoned ? EOPNOTSUPP : EALREADY));
            CHECK(ker_socket_client_reuseport_group_select(&client, previous_group, previous_aborted ? 1 : 0) == -1 && errno == EOPNOTSUPP);
            CHECK(!ker_socket_client_reuseport_group_select(&client, previous_group, previous_aborted ? 0 : 1));
        } else if (!strcmp(command, "DROP_PARENT\n")) {
            CHECK(previous_plan >= 0 && previous_group >= 0);
            close(previous_plan); previous_plan = -1;
            close(previous_group); previous_group = -1;
        } else if (!strcmp(command, "EARLY_RETIRE\n")) {
            CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, plan) == -1 && errno == EAGAIN);
        } else if (!strcmp(command, "ALIAS_RETIRE\n")) {
            uint64_t deadline = now_ns() + UINT64_C(200000000);
            unsigned attempts = 0;
            do {
                CHECK(ker_socket_client_owner_group_retire_initial_listener(&client, plan) == -1 && errno == EAGAIN);
                ++attempts;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(attempts > 1);
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
        } else if (!strcmp(command, "STREAMS0\n") || !strcmp(command, "ACTIVE0\n")) {
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
            CHECK(ker_socket_client_owner_group_abandon_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == EOPNOTSUPP);
        } else if (!strcmp(command, "QUEUED\n")) {
            CHECK(cutover >= 0 && !cutover_wait(&client, cutover, KER_SOCKET_GROUP_CUTOVER_PREPARED, 1));
        } else if (!strcmp(command, "DEAD_BEGIN\n")) {
            CHECK(cutover < 0);
            CHECK(ker_socket_client_owner_group_cutover_begin(&client, plan) == -1);
            CHECK(errno == EAGAIN || errno == ESTALE || errno == ESRCH);
            printf("DEAD_OWNER_BEGIN_REJECTED errno=%d\n", errno);
            /* pidfd death can precede capability-HUP processing. Require a
             * bounded transition to permanent rejection, not event ordering. */
            int retry_error = 0;
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1);
                retry_error = errno;
                if (retry_error == EOPNOTSUPP) break;
                CHECK(retry_error == EAGAIN || retry_error == ESTALE || retry_error == ESRCH);
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(retry_error == EOPNOTSUPP);
            printf("DEAD_OWNER_PRE_CUTOVER_RETRY_REJECTED errno=%d\n", retry_error);
        } else if (!strcmp(command, "DEAD_CUTOVER\n")) {
            /* A request can race autonomous quarantine. API success only
             * acknowledges the request; it must never certify commitment. */
            int requested = ker_socket_client_owner_group_cutover_commit(&client, cutover);
            CHECK(requested == 0 || (requested == -1 && errno == EALREADY));
            printf("DEAD_OWNER_COMMIT_REQUEST result=%d error=%d\n",
                requested, requested ? errno : 0);
            struct ker_socket_group_cutover_status state;
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            do {
                CHECK(!ker_socket_client_owner_group_cutover_poll(&client, cutover, &state));
                CHECK(state.phase != KER_SOCKET_GROUP_CUTOVER_COMMITTED &&
                    state.phase != KER_SOCKET_GROUP_CUTOVER_ABORTED && !state.accepted_packets);
                if (state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED) break;
                struct timespec pause = {.tv_nsec = 1000000};
                (void)nanosleep(&pause, NULL);
            } while (now_ns() < deadline);
            CHECK(state.phase == KER_SOCKET_GROUP_CUTOVER_QUARANTINED &&
                state.result < 0 && state.received_packets && !state.accepted_packets);
            printf("DEAD_OWNER_QUARANTINED phase=%u result=%d received=%u accepted=%u\n",
                state.phase, state.result, state.received_packets, state.accepted_packets);
            CHECK(ker_socket_client_owner_group_cutover_commit(&client, cutover) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_cutover_abort(&client, cutover) == -1 && errno == EALREADY);
            CHECK(ker_socket_client_owner_group_retry_plan(&client, plan) == -1 && errno == ECANCELED);
            CHECK(ker_socket_client_owner_group_abandon_plan(&client, plan) == -1 && errno == ECANCELED);
            CHECK(ker_socket_client_owner_group_recover_dead_plan(&client, plan) == -1 && errno == ECANCELED);
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
    if (discarded_census >= 0) close(discarded_census);
    if (previous_plan >= 0) close(previous_plan);
    if (previous_group >= 0) close(previous_group);
    close((int)transfer);
    ker_socket_client_close(&client);
    return 0;
}
