// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include "source-network-readback.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <lkl.h>

static unsigned failures;
#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition); \
        ++failures; \
    } \
} while (0)

static struct in_addr ipv4(const char *text)
{
    struct in_addr result = {0};
    CHECK(inet_pton(AF_INET, text, &result) == 1);
    return result;
}

static void expectation_tests(void)
{
    const uint64_t now = 100000000000ULL;
    const char *deadline = "130000000000";
    char valid[256];
    snprintf(valid, sizeof(valid),
        "v1|%064d|198.18.0.2|255.255.255.0|198.18.0.255|198.18.0.1|%s", 0, deadline);
    /* Replace decimal padding with the strict lower-case SHA-256 alphabet. */
    memset(valid + 3, 'a', 64);
    struct ker_source_network_expectation parsed;
    CHECK(ker_source_network_parse_expectation(valid, "198.18.0.2", "24",
        "198.18.0.1", deadline, now, &parsed) == 0);
    CHECK(parsed.version == KER_SOURCE_NETWORK_READBACK_VERSION);
    CHECK(strcmp(parsed.template_sha256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0);
    CHECK(parsed.address.s_addr == ipv4("198.18.0.2").s_addr);
    CHECK(parsed.deadline_ns == 130000000000ULL);

    struct ker_source_network_expectation sentinel;
    memset(&sentinel, 0x5a, sizeof(sentinel));
    struct ker_source_network_expectation before = sentinel;
#define BAD_EXPECT(text, addr, prefix, gateway, boot, clock) do { \
    CHECK(ker_source_network_parse_expectation((text), (addr), (prefix), (gateway), \
        (boot), (clock), &sentinel) != 0); \
    CHECK(memcmp(&sentinel, &before, sizeof(sentinel)) == 0); \
} while (0)
    char malformed[300];
    strcpy(malformed, valid); malformed[1] = '2';
    BAD_EXPECT(malformed, "198.18.0.2", "24", "198.18.0.1", deadline, now);
    strcpy(malformed, valid); malformed[strlen(malformed)] = '|'; malformed[strlen(valid) + 1] = '\0';
    BAD_EXPECT(malformed, "198.18.0.2", "24", "198.18.0.1", deadline, now);
    BAD_EXPECT("v1|abc|198.18.0.2|255.255.255.0|198.18.0.255|198.18.0.1|130000000000",
        "198.18.0.2", "24", "198.18.0.1", deadline, now);
    BAD_EXPECT(valid, "198.18.0.3", "24", "198.18.0.1", deadline, now);
    BAD_EXPECT(valid, "198.18.0.2", "023", "198.18.0.1", deadline, now);
    BAD_EXPECT(valid, "198.18.0.2", "31", "198.18.0.1", deadline, now);
    BAD_EXPECT(valid, "198.18.0.2", "24", "198.18.0.1", "130000000001", now);
    BAD_EXPECT(valid, "198.18.0.2", "24", "198.18.0.1", "130000000000", 130000000000ULL);
    BAD_EXPECT(valid, "198.18.0.2", "24", "198.18.0.1", "500000000000", now);
    BAD_EXPECT(valid, "198.18.0.2", "24", "198.18.0.1", "18446744073709551616", now);
    BAD_EXPECT("v1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|198.18.0.2|255.255.255.0|198.18.0.254|198.18.0.1|130000000000",
        "198.18.0.2", "24", "198.18.0.1", deadline, now);
    BAD_EXPECT("v1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|198.18.0.2|255.255.255.0|198.18.0.255|198.18.1.1|130000000000",
        "198.18.0.2", "24", "198.18.1.1", deadline, now);
    BAD_EXPECT("v1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|198.18.0.2|255.255.255.0|198.18.0.255|198.18.0.0|130000000000",
        "198.18.0.2", "24", "198.18.0.0", deadline, now);
    BAD_EXPECT("v1|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|198.18.0.2|255.255.255.0|198.18.0.255|-|130000000000",
        "198.18.0.2", "24", "-", deadline, now);
#undef BAD_EXPECT
}

static void close_stage_tests(void)
{
    const char *stage = "SIOCGIFADDR ioctl";
    CHECK(ker_source_network_finish_close(-EADDRNOTAVAIL, 0, &stage,
        "AF_INET datagram socket close") == -EADDRNOTAVAIL);
    CHECK(strcmp(stage, "SIOCGIFADDR ioctl") == 0);

    stage = "RTM_GETROUTE response validation";
    CHECK(ker_source_network_finish_close(-EPROTO, 0, &stage,
        "RTM_GETROUTE netlink socket close") == -EPROTO);
    CHECK(strcmp(stage, "RTM_GETROUTE response validation") == 0);

    stage = "RTM_GETROUTE response validation";
    CHECK(ker_source_network_finish_close(0, -EBADF, &stage,
        "RTM_GETROUTE netlink socket close") == -EBADF);
    CHECK(strcmp(stage, "RTM_GETROUTE netlink socket close") == 0);

    stage = "interface tuple comparison";
    CHECK(ker_source_network_finish_close(-ETIMEDOUT, -EBADF, &stage,
        "AF_INET datagram socket close") == -ETIMEDOUT);
    CHECK(strcmp(stage, "interface tuple comparison") == 0);
}

struct datagram {
    union {
        max_align_t align;
        unsigned char bytes[1024];
    } storage;
    size_t length;
};

static struct lkl_nlmsghdr *start_route(struct datagram *data, uint16_t type,
    uint32_t sequence, uint32_t reply_pid, uint16_t flags,
    uint8_t table, uint8_t route_type)
{
    memset(data, 0, sizeof(*data));
    struct lkl_nlmsghdr *header = (void *)data->storage.bytes;
    header->nlmsg_len = LKL_NLMSG_LENGTH(sizeof(struct lkl_rtmsg));
    header->nlmsg_type = type;
    header->nlmsg_seq = sequence;
    header->nlmsg_pid = reply_pid;
    header->nlmsg_flags = flags;
    if (type == LKL_RTM_NEWROUTE) {
        struct lkl_rtmsg *route = LKL_NLMSG_DATA(header);
        route->rtm_family = LKL_AF_INET;
        route->rtm_table = table;
        route->rtm_type = route_type;
        route->rtm_scope = LKL_RT_SCOPE_UNIVERSE;
    }
    data->length = LKL_NLMSG_ALIGN(header->nlmsg_len);
    return header;
}

static void add_attr(struct datagram *data, unsigned short type,
    const void *value, size_t length)
{
    struct lkl_nlmsghdr *header = (void *)data->storage.bytes;
    size_t offset = LKL_NLMSG_ALIGN(header->nlmsg_len);
    struct lkl_rtattr *attribute = (void *)(data->storage.bytes + offset);
    attribute->rta_type = type;
    attribute->rta_len = LKL_RTA_LENGTH(length);
    if (length) memcpy(LKL_RTA_DATA(attribute), value, length);
    header->nlmsg_len = offset + LKL_RTA_ALIGN(attribute->rta_len);
    data->length = LKL_NLMSG_ALIGN(header->nlmsg_len);
}

static void add_done(struct datagram *data, uint32_t sequence, uint32_t reply_pid,
    uint16_t flags)
{
    struct lkl_nlmsghdr *header = (void *)data->storage.bytes;
    memset(data, 0, sizeof(*data));
    header = (void *)data->storage.bytes;
    header->nlmsg_len = LKL_NLMSG_LENGTH(0);
    header->nlmsg_type = LKL_NLMSG_DONE;
    header->nlmsg_seq = sequence;
    header->nlmsg_pid = reply_pid;
    header->nlmsg_flags = flags;
    data->length = LKL_NLMSG_ALIGN(header->nlmsg_len);
}

static void add_valid_default(struct datagram *data, uint32_t sequence,
    uint32_t reply_pid, uint32_t ifindex, struct in_addr gateway)
{
    struct lkl_nlmsghdr *header = start_route(data, LKL_RTM_NEWROUTE, sequence,
        reply_pid, LKL_NLM_F_MULTI, LKL_RT_TABLE_MAIN, LKL_RTN_UNICAST);
    (void)header;
    add_attr(data, LKL_RTA_GATEWAY, &gateway, sizeof(gateway));
    add_attr(data, LKL_RTA_OIF, &ifindex, sizeof(ifindex));
}

static int scan_one(struct datagram *route, struct datagram *done,
    uint32_t expected_reply_pid, uint32_t expected_ifindex,
    struct in_addr expected_gateway)
{
    struct ker_source_network_route_scan scan;
    ker_source_network_route_scan_init(&scan, 0x4b535201U, expected_reply_pid,
        expected_ifindex, expected_gateway);
    struct lkl_sockaddr_nl sender = {.nl_family = LKL_AF_NETLINK};
    scan.sequence = 0x4b535201U;
    int result = ker_source_network_route_feed(&scan, route->storage.bytes,
        route->length, &sender, sizeof(sender));
    if (!result && done)
        result = ker_source_network_route_feed(&scan, done->storage.bytes,
            done->length, &sender, sizeof(sender));
    if (!result) result = ker_source_network_route_finish(&scan);
    return result;
}

static void route_tests(void)
{
    const uint32_t sequence = 0x4b535201U, portid = 91, ifindex = 7;
    struct in_addr gateway = ipv4("198.18.0.1");
    struct datagram route, done;
    add_valid_default(&route, sequence, portid, ifindex, gateway);
    add_done(&done, sequence, portid, 0);
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == 0);

    struct lkl_nlmsghdr *header = (void *)route.storage.bytes;
    header->nlmsg_pid = 0; /* Reply header uses the bound request port ID, not kernel pid. */
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EPROTO);
    add_valid_default(&route, sequence + 1, portid, ifindex, gateway);
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EPROTO);
    add_valid_default(&route, sequence, portid, ifindex, gateway);
    struct lkl_sockaddr_nl sender = {.nl_family = LKL_AF_NETLINK, .nl_pid = 2};
    struct ker_source_network_route_scan scan;
    ker_source_network_route_scan_init(&scan, sequence, portid, ifindex, gateway);
    CHECK(ker_source_network_route_feed(&scan, route.storage.bytes, route.length,
        &sender, sizeof(sender)) == -EPROTO);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    header = (void *)route.storage.bytes;
    header->nlmsg_flags |= LKL_NLM_F_DUMP_INTR;
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EAGAIN);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    uint32_t wrong_ifindex = ifindex + 1;
    add_attr(&route, LKL_RTA_OIF, &wrong_ifindex, sizeof(wrong_ifindex));
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EPROTO);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    struct in_addr wrong_gateway = ipv4("198.18.0.9");
    /* A second gateway attribute is malformed, even before tuple comparison. */
    add_attr(&route, LKL_RTA_GATEWAY, &wrong_gateway, sizeof(wrong_gateway));
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EPROTO);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    uint32_t main_table = LKL_RT_TABLE_MAIN;
    header = (void *)route.storage.bytes;
    ((struct lkl_rtmsg *)LKL_NLMSG_DATA(header))->rtm_table = LKL_RT_TABLE_UNSPEC;
    add_attr(&route, LKL_RTA_TABLE, &main_table, sizeof(main_table));
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == 0);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    add_attr(&route, LKL_RTA_MULTIPATH, "x", 1);
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EOPNOTSUPP);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    add_attr(&route, LKL_RTA_PRIORITY, &main_table, sizeof(main_table));
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EOPNOTSUPP);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    struct datagram second;
    add_valid_default(&second, sequence, portid, ifindex, gateway);
    struct ker_source_network_route_scan ambiguous;
    ker_source_network_route_scan_init(&ambiguous, sequence, portid, ifindex, gateway);
    struct lkl_sockaddr_nl kernel = {.nl_family = LKL_AF_NETLINK};
    CHECK(ker_source_network_route_feed(&ambiguous, route.storage.bytes, route.length,
        &kernel, sizeof(kernel)) == 0);
    CHECK(ker_source_network_route_feed(&ambiguous, second.storage.bytes, second.length,
        &kernel, sizeof(kernel)) == -EEXIST);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    header = (void *)route.storage.bytes;
    header->nlmsg_len = LKL_NLMSG_LENGTH(sizeof(struct lkl_rtmsg)) - 1;
    route.length = LKL_NLMSG_ALIGN(header->nlmsg_len);
    CHECK(scan_one(&route, &done, portid, ifindex, gateway) == -EPROTO);

    add_valid_default(&route, sequence, portid, ifindex, gateway);
    CHECK(scan_one(&route, NULL, portid, ifindex, gateway) == -EPROTO);
}

static struct ker_source_network_observation sample_observation(uint64_t deadline)
{
    struct ker_source_network_observation observed = {
        .version = KER_SOURCE_NETWORK_READBACK_VERSION,
        .ifindex = 7,
        .route_table = LKL_RT_TABLE_MAIN,
        .route_oif = 7,
        .address = {.s_addr = 0},
        .netmask = {.s_addr = 0},
        .broadcast = {.s_addr = 0},
        .gateway = {.s_addr = 0},
        .deadline_ns = deadline,
    };
    observed.address = ipv4("198.18.0.2");
    observed.netmask = ipv4("255.255.255.0");
    observed.broadcast = ipv4("198.18.0.255");
    observed.gateway = ipv4("198.18.0.1");
    memset(observed.template_sha256, 'a', 64);
    observed.template_sha256[64] = '\0';
    return observed;
}

static int test_host_now(uint64_t *now)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -errno;
    *now = (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
    return 0;
}

enum fake_write_mode { FAKE_SUCCESS, FAKE_LATE_SUCCESS, FAKE_SHORT, FAKE_ERROR, FAKE_EINTR, FAKE_AGAIN };
struct fake_startup {
    enum fake_write_mode mode;
    unsigned validates, writes, waits;
    uint64_t now;
    unsigned char bytes[PIPE_BUF];
    size_t length;
};
static struct fake_startup *active_fake;

static int fake_validate(int fd)
{
    (void)fd;
    ++active_fake->validates;
    return 0;
}
static int fake_now(uint64_t *now)
{
    *now = active_fake->now;
    return 0;
}
static ssize_t fake_write(int fd, const void *buffer, size_t length)
{
    (void)fd;
    ++active_fake->writes;
    if (active_fake->mode == FAKE_ERROR) return -EPIPE;
    if (active_fake->mode == FAKE_EINTR) return -EINTR;
    if (active_fake->mode == FAKE_AGAIN) return -EAGAIN;
    if (active_fake->mode == FAKE_SHORT) {
        active_fake->length = sizeof("KER_NATIVE_READY\n") - 1;
        memcpy(active_fake->bytes, buffer, active_fake->length);
        return (ssize_t)active_fake->length;
    }
    memcpy(active_fake->bytes, buffer, length);
    active_fake->length = length;
    if (active_fake->mode == FAKE_LATE_SUCCESS)
        active_fake->now = active_fake->now + 1000000000ULL;
    return (ssize_t)length;
}
static int fake_wait(int fd, uint64_t deadline)
{
    (void)fd;
    ++active_fake->waits;
    CHECK(deadline > active_fake->now);
    return -ETIMEDOUT;
}
static void startup_writer_model_tests(void)
{
    const struct ker_source_network_startup_ops ops = {
        .validate_pipe = fake_validate, .monotonic_now = fake_now,
        .write_record = fake_write, .wait_writable = fake_wait,
    };
    uint64_t now = 100000000000ULL;
    struct ker_source_network_observation observed = sample_observation(now + 1000000000ULL);
    struct fake_startup fake = {.mode = FAKE_SUCCESS, .now = now};
    active_fake = &fake;
    CHECK(ker_source_network_write_startup_with_ops(3, &observed, &ops) == 0);
    CHECK(fake.validates == 1 && fake.writes == 1 && fake.waits == 0);
    CHECK(fake.length > sizeof("KER_NATIVE_READY\n") - 1);
    CHECK(memcmp(fake.bytes, "KER_NATIVE_READY\n", sizeof("KER_NATIVE_READY\n") - 1) == 0);
    CHECK(memmem(fake.bytes, fake.length, "KER_SOURCE_NETWORK_READBACK_V1 ",
        sizeof("KER_SOURCE_NETWORK_READBACK_V1 ") - 1) != NULL);

    fake = (struct fake_startup){.mode = FAKE_LATE_SUCCESS, .now = now};
    active_fake = &fake;
    CHECK(ker_source_network_write_startup_with_ops(3, &observed, &ops) == -ETIMEDOUT);
    CHECK(fake.writes == 1 && fake.waits == 0 && fake.length > 0);

    fake = (struct fake_startup){.mode = FAKE_SHORT, .now = now};
    active_fake = &fake;
    CHECK(ker_source_network_write_startup_with_ops(3, &observed, &ops) == -EIO);
    CHECK(fake.writes == 1 && fake.waits == 0 &&
        fake.length == sizeof("KER_NATIVE_READY\n") - 1);
    CHECK(memcmp(fake.bytes, "KER_NATIVE_READY\n", fake.length) == 0);

    fake = (struct fake_startup){.mode = FAKE_ERROR, .now = now};
    active_fake = &fake;
    CHECK(ker_source_network_write_startup_with_ops(3, &observed, &ops) == -EPIPE);
    CHECK(fake.writes == 1 && fake.length == 0);

    fake = (struct fake_startup){.mode = FAKE_EINTR, .now = now};
    active_fake = &fake;
    CHECK(ker_source_network_write_startup_with_ops(3, &observed, &ops) == -EINTR);
    CHECK(fake.writes == 1 && fake.waits == 0 && fake.length == 0);

    fake = (struct fake_startup){.mode = FAKE_AGAIN, .now = now};
    active_fake = &fake;
    CHECK(ker_source_network_write_startup_with_ops(3, &observed, &ops) == -ETIMEDOUT);
    CHECK(fake.writes == 1 && fake.waits == 1 && fake.length == 0);

    fake = (struct fake_startup){.mode = FAKE_SUCCESS, .now = observed.deadline_ns};
    active_fake = &fake;
    CHECK(ker_source_network_write_startup_with_ops(3, &observed, &ops) == -ETIMEDOUT);
    CHECK(fake.writes == 0 && fake.validates == 1);
}

static void startup_writer_fd_tests(void)
{
    int pipefd[2];
    CHECK(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
    if (pipefd[0] < 0 || pipefd[1] < 0) return;
    uint64_t now;
    CHECK(test_host_now(&now) == 0);
    struct ker_source_network_observation observed = sample_observation(now + 1000000000ULL);
    CHECK(ker_source_network_write_startup(pipefd[1], &observed) == 0);
    char record[PIPE_BUF];
    ssize_t read_count = read(pipefd[0], record, sizeof(record));
    CHECK(read_count > (ssize_t)(sizeof("KER_NATIVE_READY\n") - 1));
    CHECK(memcmp(record, "KER_NATIVE_READY\n", sizeof("KER_NATIVE_READY\n") - 1) == 0);
    CHECK(memmem(record, (size_t)read_count, "route_table=254", sizeof("route_table=254") - 1) != NULL);
    close(pipefd[0]); close(pipefd[1]);

    CHECK(pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) == 0);
    if (pipefd[0] < 0 || pipefd[1] < 0) return;
    unsigned char filler[4096];
    memset(filler, 0x5a, sizeof(filler));
    size_t filled = 0;
    for (;;) {
        ssize_t count = write(pipefd[1], filler, sizeof(filler));
        if (count > 0) { filled += (size_t)count; continue; }
        CHECK(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        break;
    }
    CHECK(test_host_now(&now) == 0);
    observed = sample_observation(now + 100000000ULL);
    CHECK(ker_source_network_write_startup(pipefd[1], &observed) == -ETIMEDOUT);
    unsigned char *drained = malloc(filled ? filled : 1);
    CHECK(drained != NULL);
    if (drained) {
        size_t used = 0;
        while (used < filled) {
            ssize_t count = read(pipefd[0], drained + used, filled - used);
            if (count <= 0) break;
            used += (size_t)count;
        }
        CHECK(used == filled);
        for (size_t i = 0; i < used; ++i) CHECK(drained[i] == 0x5a);
        CHECK(memmem(drained, used, "KER_NATIVE_READY\n", sizeof("KER_NATIVE_READY\n") - 1) == NULL);
        free(drained);
    }
    close(pipefd[0]); close(pipefd[1]);

    char path[] = "/tmp/ker-source-network-readback-XXXXXX";
    int file = mkstemp(path);
    CHECK(file >= 0);
    if (file >= 0) {
        unlink(path);
        CHECK(test_host_now(&now) == 0);
        observed = sample_observation(now + 1000000000ULL);
        CHECK(ker_source_network_write_startup(file, &observed) == -ENOTSUP);
        CHECK(lseek(file, 0, SEEK_END) == 0);
        close(file);
    }
}

int main(void)
{
    expectation_tests();
    close_stage_tests();
    route_tests();
    startup_writer_model_tests();
    startup_writer_fd_tests();
    if (failures) return 1;
    puts("PASS: source network expectation, close-stage precedence, and original netlink route controls");
    return 0;
}
