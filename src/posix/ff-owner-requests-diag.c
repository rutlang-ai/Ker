#define _GNU_SOURCE
#include "ff-owner-requests-diag.h"
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/capability.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>

#define DIAG_NETLINK_PROTOCOL 4
#define DIAG_INFO_EXT_BIT 0x02u
#define DIAG_SYN_RECV_MASK (UINT32_C(1) << 3)
#define QUERY_MAX_BYTES (1024u * 1024u)
#define QUERY_MAX_DATAGRAMS 256u
#define QUERY_MAX_DURATION_NS UINT64_C(5000000000)
#define QUERY_RECV_CAPACITY 32768u

static atomic_uint next_sequence = 1;

static uint64_t monotonic_ns(void)
{
    struct timespec now = {0};
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int require_net_admin(void)
{
    struct __lkl__user_cap_header_struct header = {
        .version = _LKL_LINUX_CAPABILITY_VERSION_3};
    struct __lkl__user_cap_data_struct data[2] = {{0}};
    long result = lkl_sys_capget(&header, data);
    if (result < 0) return (int)result;
    unsigned word = LKL_CAP_NET_ADMIN / 32;
    uint32_t bit = UINT32_C(1) << (LKL_CAP_NET_ADMIN % 32);
    return (data[word].effective & bit) ? 0 : -EPERM;
}

static int check_deadline(const struct ker_ff_owner_requests_state *state)
{
    uint64_t now = monotonic_ns();
    if (!now || now < state->started_ns ||
        now - state->started_ns >= QUERY_MAX_DURATION_NS) return -ETIMEDOUT;
    return 0;
}

static int send_family_query(struct ker_ff_owner_requests_state *state,
    uint8_t family)
{
    uint32_t sequence = atomic_fetch_add_explicit(&next_sequence, 1,
        memory_order_relaxed);
    if (!sequence) sequence = atomic_fetch_add_explicit(&next_sequence, 1,
        memory_order_relaxed);
    struct ker_ff_owner_requests_diag_request request = {
        .header = {.length = sizeof(request),
            .type = KER_FF_OWNER_REQUESTS_DIAG_FAMILY,
            .flags = KER_FF_OWNER_REQUESTS_NLM_F_REQUEST |
                KER_FF_OWNER_REQUESTS_NLM_F_DUMP,
            .sequence = sequence, .port_id = 0},
        .request = {.family = family, .protocol = IPPROTO_TCP,
            .extensions = DIAG_INFO_EXT_BIT,
            .states = DIAG_SYN_RECV_MASK},
        .mark_attribute = {.length = sizeof(request.mark_attribute) + 12u,
            .type = 1u},
        .mark_instruction = {.code = 10u, .yes = 12u, .no = 16u},
        .mark_condition = {.mark = state->accumulator.mark,
            .mask = UINT32_MAX}};
    if (sizeof(request) != request.header.length ||
        request.mark_attribute.length != sizeof(request) -
            sizeof(request.header) - sizeof(request.request)) return -EPROTO;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    long rc = lkl_sys_sendto(state->fd, &request, sizeof(request), 0,
        (struct lkl_sockaddr *)&kernel, sizeof(kernel));
    if (rc < 0) return (int)rc;
    if (rc != (long)sizeof(request)) return -EIO;
    struct sockaddr_nl local = {0};
    int local_length = sizeof(local);
    rc = lkl_sys_getsockname(state->fd, (struct lkl_sockaddr *)&local,
        &local_length);
    if (rc < 0) return (int)rc;
    if (local_length != sizeof(local) || local.nl_family != AF_NETLINK ||
        !local.nl_pid) return -EPROTO;
    state->local_port_id = local.nl_pid;
    state->sequence = sequence;
    state->accumulator = (struct ker_ff_owner_requests_accumulator){
        .mark = state->accumulator.mark, .sequence = sequence,
        .local_port_id = local.nl_pid, .family = family};
    return 0;
}

void ker_ff_owner_requests_close(struct ker_ff_owner_requests_state *state)
{
    if (!state) return;
    if (state->fd >= 0) (void)lkl_sys_close(state->fd);
    memset(state, 0, sizeof(*state));
    state->fd = -1;
}

int ker_ff_owner_requests_begin(struct ker_ff_owner_requests_state *state,
    uint32_t owner_mark)
{
    if (!state || !owner_mark) return -EINVAL;
    memset(state, 0, sizeof(*state));
    state->fd = -1;
    state->started_ns = monotonic_ns();
    if (!state->started_ns) return -EIO;
    int status = require_net_admin();
    if (status) return status;

    state->fd = (int)lkl_sys_socket(AF_NETLINK,
        SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, DIAG_NETLINK_PROTOCOL);
    if (state->fd < 0) return state->fd;
    int receive_buffer = 65536;
    long rc = lkl_sys_setsockopt(state->fd, SOL_SOCKET, SO_RCVBUF,
        (char *)&receive_buffer, sizeof(receive_buffer));
    if (rc < 0) { status = (int)rc; goto fail; }
    status = check_deadline(state);
    if (status) goto fail;

    state->accumulator.mark = owner_mark;
    status = send_family_query(state, AF_INET);
    if (status) goto fail;
    status = check_deadline(state);
    if (status) goto fail;
    state->started = true;
    return 0;
fail:
    ker_ff_owner_requests_close(state);
    return status;
}

int ker_ff_owner_requests_step(struct ker_ff_owner_requests_state *state,
    const atomic_bool *cancel, uint64_t *request_count)
{
    if (!state || !state->started || state->fd < 0 || !cancel ||
        !request_count) return -EINVAL;
    if (atomic_load_explicit(cancel, memory_order_acquire)) return -ECANCELED;
    int status = check_deadline(state);
    if (status) return status;
    struct lkl_pollfd pfd = {.fd = state->fd, .events = 1 /* POLLIN */};
    long ready = lkl_sys_poll(&pfd, 1, 0);
    if (ready < 0) return (int)ready;
    if (!ready) return 0;
    if (pfd.revents & (0x008 | 0x010 | 0x020)) return -EIO;
    if (!(pfd.revents & 1)) return 0;

    unsigned char bytes[QUERY_RECV_CAPACITY];
    struct sockaddr_nl sender = {0};
    int sender_length = sizeof(sender);
    long received = lkl_sys_recvfrom(state->fd, bytes, sizeof(bytes),
        MSG_DONTWAIT | MSG_TRUNC, (struct lkl_sockaddr *)&sender,
        &sender_length);
    if (received == -EAGAIN || received == -EWOULDBLOCK) return 0;
    if (received < 0) return (int)received;
    if (!received || (unsigned long)received > sizeof(bytes) ||
        sender_length != sizeof(sender) || sender.nl_family != AF_NETLINK ||
        sender.nl_pid != 0 || sender.nl_groups != 0) return -EPROTO;
    if (++state->datagrams > QUERY_MAX_DATAGRAMS ||
        (uint64_t)received > QUERY_MAX_BYTES - state->bytes) return -E2BIG;
    state->bytes += (uint64_t)received;
    bool complete = false;
    uint64_t completed_count = 0;
    status = ker_ff_owner_requests_parse_datagram(&state->accumulator, bytes,
        (size_t)received, sender.nl_pid, &completed_count, &complete);
    if (status) return status;
    if (state->rows_total + state->accumulator.rows >
        KER_FF_OWNER_REQUESTS_MAX_ROWS) return -E2BIG;
    status = check_deadline(state);
    if (status) return status;
    if (!complete) return 0;
    state->rows_total += state->accumulator.rows;
    if (!state->family_index) {
        state->requests_total = completed_count;
        state->family_index = 1;
        status = check_deadline(state);
        if (status) return status;
        status = send_family_query(state, AF_INET6);
        return status ? status : 0;
    }
    if (UINT64_MAX - state->requests_total < completed_count) return -EOVERFLOW;
    *request_count = state->requests_total + completed_count;
    return 1;
}
