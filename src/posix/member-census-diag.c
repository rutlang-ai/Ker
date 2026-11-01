#define _GNU_SOURCE
#include "member-census-diag.h"
#include "member-census-runtime.h"
#include "tcp-payload-snapshot.h"
#include "ff-owner-requests-diag.h"
#include <errno.h>
#include <lkl.h>
#include <lkl/linux/capability.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>

#define CENSUS_MAX_BYTES (UINT64_C(4) * 1024 * 1024)
#define CENSUS_MAX_DATAGRAMS 256u
#define CENSUS_MAX_DURATION_NS UINT64_C(5000000000)
#define CENSUS_RECV_CAPACITY 32768u
#define CENSUS_POLL_MS 10
#define CENSUS_GLOBAL_JOBS 4

enum census_receive_outcome { CENSUS_RECEIVE_DATAGRAM, CENSUS_RECEIVE_WOULD_BLOCK };

static atomic_uint census_sequence = 1;

enum census_job_state { CENSUS_JOB_FREE, CENSUS_JOB_QUEUED,
    CENSUS_JOB_RUNNING, CENSUS_JOB_DONE };
struct census_job {
    enum census_job_state state;
    uint64_t ticket;
    bool abandoned;
    bool payload;
    bool requests;
    atomic_bool cancel;
    struct ker_member_census_identity identity;
    struct ker_member_census_diag_state query;
    struct ker_ff_owner_requests_state requests_query;
    int status;
    struct ker_socket_member_census_snapshot snapshot;
    struct ker_socket_member_payload_snapshot payload_snapshot;
    uint64_t request_count;
};
static pthread_mutex_t census_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t census_changed = PTHREAD_COND_INITIALIZER;
static struct census_job census_jobs[CENSUS_GLOBAL_JOBS];
static pthread_t census_worker_thread;
static bool census_worker_started;
static bool census_shutting_down;
static uint32_t census_next_member_mark = 1;
static uint64_t census_next_ticket = 1;
static uint64_t census_next_server_lease = 1;
static uint64_t census_server_lease;
static bool census_server_claimed;
static size_t census_next_job;

int ker_member_census_server_claim(uint64_t *lease)
{
    if (!lease) return -EINVAL;
    pthread_mutex_lock(&census_lock);
    if (census_shutting_down) {
        pthread_mutex_unlock(&census_lock);
        return -ESHUTDOWN;
    }
    if (census_server_claimed) {
        pthread_mutex_unlock(&census_lock);
        return -EBUSY;
    }
    if (!census_next_server_lease) {
        pthread_mutex_unlock(&census_lock);
        return -EOVERFLOW;
    }
    census_server_lease = census_next_server_lease;
    if (census_next_server_lease == UINT64_MAX) census_next_server_lease = 0;
    else ++census_next_server_lease;
    census_server_claimed = true;
    *lease = census_server_lease;
    pthread_mutex_unlock(&census_lock);
    return 0;
}

int ker_member_census_server_release(uint64_t lease)
{
    if (!lease) return -EINVAL;
    pthread_mutex_lock(&census_lock);
    if (!census_server_claimed || census_server_lease != lease) {
        pthread_mutex_unlock(&census_lock);
        return -ESTALE;
    }
    census_server_claimed = false;
    census_server_lease = 0;
    pthread_mutex_unlock(&census_lock);
    return 0;
}

int ker_member_census_mark_allocate(uint32_t *mark)
{
    if (!mark) return -EINVAL;
    pthread_mutex_lock(&census_lock);
    if (!census_next_member_mark) {
        pthread_mutex_unlock(&census_lock);
        return -EOVERFLOW;
    }
    *mark = census_next_member_mark;
    if (census_next_member_mark == UINT32_MAX) census_next_member_mark = 0;
    else ++census_next_member_mark;
    pthread_mutex_unlock(&census_lock);
    return 0;
}

static uint64_t monotonic_ns(void)
{
    struct timespec now = {0};
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

static int check_query_deadline(const struct ker_member_census_diag_state *state)
{
    uint64_t now = monotonic_ns();
    if (!now || now < state->start_ns ||
        now - state->start_ns >= CENSUS_MAX_DURATION_NS) return -ETIMEDOUT;
    return 0;
}

int ker_member_census_diag_require_net_admin(void)
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

static int census_receive_datagram(int fd, uint32_t local_port_id,
    struct ker_member_census_accumulator *accumulator,
    struct ker_socket_member_census_snapshot *snapshot, bool *complete,
    size_t *datagram_length, enum census_receive_outcome *outcome)
{
    if (!outcome) return -EINVAL;
    *outcome = CENSUS_RECEIVE_DATAGRAM;
    unsigned char bytes[CENSUS_RECV_CAPACITY];
    struct sockaddr_nl sender = {0};
    int sender_length = sizeof(sender);
    long received = lkl_sys_recvfrom(fd, bytes, sizeof(bytes),
        MSG_DONTWAIT | MSG_TRUNC, (struct lkl_sockaddr *)&sender, &sender_length);
    if (received == -EAGAIN || received == -EWOULDBLOCK) {
        *outcome = CENSUS_RECEIVE_WOULD_BLOCK;
        return 0;
    }
    if (received < 0) return (int)received;
    if ((unsigned long)received > sizeof(bytes) ||
        sender_length != sizeof(sender) || sender.nl_family != AF_NETLINK ||
        sender.nl_pid != 0 || sender.nl_groups != 0) return -EPROTO;
    if (!received) return -EPROTO;
    if (datagram_length) *datagram_length = (size_t)received;
    accumulator->local_port_id = local_port_id;
    return ker_member_census_parse_datagram(accumulator, bytes, (size_t)received,
        sender.nl_pid, snapshot, complete);
}

static void *census_worker(void *unused)
{
    (void)unused;
    for (;;) {
        pthread_mutex_lock(&census_lock);
        size_t selected = CENSUS_GLOBAL_JOBS;
        for (;;) {
            for (size_t n = 0; n < CENSUS_GLOBAL_JOBS; ++n) {
                size_t i = (census_next_job + n) % CENSUS_GLOBAL_JOBS;
                if (census_jobs[i].state == CENSUS_JOB_QUEUED) { selected = i; break; }
            }
            if (selected < CENSUS_GLOBAL_JOBS) break;
            if (census_shutting_down) {
                pthread_mutex_unlock(&census_lock);
                return NULL;
            }
            pthread_cond_wait(&census_changed, &census_lock);
        }
        struct census_job *job = &census_jobs[selected];
        census_next_job = (selected + 1) % CENSUS_GLOBAL_JOBS;
        if (atomic_load_explicit(&job->cancel, memory_order_acquire)) {
            bool close_query = job->query.started;
            bool close_requests = job->requests_query.started;
            pthread_mutex_unlock(&census_lock);
            if (close_query) ker_member_census_diag_close(&job->query);
            if (close_requests) ker_ff_owner_requests_close(&job->requests_query);
            pthread_mutex_lock(&census_lock);
            job->state = job->abandoned ? CENSUS_JOB_FREE : CENSUS_JOB_DONE;
            job->status = -ECANCELED;
            pthread_cond_broadcast(&census_changed);
            pthread_mutex_unlock(&census_lock);
            continue;
        }
        job->state = CENSUS_JOB_RUNNING;
        struct ker_member_census_identity identity = job->identity;
        bool payload_job = job->payload;
        bool requests_job = job->requests;
        pthread_mutex_unlock(&census_lock);

        struct ker_socket_member_census_snapshot snapshot = {0};
        struct ker_socket_member_payload_snapshot payload_snapshot = {0};
        uint64_t request_count = 0;
        int progress = 0;
        int status = 0;
        bool complete;
        if (payload_job) {
            status = ker_native_tcp_payload_snapshot(identity.mark, &payload_snapshot);
            complete = true;
        } else if (requests_job) {
            if (!job->requests_query.started)
                progress = ker_ff_owner_requests_begin(&job->requests_query, identity.mark);
            else
                progress = ker_ff_owner_requests_step(&job->requests_query,
                    &job->cancel, &request_count);
            complete = progress != 0;
            status = progress < 0 ? progress : 0;
        } else {
            if (!job->query.started)
                progress = ker_member_census_diag_begin(&job->query, &identity);
            else
                progress = ker_member_census_diag_step(&job->query, &job->cancel, &snapshot);
            complete = progress != 0;
            status = progress < 0 ? progress : 0;
        }
        if (complete && !payload_job && !requests_job)
            ker_member_census_diag_close(&job->query);
        if (complete && requests_job) ker_ff_owner_requests_close(&job->requests_query);

        pthread_mutex_lock(&census_lock);
        if (complete) {
            job->status = status;
            if (!status) {
                if (payload_job) job->payload_snapshot = payload_snapshot;
                else if (requests_job) job->request_count = request_count;
                else job->snapshot = snapshot;
            }
            job->state = job->abandoned ? CENSUS_JOB_FREE : CENSUS_JOB_DONE;
            pthread_cond_broadcast(&census_changed);
        } else {
            job->state = CENSUS_JOB_QUEUED;
        }
        pthread_mutex_unlock(&census_lock);
        if (!complete) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)syscall(SYS_nanosleep, &pause, NULL);
        }
    }
}

int ker_member_census_query_submit(const struct ker_member_census_identity *identity,
    uint64_t *ticket)
{
    if (!identity || !ticket || !identity->mark || !identity->local_port ||
        !identity->listener_cookie) return -EINVAL;
    /* LKL host threads inherit host0 credentials, not the submitting caller's
     * current credentials. Check authority here before queueing and again in
     * the worker; never let a privileged worker authorize a restricted caller. */
    int authority = ker_member_census_diag_require_net_admin();
    if (authority) return authority;
    pthread_mutex_lock(&census_lock);
    if (census_shutting_down) {
        pthread_mutex_unlock(&census_lock);
        return -ESHUTDOWN;
    }
    size_t slot = CENSUS_GLOBAL_JOBS;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i)
        if (census_jobs[i].state == CENSUS_JOB_FREE) { slot = i; break; }
    if (slot == CENSUS_GLOBAL_JOBS || !census_next_ticket) {
        pthread_mutex_unlock(&census_lock);
        return slot == CENSUS_GLOBAL_JOBS ? -EAGAIN : -EOVERFLOW;
    }
    if (!census_worker_started) {
        int created = pthread_create(&census_worker_thread, NULL, census_worker, NULL);
        if (created) {
            pthread_mutex_unlock(&census_lock);
            return -created;
        }
        census_worker_started = true;
    }
    struct census_job *job = &census_jobs[slot];
    memset(job, 0, sizeof(*job));
    atomic_init(&job->cancel, false);
    job->state = CENSUS_JOB_QUEUED;
    job->ticket = census_next_ticket;
    if (census_next_ticket == UINT64_MAX) census_next_ticket = 0;
    else ++census_next_ticket;
    job->identity = *identity;
    *ticket = job->ticket;
    pthread_cond_signal(&census_changed);
    pthread_mutex_unlock(&census_lock);
    return 0;
}

int ker_member_payload_query_submit(uint32_t mark, uint64_t *ticket)
{
    if (!mark || !ticket) return -EINVAL;
    int authority = ker_member_census_diag_require_net_admin();
    if (authority) return authority;
    pthread_mutex_lock(&census_lock);
    if (census_shutting_down) {
        pthread_mutex_unlock(&census_lock);
        return -ESHUTDOWN;
    }
    size_t slot = CENSUS_GLOBAL_JOBS;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i)
        if (census_jobs[i].state == CENSUS_JOB_FREE) { slot = i; break; }
    if (slot == CENSUS_GLOBAL_JOBS || !census_next_ticket) {
        pthread_mutex_unlock(&census_lock);
        return slot == CENSUS_GLOBAL_JOBS ? -EAGAIN : -EOVERFLOW;
    }
    if (!census_worker_started) {
        int created = pthread_create(&census_worker_thread, NULL, census_worker, NULL);
        if (created) {
            pthread_mutex_unlock(&census_lock);
            return -created;
        }
        census_worker_started = true;
    }
    struct census_job *job = &census_jobs[slot];
    memset(job, 0, sizeof(*job));
    atomic_init(&job->cancel, false);
    job->state = CENSUS_JOB_QUEUED;
    job->payload = true;
    job->identity.mark = mark;
    job->ticket = census_next_ticket;
    if (census_next_ticket == UINT64_MAX) census_next_ticket = 0;
    else ++census_next_ticket;
    *ticket = job->ticket;
    pthread_cond_signal(&census_changed);
    pthread_mutex_unlock(&census_lock);
    return 0;
}

int ker_member_requests_query_submit(uint32_t mark, uint64_t *ticket)
{
    if (!mark || !ticket) return -EINVAL;
    int authority = ker_member_census_diag_require_net_admin();
    if (authority) return authority;
    pthread_mutex_lock(&census_lock);
    if (census_shutting_down) {
        pthread_mutex_unlock(&census_lock);
        return -ESHUTDOWN;
    }
    size_t slot = CENSUS_GLOBAL_JOBS;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i)
        if (census_jobs[i].state == CENSUS_JOB_FREE) { slot = i; break; }
    if (slot == CENSUS_GLOBAL_JOBS || !census_next_ticket) {
        pthread_mutex_unlock(&census_lock);
        return slot == CENSUS_GLOBAL_JOBS ? -EAGAIN : -EOVERFLOW;
    }
    if (!census_worker_started) {
        int created = pthread_create(&census_worker_thread, NULL, census_worker, NULL);
        if (created) {
            pthread_mutex_unlock(&census_lock);
            return -created;
        }
        census_worker_started = true;
    }
    struct census_job *job = &census_jobs[slot];
    memset(job, 0, sizeof(*job));
    atomic_init(&job->cancel, false);
    job->state = CENSUS_JOB_QUEUED;
    job->requests = true;
    job->identity.mark = mark;
    job->ticket = census_next_ticket;
    if (census_next_ticket == UINT64_MAX) census_next_ticket = 0;
    else ++census_next_ticket;
    *ticket = job->ticket;
    pthread_cond_signal(&census_changed);
    pthread_mutex_unlock(&census_lock);
    return 0;
}

int ker_member_census_query_poll(uint64_t ticket, int *query_status,
    struct ker_socket_member_census_snapshot *snapshot)
{
    if (!ticket || !query_status || !snapshot) return -EINVAL;
    pthread_mutex_lock(&census_lock);
    struct census_job *job = NULL;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i)
        if (census_jobs[i].state != CENSUS_JOB_FREE && census_jobs[i].ticket == ticket) {
            job = &census_jobs[i]; break;
        }
    if (!job || job->payload) { pthread_mutex_unlock(&census_lock); return -ENOENT; }
    if (job->state != CENSUS_JOB_DONE) { pthread_mutex_unlock(&census_lock); return 0; }
    int status = job->status;
    if (!status) *snapshot = job->snapshot;
    *query_status = status;
    memset(job, 0, sizeof(*job));
    job->state = CENSUS_JOB_FREE;
    pthread_mutex_unlock(&census_lock);
    return 1;
}

int ker_member_payload_query_poll(uint64_t ticket, int *query_status,
    struct ker_socket_member_payload_snapshot *snapshot)
{
    if (!ticket || !query_status || !snapshot) return -EINVAL;
    pthread_mutex_lock(&census_lock);
    struct census_job *job = NULL;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i)
        if (census_jobs[i].state != CENSUS_JOB_FREE && census_jobs[i].ticket == ticket) {
            job = &census_jobs[i]; break;
        }
    if (!job || !job->payload) {
        pthread_mutex_unlock(&census_lock);
        return -ENOENT;
    }
    if (job->state != CENSUS_JOB_DONE) {
        pthread_mutex_unlock(&census_lock);
        return 0;
    }
    int status = job->status;
    if (!status) *snapshot = job->payload_snapshot;
    *query_status = status;
    memset(job, 0, sizeof(*job));
    job->state = CENSUS_JOB_FREE;
    pthread_mutex_unlock(&census_lock);
    return 1;
}

int ker_member_requests_query_poll(uint64_t ticket, int *query_status,
    uint64_t *request_count)
{
    if (!ticket || !query_status || !request_count) return -EINVAL;
    pthread_mutex_lock(&census_lock);
    struct census_job *job = NULL;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i)
        if (census_jobs[i].state != CENSUS_JOB_FREE && census_jobs[i].ticket == ticket) {
            job = &census_jobs[i]; break;
        }
    if (!job || !job->requests) {
        pthread_mutex_unlock(&census_lock);
        return -ENOENT;
    }
    if (job->state != CENSUS_JOB_DONE) {
        pthread_mutex_unlock(&census_lock);
        return 0;
    }
    int status = job->status;
    if (!status) *request_count = job->request_count;
    *query_status = status;
    memset(job, 0, sizeof(*job));
    job->state = CENSUS_JOB_FREE;
    pthread_mutex_unlock(&census_lock);
    return 1;
}

int ker_member_census_query_cancel(uint64_t ticket)
{
    if (!ticket) return -EINVAL;
    pthread_mutex_lock(&census_lock);
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i) {
        struct census_job *job = &census_jobs[i];
        if (job->state == CENSUS_JOB_FREE || job->ticket != ticket) continue;
        job->abandoned = true;
        atomic_store_explicit(&job->cancel, true, memory_order_release);
        if (job->state == CENSUS_JOB_DONE) {
            memset(job, 0, sizeof(*job));
            job->state = CENSUS_JOB_FREE;
        }
        pthread_cond_signal(&census_changed);
        pthread_mutex_unlock(&census_lock);
        return 0;
    }
    pthread_mutex_unlock(&census_lock);
    return -ENOENT;
}

void ker_member_census_runtime_shutdown(void)
{
    pthread_mutex_lock(&census_lock);
    census_shutting_down = true;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i) {
        struct census_job *job = &census_jobs[i];
        if (job->state != CENSUS_JOB_FREE)
            atomic_store_explicit(&job->cancel, true, memory_order_release);
    }
    pthread_cond_broadcast(&census_changed);
    bool join = census_worker_started;
    pthread_mutex_unlock(&census_lock);
    if (join) {
        /* The worker owns query descriptors and may still be inside an LKL
         * syscall. Clearing its job storage or tearing down LKL after a
         * failed join would leave it using freed state. Shutdown is never
         * called by the worker itself; fail closed if that invariant or the
         * join operation fails. */
        if (pthread_equal(pthread_self(), census_worker_thread) ||
            pthread_join(census_worker_thread, NULL) != 0)
            abort();
    }
    pthread_mutex_lock(&census_lock);
    census_worker_started = false;
    for (size_t i = 0; i < CENSUS_GLOBAL_JOBS; ++i) {
        memset(&census_jobs[i], 0, sizeof(census_jobs[i]));
        census_jobs[i].state = CENSUS_JOB_FREE;
    }
    pthread_mutex_unlock(&census_lock);
}

int ker_member_census_diag_begin(struct ker_member_census_diag_state *state,
    const struct ker_member_census_identity *identity)
{
    if (!state || !identity || !identity->mark || !identity->local_port ||
        !identity->listener_cookie) return -EINVAL;
    memset(state, 0, sizeof(*state));
    state->fd = -1;
    state->start_ns = monotonic_ns();
    if (!state->start_ns) return -EIO;
    int authority = ker_member_census_diag_require_net_admin();
    if (authority) return authority;
    if (check_query_deadline(state)) return -ETIMEDOUT;
    state->accumulator.seen_cookie_capacity = KER_MEMBER_CENSUS_COOKIE_HASH_SLOTS;
    state->accumulator.seen_cookies = calloc(
        state->accumulator.seen_cookie_capacity, sizeof(*state->accumulator.seen_cookies));
    if (!state->accumulator.seen_cookies) return -ENOMEM;
    state->identity = *identity;
    if (check_query_deadline(state)) { ker_member_census_diag_close(state); return -ETIMEDOUT; }
    state->fd = (int)lkl_sys_socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
        KER_MEMBER_CENSUS_NETLINK_PROTOCOL);
    if (state->fd < 0) {
        int error = state->fd;
        state->fd = -1;
        ker_member_census_diag_close(state);
        return error;
    }
    if (check_query_deadline(state)) { ker_member_census_diag_close(state); return -ETIMEDOUT; }

    int receive_buffer = 65536;
    long option_result = lkl_sys_setsockopt(state->fd, SOL_SOCKET, SO_RCVBUF,
        (char *)&receive_buffer, sizeof(receive_buffer));
    if (option_result < 0) goto fail;
    if (check_query_deadline(state)) { option_result = -ETIMEDOUT; goto fail; }

    unsigned int sequence = atomic_fetch_add_explicit(&census_sequence, 1,
        memory_order_relaxed);
    if (!sequence) sequence = atomic_fetch_add_explicit(&census_sequence, 1,
        memory_order_relaxed);
    struct ker_member_census_diag_request request = {
        .header = {.length = sizeof(request),
            .type = KER_MEMBER_CENSUS_DIAG_FAMILY_REQUEST,
            .flags = KER_MEMBER_CENSUS_NLM_F_REQUEST | KER_MEMBER_CENSUS_NLM_F_DUMP,
            .sequence = sequence, .port_id = 0},
        .request = {.family = AF_INET, .protocol = IPPROTO_TCP,
            .states = UINT32_MAX,
            .id = {.source_port = htons(identity->local_port)}},
        .bytecode_attribute = {.length = sizeof(request.bytecode_attribute) +
            sizeof(request.mark_instruction) + sizeof(request.condition),
            .type = KER_MEMBER_CENSUS_IN_DIAG_REQ_BYTECODE},
        .mark_instruction = {.code = KER_MEMBER_CENSUS_IN_DIAG_BC_MARK_COND,
            .yes = sizeof(request.mark_instruction) + sizeof(request.condition),
            .no = sizeof(request.mark_instruction) + sizeof(request.condition) + 4},
        .condition = {.mark = identity->mark, .mask = UINT32_MAX}};
    if (sizeof(request) != request.header.length ||
        request.bytecode_attribute.length != sizeof(request) -
            sizeof(request.header) - sizeof(request.request)) {
        option_result = -EPROTO; goto fail;
    }

    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    long sent = lkl_sys_sendto(state->fd, &request, sizeof(request), 0,
        (struct lkl_sockaddr *)&kernel, sizeof(kernel));
    if (sent < 0) { option_result = sent; goto fail; }
    if (sent != (long)sizeof(request)) { option_result = -EIO; goto fail; }
    if (check_query_deadline(state)) { option_result = -ETIMEDOUT; goto fail; }

    struct sockaddr_nl local = {0};
    int local_length = sizeof(local);
    long name_result = lkl_sys_getsockname(state->fd,
        (struct lkl_sockaddr *)&local, &local_length);
    if (name_result < 0) { option_result = name_result; goto fail; }
    if (check_query_deadline(state)) { option_result = -ETIMEDOUT; goto fail; }
    if (local_length != sizeof(local) || local.nl_family != AF_NETLINK || !local.nl_pid) {
        option_result = -EPROTO; goto fail;
    }
    state->local_port_id = local.nl_pid;
    state->accumulator = (struct ker_member_census_accumulator){
        .mark = identity->mark, .local_port = identity->local_port,
        .sequence = sequence, .local_port_id = local.nl_pid,
        .listener_cookie = identity->listener_cookie,
        .seen_cookies = state->accumulator.seen_cookies,
        .seen_cookie_capacity = state->accumulator.seen_cookie_capacity};
    state->started = true;
    return 0;
fail:
    ker_member_census_diag_close(state);
    return (int)option_result;
}

int ker_member_census_diag_step(struct ker_member_census_diag_state *state,
    const atomic_bool *cancel, struct ker_socket_member_census_snapshot *snapshot)
{
    if (!state || !state->started || state->fd < 0 || !cancel || !snapshot) return -EINVAL;
    if (atomic_load_explicit(cancel, memory_order_acquire)) return -ECANCELED;
    int deadline = check_query_deadline(state);
    if (deadline) return deadline;
    struct lkl_pollfd pollfd = {.fd = state->fd, .events = 1 /* POLLIN */};
    long ready = lkl_sys_poll(&pollfd, 1, 0);
    if (ready < 0) return (int)ready;
    deadline = check_query_deadline(state);
    if (deadline) return deadline;
    if (!ready) return 0;
    if (pollfd.revents & (0x008 | 0x010 | 0x020)) return -EIO;
    if (!(pollfd.revents & 1)) return 0;
    struct ker_socket_member_census_snapshot complete_snapshot = {0};
    bool complete = false;
    enum census_receive_outcome outcome;
    size_t datagram_length = 0;
    int parsed = census_receive_datagram(state->fd, state->local_port_id,
        &state->accumulator, &complete_snapshot, &complete, &datagram_length, &outcome);
    int receive_status = ker_member_census_receive_status(
        outcome == CENSUS_RECEIVE_WOULD_BLOCK, parsed);
    if (receive_status) return receive_status;
    if (outcome == CENSUS_RECEIVE_WOULD_BLOCK) return 0;
    if (++state->datagrams > CENSUS_MAX_DATAGRAMS) return -E2BIG;
    deadline = check_query_deadline(state);
    if (deadline) return deadline;
    if (state->accumulator.total > KER_MEMBER_CENSUS_MAX_ROWS) return -E2BIG;
    if (UINT64_MAX - state->bytes_total < datagram_length) return -EOVERFLOW;
    state->bytes_total += datagram_length;
    if (state->bytes_total > CENSUS_MAX_BYTES) return -E2BIG;
    if (!complete) return 0;
    *snapshot = complete_snapshot;
    return 1;
}

void ker_member_census_diag_close(struct ker_member_census_diag_state *state)
{
    if (!state) return;
    if (state->fd >= 0) (void)lkl_sys_close(state->fd);
    state->fd = -1;
    state->started = false;
    free(state->accumulator.seen_cookies);
    state->accumulator.seen_cookies = NULL;
    state->accumulator.seen_cookie_capacity = 0;
}
