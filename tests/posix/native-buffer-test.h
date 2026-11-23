/* Real original-Linux mappings and zerocopy error-queue completion checks. */
#include <ker/posix.h>
#include <dlfcn.h>
#include <linux/errqueue.h>
#include <poll.h>
#include <stdint.h>
#include <pthread.h>
#include <limits.h>
static void *(*buffer_allocate)(size_t);
static int (*buffer_release)(void *);
static void *(*buffer_resize)(void *, size_t);
static int (*buffer_run)(ker_posix_loop_func, void *);
static void (*buffer_stop)(void);
static unsigned sent_ids, completed_ids, family_copied[2], family_direct[2], current_family;
static bool completed[1024];
static size_t sent_lengths[1024];
static size_t copied_bytes[2], direct_bytes[2], udp_copied_bytes[2], tcp_direct_bytes[2];
static bool current_tcp;
static void *buffer_thread(void *opaque)
{
    unsigned char *inherited = opaque;
    check(inherited[0] == 0x2a, "cross-thread native mapping access");
    unsigned char *resized = buffer_resize(inherited, 8193);
    check(resized && resized[0] == 0x2a && !resized[8192], "cross-thread native mapping resize");
    check(!buffer_release(resized), "cross-thread mapping release");
    for (unsigned turn = 0; turn < 16; turn++) {
        unsigned char *p = buffer_allocate(8193); check(p, "concurrent native mapping");
        check(!p[0] && !p[8192], "concurrent mapping zero initialization");
        memset(p, 0x31, 8193); check(!buffer_release(p), "concurrent mapping release");
    }
    return NULL;
}
static void buffer_init(void)
{
    buffer_allocate = dlsym(RTLD_DEFAULT, "ker_posix_buffer_alloc");
    buffer_release = dlsym(RTLD_DEFAULT, "ker_posix_buffer_free");
    buffer_resize = dlsym(RTLD_DEFAULT, "ker_posix_buffer_realloc");
    buffer_run = dlsym(RTLD_DEFAULT, "ker_posix_run");
    buffer_stop = dlsym(RTLD_DEFAULT, "ker_posix_stop_run");
    check(buffer_allocate && buffer_release && buffer_resize && buffer_run && buffer_stop, "native buffer API");
    int sentinel = 0xCAFE;
    check(buffer_resize(&sentinel, 0) == &sentinel && sentinel == 0xCAFE, "zero resize pointer identity");
    errno = 0; check(!buffer_allocate(0) && errno == EINVAL, "zero allocation rejected");
    errno = 0; check(!buffer_allocate(SIZE_MAX) && errno == EINVAL, "allocation overflow rejected");
    unsigned char *retained = buffer_allocate(16); check(retained, "retained allocation");
    memset(retained, 0x39, 16);
    int negative[] = {-1, INT_MIN};
    for (unsigned i = 0; i < sizeof(negative) / sizeof(negative[0]); i++) {
        errno = 0;
        check(!buffer_allocate((size_t)negative[i]) && errno == EINVAL, "negative converted allocation rejected");
        for (unsigned j = 0; j < 16; j++) check(retained[j] == 0x39, "invalid allocation preserves live bytes");
    }
    check(!buffer_release(retained), "retained allocation release");
    puts("BUFFER_SOURCE_CASE test_ff_zc_mbuf_get_negative_len_returns_error");
    char foreign[8] = "owned";
    check(buffer_release(foreign) == -1 && errno == EINVAL && !strcmp(foreign, "owned"), "foreign memory preserved");
    check(buffer_release(NULL) == -1 && errno == EINVAL, "NULL release rejected");
    for (unsigned turn = 0; turn < 64; turn++) {
        size_t length = 4097 + turn;
        unsigned char *p = buffer_allocate(length);
        check(p && !((uintptr_t)p & 4095), "original Linux page-aligned mapping");
        for (size_t i = 0; i < length; i++) check(!p[i], "native mapping zero initialized");
        memset(p, 0x5c, length);
        check(buffer_release(p + 1) == -1 && errno == EINVAL && p[0] == 0x5c, "interior release preserves mapping");
        check(!buffer_release(p), "native mapping release");
        check(buffer_release(p) == -1 && errno == EINVAL, "duplicate release rejected");
    }
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) {
        unsigned char *p = buffer_allocate(4097); check(p, "producer native mapping"); p[0] = 0x2a;
        check(!pthread_create(&threads[i], NULL, buffer_thread, p), "native mapping consumer thread");
    }
    for (unsigned i = 0; i < 4; i++) check(!pthread_join(threads[i], NULL), "native mapping thread joined");
}
static void buffer_socket(int fd, unsigned family, bool tcp)
{
    int one = 1;
    check(!setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one)), "original SO_ZEROCOPY enable");
    sent_ids = completed_ids = 0; current_family = family; current_tcp = tcp; memset(completed, 0, sizeof(completed));
}
static void buffer_sent(size_t length, bool datagram)
{
    if (length || datagram) { check(sent_ids < sizeof(completed), "bounded completion IDs"); sent_lengths[sent_ids++] = length; }
}
static void buffer_complete(int fd)
{
    while (completed_ids < sent_ids) {
        char control[256], unused;
        struct iovec vector = {&unused, 1};
        struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = sizeof(control)};
        ssize_t result = recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT);
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd event = {fd, POLLERR, 0};
            check(poll(&event, 1, 5000) == 1 && (event.revents & POLLERR), "native zerocopy completion readiness");
            continue;
        }
        check(result >= 0 && !(message.msg_flags & MSG_CTRUNC), "native zerocopy error queue");
        bool found = false;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (!((c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVERR) ||
                  (c->cmsg_level == SOL_IPV6 && c->cmsg_type == IPV6_RECVERR))) continue;
            check(c->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err)), "full extended error");
            struct sock_extended_err *error = (void *)CMSG_DATA(c);
            check(error->ee_origin == SO_EE_ORIGIN_ZEROCOPY && error->ee_errno == 0 &&
                error->ee_info <= error->ee_data && error->ee_data < sent_ids &&
                (error->ee_code == 0 || error->ee_code == SO_EE_CODE_ZEROCOPY_COPIED), "original zerocopy completion range/code");
            for (unsigned id = error->ee_info; id <= error->ee_data; id++) {
                check(!completed[id], "completion IDs consumed exactly once");
                completed[id] = true; completed_ids++;
                if (error->ee_code) { family_copied[current_family]++; copied_bytes[current_family] += sent_lengths[id];
                    if (!current_tcp) udp_copied_bytes[current_family] += sent_lengths[id]; }
                else { family_direct[current_family]++; direct_bytes[current_family] += sent_lengths[id];
                    if (current_tcp) tcp_direct_bytes[current_family] += sent_lengths[id]; }
            }
            found = true;
        }
        check(found, "missing zerocopy completion control message");
    }
}
/* Rejected inputs must neither deliver data nor consume a completion ID. */
static void buffer_rejected(int fd, int receiver, const unsigned char *registered)
{
    unsigned char unused;
    struct iovec vector = {&unused, 1};
    char control[256];
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)};
    check(recv(receiver, &unused, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN, "invalid input delivered no datagram");
    check(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "invalid input produced no completion");
    for (unsigned i = 0; i < 16384; i++) check(registered[i] == 0x41, "rejected input preserves caller storage");
}
static void *buffer_toggle(void *opaque)
{
    int fd = *(int *)opaque;
    for (unsigned i = 0; i < 200; i++) {
        int enabled = i & 1;
        check(!setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &enabled, sizeof(enabled)), "concurrent SO_ZEROCOPY update");
    }
    return NULL;
}
static void buffer_guards(void)
{
    int receiver = socket(AF_INET, SOCK_DGRAM, 0), fd = socket(AF_INET, SOCK_DGRAM, 0);
    check(receiver >= 0 && fd >= 0, "native guard sockets");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    check(!bind(receiver, (void *)&address, length) && !getsockname(receiver, (void *)&address, &length) &&
          !connect(fd, (void *)&address, length), "native guard loopback peer");
    struct timeval timeout = {.tv_sec = 3};
    check(!setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), "guard receive timeout");
    enum { host_size = 32 };
    unsigned char *registered = buffer_allocate(16384), received[16384], *host_bytes = malloc(host_size);
    check(host_bytes, "foreign host malloc storage with live native VMAs");
    check(registered, "live VMA during foreign-memory guard tests");
    memset(registered, 0x41, 16384); memset(host_bytes, 0x5b, host_size);
    buffer_socket(fd, 0, false);
    check(send(fd, NULL, 16, MSG_ZEROCOPY) == -1 && errno == EFAULT, "NULL native send rejected");
    struct iovec invalid = {NULL, 16};
    struct msghdr invalid_message = {.msg_iov = &invalid, .msg_iovlen = 1};
    check(sendmsg(fd, &invalid_message, MSG_ZEROCOPY) == -1 && errno == EFAULT, "NULL native sendmsg rejected");
    struct mmsghdr invalid_batch = {.msg_hdr = invalid_message, .msg_len = 777};
    check(sendmmsg(fd, &invalid_batch, 1, MSG_ZEROCOPY) == -1 && errno == EFAULT && invalid_batch.msg_len == 777,
          "NULL native sendmmsg rejected without changing msg_len");
    buffer_rejected(fd, receiver, registered);
    puts("BUFFER_SOURCE_CASE test_ff_zc_send_mb_null_returns_einval");
    /* Single native mappings cannot exceed INT_MAX. This proves one-extent
     * validation, not an ff_zc ABI or an aggregate vector length limit. */
    size_t oversized = (size_t)INT_MAX + 1;
    check(send(fd, registered, oversized, MSG_ZEROCOPY) == -1 && errno == EFAULT, "oversized mapped send rejected");
    invalid.iov_base = registered; invalid.iov_len = oversized;
    check(sendmsg(fd, &invalid_message, MSG_ZEROCOPY) == -1 && errno == EFAULT, "oversized mapped sendmsg rejected");
    buffer_rejected(fd, receiver, registered);
    puts("BUFFER_SOURCE_CASE test_ff_zc_send_nbytes_overflow_returns_einval");
    check(send(fd, registered, 16, MSG_ZEROCOPY) == 16, "valid mapped send reaches original Linux");
    check(recv(receiver, received, sizeof(received), 0) == 16 && !memcmp(received, registered, 16),
          "valid mapped bytes delivered exactly");
    buffer_sent(16, true); buffer_complete(fd); /* First successful send must retain ID zero. */
    puts("BUFFER_SOURCE_CASE test_ff_zc_send_valid_args_proceeds");
    check(send(fd, host_bytes, host_size, MSG_ZEROCOPY) == -1 && errno == EFAULT,
          "foreign zerocopy storage rejected before GUP with live VMAs");
    check(send(fd, registered + 16380, 16, MSG_ZEROCOPY) == -1 && errno == EFAULT, "mapping range overflow rejected");
    struct iovec vectors[] = {{registered, 16}, {host_bytes, 16}, {registered + 16, 16}};
    struct msghdr mixed = {.msg_iov = vectors, .msg_iovlen = 2};
    check(sendmsg(fd, &mixed, MSG_ZEROCOPY) == -1 && errno == EFAULT, "mixed registered/foreign iov rejected");
    struct mmsghdr batch[3] = {0};
    for (unsigned i = 0; i < 3; i++) {
        batch[i].msg_hdr.msg_iov = &vectors[i]; batch[i].msg_hdr.msg_iovlen = 1; batch[i].msg_len = 777;
    }
    errno = 19;
    check(sendmmsg(fd, batch, 3, MSG_ZEROCOPY) == 1 && batch[0].msg_len == 16 &&
          batch[1].msg_len == 777 && batch[2].msg_len == 777 && errno == 19,
          "sendmmsg preserves accepted prefix, untouched suffix and success errno");
    check(recv(receiver, received, sizeof(received), 0) == 16 && !memcmp(received, registered, 16), "valid batch prefix delivered");
    buffer_sent(16, true); buffer_complete(fd);
    check(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == -1 && errno == EAGAIN, "rejected batch suffix not delivered");
    check(sendmmsg(fd, &batch[1], 1, MSG_ZEROCOPY) == -1 && errno == EFAULT, "invalid first batch message rejected");
    check(sendmmsg(fd, &batch[2], 1, MSG_ZEROCOPY) == 1 && batch[2].msg_len == 16, "retained valid suffix can be sent");
    check(recv(receiver, received, sizeof(received), 0) == 16, "suffix delivered once");
    buffer_sent(16, true); buffer_complete(fd);
    unsigned char *second = buffer_allocate(4097); check(second, "second registered VMA");
    memset(second, 0x42, 4097);
    struct iovec valid[] = {{registered, 4096}, {second, 4096}};
    mixed.msg_iov = valid;
    check(sendmsg(fd, &mixed, MSG_ZEROCOPY) == 8192, "native scatter-gather registered sendmsg");
    check(recv(receiver, received, sizeof(received), 0) == 8192 && !memcmp(received, registered, 4096) &&
          !memcmp(received + 4096, second, 4096), "multiple registered VMAs delivered");
    buffer_sent(8192, true); buffer_complete(fd);
    check(send(fd, host_bytes, host_size, 0) == host_size, "unflagged host-memory copy retained");
    check(recv(receiver, received, sizeof(received), 0) == host_size && !memcmp(received, host_bytes, host_size), "unflagged host bytes exact");
    int zero = 0;
    check(!setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &zero, sizeof(zero)), "disable original SO_ZEROCOPY");
    check(send(fd, host_bytes, host_size, MSG_ZEROCOPY) == host_size, "Linux ignored MSG_ZEROCOPY when SO disabled");
    check(recv(receiver, received, sizeof(received), 0) == host_size, "disabled-option copy delivered");
    check(setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, NULL, sizeof(int)) == -1 && errno == EFAULT,
          "NULL zerocopy option rejected safely");
    int alias = dup(fd); check(alias >= 0, "zerocopy socket alias");
    pthread_t toggler;
    check(!pthread_create(&toggler, NULL, buffer_toggle, &alias), "start concurrent option updates");
    for (unsigned i = 0; i < 100; i++) {
        ssize_t sent = send(fd, host_bytes, host_size, MSG_ZEROCOPY | MSG_NOSIGNAL);
        if (sent < 0) check(errno == EFAULT, "concurrent registered-domain rejection");
        else check(sent == host_size && recv(receiver, received, sizeof(received), 0) == host_size &&
                   !memcmp(received, host_bytes, host_size), "concurrent option-disabled copy delivered");
    }
    check(!pthread_join(toggler, NULL) && !close(alias), "option updates and alias joined");
    check(!close(fd) && !close(receiver) && !buffer_release(registered) && !buffer_release(second), "guard mapping/socket cleanup");
    free(host_bytes);
    memset(family_copied, 0, sizeof(family_copied)); memset(family_direct, 0, sizeof(family_direct));
    memset(copied_bytes, 0, sizeof(copied_bytes)); memset(direct_bytes, 0, sizeof(direct_bytes));
    memset(udp_copied_bytes, 0, sizeof(udp_copied_bytes)); memset(tcp_direct_bytes, 0, sizeof(tcp_direct_bytes));
}
static int buffer_end(void *argument) { (void)argument; buffer_stop(); return 0; }
static void buffer_finish(void)
{
    /* Deliberate residual mapping: explicit run teardown must reclaim it. */
    void *residual = buffer_allocate(8193); check(residual, "residual mapping");
    check(!buffer_run(buffer_end, NULL), "mapped-buffer socket drain and native shutdown");
    errno = 0; check(!buffer_allocate(1) && errno == ENETDOWN, "allocation after shutdown rejected");
    check(buffer_release(residual) == -1 && errno == ENETDOWN, "stale release after shutdown rejected without dereference");
    for (unsigned family = 0; family < 2; family++)
        printf("BUFFER_COMPLETIONS {\"family\":%u,\"copied\":%u,\"direct\":%u,\"copied_bytes\":%zu,\"direct_bytes\":%zu,\"udp_copied_bytes\":%zu,\"tcp_direct_bytes\":%zu}\n",
            family, family_copied[family], family_direct[family], copied_bytes[family], direct_bytes[family], udp_copied_bytes[family], tcp_direct_bytes[family]);
}
