#define _GNU_SOURCE
#include "linux-mptcp-socket-wire.h"
#include "linux-selftest-runtime.h"
#include <dlfcn.h>
#include <errno.h>
#include <linux/mptcp.h>
#include <linux/tcp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* A thread per socket preserves blocking accept/connect/read on one original
 * kernel. Only the harness transport runs in the host; all IP socket syscalls
 * below go through the real POSIX facade. No fork occurs in the kernel owner. */
struct client { int host, native; pthread_t thread; };
static struct client clients[64];
static unsigned clients_count;
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint stopping, live, sockets_count, mptcp_count, accepts_count;
static atomic_ulong reads_count, writes_count, received_bytes, sent_bytes, infos_count, full_count, inq_count;
static atomic_uint negotiated_count, fallback_count;
static atomic_uint fallback_info_unsupported, fallback_info_no_proto;

static int observe_connection(int fd)
{
    int protocol;
    socklen_t size = sizeof(protocol);
    if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &size)) return -1;
    if (protocol != IPPROTO_MPTCP) return 0;
    struct mptcp_info info = {0};
    size = sizeof(info);
    if (getsockopt(fd, SOL_MPTCP, MPTCP_INFO, &info, &size)) {
        /* Pinned mptcp_getsockopt delegates to tcp_getsockopt after fallback.
         * Its real EOPNOTSUPP/ENOPROTOOPT is evidence, never a fabricated info
         * record or an error to inject into the original successful connect. */
        int error = errno;
        if (error != EOPNOTSUPP && error != ENOPROTOOPT) return -1;
        struct tcp_info tcp = {0};
        size = sizeof(tcp);
        if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &tcp, &size)) return -1;
        if (error == EOPNOTSUPP) atomic_fetch_add(&fallback_info_unsupported, 1);
        else atomic_fetch_add(&fallback_info_no_proto, 1);
        atomic_fetch_add(&fallback_count, 1);
        return 0;
    }
    if (info.mptcpi_flags & MPTCP_INFO_FLAG_FALLBACK) atomic_fetch_add(&fallback_count, 1);
    else if (info.mptcpi_flags & MPTCP_INFO_FLAG_REMOTE_KEY_RECEIVED) atomic_fetch_add(&negotiated_count, 1);
    else { errno = EPROTO; return -1; }
    return 0;
}

static int start_client(int host, int native);
static long dispatch(struct client *client, struct ms_message *m, unsigned char *data, int *pass_fd)
{
    int fd = client->native;
    size_t input = m->length;
    m->length = 0;
    if (m->operation == MS_STOP) {
        if (fd >= 0 || input) { errno = EINVAL; return -1; }
        if (atomic_load(&live)) { errno = EBUSY; return -1; }
        atomic_store(&stopping, 1); return 0;
    }
    if (m->operation == MS_SOCKET) {
        if (fd >= 0 || input || (m->a != AF_INET && m->a != AF_INET6) || m->b != SOCK_STREAM ||
            (m->c != IPPROTO_MPTCP && m->c != IPPROTO_TCP)) { errno = EOPNOTSUPP; return -1; }
        client->native = socket((int)m->a, (int)m->b, (int)m->c);
        if (client->native < 0) return -1;
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(client->native) != 1) { close(client->native); client->native = -1; errno = ENOTSUP; return -1; }
        atomic_fetch_add(&sockets_count, 1); atomic_fetch_add(&live, 1);
        if (m->c == IPPROTO_MPTCP) atomic_fetch_add(&mptcp_count, 1);
        return 0;
    }
    if (fd < 0) { errno = ENOTCONN; return -1; }
    switch (m->operation) {
    case MS_NAME:
    case MS_PEER: {
        socklen_t length = sizeof(struct sockaddr_storage);
        memset(data, 0, length);
        long result = m->operation == MS_NAME ? getsockname(fd, (void *)data, &length) : getpeername(fd, (void *)data, &length);
        if (!result) m->length = length;
        return result;
    }
    case MS_BIND:
    case MS_CONNECT:
        if (input < sizeof(sa_family_t) || input > sizeof(struct sockaddr_storage)) { errno = EINVAL; return -1; }
        if (m->operation == MS_BIND) return bind(fd, (void *)data, (socklen_t)input);
        if (connect(fd, (void *)data, (socklen_t)input)) return -1;
        return observe_connection(fd);
    case MS_LISTEN: return listen(fd, (int)m->a);
    case MS_ACCEPT: {
        int native = accept(fd, NULL, NULL);
        if (native < 0) return -1;
        if (observe_connection(native)) { int e = errno; close(native); errno = e; return -1; }
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) { int e = errno; close(native); errno = e; return -1; }
        if (start_client(pair[0], native)) { int e = errno; close(pair[0]); close(pair[1]); close(native); errno = e; return -1; }
        atomic_fetch_add(&accepts_count, 1);
        *pass_fd = pair[1]; return 0;
    }
    case MS_SETOPT: return setsockopt(fd, (int)m->a, (int)m->b, data, (socklen_t)input);
    case MS_GETOPT: {
        socklen_t length = m->c;
        size_t capacity = (int)length < 0 ? 0 : length;
        if (capacity > input) { errno = EINVAL; return -1; }
        struct mptcp_full_info *full = (void *)data;
        int nested = m->a == SOL_MPTCP && m->b == MPTCP_FULL_INFO;
        if (nested) {
            if (capacity < offsetof(struct mptcp_full_info, mptcp_info) || capacity > sizeof(*full) || full->size_arrays_user > 2 ||
                full->size_sfinfo_user > sizeof(struct mptcp_subflow_info) ||
                full->size_tcpinfo_user > sizeof(struct tcp_info) || full->subflow_info || full->tcp_info ||
                input != capacity + full->size_arrays_user * (full->size_sfinfo_user + full->size_tcpinfo_user)) {
                errno = EOPNOTSUPP; return -1;
            }
            full->subflow_info = (uintptr_t)(data + capacity);
            full->tcp_info = (uintptr_t)(data + capacity + full->size_arrays_user * full->size_sfinfo_user);
        }
        long result = getsockopt(fd, (int)m->a, (int)m->b, data, &length);
        int error = errno;
        if (nested) { full->subflow_info = 0; full->tcp_info = 0; }
        m->length = (uint32_t)input; m->c = length;
        if (!result && m->a == SOL_MPTCP) {
            atomic_fetch_add(&infos_count, 1);
            if (nested) atomic_fetch_add(&full_count, 1);
        }
        errno = error; return result;
    }
    case MS_READ: {
        if (m->a > MS_MAX) { errno = EMSGSIZE; return -1; }
        ssize_t result = read(fd, data, m->a);
        if (result >= 0) { m->length = (uint32_t)result; atomic_fetch_add(&received_bytes, (unsigned long)result); }
        atomic_fetch_add(&reads_count, 1); return result;
    }
    case MS_WRITE: {
        ssize_t result = write(fd, data, input);
        if (result >= 0) atomic_fetch_add(&sent_bytes, (unsigned long)result);
        atomic_fetch_add(&writes_count, 1); return result;
    }
    case MS_IOCTL: {
        if (m->a != FIONREAD && m->a != TIOCOUTQ && m->a != 0x894b) { errno = EOPNOTSUPP; return -1; }
        int value = 0;
        long result = ioctl(fd, m->a, &value);
        if (!result) { memcpy(data, &value, sizeof(value)); m->length = sizeof(value); atomic_fetch_add(&inq_count, 1); }
        return result;
    }
    case MS_RECVMSG: {
        if (m->a > MS_MAX / 2 || m->b > MS_MAX / 2) { errno = EMSGSIZE; return -1; }
        unsigned char control[MS_MAX / 2];
        struct iovec iov = {data, m->a};
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = control, .msg_controllen = m->b};
        ssize_t result = recvmsg(fd, &msg, (int)m->c);
        if (result >= 0) {
            if ((size_t)result > iov.iov_len || msg.msg_controllen > m->b) { errno = EOVERFLOW; return -1; }
            memcpy(data + result, control, msg.msg_controllen);
            m->length = (uint32_t)result + (uint32_t)msg.msg_controllen;
            m->b = (uint32_t)msg.msg_controllen; m->c = msg.msg_flags;
            atomic_fetch_add(&received_bytes, (unsigned long)result);
            atomic_fetch_add(&inq_count, 1);
        }
        atomic_fetch_add(&reads_count, 1); return result;
    }
    default: errno = EOPNOTSUPP; return -1;
    }
}
static void *serve(void *argument)
{
    struct client *client = argument;
    struct { struct ms_message h; unsigned char data[MS_MAX]; } packet;
    for (;;) {
        ssize_t n = syscall(SYS_recvfrom, client->host, &packet, sizeof(packet), MSG_TRUNC, NULL, NULL);
        if (n < (ssize_t)sizeof(packet.h) || n > (ssize_t)sizeof(packet) ||
            packet.h.magic != MS_MAGIC || packet.h.length != (size_t)n - sizeof(packet.h)) break;
        int pass_fd = -1;
        long result = dispatch(client, &packet.h, packet.data, &pass_fd);
        packet.h.result = result < 0 ? -errno : result;
        struct iovec iov = {&packet, sizeof(packet.h) + packet.h.length};
        union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(int))]; } control;
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
        if (pass_fd >= 0) {
            msg.msg_control = control.data; msg.msg_controllen = sizeof(control.data);
            memset(control.data, 0, sizeof(control.data));
            struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
            c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(c), &pass_fd, sizeof(pass_fd));
        }
        ssize_t sent = syscall(SYS_sendmsg, client->host, &msg, MSG_NOSIGNAL);
        if (pass_fd >= 0) close(pass_fd);
        if (sent != (ssize_t)iov.iov_len) break;
    }
    if (client->native >= 0) { close(client->native); atomic_fetch_sub(&live, 1); }
    close(client->host);
    return NULL;
}
static int start_client(int host, int native)
{
    pthread_mutex_lock(&clients_lock);
    int error = EMFILE;
    if (clients_count < 64) {
        struct client *client = &clients[clients_count];
        *client = (struct client){.host = host, .native = native};
        if (native >= 0) atomic_fetch_add(&live, 1);
        error = pthread_create(&client->thread, NULL, serve, client);
        if (!error) clients_count++;
        else if (native >= 0) atomic_fetch_sub(&live, 1);
    }
    pthread_mutex_unlock(&clients_lock);
    if (error) { errno = error; return -1; }
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 3 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    long (*call)(unsigned, const unsigned long[6]) = dlsym(RTLD_DEFAULT, "ker_linux_selftest_call");
    if (!call) return 3;
    unsigned long args[6] = {if_nametoindex("lo"), 0, 0, 0, 0, 0};
    if (!args[0] || call(KER_TEST_IF_UP, args)) return 4;
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX}; strcpy(address.sun_path, argv[1]);
    if (listener < 0 || bind(listener, (void *)&address, sizeof(address)) || listen(listener, 16)) return 5;
    while (!atomic_load(&stopping)) {
        struct pollfd p = {.fd = listener, .events = POLLIN};
        int result = poll(&p, 1, 100);
        if (result < 0) return 6;
        if (!result) continue;
        int host = accept(listener, NULL, NULL);
        if (host < 0 || start_client(host, -1)) return 7;
    }
    close(listener); unlink(argv[1]);
    for (unsigned i = 0; i < clients_count; i++) pthread_join(clients[i].thread, NULL);
    FILE *stats = fopen(argv[2], "w");
    if (!stats) return 8;
    fprintf(stats, "{\"sockets\":%u,\"mptcp\":%u,\"accepts\":%u,\"live\":%u,"
        "\"reads\":%lu,\"writes\":%lu,\"received\":%lu,\"sent\":%lu,"
        "\"infos\":%lu,\"full_info\":%lu,\"inq\":%lu,\"negotiated\":%u,\"fallback\":%u,"
        "\"fallback_info_eopnotsupp\":%u,\"fallback_info_enoprotoopt\":%u}\n",
        atomic_load(&sockets_count), atomic_load(&mptcp_count), atomic_load(&accepts_count), atomic_load(&live),
        atomic_load(&reads_count), atomic_load(&writes_count), atomic_load(&received_bytes), atomic_load(&sent_bytes),
        atomic_load(&infos_count), atomic_load(&full_count), atomic_load(&inq_count),
        atomic_load(&negotiated_count), atomic_load(&fallback_count),
        atomic_load(&fallback_info_unsupported), atomic_load(&fallback_info_no_proto));
    return fclose(stats) ? 9 : 0;
}
