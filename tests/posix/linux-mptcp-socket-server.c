#define _GNU_SOURCE
#include <netinet/in.h>
#include <net/if.h>
#include "linux-mptcp-socket-wire.h"
#include "linux-selftest-runtime.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <sched.h>
#include <signal.h>
#include <linux/mptcp.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* A thread per socket preserves blocking accept/connect/read on one original
 * kernel. Only the harness transport runs in the host; all IP socket syscalls
 * below go through the real POSIX facade. No fork occurs in the kernel owner. */
struct client { int host, native, ns, input, upload, retire; size_t input_size, uploaded;
    pid_t pid; atomic_int active, finished; pthread_t thread; pthread_cond_t work; };
static struct client clients[4096];
static unsigned clients_count;
static atomic_ulong channels_opened;
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint stopping, live, sockets_count, mptcp_count, accepts_count;
static atomic_ulong reads_count, writes_count, received_bytes, sent_bytes, infos_count, full_count, inq_count;
static atomic_uint negotiated_count, fallback_count, raw_count, filter_sets, filter_gets;
static atomic_uint fallback_info_unsupported, fallback_info_no_proto;
static atomic_ulong sendfile_calls, imported_files;

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

static int start_client(int host, int native, int ns, pid_t pid);
#include "linux-mptcp-diag-runtime.inc"
static long dispatch(struct client *client, struct ms_message *m, unsigned char *data, int *pass_fd)
{
    int fd = client->native;
    size_t input = m->length;
    m->length = 0;
    if (m->operation == MS_STOP) {
        if (fd >= 0 || input) { errno = EINVAL; return -1; }
        if (atomic_load(&live)) { errno = EBUSY; return -1; }
        return 0;
    }
    long control_result;
    if (diag_control(m, data, input, &control_result)) return control_result;
    if (m->operation == MS_SOCKET) {
        int netlink = m->a == AF_NETLINK && ((m->b & ~SOCK_CLOEXEC) == SOCK_RAW || (m->b & ~SOCK_CLOEXEC) == SOCK_DGRAM) &&
                  (m->c == NETLINK_SOCK_DIAG || m->c == NETLINK_ROUTE || m->c == NETLINK_GENERIC || m->c == NETLINK_NETFILTER);
        int raw = (m->a == AF_INET || m->a == AF_INET6) &&
                (((m->b & ~SOCK_CLOEXEC) == SOCK_RAW &&
                   (m->c == IPPROTO_RAW || (m->a == AF_INET && m->c == IPPROTO_ICMP) ||
                    (m->a == AF_INET6 && m->c == IPPROTO_ICMPV6))) ||
                 ((m->b & ~SOCK_CLOEXEC) == SOCK_DGRAM &&
                   (m->c == 0 || (m->a == AF_INET && m->c == IPPROTO_ICMP) ||
                    (m->a == AF_INET6 && m->c == IPPROTO_ICMPV6))));
        if (fd >= 0 || (!netlink && !raw && ((m->a != AF_INET && m->a != AF_INET6) || m->b != SOCK_STREAM ||
            (m->c != IPPROTO_MPTCP && m->c != IPPROTO_TCP && m->c != 0)))) { errno = EOPNOTSUPP; return -1; }
        if (select_namespace(input ? (char *)data : "", input, &client->ns)) return -1;
        client->native = raw ? (int)native_call(KER_TEST_RAW_SOCKET, m->a, m->b, m->c) : netlink ? (int)native_call(KER_TEST_NETLINK, m->b, m->c, 0) : socket((int)m->a, (int)m->b, (int)m->c);
        if (client->native < 0) return -1;
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(client->native) != (netlink ? 3 : 1)) { close(client->native); client->native = -1; errno = ENOTSUP; return -1; }
        atomic_fetch_add(&sockets_count, 1); mark_active(client);
        if (netlink) atomic_fetch_add(&diag_netlinks, 1);
        if (raw) atomic_fetch_add(&raw_count, 1);
        if (!netlink && m->c == IPPROTO_MPTCP) atomic_fetch_add(&mptcp_count, 1);
        return 0;
    }
    if (fd < 0) { errno = ENOTCONN; return -1; }
    switch (m->operation) {
    case MS_INPUT_START:
        if (input || m->a > MS_INPUT_MAX) { errno = EINVAL; return -1; }
        if (client->input >= 0) { close(client->input); client->input = -1; }
        if (client->upload >= 0) syscall(SYS_close, client->upload);
        client->upload = (int)syscall(SYS_memfd_create, "mptcp-sendfile-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        client->input_size = m->a; client->uploaded = 0;
        return client->upload < 0 ? -1 : 0;
    case MS_INPUT_WRITE: {
        if (client->upload < 0 || input > client->input_size - client->uploaded) { errno = EINVAL; return -1; }
        size_t done = 0;
        while (done < input) {
            ssize_t n = syscall(SYS_write, client->upload, data + done, input - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { if (!n) errno = EIO; return -1; }
            done += (size_t)n; client->uploaded += (size_t)n;
        }
        return 0;
    }
    case MS_INPUT_END: {
        if (input || client->upload < 0 || client->uploaded != client->input_size) { errno = EINVAL; return -1; }
        int (*import_input)(int) = dlsym(RTLD_DEFAULT, "ker_linux_selftest_input");
        if (!import_input) { errno = EOPNOTSUPP; return -1; }
        if (syscall(SYS_fcntl, client->upload, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) return -1;
        client->input = import_input(client->upload); int error = errno;
        syscall(SYS_close, client->upload); client->upload = -1;
        if (client->input < 0) { errno = error; return -1; }
        atomic_fetch_add(&imported_files, 1); return 0;
    }
    case MS_SENDFILE: {
        if (m->b == 1) {
            if (input != sizeof(int64_t) || client->input < 0) { errno = EINVAL; return -1; }
            int64_t position; memcpy(&position, data, sizeof(position));
            if (position < 0) { errno = EINVAL; return -1; }
            off_t offset = (off_t)position;
            ssize_t result = sendfile(fd, client->input, &offset, m->a);
            atomic_fetch_add(&sendfile_calls, 1);
            if (result < 0) return -1;
            atomic_fetch_add(&sent_bytes, (unsigned long)result);
            position = offset; memcpy(data, &position, sizeof(position)); m->length = sizeof(position);
            return result;
        }
        if (input < sizeof(int64_t) || m->a > MS_MAX) { errno = EINVAL; return -1; }
        int64_t position; memcpy(&position, data, sizeof(position));
        if (position < 0) { errno = EINVAL; return -1; }
        int (*import_input)(int) = dlsym(RTLD_DEFAULT, "ker_linux_selftest_input");
        if (!import_input) { errno = EOPNOTSUPP; return -1; }
        int host = (int)syscall(SYS_memfd_create, "mptcp-sendfile-input", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (host < 0) return -1;
        size_t size = input - sizeof(position), done = 0;
        while (done < size) {
            ssize_t n = syscall(SYS_write, host, data + sizeof(position) + done, size - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { int error = n ? errno : EIO; syscall(SYS_close, host); errno = error; return -1; }
            done += (size_t)n;
        }
        if (syscall(SYS_fcntl, host, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) {
            int error = errno; syscall(SYS_close, host); errno = error; return -1;
        }
        int native_file = import_input(host), error = errno;
        syscall(SYS_close, host);
        if (native_file < 0) { errno = error; return -1; }
        atomic_fetch_add(&imported_files, 1);
        off_t offset = (off_t)position;
        ssize_t result = sendfile(fd, native_file, &offset, m->a); error = errno;
        close(native_file);
        atomic_fetch_add(&sendfile_calls, 1);
        if (result < 0) { errno = error; return -1; }
        atomic_fetch_add(&sent_bytes, (unsigned long)result);
        position = offset; memcpy(data, &position, sizeof(position)); m->length = sizeof(position);
        return result;
    }
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
        /* AF_UNSPEC is the original helper's full disconnect operation.
         * Its successful return does not describe an established connection. */
        if (((struct sockaddr *)data)->sa_family == AF_UNSPEC) return 0;
        return observe_connection(fd);
    case MS_LISTEN: return listen(fd, (int)m->a);
    case MS_ACCEPT: {
        int native = accept(fd, NULL, NULL);
        if (native < 0) return -1;
        if (observe_connection(native)) { int e = errno; close(native); errno = e; return -1; }
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) { int e = errno; close(native); errno = e; return -1; }
        if (start_client(pair[0], native, client->ns, client->pid)) { int e = errno; close(pair[0]); close(pair[1]); close(native); errno = e; return -1; }
        atomic_fetch_add(&accepts_count, 1);
        *pass_fd = pair[1]; return 0;
    }
    case MS_SETOPT: {
        int replace = (m->a == IPPROTO_IP || m->a == IPPROTO_IPV6) && m->b == IPT_SO_SET_REPLACE;
        size_t count = 0;
        if (replace) {
            size_t offset = m->a == IPPROTO_IP ? offsetof(struct ipt_replace, counters) : offsetof(struct ip6t_replace, counters);
            size_t number = m->a == IPPROTO_IP ? offsetof(struct ipt_replace, num_counters) : offsetof(struct ip6t_replace, num_counters);
            if (input < offset + sizeof(void *)) { errno = EINVAL; return -1; }
            unsigned n; void *old; memcpy(&n, data + number, sizeof(n)); memcpy(&old, data + offset, sizeof(old)); count = n;
            if (old || count > (MS_MAX - input) / sizeof(struct xt_counters)) { errno = EINVAL; return -1; }
            void *counters = data + input; memset(counters, 0, count * sizeof(struct xt_counters));
            memcpy(data + offset, &counters, sizeof(counters));
        }
        long result = setsockopt(fd, (int)m->a, (int)m->b, data, (socklen_t)input);
        if (replace && !result) { m->length = (uint32_t)(count * sizeof(struct xt_counters)); memmove(data, data + input, m->length); }
        if (!result && (m->a == IPPROTO_IP || m->a == IPPROTO_IPV6) && m->b >= IPT_BASE_CTL) atomic_fetch_add(&filter_sets, 1);
        return result;
    }
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
        if (!result && (m->a == IPPROTO_IP || m->a == IPPROTO_IPV6) && m->b >= IPT_BASE_CTL) atomic_fetch_add(&filter_gets, 1);
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
    case MS_FCNTL:
        if (m->a != F_GETFL && m->a != F_SETFL && m->a != F_GETFD && m->a != F_SETFD) { errno = EOPNOTSUPP; return -1; }
        return fcntl(fd, (int)m->a, m->b);
    case MS_SHUTDOWN: return shutdown(fd, (int)m->a);
    case MS_POLL: {
        if (m->a > 50) { errno = EINVAL; return -1; }
        struct pollfd p = {.fd = fd, .events = (short)m->b};
        long result = poll(&p, 1, (int)m->a); m->b = (uint32_t)p.revents; return result;
    }
    case MS_SENDMSG:
    case MS_RECVMSG: {
        if (input < sizeof(struct ms_io)) { errno = EINVAL; return -1; }
        struct ms_io io; memcpy(&io, data, sizeof(io));
        int sending = m->operation == MS_SENDMSG;
        if (io.name > sizeof(struct sockaddr_storage) || io.data > MS_MAX || io.control > MS_MAX ||
            sizeof(io) + (size_t)io.data + io.control + io.name > MS_MAX ||
            input != sizeof(io) + (sending ? (size_t)io.data + io.control + io.name : 0)) { errno = EMSGSIZE; return -1; }
        struct iovec iov = {data + sizeof(io), io.data};
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
            .msg_control = io.control ? data + sizeof(io) + io.data : NULL, .msg_controllen = io.control,
            .msg_name = io.name ? data + sizeof(io) + io.data + io.control : NULL, .msg_namelen = io.name};
        ssize_t result = sending ? sendmsg(fd, &msg, (int)io.flags) : recvmsg(fd, &msg, (int)io.flags);
        if (result >= 0) {
            if (!sending) {
                size_t copied = (size_t)result < io.data ? (size_t)result : io.data;
                if (msg.msg_namelen > io.name || msg.msg_controllen > io.control) { errno = EOVERFLOW; return -1; }
                if (msg.msg_controllen) memmove(data + sizeof(io) + copied, msg.msg_control, msg.msg_controllen);
                if (msg.msg_namelen) memmove(data + sizeof(io) + copied + msg.msg_controllen, msg.msg_name, msg.msg_namelen);
                io.data = (uint32_t)copied; io.control = (uint32_t)msg.msg_controllen;
                io.name = msg.msg_namelen; io.flags = msg.msg_flags;
                memcpy(data, &io, sizeof(io));
                m->length = (uint32_t)(sizeof(io) + copied + io.control + io.name);
                atomic_fetch_add(&received_bytes, (unsigned long)result); atomic_fetch_add(&inq_count, 1);
            } else atomic_fetch_add(&sent_bytes, (unsigned long)result);
            if (client->ns >= 0) atomic_fetch_add(sending ? &diag_sends : &diag_receives, 1);
        }
        atomic_fetch_add(sending ? &writes_count : &reads_count, 1);
        return result;
    }
    default: errno = EOPNOTSUPP; return -1;
    }
}
static void serve_channel(struct client *client)
{
    /* Signals belong to the original caller, not the shared kernel owner.
     * Return the real EPIPE; the proxy delivers SIGPIPE in that caller. */
    sigset_t blocked; sigemptyset(&blocked); sigaddset(&blocked, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &blocked, NULL)) abort();
    struct { struct ms_message h; unsigned char data[MS_MAX]; } packet;
    for (;;) {
        ssize_t n = syscall(SYS_recvfrom, client->host, &packet, sizeof(packet), MSG_TRUNC, NULL, NULL);
        if (n < 0 && errno == EINTR) continue;
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
        /* Publish STOP only after its reply is queued. The coordinator may
         * then close idle control channels without racing this acknowledgement. */
        if (packet.h.operation == MS_STOP && result == 0) {
            atomic_store(&stopping, 1); break;
        }
    }
    if (client->native >= 0) {
        if (close(client->native)) abort();
        atomic_store_explicit(&client->active, 0, memory_order_release); atomic_fetch_sub(&live, 1);
    }
    pthread_mutex_lock(&clients_lock);
    syscall(SYS_close, client->host);
    client->host = -1;
    pthread_mutex_unlock(&clients_lock);
    if (client->input >= 0) close(client->input);
    if (client->upload >= 0) syscall(SYS_close, client->upload);
    /* A persistent native task must leave the retired namespace before its
     * next channel, so idle workers cannot pin the shell's deleted topology. */
    if (native_call(KER_TEST_SETNS, root_namespace, CLONE_NEWNET, 0)) {
        perror("mptcp fixture worker namespace release"); abort();
    }
}
static void *serve(void *argument)
{
    struct client *client = argument;
    for (;;) {
        serve_channel(client);
        pthread_mutex_lock(&clients_lock);
        client->host = -1;
        atomic_store_explicit(&client->finished, 1, memory_order_release);
        while (client->host < 0 && !client->retire)
            pthread_cond_wait(&client->work, &clients_lock);
        int done = client->host < 0;
        pthread_mutex_unlock(&clients_lock);
        if (done) return NULL;
    }
}
static int start_client(int host, int native, int ns, pid_t pid)
{
    pthread_mutex_lock(&clients_lock);
    int error = EMFILE;
    unsigned index;
    for (index = 0; index < clients_count; index++)
        if (atomic_load_explicit(&clients[index].finished, memory_order_acquire)) break;
    if (index < 4096) {
        struct client *client = &clients[index];
        int created = index == clients_count;
        /* Keep each native host task alive across channels. Creating and
         * destroying thousands of LKL host tasks can reenter its scheduler
         * through TLS retirement; unrelated channels need no new task. */
        client->host = host; client->native = native; client->ns = ns;
        client->input = -1; client->upload = -1;
        client->uploaded = 0; client->input_size = 0; client->pid = pid;
        atomic_store_explicit(&client->finished, 0, memory_order_release);
        if (native >= 0) mark_active(client);
        error = created ? pthread_cond_init(&client->work, NULL) : 0;
        if (!error && created) error = pthread_create(&client->thread, NULL, serve, client);
        if (!error) {
            atomic_fetch_add(&channels_opened, 1);
            if (created) clients_count++;
            else pthread_cond_signal(&client->work);
        } else if (native >= 0) atomic_fetch_sub(&live, 1);
    }
    pthread_mutex_unlock(&clients_lock);
    if (error) { errno = error; return -1; }
    return 0;
}
int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3 || strlen(argv[1]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    long (*call)(unsigned, const unsigned long[6]) = dlsym(RTLD_DEFAULT, "ker_linux_selftest_call");
    if (!call) return 3;
    unsigned long args[6] = {if_nametoindex("lo"), 0, 0, 0, 0, 0};
    if (!args[0] || call(KER_TEST_IF_UP, args) || diag_initialize(call)) return 4;
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX}; strcpy(address.sun_path, argv[1]);
    if (listener < 0 || bind(listener, (void *)&address, sizeof(address)) || listen(listener, 16)) return 5;
    while (!atomic_load(&stopping)) {
        struct pollfd p = {.fd = listener, .events = POLLIN};
        int result = poll(&p, 1, 100);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) { perror("mptcp fixture listener poll"); return 6; }
        if (!result) continue;
        int host = accept(listener, NULL, NULL);
        if (host < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        struct ucred peer; socklen_t size = sizeof(peer);
        if (host < 0 || syscall(SYS_getsockopt, host, SOL_SOCKET, SO_PEERCRED, &peer, &size) ||
            start_client(host, -1, -1, peer.pid)) { perror("mptcp fixture client start"); return 7; }
    }
    close(listener); unlink(argv[1]);
    pthread_mutex_lock(&clients_lock);
    /* STOP requires zero native sockets. An idle administrative RPC channel
     * can still be held by a caller, so close admission and wake those readers
     * rather than waiting for a host-side EOF that may never arrive. */
    for (unsigned i = 0; i < clients_count; i++)
        if (clients[i].host >= 0) syscall(SYS_shutdown, clients[i].host, SHUT_RDWR);
    pthread_mutex_unlock(&clients_lock);
    fputs("KER_MPTCP_FIXTURE_CHANNELS_DRAINED\n", stderr);
    for (unsigned i = 0; i < clients_count; i++) {
        /* Retire one persistent LKL host task at a time. Workers return to
         * root namespace before receiving their individual exit permission. */
        pthread_mutex_lock(&clients_lock);
        clients[i].retire = 1;
        pthread_cond_signal(&clients[i].work);
        pthread_mutex_unlock(&clients_lock);
        int error = pthread_join(clients[i].thread, NULL);
        if (error) { errno = error; perror("mptcp fixture worker join"); return 11; }
        pthread_cond_destroy(&clients[i].work);
    }
    fputs("KER_MPTCP_FIXTURE_TASKS_RETIRED\n", stderr);
    if (close(root_namespace)) return 10;
    FILE *stats = fopen(argv[2], "w");
    if (!stats) return 8;
    fprintf(stats, "{\"sockets\":%u,\"mptcp\":%u,\"accepts\":%u,\"live\":%u,"
        "\"reads\":%lu,\"writes\":%lu,\"received\":%lu,\"sent\":%lu,"
        "\"infos\":%lu,\"full_info\":%lu,\"inq\":%lu,\"negotiated\":%u,\"fallback\":%u,"
        "\"fallback_info_eopnotsupp\":%u,\"fallback_info_enoprotoopt\":%u,\"channel_slots\":%u,\"channels_opened\":%lu,"
        "\"namespaces_created\":%u,\"namespaces_deleted\":%u,\"netlinks\":%u,"
        "\"diag_sends\":%lu,\"diag_receives\":%lu,\"max_live\":%u,\"raw_sockets\":%u,\"filter_sets\":%u,\"filter_gets\":%u,\"mp_join_syn_rx\":%lu,\"mp_join_ack_rx\":%lu,\"sendfile_calls\":%lu,\"imported_files\":%lu}\n",
        atomic_load(&sockets_count), atomic_load(&mptcp_count), atomic_load(&accepts_count), atomic_load(&live),
        atomic_load(&reads_count), atomic_load(&writes_count), atomic_load(&received_bytes), atomic_load(&sent_bytes),
        atomic_load(&infos_count), atomic_load(&full_count), atomic_load(&inq_count),
        atomic_load(&negotiated_count), atomic_load(&fallback_count),
        atomic_load(&fallback_info_unsupported), atomic_load(&fallback_info_no_proto),
        clients_count, atomic_load(&channels_opened),
        atomic_load(&namespaces_created), atomic_load(&namespaces_deleted), atomic_load(&diag_netlinks),
        atomic_load(&diag_sends), atomic_load(&diag_receives), atomic_load(&max_live),
        atomic_load(&raw_count), atomic_load(&filter_sets), atomic_load(&filter_gets),
        atomic_load(&join_syn_rx), atomic_load(&join_ack_rx), atomic_load(&sendfile_calls), atomic_load(&imported_files));
    return fclose(stats) ? 9 : 0;
}
