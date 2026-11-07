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
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
#include <sys/epoll.h>
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NET_DEVICE_SELFTEST)
#include <linux/sockios.h>
#include <linux/if_tun.h>
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_SOCKET_FILTER_SELFTEST)
#include <linux/filter.h>
#endif

/* A thread per socket preserves blocking accept/connect/read on one original
 * kernel. Only the harness transport runs in the host; all IP socket syscalls
 * below go through the real POSIX facade. No fork occurs in the kernel owner. */
struct client { int host, native, ns, input, upload, retire; size_t input_size, uploaded;
    pid_t pid; atomic_int active, finished; pthread_t thread; pthread_cond_t work;
#ifdef KER_NETLINK_DUMPS_SELFTEST
    int message_queue;
#endif
#ifdef KER_PACKETDRILL_SELFTEST
    char proc_path[129];
#endif
};
static struct client clients[4096];
static unsigned clients_count;
static atomic_ulong channels_opened;
#ifdef KER_NETLINK_DUMPS_SELFTEST
static atomic_uint mq_opens, mq_notifications, mq_closes, notified_netlink_closes, generic_netlinks;
static atomic_int notified_netlink = -1;
#endif
#ifdef KER_MACVTAP_SELFTEST
static atomic_uint macvtap_opens, macvtap_write_einval, macvtap_writes;
static atomic_ulong macvtap_bytes;
#endif
#ifdef KER_SOCKET_CREATION_SELFTEST
static atomic_uint creation_attempts, creation_eafnosupport, creation_eprotonosupport;
static atomic_uint creation_tcp, creation_udp;
#endif
#ifdef KER_PACKETDRILL_SELFTEST
static atomic_ulong packetdrill_offloads, packetdrill_timestamps;
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
static atomic_ulong native_epoll_creates, native_epoll_controls, native_epoll_waits;
#endif
#ifdef KER_NETWORK_SELFTEST
static atomic_uint udp_count;
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NET_DEVICE_SELFTEST)
static atomic_ulong native_tun_opens;
#endif
#ifdef KER_NET_DEVICE_SELFTEST
static atomic_uint dccp_count;
static atomic_ulong namespace_tcp_active, namespace_tcp_passive;
static atomic_ulong tun_if_sets, tun_queue_calls, tun_attaches, tun_detaches, tun_queue_einval;
#endif
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t clients_drained = PTHREAD_COND_INITIALIZER;
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
#ifdef KER_PACKETDRILL_SELFTEST
#include "linux-packetdrill-send.inc"
#endif
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
#ifdef KER_NETLINK_DUMPS_SELFTEST
    if (m->operation == MS_MQ_OPEN) {
        if (fd >= 0 || !input || input > 256 || data[input - 1] ||
            strlen((char *)data) + 1 != input) { errno = EINVAL; return -1; }
        if (select_namespace("", 1, &client->ns)) return -1;
        client->native = (int)native_call(KER_TEST_MQ_OPEN, (unsigned long)data, m->a, m->b);
        if (client->native < 0) return -1;
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(client->native) != 3) {
            close(client->native); client->native = -1; errno = ENOTSUP; return -1;
        }
        client->message_queue = 1; atomic_fetch_add(&mq_opens, 1);
        mark_active(client); return 0;
    }
#endif
#ifdef KER_PACKETDRILL_SELFTEST
    if (m->operation == MS_PROC_OPEN) {
        if (fd >= 0 || !input || data[input - 1]) { errno = EINVAL; return -1; }
        size_t prefix = strlen((char *)data) + 1;
        if (prefix >= input) { errno = EINVAL; return -1; }
        const char *path = (char *)data + prefix;
        if (strlen(path) + prefix + 1 != input || strlen(path) >= sizeof(client->proc_path) ||
            strncmp(path, "/proc/sys/net/", 14) || strstr(path, "..") ||
            (m->a & O_ACCMODE) != O_WRONLY || (m->a & ~(O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC))) { errno = EINVAL; return -1; }
        if (select_namespace((char *)data, prefix, &client->ns)) return -1;
        client->native = (int)native_call(KER_TEST_OPEN, (unsigned long)path, m->a, 0);
        if (client->native < 0) return -1;
        strcpy(client->proc_path, path);
        mark_active(client); return 0;
    }
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NET_DEVICE_SELFTEST)
#ifdef KER_MACVTAP_SELFTEST
    if (m->operation == MS_MACVTAP_OPEN) {
        if (fd >= 0 || select_namespace(input ? (char *)data : "", input, &client->ns)) return -1;
        client->native = (int)native_call(KER_TEST_OPEN_MACVTAP, m->a, 0, 0);
        if (client->native < 0) return -1;
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(client->native) != 3) {
            close(client->native); client->native = -1; errno = ENOTSUP; return -1;
        }
        atomic_fetch_add(&macvtap_opens, 1); mark_active(client); return 0;
    }
#endif
    if (m->operation == MS_TUN_OPEN) {
        if (fd >= 0 || select_namespace(input ? (char *)data : "", input, &client->ns)) return -1;
        client->native = (int)native_call(KER_TEST_OPEN_TUN, 0, 0, 0);
        if (client->native < 0) return -1;
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(client->native) != 3) { close(client->native); client->native = -1; errno = ENOTSUP; return -1; }
        atomic_fetch_add(&native_tun_opens, 1);
        mark_active(client); return 0;
    }
#endif
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
    if (m->operation == MS_EPOLL_OPEN) {
        if (fd >= 0 || select_namespace(input ? (char *)data : "", input, &client->ns)) return -1;
        client->native = epoll_create((int)m->a);
        if (client->native < 0) return -1;
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(client->native) != 2) { close(client->native); client->native = -1; errno = ENOTSUP; return -1; }
        atomic_fetch_add(&native_epoll_creates, 1);
        mark_active(client); return client->native;
    }
#endif
    if (m->operation == MS_SOCKET) {
        int packet = 0;
#ifdef KER_PACKETDRILL_SELFTEST
        packet = m->a == AF_PACKET && m->b == SOCK_RAW;
#endif
        int netlink = m->a == AF_NETLINK && ((m->b & ~SOCK_CLOEXEC) == SOCK_RAW || (m->b & ~SOCK_CLOEXEC) == SOCK_DGRAM) &&
                  (m->c == NETLINK_SOCK_DIAG || m->c == NETLINK_ROUTE || m->c == NETLINK_GENERIC || m->c == NETLINK_NETFILTER);
        int raw = (m->a == AF_INET || m->a == AF_INET6) &&
                (((m->b & ~SOCK_CLOEXEC) == SOCK_RAW &&
                   (m->c == IPPROTO_RAW || (m->a == AF_INET && m->c == IPPROTO_ICMP) ||
                    (m->a == AF_INET6 && m->c == IPPROTO_ICMPV6))) ||
                 ((m->b & ~SOCK_CLOEXEC) == SOCK_DGRAM &&
                   (m->c == 0 || (m->a == AF_INET && m->c == IPPROTO_ICMP) ||
                    (m->a == AF_INET6 && m->c == IPPROTO_ICMPV6))));
        int udp = 0;
#ifdef KER_NETWORK_SELFTEST
        udp = (m->a == AF_INET || m->a == AF_INET6) && m->b == SOCK_DGRAM &&
              (m->c == 0 || m->c == IPPROTO_UDP);
        if (udp) raw = 0;
#endif
        int dccp = 0;
#ifdef KER_NET_DEVICE_SELFTEST
        dccp = (m->a == AF_INET || m->a == AF_INET6) && m->b == SOCK_DCCP &&
               (m->c == 0 || m->c == IPPROTO_DCCP);
#endif
        int creation = 0;
#ifdef KER_SOCKET_CREATION_SELFTEST
        creation = m->a == AF_INET || (m->a == AF_MAX && m->b == 0 && m->c == 0);
#endif
        if (fd >= 0 || (!creation && !dccp && !udp && !packet && !netlink && !raw && ((m->a != AF_INET && m->a != AF_INET6) || m->b != SOCK_STREAM ||
            (m->c != IPPROTO_MPTCP && m->c != IPPROTO_TCP && m->c != 0)))) { errno = EOPNOTSUPP; return -1; }
        if (select_namespace(input ? (char *)data : "", input, &client->ns)) return -1;
#ifdef KER_SOCKET_CREATION_SELFTEST
        atomic_fetch_add(&creation_attempts, 1);
        /* IPv4 exercises the real POSIX facade. AF_MAX uses the private
         * native call, because non-network public families belong to host IPC. */
        if (m->a == AF_MAX) client->native = (int)native_call(KER_TEST_SOCKET, m->a, m->b, m->c);
        else
#endif
        client->native = raw ? (int)native_call(KER_TEST_RAW_SOCKET, m->a, m->b, m->c) : netlink ? (int)native_call(KER_TEST_NETLINK, m->b, m->c, 0) : socket((int)m->a, (int)m->b, (int)m->c);
#ifdef KER_SOCKET_CREATION_SELFTEST
        if (client->native < 0) {
            if (errno == EAFNOSUPPORT) atomic_fetch_add(&creation_eafnosupport, 1);
            if (errno == EPROTONOSUPPORT) atomic_fetch_add(&creation_eprotonosupport, 1);
        } else {
            int protocol = 0; socklen_t size = sizeof(protocol);
            if (getsockopt(client->native, SOL_SOCKET, SO_PROTOCOL, &protocol, &size) || size != sizeof(protocol)) {
                close(client->native); client->native = -1; errno = ENOTSUP; return -1;
            }
            if (protocol == IPPROTO_TCP) atomic_fetch_add(&creation_tcp, 1);
            if (protocol == IPPROTO_UDP) atomic_fetch_add(&creation_udp, 1);
        }
#endif
        if (client->native < 0) return -1;
        int (*kind)(int) = dlsym(RTLD_DEFAULT, "ker_posix_descriptor_kind");
        if (!kind || kind(client->native) != ((packet || netlink) ? 3 : 1)) { close(client->native); client->native = -1; errno = ENOTSUP; return -1; }
#ifdef KER_NET_DEVICE_SELFTEST
        if (udp || dccp) {
            int protocol = 0; socklen_t size = sizeof(protocol);
            if (getsockopt(client->native, SOL_SOCKET, SO_PROTOCOL, &protocol, &size) ||
                size != sizeof(protocol) || protocol != (dccp ? IPPROTO_DCCP : IPPROTO_UDP)) {
                close(client->native); client->native = -1; errno = ENOTSUP; return -1;
            }
        }
        if (dccp) atomic_fetch_add(&dccp_count, 1);
#endif
        atomic_fetch_add(&sockets_count, 1); mark_active(client);
#ifdef KER_NETWORK_SELFTEST
        if (udp) atomic_fetch_add(&udp_count, 1);
#endif
        if (netlink) atomic_fetch_add(&diag_netlinks, 1);
#ifdef KER_NETLINK_DUMPS_SELFTEST
        if (netlink && m->c == NETLINK_GENERIC) atomic_fetch_add(&generic_netlinks, 1);
#endif
        if (raw || packet) atomic_fetch_add(&raw_count, 1);
        if (!netlink && m->c == IPPROTO_MPTCP) atomic_fetch_add(&mptcp_count, 1);
        return 0;
    }
    if (fd < 0) { errno = ENOTCONN; return -1; }
    switch (m->operation) {
#ifdef KER_NETLINK_DUMPS_SELFTEST
    case MS_NETLINK_HANDLE: {
        int domain = 0; socklen_t size = sizeof(domain);
        if (input || getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &size) || domain != AF_NETLINK) {
            errno = EINVAL; return -1;
        }
        return fd;
    }
    case MS_MQ_NOTIFY: {
        if (!client->message_queue || input != 32) { errno = EINVAL; return -1; }
        long result = native_call(KER_TEST_MQ_NOTIFY, fd, m->a, (unsigned long)data);
        if (!result) {
            atomic_store(&notified_netlink, (int)m->a);
            atomic_fetch_add(&mq_notifications, 1);
        }
        return result;
    }
#endif
    case MS_CLOSE: {
        if (input) { errno = EINVAL; return -1; }
        int result = close(fd);
        if (!result) {
#ifdef KER_NETLINK_DUMPS_SELFTEST
            if (fd == atomic_load(&notified_netlink)) atomic_fetch_add(&notified_netlink_closes, 1);
            if (client->message_queue) atomic_fetch_add(&mq_closes, 1);
#endif
            client->native = -1;
            atomic_store_explicit(&client->active, 0, memory_order_release);
            atomic_fetch_sub(&live, 1);
        }
        return result;
    }
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NETWORK_SELFTEST)
    case MS_EPOLL_CTL: {
        struct epoll_event event;
        if (input && input != sizeof(event)) { errno = EINVAL; return -1; }
        if (input) memcpy(&event, data, sizeof(event));
        /* The target socket owns this RPC channel and cannot be recycled
         * while its request is being dispatched. No frontend fd is used. */
        int result = epoll_ctl((int)m->a, (int)m->b, fd, input ? &event : NULL);
        if (!result) atomic_fetch_add(&native_epoll_controls, 1);
        return result;
    }
    case MS_EPOLL_WAIT: {
        if (input || m->a > 64 || !m->a || (m->b > 1000 && m->b != UINT32_MAX)) { errno = EINVAL; return -1; }
        struct epoll_event events[64];
        long result = epoll_wait(fd, events, (int)m->a, (int)m->b);
        if (result >= 0) {
            m->length = (uint32_t)result * sizeof(events[0]); memcpy(data, events, m->length);
            atomic_fetch_add(&native_epoll_waits, 1);
        }
        return result;
    }
#endif
#ifdef KER_PACKETDRILL_SELFTEST
    case MS_PACKET_SENDV:
        return packetdrill_send_vectors(fd, m->a, data, input);
#endif
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
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_SOCKET_FILTER_SELFTEST)
        if (m->a == SOL_SOCKET && m->b == SO_ATTACH_FILTER) {
            struct sock_fprog program;
            if (input < sizeof(program)) { errno = EINVAL; return -1; }
            memcpy(&program, data, sizeof(program));
            size_t bytes = (size_t)program.len * sizeof(struct sock_filter);
            if (program.filter || bytes != input - sizeof(program)) { errno = EINVAL; return -1; }
            program.filter = (void *)(data + sizeof(program));
            long result = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program));
            if (!result) atomic_fetch_add(&filter_sets, 1);
            return result;
        }
#endif
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
#ifndef KER_PACKETDRILL_SELFTEST
        if (m->a == MS_WRITE_PROC_TARGET) { errno = EOPNOTSUPP; return -1; }
#else
        if (m->a == MS_WRITE_PROC_TARGET && !client->proc_path[0]) { errno = EINVAL; return -1; }
#endif
        ssize_t result = write(fd, data, input);
#ifdef KER_MACVTAP_SELFTEST
        if (result < 0 && errno == EINVAL) atomic_fetch_add(&macvtap_write_einval, 1);
        if (result >= 0) {
            atomic_fetch_add(&macvtap_writes, 1);
            atomic_fetch_add(&macvtap_bytes, (unsigned long)result);
        }
#endif
        if (result >= 0) atomic_fetch_add(&sent_bytes, (unsigned long)result);
#ifdef KER_PACKETDRILL_SELFTEST
        if (result >= 0 && m->a == MS_WRITE_PROC_TARGET) {
            m->length = (uint32_t)strlen(client->proc_path) + 1;
            memcpy(data, client->proc_path, m->length);
        }
#endif
        atomic_fetch_add(&writes_count, 1); return result;
    }
    case MS_IOCTL: {
#if defined(KER_PACKETDRILL_SELFTEST) || defined(KER_NET_DEVICE_SELFTEST)
        if (m->a == TUNSETIFF || m->a == TUNSETQUEUE || m->a == SIOCGIFFLAGS || m->a == SIOCSIFFLAGS ||
            m->a == SIOCGIFADDR || m->a == SIOCSIFADDR || m->a == SIOCSIFNETMASK ||
            m->a == SIOCGIFMTU || m->a == SIOCSIFMTU) {
            if (input != sizeof(struct ifreq)) { errno = EINVAL; return -1; }
            long result = ioctl(fd, m->a, data);
#ifdef KER_NET_DEVICE_SELFTEST
            if (m->a == TUNSETIFF && !result) atomic_fetch_add(&tun_if_sets, 1);
            if (m->a == TUNSETQUEUE) {
                atomic_fetch_add(&tun_queue_calls, 1);
                struct ifreq *request = (void *)data;
                if (!result && request->ifr_flags == IFF_ATTACH_QUEUE) atomic_fetch_add(&tun_attaches, 1);
                if (!result && request->ifr_flags == IFF_DETACH_QUEUE) atomic_fetch_add(&tun_detaches, 1);
                if (result < 0 && errno == EINVAL) atomic_fetch_add(&tun_queue_einval, 1);
            }
#endif
            if (!result) m->length = sizeof(struct ifreq);
            return result;
        }
#endif
#ifdef KER_PACKETDRILL_SELFTEST
        if (m->a == TUNSETOFFLOAD) {
            if (input) { errno = EINVAL; return -1; }
            long result = ioctl(fd, m->a, (unsigned long)m->b);
            if (!result) atomic_fetch_add(&packetdrill_offloads, 1);
            return result;
        }
        if (m->a == SIOCGSTAMP) {
            struct timeval timestamp;
            long result = ioctl(fd, m->a, &timestamp);
            if (!result) {
                memcpy(data, &timestamp, sizeof(timestamp)); m->length = sizeof(timestamp);
                atomic_fetch_add(&packetdrill_timestamps, 1);
            }
            return result;
        }
#endif
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
#ifdef KER_NETLINK_DUMPS_SELFTEST
        if (client->message_queue) atomic_fetch_add(&mq_closes, 1);
#endif
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
        pthread_cond_signal(&clients_drained);
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
#ifdef KER_NETLINK_DUMPS_SELFTEST
        client->message_queue = 0;
#endif
#ifdef KER_PACKETDRILL_SELFTEST
        client->proc_path[0] = '\0';
#endif
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
    for (unsigned i = 0; i < clients_count; i++)
        while (!atomic_load_explicit(&clients[i].finished, memory_order_acquire))
            pthread_cond_wait(&clients_drained, &clients_lock);
    pthread_mutex_unlock(&clients_lock);
    fputs("KER_MPTCP_FIXTURE_CHANNELS_DRAINED\n", stderr);
    if (close(root_namespace)) return 10;
    /* All RPC work, descriptor closes and namespace releases have completed.
     * Halt the native kernel while its host tasks remain parked. Retiring a
     * pthread first invokes LKL's task TLS destructor, which can schedule a
     * different host task that is waiting here rather than entering Linux.
     * Native halt reclaims those tasks and deletes the TLS key before the
     * pthreads exit, so no destructor can enter a stranded scheduler. */
    if (native_call(KER_TEST_FINALIZE, 0, 0, 0)) {
        perror("mptcp fixture native finalize"); return 12;
    }
    fputs("KER_MPTCP_FIXTURE_NATIVE_HALTED\n", stderr);
    for (unsigned i = 0; i < clients_count; i++) {
        /* Native state is gone; join every remaining host transport worker. */
        pthread_mutex_lock(&clients_lock);
        clients[i].retire = 1;
        pthread_cond_signal(&clients[i].work);
        pthread_mutex_unlock(&clients_lock);
        int error = pthread_join(clients[i].thread, NULL);
        if (error) { errno = error; perror("mptcp fixture worker join"); return 11; }
        pthread_cond_destroy(&clients[i].work);
    }
    fputs("KER_MPTCP_FIXTURE_TASKS_RETIRED\n", stderr);
    FILE *stats = fopen(argv[2], "w");
    if (!stats) return 8;
    const char *extra = "";
#ifdef KER_PACKETDRILL_SELFTEST
    char packetdrill_counts[512];
    snprintf(packetdrill_counts, sizeof(packetdrill_counts),
        ",\"tun_opens\":%lu,\"tun_offloads\":%lu,\"packet_timestamps\":%lu,"
        "\"epoll_creates\":%lu,\"epoll_controls\":%lu,\"epoll_waits\":%lu",
        atomic_load(&native_tun_opens), atomic_load(&packetdrill_offloads), atomic_load(&packetdrill_timestamps),
        atomic_load(&native_epoll_creates), atomic_load(&native_epoll_controls), atomic_load(&native_epoll_waits));
    extra = packetdrill_counts;
#endif
#ifdef KER_NETWORK_SELFTEST
    char network_counts[512];
    snprintf(network_counts, sizeof(network_counts),
        ",\"udp_sockets\":%u,\"epoll_creates\":%lu,\"epoll_controls\":%lu,\"epoll_waits\":%lu",
        atomic_load(&udp_count), atomic_load(&native_epoll_creates),
        atomic_load(&native_epoll_controls), atomic_load(&native_epoll_waits));
#ifdef KER_NET_DEVICE_SELFTEST
    size_t used = strlen(network_counts);
    snprintf(network_counts + used, sizeof(network_counts) - used,
        ",\"dccp_sockets\":%u,\"tun_opens\":%lu,\"tun_if_sets\":%lu,\"tun_queue_calls\":%lu,"
        "\"tun_attaches\":%lu,\"tun_detaches\":%lu,\"tun_queue_einval\":%lu,"
        "\"namespace_tcp_active\":%lu,\"namespace_tcp_passive\":%lu",
        atomic_load(&dccp_count), atomic_load(&native_tun_opens), atomic_load(&tun_if_sets),
        atomic_load(&tun_queue_calls), atomic_load(&tun_attaches), atomic_load(&tun_detaches),
        atomic_load(&tun_queue_einval), atomic_load(&namespace_tcp_active), atomic_load(&namespace_tcp_passive));
#endif
    extra = network_counts;
#endif
#ifdef KER_NETLINK_DUMPS_SELFTEST
    char mq_counts[1024];
    snprintf(mq_counts, sizeof(mq_counts),
        "%s,\"mq_opens\":%u,\"mq_notifications\":%u,\"mq_closes\":%u,"
        "\"notified_netlink_closes\":%u,\"generic_netlinks\":%u", extra,
        atomic_load(&mq_opens), atomic_load(&mq_notifications), atomic_load(&mq_closes),
        atomic_load(&notified_netlink_closes), atomic_load(&generic_netlinks));
    extra = mq_counts;
#endif
#ifdef KER_MACVTAP_SELFTEST
    char macvtap_counts[1024];
    snprintf(macvtap_counts, sizeof(macvtap_counts),
        "%s,\"macvtap_opens\":%u,\"macvtap_write_einval\":%u,"
        "\"macvtap_writes\":%u,\"macvtap_bytes\":%lu", extra,
        atomic_load(&macvtap_opens), atomic_load(&macvtap_write_einval),
        atomic_load(&macvtap_writes), atomic_load(&macvtap_bytes));
    extra = macvtap_counts;
#endif
#ifdef KER_SOCKET_CREATION_SELFTEST
    char creation_counts[1024];
    snprintf(creation_counts, sizeof(creation_counts),
        "%s,\"creation_attempts\":%u,\"creation_eafnosupport\":%u,\"creation_eprotonosupport\":%u,"
        "\"creation_tcp\":%u,\"creation_udp\":%u", extra,
        atomic_load(&creation_attempts), atomic_load(&creation_eafnosupport),
        atomic_load(&creation_eprotonosupport), atomic_load(&creation_tcp), atomic_load(&creation_udp));
    extra = creation_counts;
#endif
    fprintf(stats, "{\"sockets\":%u,\"mptcp\":%u,\"accepts\":%u,\"live\":%u,"
        "\"reads\":%lu,\"writes\":%lu,\"received\":%lu,\"sent\":%lu,"
        "\"infos\":%lu,\"full_info\":%lu,\"inq\":%lu,\"negotiated\":%u,\"fallback\":%u,"
        "\"fallback_info_eopnotsupp\":%u,\"fallback_info_enoprotoopt\":%u,\"channel_slots\":%u,\"channels_opened\":%lu,"
        "\"namespaces_created\":%u,\"namespaces_deleted\":%u,\"netlinks\":%u,"
        "\"diag_sends\":%lu,\"diag_receives\":%lu,\"max_live\":%u,\"raw_sockets\":%u,\"filter_sets\":%u,\"filter_gets\":%u,\"mp_join_syn_rx\":%lu,\"mp_join_ack_rx\":%lu,\"sendfile_calls\":%lu,\"imported_files\":%lu%s}\n",
        atomic_load(&sockets_count), atomic_load(&mptcp_count), atomic_load(&accepts_count), atomic_load(&live),
        atomic_load(&reads_count), atomic_load(&writes_count), atomic_load(&received_bytes), atomic_load(&sent_bytes),
        atomic_load(&infos_count), atomic_load(&full_count), atomic_load(&inq_count),
        atomic_load(&negotiated_count), atomic_load(&fallback_count),
        atomic_load(&fallback_info_unsupported), atomic_load(&fallback_info_no_proto),
        clients_count, atomic_load(&channels_opened),
        atomic_load(&namespaces_created), atomic_load(&namespaces_deleted), atomic_load(&diag_netlinks),
        atomic_load(&diag_sends), atomic_load(&diag_receives), atomic_load(&max_live),
        atomic_load(&raw_count), atomic_load(&filter_sets), atomic_load(&filter_gets),
        atomic_load(&join_syn_rx), atomic_load(&join_ack_rx), atomic_load(&sendfile_calls), atomic_load(&imported_files), extra);
    return fclose(stats) ? 9 : 0;
}
