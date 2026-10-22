#define _GNU_SOURCE
#include "fd-table.h"
#include "diagnostics.h"
#include "lifecycle.h"
#include "host-memory.h"
#include "host-thread.h"
#include "host-clock.h"
#include "host-timer.h"
#include "host-entropy.h"
#include "realtime-clock.h"
#include "ipv6-route.h"
#include "vlan.h"
#include "packet-channel.h"
#include "packet-device.h"
#include "mtu-control.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <lkl/linux/time.h>
#include <lkl/linux/virtio_net.h>
#include <lkl/linux/time_types.h>
#include <lkl.h>
#include <lkl_host.h>
#include <sys/utsname.h>
#include <ker/posix.h>

_Static_assert(sizeof(struct ker_packet_header) == sizeof(struct lkl_virtio_net_hdr_v1),
    "packet channel must match the imported virtio-net ABI");
static atomic_bool ready;
static struct lkl_netdev *device;
static int startup_fd = -1;
static unsigned int drain_timeout = 5000;
static char release[65];
uint64_t ker_posix_capabilities(void)
{
    return ker_native_ready() ? KER_CAP_DPDK_IO | KER_CAP_LINUX_STACK | KER_CAP_IPV4 | KER_CAP_TCP : 0;
}
const char *ker_posix_kernel_release(void) { return ker_native_ready() ? release : NULL; }
bool ker_native_ready(void) { return atomic_load_explicit(&ready, memory_order_acquire); }
static void fail(const char *operation, int error)
{
    char message[256];
    int length = snprintf(message, sizeof(message), "ker native Linux startup failed: %s (%d)\n", operation, error);
    (void)syscall(SYS_write, STDERR_FILENO, message, (size_t)length);
    _Exit(125);
}
static const char *required(const char *name)
{
    const char *value = getenv(name);
    if (!value || !*value) fail(name, -EINVAL);
    return value;
}
static long parse_number(const char *text, long maximum)
{
    char *end;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || !*text || *end || value < 0 || value > maximum) fail("invalid numeric configuration", -EINVAL);
    return value;
}
static struct in6_addr add_ipv6_address(int index, const char *configuration)
{
    char text[INET6_ADDRSTRLEN + 5];
    if (strlen(configuration) >= sizeof(text)) fail("IPv6 address length", -EINVAL);
    strcpy(text, configuration);
    char *slash = strchr(text, '/');
    if (!slash) fail("IPv6 address/prefix", -EINVAL);
    *slash++ = 0;
    struct in6_addr address6;
    if (inet_pton(AF_INET6, text, &address6) != 1 || IN6_IS_ADDR_UNSPECIFIED(&address6) ||
        IN6_IS_ADDR_MULTICAST(&address6) || IN6_IS_ADDR_LOOPBACK(&address6) ||
        IN6_IS_ADDR_V4MAPPED(&address6)) fail("IPv6 unicast address", -EINVAL);
    unsigned int prefix6 = (unsigned int)parse_number(slash, 128);
    /* Queue original Linux DAD for all addresses before waiting. Serial
     * add-and-wait would exceed the launch deadline at the 32-VIP limit. */
    int result = lkl_if_add_ip(index, LKL_AF_INET6, &address6, prefix6);
    if (result) fail("IPv6 interface configuration", result);
    return address6;
}
static void fork_child(void)
{
    static const char error[] = "ker: fork after native kernel initialization is unsupported; launch each process with ker-run\n";
    (void)syscall(SYS_write, STDERR_FILENO, error, sizeof(error) - 1);
    syscall(SYS_exit_group, 125);
}
__attribute__((constructor)) static void initialize(void)
{
    int fd = (int)parse_number(required("KER_PACKET_FD"), INT_MAX), type = 0;
    socklen_t length = sizeof(type);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_DGRAM)
        fail("packet descriptor is not a datagram channel", -EINVAL);
    if (syscall(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC) < 0) fail("packet descriptor flags", -errno);
    unsigned int parts[6];
    char extra;
    if (sscanf(required("LKL_HIJACK_NET_MAC"), "%x:%x:%x:%x:%x:%x%c",
        &parts[0], &parts[1], &parts[2], &parts[3], &parts[4], &parts[5], &extra) != 6)
        fail("invalid Ethernet address", -EINVAL);
    unsigned char mac[6];
    for (unsigned int i = 0; i < 6; ++i) {
        if (parts[i] > 255) fail("invalid Ethernet address", -EINVAL);
        mac[i] = (unsigned char)parts[i];
    }
    struct in_addr address;
    if (inet_pton(AF_INET, required("LKL_HIJACK_NET_IP"), &address) != 1)
        fail("IPv4 address", -EINVAL);
    long prefix = parse_number(required("LKL_HIJACK_NET_NETMASK_LEN"), 32);
    const char *mtu_text = getenv("KER_PACKET_MTU");
    long mtu = mtu_text ? parse_number(mtu_text, KER_NATIVE_MAX_MTU) : KER_NATIVE_DEFAULT_MTU;
    if (mtu < KER_NATIVE_MIN_MTU) fail("interface MTU below IPv6 minimum", -EINVAL);
    long maximum = parse_number(required("KER_PACKET_MAX_MTU"), KER_NATIVE_MAX_MTU);
    if (maximum < mtu) fail("MTU exceeds deployment ceiling", -EINVAL);
    int mtu_fd = (int)parse_number(required("KER_PACKET_CONTROL_FD"), INT_MAX);
    length = sizeof(type);
    if (syscall(SYS_getsockopt, mtu_fd, SOL_SOCKET, SO_TYPE, &type, &length) || type != SOCK_SEQPACKET ||
        syscall(SYS_fcntl, mtu_fd, F_SETFD, FD_CLOEXEC) < 0)
        fail("invalid MTU control channel", -EINVAL);
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_thread_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    ker_native_host_timer_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    int result = lkl_init(&lkl_host_ops);
    if (result) fail("kernel initialization", result);
    device = ker_packet_device_create(fd);
    if (!device) fail("packet device allocation", -ENOMEM);
    /* Live jumbo growth needs multiple virtio buffers even at MTU1500 startup.
     * The original LKL transport implements mergeable buffers, including num_buffers accounting; this
     * does not enable checksum or segmentation offloads. */
    struct lkl_netdev_args args = {.mac = mac, .offload = maximum > 1500 ?
        (1U << LKL_VIRTIO_NET_F_MRG_RXBUF) : 0};
    result = lkl_netdev_add(device, &args);
    if (result < 0) fail("packet device registration", result);
    device->id = result;
    result = lkl_start_kernel("%s", "mem=64M");
    if (result) fail("kernel boot", result);
    result = ker_native_seed_entropy();
    if (result) fail("native entropy initialization", result);
    result = ker_native_sync_realtime();
    if (result) fail("native realtime clock initialization", result);
    /* Linux UAPI new_utsname is six 65-byte fields on both ABI domains. */
    _Static_assert(sizeof(struct utsname) == 6 * 65, "uname ABI");
    struct utsname identity;
    long parameters[6] = {(long)&identity, 0, 0, 0, 0, 0};
    result = (int)lkl_syscall(__lkl__NR_uname, parameters);
    if (result || strcmp(identity.release, KER_NATIVE_KERNEL_RELEASE))
        fail("kernel identity differs from its source proof", result ? result : -EINVAL);
    memcpy(release, identity.release, sizeof(release));
    result = lkl_set_fd_limit(KER_FD_LIMIT);
    if (result) fail("native descriptor budget", result);
    result = lkl_mount_fs("proc");
    if (result < 0) fail("native procfs diagnostics", result);
    /* Apply validated Linux names in this private kernel before interfaces
     * become ready. Keep value validation and protocol policy in Linux. */
    const char *sysctls = getenv("KER_NATIVE_SYSCTLS");
    if (sysctls && *sysctls) {
        if (strlen(sysctls) > 32 * (128 + 1 + 256 + 1))
            fail("network sysctl configuration length", -EINVAL);
        char *copy = strdup(sysctls);
        if (!copy) fail("network sysctl allocation", -ENOMEM);
        char *rest = copy, *entry;
        unsigned int count = 0;
        while ((entry = strsep(&rest, "\n"))) {
            char *value = strchr(entry, '=');
            if (++count > 32 || !value) fail("network sysctl setting", -EINVAL);
            *value++ = 0;
            size_t key_length = strlen(entry), length = strlen(value);
            if (strncmp(entry, "net.", 4) || !strchr(entry + 4, '.') ||
                key_length > 128 || !length || length > 256 || strchr(value, '\r'))
                fail("network sysctl key/value", -EINVAL);
            char path[sizeof("/proc/sys/") + 128];
            memcpy(path, "/proc/sys/", 10);
            for (size_t i = 0; i < key_length; i++) {
                unsigned char ch = (unsigned char)entry[i];
                if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                      (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' ||
                      (ch == '.' && i && entry[i - 1] != '.' && i + 1 < key_length)))
                    fail("network sysctl path", -EINVAL);
                path[10 + i] = ch == '.' ? '/' : (char)ch;
            }
            path[10 + key_length] = 0;
            long sysfd = lkl_sys_open(path, LKL_O_WRONLY, 0);
            if (sysfd < 0) fail(path, (int)sysfd);
            long written = lkl_sys_write(sysfd, value, length);
            long closed = lkl_sys_close(sysfd);
            if (written != (long)length) fail(path, written < 0 ? (int)written : -EIO);
            if (closed) fail(path, (int)closed);
        }
        free(copy);
    }
    const char *ecn_text = getenv("KER_NATIVE_TCP_ECN");
    if (ecn_text) {
        long mode = parse_number(ecn_text, 2);
        long fd = lkl_sys_open("/proc/sys/net/ipv4/tcp_ecn", LKL_O_WRONLY, 0);
        if (fd < 0) fail("native TCP ECN sysctl open", (int)fd);
        char setting[] = {(char)('0' + mode), '\n'};
        long written = lkl_sys_write(fd, setting, sizeof(setting));
        long closed = lkl_sys_close(fd);
        if (written != (long)sizeof(setting)) fail("native TCP ECN sysctl write",
            written < 0 ? (int)written : -EIO);
        if (closed) fail("native TCP ECN sysctl close", (int)closed);
    }
    result = lkl_if_up(1);
    if (result) fail("loopback activation", result);
    int index = lkl_netdev_get_ifindex(device->id);
    if (index <= 0) fail("network interface lookup", index);
    result = lkl_if_set_ipv4(index, address.s_addr, prefix);
    if (result) fail("IPv4 interface configuration", result);
    const char *vip_text = getenv("KER_NATIVE_VIP_ADDRESSES");
    if (vip_text && *vip_text) {
        char *copy = strdup(vip_text);
        if (!copy) fail("VIP address allocation", -ENOMEM);
        char *rest = copy, *entry;
        unsigned int count = 0;
        while ((entry = strsep(&rest, ","))) {
            char *slash = strchr(entry, '/');
            if (++count > 32 || !slash) fail("VIP address/prefix", -EINVAL);
            *slash++ = 0;
            struct in_addr vip;
            if (inet_pton(AF_INET, entry, &vip) != 1) fail("VIP IPv4 address", -EINVAL);
            long vip_prefix = parse_number(slash, 32);
            result = lkl_if_set_ipv4(index, vip.s_addr, (unsigned int)vip_prefix);
            if (result) fail("VIP IPv4 configuration", result);
        }
        free(copy);
    }
    result = lkl_if_set_mtu(index, (int)mtu);
    if (result) fail("interface MTU", result);
    ker_mtu_control_init(mtu_fd, index, (int)maximum);
    result = lkl_if_up(index);
    if (result) fail("interface activation", result);
    result = ker_native_configure_vlans(index, (int)mtu, getenv("KER_NATIVE_VLANS"));
    if (result) fail("VLAN configuration", result);
    result = ker_native_configure_vlan_gateway(getenv("KER_NATIVE_VLAN_GATEWAY"));
    if (result < 0) fail("VLAN IPv4 default route", result);
    result = ker_native_configure_vlan_gateway6(getenv("KER_NATIVE_VLAN_GATEWAY6"));
    if (result < 0) fail("VLAN IPv6 default route", result);
    const char *address6_text = getenv("KER_NATIVE_ADDRESS6");
    struct in6_addr dad_addresses[33];
    unsigned int dad_count = 0;
    if (address6_text) dad_addresses[dad_count++] = add_ipv6_address(index, address6_text);
    const char *vip6_text = getenv("KER_NATIVE_VIP_ADDRESSES6");
    if (vip6_text && *vip6_text) {
        if (!address6_text) fail("IPv6 VIP requires primary IPv6 address", -EINVAL);
        char *copy = strdup(vip6_text);
        if (!copy) fail("IPv6 VIP allocation", -ENOMEM);
        char *save = NULL;
        unsigned int count = 0;
        for (char *entry = strtok_r(copy, ",", &save); entry; entry = strtok_r(NULL, ",", &save)) {
            if (++count > 32) fail("IPv6 VIP address count", -EINVAL);
            dad_addresses[dad_count++] = add_ipv6_address(index, entry);
        }
        free(copy);
    }
    for (unsigned int i = 0; i < dad_count; ++i) {
        result = lkl_if_wait_ipv6_dad(index, &dad_addresses[i]);
        if (result) fail("IPv6 interface configuration/DAD", result);
    }
    const char *gateway6_text = getenv("KER_NATIVE_GATEWAY6");
    if (gateway6_text) {
        struct in6_addr gateway6;
        if (!address6_text || inet_pton(AF_INET6, gateway6_text, &gateway6) != 1 ||
            IN6_IS_ADDR_UNSPECIFIED(&gateway6) || IN6_IS_ADDR_MULTICAST(&gateway6) ||
            IN6_IS_ADDR_LOOPBACK(&gateway6) || IN6_IS_ADDR_V4MAPPED(&gateway6))
            fail("IPv6 gateway address", -EINVAL);
        result = ker_native_set_ipv6_gateway(index, &gateway6);
        if (result) fail("IPv6 default route", result);
    }
    const char *gateway = getenv("LKL_HIJACK_NET_GATEWAY");
    if (gateway) {
        if (inet_pton(AF_INET, gateway, &address) != 1) fail("gateway address", -EINVAL);
        result = lkl_set_ipv4_gateway(address.s_addr);
        if (result) fail("default route", result);
    }
    const char *timeout = getenv("KER_SHUTDOWN_TIMEOUT_MS");
    if (timeout) drain_timeout = (unsigned int)parse_number(timeout, 60000);
    if (pthread_atfork(NULL, NULL, fork_child)) fail("fork boundary", -ENOMEM);
    atomic_store_explicit(&ready, true, memory_order_release);
    startup_fd = (int)parse_number(required("KER_STARTUP_FD"), INT_MAX);
    if (syscall(SYS_fcntl, startup_fd, F_SETFD, FD_CLOEXEC) < 0) fail("startup descriptor flags", -errno);
    static const char started[] = "KER_NATIVE_READY\n";
    if (syscall(SYS_write, startup_fd, started, sizeof(started) - 1) != sizeof(started) - 1)
        fail("startup acknowledgement", -EIO);

}
__attribute__((destructor)) static void finalize(void)
{
    if (!atomic_exchange_explicit(&ready, false, memory_order_acq_rel)) return;
    ker_fd_close_all();
    int drained = ker_native_drain(drain_timeout);
    if (drained) {
        static const char error[] = "ker: native Linux send queues did not drain before shutdown\n";
        (void)syscall(SYS_write, STDERR_FILENO, error, sizeof(error) - 1);
    }
    static const char stopping[] = "KER_NATIVE_STOPPING\n";
    (void)syscall(SYS_write, startup_fd, stopping, sizeof(stopping) - 1);
    struct ker_native_counters counters;
    int diagnosed = ker_native_counters(&counters);
    if (!diagnosed) {
        char json[2048];
        int length = snprintf(json, sizeof(json), "KER_NATIVE_STATS {\"active_opens\":%llu,\"passive_opens\":%llu,"
            "\"retransmitted_segments\":%llu,\"zero_window_probes\":%llu,\"out_of_order_queued\":%llu,"
            "\"udp_in_datagrams\":%llu,\"udp_out_datagrams\":%llu,\"udp_in_errors\":%llu,\"udp_no_ports\":%llu,"
            "\"udp6_in_datagrams\":%llu,\"udp6_out_datagrams\":%llu,\"udp6_in_errors\":%llu,\"udp6_no_ports\":%llu,"
            "\"ip6_frag_ok\":%llu,\"ip6_frag_creates\":%llu,\"ip6_reasm_ok\":%llu,\"ip6_reasm_fails\":%llu,\"ip6_reasm_timeouts\":%llu,"
            "\"ip_frag_ok\":%llu,\"ip_frag_creates\":%llu,\"ip_reasm_ok\":%llu,\"ip_reasm_fails\":%llu,\"tcp_ecn\":%llu}\n",
            (unsigned long long)counters.active_opens, (unsigned long long)counters.passive_opens,
            (unsigned long long)counters.retransmitted_segments, (unsigned long long)counters.zero_window_probes,
            (unsigned long long)counters.out_of_order_queued,
            (unsigned long long)counters.udp_in_datagrams, (unsigned long long)counters.udp_out_datagrams,
            (unsigned long long)counters.udp_in_errors, (unsigned long long)counters.udp_no_ports,
            (unsigned long long)counters.udp6_in_datagrams, (unsigned long long)counters.udp6_out_datagrams,
            (unsigned long long)counters.udp6_in_errors, (unsigned long long)counters.udp6_no_ports,
            (unsigned long long)counters.ip6_frag_ok, (unsigned long long)counters.ip6_frag_creates,
            (unsigned long long)counters.ip6_reasm_ok, (unsigned long long)counters.ip6_reasm_fails,
            (unsigned long long)counters.ip6_reasm_timeouts,
            (unsigned long long)counters.ip_frag_ok, (unsigned long long)counters.ip_frag_creates,
            (unsigned long long)counters.ip_reasm_ok, (unsigned long long)counters.ip_reasm_fails,
            (unsigned long long)counters.tcp_ecn);
        if (length > 0 && (size_t)length < sizeof(json))
            (void)syscall(SYS_write, startup_fd, json, (size_t)length);
    }
    lkl_netdev_remove(device->id);
    lkl_netdev_free(device);
    lkl_sys_halt();
    lkl_cleanup();
    const char *status = drained ? "KER_NATIVE_INCOMPLETE\n" : "KER_NATIVE_DONE\n";
    (void)syscall(SYS_write, startup_fd, status, strlen(status));
    syscall(SYS_close, startup_fd);
}
