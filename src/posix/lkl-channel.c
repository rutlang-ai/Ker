#define _GNU_SOURCE
#include "fd-table.h"
#include "diagnostics.h"
#include "lifecycle.h"
#include "host-memory.h"
#include "host-thread.h"
#include "host-clock.h"
#include "host-entropy.h"
#include "packet-channel.h"
#include "packet-device.h"
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
    ker_native_host_memory_init(&lkl_host_ops);
    ker_native_host_thread_init(&lkl_host_ops);
    ker_native_host_clock_init(&lkl_host_ops);
    lkl_host_ops.print = NULL;
    int result = lkl_init(&lkl_host_ops);
    if (result) fail("kernel initialization", result);
    device = ker_packet_device_create(fd);
    if (!device) fail("packet device allocation", -ENOMEM);
    /* Jumbo RX needs multiple virtio buffers. The original LKL transport
     * implements mergeable buffers, including num_buffers accounting; this
     * does not enable checksum or segmentation offloads. */
    struct lkl_netdev_args args = {.mac = mac, .offload = mtu > 1500 ?
        (1U << LKL_VIRTIO_NET_F_MRG_RXBUF) : 0};
    result = lkl_netdev_add(device, &args);
    if (result < 0) fail("packet device registration", result);
    device->id = result;
    result = lkl_start_kernel("%s", "mem=64M");
    if (result) fail("kernel boot", result);
    result = ker_native_seed_entropy();
    if (result) fail("native entropy initialization", result);
    /* LKL's POSIX host clock is monotonic, including its persistent-clock
     * seed. Give Linux realtime its wall-clock epoch without changing the
     * monotonic clocksource used by protocol timers. Only this private kernel
     * is changed; the host clock is never set. */
    struct timespec host_time;
    if (clock_gettime(CLOCK_REALTIME, &host_time)) fail("host realtime clock", -errno);
    struct __lkl__kernel_timespec native_time = {
        .tv_sec = host_time.tv_sec, .tv_nsec = host_time.tv_nsec};
    result = (int)lkl_sys_clock_settime(LKL_CLOCK_REALTIME, &native_time);
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
    result = lkl_if_set_mtu(index, (int)mtu);
    if (result) fail("interface MTU", result);
    result = lkl_if_up(index);
    if (result) fail("interface activation", result);
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
        char json[1024];
        int length = snprintf(json, sizeof(json), "KER_NATIVE_STATS {\"active_opens\":%llu,\"passive_opens\":%llu,"
            "\"retransmitted_segments\":%llu,\"zero_window_probes\":%llu,\"out_of_order_queued\":%llu,"
            "\"udp_in_datagrams\":%llu,\"udp_out_datagrams\":%llu,\"udp_in_errors\":%llu,\"udp_no_ports\":%llu,"
            "\"ip_frag_ok\":%llu,\"ip_frag_creates\":%llu,\"ip_reasm_ok\":%llu,\"ip_reasm_fails\":%llu,\"tcp_ecn\":%llu}\n",
            (unsigned long long)counters.active_opens, (unsigned long long)counters.passive_opens,
            (unsigned long long)counters.retransmitted_segments, (unsigned long long)counters.zero_window_probes,
            (unsigned long long)counters.out_of_order_queued,
            (unsigned long long)counters.udp_in_datagrams, (unsigned long long)counters.udp_out_datagrams,
            (unsigned long long)counters.udp_in_errors, (unsigned long long)counters.udp_no_ports,
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
