# Original Linux TCP queued-payload snapshot

## SDK use

The broker SDK reads a snapshot through an authenticated member-census
capability:

    struct ker_socket_member_payload_snapshot snapshot;
    if (ker_socket_client_member_payload_snapshot(&client, member_census_cap,
            &snapshot) == 0) {
        /* snapshot.payload_bytes and snapshot.sampled_sockets are valid */
    }

The call returns zero only for a completed snapshot. On error it leaves the
caller-provided output structure unchanged. The operation requires the
capability's READ right and does not accept a mark from the SDK caller.

The managed TAP integration currently exercises IPv4 TCP traffic. The collector
also selects AF_INET6 sockets; the runtime test covers that with an idle IPv6
loopback connection pair, not end-to-end managed IPv6 traffic. Host sockets
and LKL sockets with other marks are excluded. Privileged code in the same LKL
instance can set marks and is within the trusted boundary.

## Upstream accounting references

In the pinned Linux revision
[7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/tcp_output.c?id=7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e),
[tcp_event_new_data_sent()](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/tcp_output.c?id=7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e#n67)
unlinks a sent skb from sk_write_queue before inserting it into
tcp_rtx_queue. The original retransmit path trims a retained skb to the
cumulative ACK via
[tcp_trim_head() and tp->snd_una](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/tcp_output.c?id=7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e#n1733).
The receive path can also retain an acknowledged prefix within an skb
([`tcp_clean_rtx_queue()` in `tcp_input.c`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/tcp_input.c?id=7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e#n3385)); therefore the adapter intersects each skb sequence interval with `snd_una` instead of counting its full length.
These queue transitions and sequence rules are why the adapter walks both
queues and accounts the payload suffix at the sampled snd_una.

The overlay changes the native Linux input fingerprint. Build a fresh artifact
with `python3 tools/build-native-linux.py --cache /path/to/cache --build /path/to/native-build`,
then configure Ker with `-DKER_NATIVE_LINUX_BUILD=/path/to/native-build`;
older native Linux artifacts fail the existing fingerprint check. From the
CMake build directory, build the focused targets with
`cmake --build . --target ker-posix ker-tcp-payload-accounting-test ker-member-census-runtime-test ker-socket-broker-inherited-group-client`
and run the focused tests with
`ctest --output-on-failure -R 'tcp-payload-accounting-intervals|native-linux-builder-wiring|native-linux-fingerprint-stale-inputs|native-member-census-runtime|native-socket-broker-member-census'`.
The real packet oracle additionally needs the configured TAP/network test
prerequisites described by `native-socket-broker.py`.
The C9 adapter adds a bounded, read-only snapshot of TCP payload still queued
for transmission by original Linux. It scans at most 4096 marked full TCP
sockets in the current LKL network namespace, with an upper bound of 262144
hash buckets, 65536 visited hash entries, 1024 entries per bucket, and 65536
queue skb nodes across the sample (at most 16384 for any one socket). It
includes full sockets whose
application descriptor has already closed. LISTEN, TIME_WAIT, and request
sockets are excluded. A larger matching set, exhausted hash-work budget,
malformed TCP sequence interval, counter overflow, allocation failure, or
incomplete socket revalidation returns an error (EOVERFLOW for a matching set
over capacity and EAGAIN for an incomplete traversal); the adapter never
converts an incomplete scan into a zero result. `sampled_sockets` reports the
number of unique full-socket references collected and successfully sampled; a
socket that changes to TCP_CLOSE before its queue read may be included with
zero payload.

The broker supplies the mark from its authenticated, immutable member-census
capability. The public SDK operation does not accept a mark. The kernel control
device is mode 0600 and checks CAP_NET_ADMIN in the current network
namespace's owning user namespace for every request. A privileged process
inside the same LKL instance is within this trusted boundary. The device keeps
no socket references or per-socket metadata after a request completes.

For each socket, the adapter takes `lock_sock`, samples `snd_una`, and walks
the disjoint TCP write and retransmit queues while holding that lock. It
counts the skb payload interval at or after the sampled cumulative ACK,
excluding SYN and FIN sequence space. This retains a partially acknowledged
skb's unacknowledged suffix even when Linux represents it as one packet; SACK
alone does not advance the cumulative ACK. GSO and non-linear skb payload use
Linux's logical `skb->len`, not wire-frame length or truesize. Socket samples
are sequential, not an atomic namespace-wide snapshot. A concurrent socket
rehash can make the scan incomplete; duplicate pointers are detected and
cause EAGAIN. Callers need admission quiescence before using the result as a
complete generation-wide drain condition.

This primitive does not implement F-Stack `ff_socket_snd_pending`, a reload
state machine, admission barrier, or final-drain guarantee. A caller must
provide a quiescence/admission protocol before treating a zero sample as a
promotion decision. The test oracle uses real original-Linux TCP traffic and
independent packet/ACK observations.

The implementation is Ker-owned under `src/posix/lkl-overlay`. The pinned LKL
architecture Makefile already exists upstream, so the fingerprinted builder
adds exactly one `obj-y` entry to its generated source tree rather than
replacing the upstream file. No Linux protocol source, `net/`, or
`include/net/` file is changed.
