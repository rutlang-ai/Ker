# Native TCP ingress freeze primitive

The C24 phase adds a private LKL adapter for one narrowly scoped barrier: hold
new IPv4 TCP initial SYNs before Linux listener lookup while a coordinator
chooses a reuseport member. It does not move, drain, or reimplement existing TCP
flows, and it does not qualify Nginx graceful reload or F-Stack packet dispatch.

The trusted controller supplies a raw **LKL** listener descriptor together
with its observed `SO_COOKIE` and `SO_MARK`; a host/application fd must first be
resolved by its owner into that LKL descriptor. The kernel validates and retains
the exact listener incarnation, then derives its bound IPv4 address and TCP
port. The controller cannot choose an arbitrary tuple. Matching initial SYNs
enter NFQUEUE 88 and remain the original skb. The adapter accepts them only by
the exact recorded packet ID, so Linux continues its ordinary lookup with the
unchanged packet. Queue 87 remains the independent C20 LOCAL_OUT SYN-ACK queue.
Configuration is per queue number and socket port ID. The adapter never sends
obsolete PF-wide bind/unbind commands; closing its netlink socket releases only
queue 88 owned by that socket.

The successful order is: keep the selector on member 0 while the gate is armed;
complete the coordinator's successful selector-1 operation while the gate is
still armed; then DISARM, drain every already-enqueued q88 notification to an
empty socket, reconcile the exact kernel attempt count against delivered packet
IDs, and accept each ID once. DISARM is a serialized ingress cutoff, not a
request-queue drain: pre-freeze SYNs may already have created Linux request
sockets. No ACCEPT is allowed before DISARM and drain completion. A q88 queue
holds at most 64 original skbs, copies up to 256 bytes for header validation,
and never enables fail-open. A full queue drops further matching SYNs; the
kernel attempt counter makes that mismatch fail closed instead of reporting a
healthy cutover. TCP Fast Open payload is never reconstructed; validation uses
the copied IPv4/TCP headers and verdict reinjects the original skb.

ARM creates one 30-second absolute kernel lease. Receive calls do not extend it.
After expiry, matching initial SYNs are dropped; CHECK and healthy DISARM refuse
success. A successful DISARM returns total matching attempts plus expired and
hook-inventory fault counts. Healthy drain requires those fault counts to be
zero and the delivered ID count to equal the kernel attempt count. An uncertain
verdict or mismatch can explicitly quarantine: the kernel retains the exact tuple
and lease in a terminal drop state, then closing the NFQUEUE socket drops its
queued skbs. Matching future SYNs are dropped directly. This is terminal
fail-closed cleanup, not rollback or a healthy retry. The coordinator must keep the old
listener alive until the lease is released.

The source audit used the existing baseline artifact at
`/dev/shm/ker-c15-native-full/source-399c02b3aa05a7ee`: Linux revision
`7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`, manifest fingerprint
`399c02b3aa05a7ee2a35c13fca64a279198c0d0675a8dc218eddc07399525b8d`, and
config SHA-256 `c9589a31cd1cf9a46a43465a39742aeb9150fd801242a8ae04b28fcec8f86e6d`.
This is source/config evidence only; the C24 overlay has not yet been built or
qualified. The code rejects unsupported profiles: SMP, preemptible kernels,
modules, nftables, iptables, conntrack, IPVS, and BPF syscall hooks. In the
pinned profile the runtime LOCAL_IN inventory must contain exactly the Ker q88
hook; ARM, CHECK, DISARM, RELEASE, and every matching SYN revalidate that list.
This is not a general guarantee for other kernel profiles or privileged hook
registrants.

The pinned Linux path is `ip_local_deliver()` through `NF_INET_LOCAL_IN` in
`net/ipv4/ip_input.c`, then `ip_local_deliver_finish()` and
`ip_protocol_deliver_rcu()`, followed by `tcp_v4_rcv()` and the direct LISTEN
branch in `tcp_v4_do_rcv()`. In this artifact these anchors are
`ip_local_deliver()` lines 242-257, `ip_local_deliver_finish()` lines 227-237,
`ip_protocol_deliver_rcu()` lines 187-225, `tcp_v4_rcv()` line 2183, and the
LISTEN branch lines 2346-2348. The normal request path remains
`tcp_v4_conn_request()` from line 1720 and `tcp_conn_request()` / SYN-ACK
handling in `net/ipv4/tcp_input.c`. Ker only holds and later reinjects the
original skb.

This phase is a kernel/UAPI/controller primitive. It has no Nginx caller,
master/worker orchestration, held-stream continuity claim, or actual F-Stack
callback registration proof. A successful build or q88 unit check must not be
presented as graceful reload support.
