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
The C24 overlay was built as artifact fingerprint
`22813a0c8cdd737a714a131d519098a62cb3df90a63d50c3eb4fc7f29b737327`; its
source tree is `c03361ebd67b3f425062b170a2b0945da4f6d935`, and its `liblkl`
hash begins `45118e82`. The original Linux `net/` and `include/net/` source
trees and pinned config are unchanged from the baseline. This fingerprint is
required for the C24 claims below. The code rejects unsupported profiles: SMP, preemptible kernels,
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

The focused `native-c24-ingress-freeze-tap` test passed against that built
artifact. It drives real TCP packets through TAP and original Linux: q88 holds
an exact initial SYN and prevents SYN-ACK; the test changes the original Linux
SO_REUSEPORT cBPF selector from member 0 to member 1 while q88 remains armed;
after the gate releases the unchanged packet, Linux completes the handshake
and the request is accepted and echoed on member 1. An established member-0
stream echoes before and after cutover. In the same LKL instance, the existing
C20 q87 adapter receives the real generated SYN-ACK, validates its queue
notification, accepts that exact q87 packet ID, then disables and retires q87.
This verifies raw q87/q88 queue coexistence without PF-wide bind/unbind. A
separate TAP case exercises lease expiry, terminal quarantine, and drops a
later matching SYN while preserving the established stream; another exercises
an explicit abort after serialized DISARM and drain, before selector change,
then proves the held and future SYNs are dropped. A fourth case sends 65
distinct real host SYNs while q88 is armed: it records at most 64 exact q88
IDs, verifies the kernel attempt count exceeds 64, rejects healthy drain, and
enters terminal quarantine while the old stream remains live. Every case
checks its own ker-run statistics for zero outstanding resources and a
successful worker exit, and saves its packet IDs, verdict/counter evidence,
and statistics under `/dev/shm/ker-c24-case-*-evidence.json`.

State tests cover duplicate IDs, the 64-ID capacity, attempt-count mismatch,
expiry, ACK uncertainty, and quarantine after disarm. The overflow TAP case
forces the real NFQUEUE ID limit with 65 actual SYNs; it does not simulate a
lost q88 verdict ACK. The raw q87 coexistence case does not run the C20
F-Stack flow-map admission worker.
This phase remains a private kernel/UAPI/controller primitive: there is no
typed broker selector, production F-Stack packet callback registration, Nginx
caller, master/worker orchestration, or graceful reload qualification. A
successful build or TAP primitive test must not be presented as graceful
reload support.
