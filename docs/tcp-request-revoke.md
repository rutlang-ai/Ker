# Original Linux TCP request revocation adapter

The C14 adapter provides a private, privileged operation that asks the pinned
original Linux TCP stack to remove one stateful `TCP_NEW_SYN_RECV` request.
It is not a public SDK operation and is not wired to an F-Stack reload hook.
It does not revoke established children, valid-cookie TCP Fast Open full
sockets, or stateless SYN-cookie handshakes.

## Identity and authority

The fixed 72-byte private ioctl identifies one request by address family,
network-order local and remote ports, local and remote addresses, interface
index, request cookie, owner mark, and the exact listener cookie. IPv4 address
padding and reserved fields must be zero. The all-ones wildcard cookie is
rejected. The mark is supplied only by a trusted privileged caller of the
private device; this C14 adapter does not bind a broker metadata capability or
accept an untrusted SDK mark. The device is mode `0600` and checks
`CAP_NET_ADMIN` in the current network namespace's owning user namespace for
every ioctl. A privileged process in the same LKL instance remains inside the
trusted boundary.

The userspace adapter discovers the private misc device through `/proc/misc`,
creates a temporary mode-0600 node, opens it, performs the ioctl, then closes
and unlinks the node. It does not install a persistent device node.

A zero return means original Linux's canonical
`inet_csk_reqsk_queue_drop()` returned true for the matched request. A missing
request returns `ENOENT`; an identity, owner, listener, or state mismatch
returns `ESTALE`; a request that loses the race to promotion or timer cleanup
returns `EAGAIN`. Invalid input and insufficient capability fail with
`EINVAL` and `EPERM`. Callers must handle failures as failures; no result means
that a request was successfully revoked unless the return is zero.

## Original Linux behavior and races

The adapter uses the pinned Linux 6.12.113
[`inet_diag_find_one_icsk()` lookup](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/inet_diag.c?id=7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e#n519)
with the exact tuple and request cookie, then checks the request state and
TCP request operations before accessing request-specific fields. It validates
the request mark and tuple against the ioctl and takes the request's listener
reference. Under the listener socket lock it rechecks the live TCP listener,
network namespace, family, mark, listener cookie, and request identity before
calling the original drop helper.

The adapter never holds an ehash lock while calling the original helper. The
helper owns the hash, timer, and queue reference changes; its boolean result is
the only success evidence. ACK promotion can win first and produce a full child,
which is rejected by the request-state check. Listener close or replacement
fails exact listener-cookie validation. Races are reported as errors rather
than successful revocations. See the pinned
[`inet_csk_reqsk_queue_drop()` implementation](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/inet_connection_sock.c?id=7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e#n1032)
and the TCP ACK hashdance in
[`inet_hashtables.c`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/inet_hashtables.c?id=7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e#n656).

## Build and tests

The Ker-owned driver and UAPI live under `src/posix/lkl-overlay`; the pinned
Linux protocol sources remain unchanged. The fingerprinted native-Linux
builder appends the request-revocation object to the generated LKL Kbuild
input. Rebuild the native artifact after changing this overlay:

```sh
python3 tools/build-native-linux.py --cache <cache> --build <native-build>
cmake -S . -B <build> -DKER_WITH_NATIVE_TCP=ON -DKER_WITH_DPDK=ON \
  -DKER_NATIVE_LINUX_BUILD=<native-build> -DBUILD_TESTING=ON
cmake --build <build> --target ker-tcp-request-revoke-abi-test \
  ker-tcp-request-revoke-runtime-test ker-posix-member-census-test-runtime \
  ker-io-worker ker-app ker-ini ker-posix
ctest --test-dir <build> --output-on-failure \
  -R 'tcp-request-revoke-private-abi|native-tcp-request-revoke-wire'
```

The wire fixture checks real IPv4 and IPv6 half-open requests over TAP,
wrong mark/request/listener identity, `CAP_NET_ADMIN` denial without removing
the request, and successful revocation followed by a late-ACK reset. For the
ACK-win case it captures the request cookie while the host's third ACK is
blocked, then flushes the rule and sends data through the same real host TCP
socket; original Linux promotes the request, and revoking with the saved
request identity fails while the full child completes bidirectional data.
It also tests listener close/rebind with a fresh request. It requires
the verified pinned native-Linux build, DPDK TAP PMD, `unshare`, `ip`, `nft`,
AF_PACKET access, and the corresponding namespace capabilities. The builder
wiring and UAPI layout checks are separate compile-time/unit checks.

This private primitive is not yet an admission barrier, generation migration,
or graceful-reload state machine. No caller should use it as a complete drain
or promotion decision.
