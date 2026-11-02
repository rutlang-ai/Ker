# Original Linux TCP request-socket census primitive

`ker_ff_owner_requests_begin/step/close` is a private adapter for one bounded
query over sequential IPv4 and IPv6 INET_DIAG dumps in the original LKL network
namespace. Each family is sampled at a different time, so the result is
non-atomic. Keep the marked listener live through the zero observation: closing
it may remove or change request-socket state. The owner mark must come from an
authenticated worker context; the primitive itself does not authorize or
expose arbitrary marks. The C13 wire fixture passes a deterministic mark only
through its noninstalled test runtime.

The request asks Linux for `TCP_SYN_RECV` over IPv4 and IPv6 and requests
`INET_DIAG_INFO`. It applies a full-mask `INET_DIAG_MARK` filter and requires
the returned mark on every row. A row without `INET_DIAG_INFO` is a request
socket; a row with the complete pinned Linux 6.12 `tcp_info` payload represents
a full TCP socket in `SYN_RECV` and is excluded. The count is not filtered by
port: it covers all request sockets carrying that owner mark.

The query is fail closed. It needs current LKL `CAP_NET_ADMIN`, rejects wrong
sender/sequence/port, missing mark, malformed or duplicate rows, short info,
interrupted or partial dumps, and publishes only after a successful
`NLMSG_DONE`. It bounds work to 4,096 rows, 1 MiB, 256 datagrams, and five
seconds. Linux INET_DIAG still scans the namespace's request tables, so these
bounds limit the returned work and time but do not make the kernel-side scan
constant-time.

This is a count of Linux `request_sock` instances, not every TCP socket in
`SYN_RECV`. It excludes full sockets (including valid-cookie TCP Fast Open)
and stateless SYN-cookie handshakes, which have no persistent request entry.
The pinned F-Stack `ff_syncache_count()` counts its persistent syncache entries;
F-Stack's TFO/cookie fast paths can bypass that cache too. The sources therefore
do not support claiming this Linux count is a universal one-for-one
replacement for F-Stack's counter. It is suitable only for the explicitly
bounded normal request-socket drain profile, with TFO and forced-cookie cases
tested and reported separately.

The F-Stack `ff_syncache_count()` bridge sends op 47 through the existing
owner capability. The broker resolves the actor's process-bound owner record,
checks its read right and network-history restrictions, then submits this
mark-only query on the asynchronous bounded worker. Callers cannot supply a
mark, port, or filter. A lost/forked owner context and any query failure abort
the hook rather than returning a fabricated count. This provides a
process-authenticated snapshot; it does not implement packet dispatch, SYN
admission, generation flow-map, or DPDK drain-ring behavior.

`cmake/FStackOwnerRequestsTests.cmake` registers parser/UAPI-layout checks and
a noninstalled test-runtime library. The production NativeLinux target links
the adapter and the existing process-owned diagnostic worker. The
`native-fstack-process-payload-owner` test exercises the built-runtime
`ff_syncache_count()` path: a marked F-Stack listener reports 0, then 1 while a
host ACK is held, and 0 after an injected wire ACK. Existing C12 owner-history,
fork, payload, and process-isolation checks run in the same harness. The same
test script can be run with installed `libfstack`, `libker-socket-preload`,
`libker-posix`, and `ker-run` paths to repeat the installed-consumer proof.
`tests/posix/native-ff-owner-requests.py` exercises a real marked Linux listener
in the isolated LKL/TAP fixture: an ACK-only nft rule holds a normal handshake
in `SYN_RECV` over IPv4 and IPv6, a raw Ethernet ACK completes it, a valid-cookie
TFO full socket is excluded, and forced syncookies are checked separately.
The test requires `unshare`, `ip`, `nft`, the configured
DPDK TAP PMD, and the verified pinned native-Linux build. It does not run as a
host TCP substitute.

`config/native-linux.defconfig` enables `CONFIG_SYN_COOKIES` so the fixture can
exercise the stateless-cookie case. That changes the native build fingerprint;
an older prepared kernel whose `.config` lacks this option is not evidence for
the forced-cookie case and must not silently skip it.

This hook only supplies a request-socket count for the bounded caller profile.
It does not enable graceful reload, generation drain, or any lifecycle behavior.
For a full SDK install and strict imported consumer, configure with
`-DKER_WITH_NATIVE_TCP=ON -DBUILD_TESTING=OFF -DKER_BUILD_EXAMPLES=OFF
-DKER_NATIVE_LINUX_BUILD=<verified-build> -DKER_BUILD_FSTACK_NGINX_RUNTIME=ON`,
build and install, then configure a C17 consumer with
`-DCMAKE_PREFIX_PATH=<install-prefix>` and `find_package(ker CONFIG REQUIRED)`.
Link it to `ker::socket-client` and call
`ker_socket_client_ff_owner_requests()`; the installed `share/ker/native-linux/build.json`
records the fingerprint checked by the product build.
