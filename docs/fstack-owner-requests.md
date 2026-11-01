# Original Linux TCP request-socket census primitive

`ker_ff_owner_requests_begin/step/close` is a private adapter for one bounded
INET_DIAG dump in the original LKL network namespace. The owner mark must come
from an authenticated worker context; the primitive itself does not authorize
or expose arbitrary marks. The C13 wire fixture passes a deterministic mark
only through its noninstalled test runtime.

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

The runtime hook remains private until the process owner supplies the mark
from its authenticated listener/worker context. No packet dispatcher, SYN
admission, generation flow-map, or DPDK drain-ring behavior is implemented by
this primitive.

The standalone test module is `cmake/FStackOwnerRequestsTests.cmake`; the
NativeLinux CMake integration should include it and call
`ker_enable_ff_owner_requests_adapter()` for the private adapter source, then
call `ker_add_ff_owner_requests_tests()` within its test-enabled native-Linux
block. That creates parser/UAPI-layout checks and a noninstalled test-runtime library.
`tests/posix/native-ff-owner-requests.py` exercises a real marked Linux listener
in the isolated LKL/TAP fixture: an ACK-only nft rule holds a normal handshake
in `SYN_RECV`, a raw Ethernet ACK completes it, and forced syncookies are
checked separately. The test requires `unshare`, `ip`, `nft`, the configured
DPDK TAP PMD, and the verified pinned native-Linux build. It does not run as a
host TCP substitute.

`config/native-linux.defconfig` enables `CONFIG_SYN_COOKIES` so the fixture can
exercise the stateless-cookie case. That changes the native build fingerprint;
an older prepared kernel whose `.config` lacks this option is not evidence for
the forced-cookie case and must not silently skip it.
