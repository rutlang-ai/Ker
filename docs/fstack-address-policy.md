# Explicit caller source-address policy

`ker::address_policy` exports two C APIs in `<ker/address-policy.h>`:
registration and source-address dispatch. The caller owns its policy, address
storage and sockets. This component does not install a hidden POSIX connect
hook or modify Linux's source-address selection implementation. A caller
explicitly requests a policy address, binds that address through the original
Linux socket API, then connects; an all-zero address leaves selection to Linux.
Linux allocates the port and owns TCP/UDP processing throughout.

The original F-Stack callback dispatch is compiled unchanged from literal
excerpts of pinned `lib/ff_dpdk_if.c` and `lib/ff_api.h`. The complete C source
is shared with `third_party/fstack-pools`; the complete header is retained in
`third_party/fstack-address-policy`. Manifest Git blob/SHA256 checks and
`address-policy-import.py` verify both files and reconstruct every compiled
excerpt. No FreeBSD protocol code is compiled. Upstream helper names are
private; only the two documented Ker APIs are exported.

Input family values preserve F-Stack's2/28 convention. The callback sees2/10,
respectively. Both address pointers, the uint16 port and callback return value
are forwarded unchanged. With no callback, dispatch returns0 without touching
the pointers, even for an unknown family. With a callback, an unknown family
returns host `EADDRNOTAVAIL` without calling it. Callers supply address storage
of the appropriate size and decide the port representation; the adapter does
not convert it.

Replacement and NULL registration wait for all active calls to finish before
changing the original pointer. A writer prevents new outer calls from entering
until replacement completes; nested calls may finish using the same pointer.
Registering from a callback returns `EDEADLK` and changes nothing. Deferred
cancellation releases an active dispatch lease, including when cancellation
occurs inside caller code; registration defers cancellation until its update
finishes. Callbacks must not longjmp out. Fork requires quiescent callers.

Four complete unchanged source functions in `tests/fstack-address-source.inc`
run against the public API, with only the cmocka assertions mapped to CHECK:

| Source case | CTest selector |
|---|---|
| `test_ff_regist_pcblddr_fun_smoke` | `fstack-address-policy-register` |
| `test_ff_in_pcbladdr_no_callback` | `fstack-address-policy-default` |
| `test_ff_in_pcbladdr_af_inet_dispatches` | `fstack-address-policy-ipv4` |
| `test_ff_in_pcbladdr_af_inet6_freebsd_to_linux_remap` | `fstack-address-policy-ipv6` |

The lifetime regression checks held-callback replacement and unregister barriers,
nested calls while a writer waits, reentrant registration refusal, and cleanup
after deferred cancellation. It adds no extra upstream completion count.

`native-fstack-address-policy-sockets` is an actual public-API caller under
`ker-run`: it exchanges exact TCP payloads in both directions through original
Linux IPv4/IPv6 loopback. It verifies source127.0.0.2 on both client and accepted
peer, callback destination/port identity, IPv6 remapping, kernel-assigned ports,
policy denial before connection, and FIN/EOF. It performs six exchanges:
default4/6, callback4/6, then default4/6 after unregister. The real original null
PMD starts the native runtime; these loopback exchanges provide no external-wire
evidence. Runtime shutdown must acknowledge completion with no outstanding
mbufs, native buffer mappings or option guards. Optional `--evidence` records
the full application stdout/stderr, native statistics, kernel release,
configuration and executable/library/launcher/PMD SHA256 inputs without
overwriting an existing record. Missing-PMD skip77 never qualifies completion.

Qualification includes Debug/static and Release/shared source/lifetime tests,
the native caller and a separately configured installed consumer using only
`find_package(ker)` and `ker::address_policy`. The installed application and
assertion fixtures are exact source copies. This component needs no EAL and
does not depend on DPDK; the native socket qualification uses the actual native
kernel/EAL runtime separately.
