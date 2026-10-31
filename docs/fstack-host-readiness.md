# Original host readiness duplicate registration

This batch qualifies exactly
`tests/unit/test_ff_host_interface.c::test_ff_host_kqueue_ctl_add_idempotent`
at F-Stack revision `646a641cfff77f4815e1e29829a09e1ed15a2999`.

The original complete test function is retained byte for byte. The four host
helper bodies are unchanged excerpts of `lib/ff_host_interface.c`, with private
caller-side names. The complete source, pin, hash and license remain in
`third_party/fstack-host-readiness`; `fstack-host-readiness-original-import`
verifies the excerpts and the assertion function against the retained sources.

The repeated ADD reaches original Linux `epoll_ctl`: EEXIST triggers the original
helper's MOD fallback, replacing the application tag. The source assertion
requires exactly one event carrying the second tag. Native-runtime capability,
symbol ownership and the host-network syscall restriction prevent a libc-only
process from satisfying this qualification. The loopback sockets, registration
and readiness all belong to the original Linux kernel.

`ker-host-readiness-echo` is an actual caller of the same helper. It re-registers
the listener, UDP socket and accepted TCP socket, dispatches their replacement
tags, and echoes independently sent host TCP/UDP payloads over the original TAP
PMD and Linux stack. A separate test installs the caller and its upstream license
into an independent prefix before exercising it. Both positive profiles require
native shutdown acknowledgements and zero outstanding PMD mbufs. Injecting an
EPOLL_CTL_MOD failure forwards the real ADD and wait operations but makes the
original updated-tag assertion fail, demonstrating that a missing fallback
cannot pass through stale readiness.

The adapter belongs to the caller example, not Ker's exported API. It does not
add a FreeBSD `ff_kevent` ABI, EVFILT flags, a mixed host/native descriptor
namespace or a protocol implementation. Its inherited void/error behavior is
preserved; callers needing an error-reporting registration API should use native
epoll directly. Fatal mmap, hardclock and all other unfinished source contracts
remain unqualified.

With the pinned native Linux build and DPDK configured, build
`ker-host-readiness-source-test`, `ker-host-readiness-mod-failure-test`,
`ker-host-readiness-echo`, `ker-posix`, `ker-app` and `ker-io-worker`, then run:

```sh
ctest --test-dir build --output-on-failure -R '^(native-fstack-host-readiness-|fstack-host-readiness-original-import)'
python3 tests/fstack_migration.py
```

The installed executable runs through `ker-run`, like the other native examples.
No original upstream test harness or FreeBSD network implementation is compiled.
