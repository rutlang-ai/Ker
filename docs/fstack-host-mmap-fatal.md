# Caller fatal mmap policy

`test_ff_mmap_failure_exits` is scenario-adapted through the complete unchanged
source function from pinned F-Stack revision
`646a641cfff77f4815e1e29829a09e1ed15a2999`. The namespaced caller library retains
`ff_mmap` and `ff_munmap` bodies and flag definitions byte-for-byte; source/header
hashes, excerpts and the original assertion are checked by
`fstack-host-mmap-original-import`.

The application chooses F-Stack's fail-stop allocation policy. Its real invalid
mapping reaches Ker's active POSIX mmap adapter, emits the original diagnostic
and terminates with exit status 1. The original assertion's
`expect_assert_failure` host macro delegates observation to the outer process:
it arms a marker before the original expression and exits 3 if that expression
returns. It does not intercept `exit`, manufacture MAP_FAILED or replace mmap.
The native launcher must return exactly 1, with the diagnostic and armed marker,
and without the returned marker. Startup/infrastructure failure status 125
cannot satisfy this test. Both ordinary and NDEBUG helper builds are exercised.

Before the source assertion, the same application proves that ordinary Ker mmap
returns MAP_FAILED/EINVAL for the invalid flags. Symbol ownership and active
native capabilities are checked. A test-only linker control replaces only the
caller fail-stop wrapper with a real mmap error return. The outer harness must
observe exit 3 and the returned marker, distinguishing an error return from
termination. Original DPDK net_null starts successfully and has zero outstanding
mbufs after each process exits.

The helper also has a real consumer: `ker-host-readiness-echo` allocates its
TCP/UDP payload buffer with the retained mapping body, checks zero initialization,
uses it for exact external TCP/UDP exchanges through original Linux and DPDK TAP,
and releases it with the retained unmap body. `mincore` must then report ENOMEM.
The independently installed example repeats this exchange and reclamation;
native counters, orderly shutdown and zero outstanding mbufs are required.
The caller library is linked into the installed executable and the upstream
license accompanies that example.

This qualifies only the caller's non-page-array mapping policy. Page-array mode
is rejected at build time. It adds no exported Ker mapping API, changes no
original Linux/F-Stack/DPDK function body, and does not qualify LKL's fixed-address
mmap callback failure, FreeBSD ABI, RSS allocation or hardclock behavior.

With native Linux/DPDK prerequisites configured and matching PMDs available:

```sh
cmake --build build --target ker-host-mmap-fatal-debug-test \
  ker-host-mmap-fatal-release-test ker-host-mmap-return-control-test \
  ker-host-readiness-source-test ker-host-readiness-mod-failure-test \
  ker-host-readiness-echo ker-posix ker-io-worker ker-app
ctest --test-dir build --output-on-failure \
  -R '^(native-fstack-host-(readiness-|mmap-fatal-)|fstack-host-(readiness|mmap)-original-import)'
```

All nine checks must pass; missing namespace, native runtime or PMD support is a
failure, not a successful skip.
