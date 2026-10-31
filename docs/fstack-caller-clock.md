# Caller polling interval formula

This qualifies exactly
`tests/unit/test_ff_dpdk_if.c::test_ut_nr_17_hardclock_interval` at pinned F-Stack
revision `646a641cfff77f4815e1e29829a09e1ed15a2999`. The complete original source
function and all assertions are retained unchanged. The implementation of
`ff_hardclock_interval_tsc` is an unchanged excerpt of the retained full
`third_party/fstack-pools/ff_dpdk_if.c`, namespaced in a caller library.
`fstack-caller-clock-original-import` verifies its bytes, source hash, license
and complete assertion function.

The source contract is a pure formula:
`ceil(clock_hz / 1000000) * floor(1000000 / requested_hz)`. It checks fixed
1 GHz/100 Hz and 2.5 GHz/1000 Hz examples, the 2.999999 GHz ceiling case, legacy
equivalence at decade rates and zero return for requested rates 0 and >1000000.
Five complete runs execute in a native application. A test-only round-down
mutation must fail the original 30000000-tick assertion; the harness requires
that actual assertion failure, not just any nonzero status. Native capability
and symbol-owner checks run first. The ordinary source profile shuts down
cleanly; both source profiles require successful original net_null PMD startup
and zero outstanding mbufs.

The function has a real caller. `ker-host-readiness-echo <port> [poll_hz]` now uses
it to derive the delay before polling original Linux readiness. Its supported
clock is CLOCK_MONOTONIC nanoseconds (1000000000 ticks per second), so no EAL/TSC
calibration is needed in the application process. The default 1000 Hz produces
a 1000000 ns delay; 100 Hz produces 10000000 ns. Other supported rates retain
the original microsecond quantization and integer truncation. `nanosleep`
retries interruptions, and the caller has a ten-second progress budget. The
formula controls caller polling only; Linux owns all protocol behavior.

Independent host TCP/UDP payloads traverse the original TAP PMD and imported
Linux stack. The 100 Hz and 1000 Hz caller profiles require exact payloads and
native TCP/UDP counters, real completed waits whose total monotonic duration
is at least `waits * interval_ns`, mapped payload reclamation, orderly native
shutdown and zero outstanding mbufs. The outer host also bounds the reported
duration by its own elapsed time. The installed executable repeats the default-rate
exchange from an independent installation prefix, including both upstream
licenses. Scheduler overhead may lengthen waits; no upper latency or real-time
guarantee is claimed. Rates 0 and 1000001 return status 2 before opening sockets
or announcing readiness and still perform clean native shutdown.

The 1000000 Hz delayed-peer profile waits for a test-only marker after the
10001st successful readiness poll before sending either peer payload. It
requires both exchanges to complete after more than 10000 caller waits, while
the same profile fails with the former fixed iteration ceiling.

This adapts the complete pure source interval contract through a caller that
uses it. It adds no FreeBSD hardclock implementation or Ker exported clock API,
and does not qualify hardclock callbacks, rte_timer dispatch, physical TSC
calibration, Linux tick cadence or TCP retransmission timing. The original
Linux/F-Stack/DPDK bodies remain unchanged. Wider uint64 frequency overflow
behavior is not newly qualified; the caller passes the fixed nanosecond rate.

With the native Linux and DPDK prerequisites configured:

```sh
cmake --build build --target ker-caller-clock-source-test \
  ker-caller-clock-round-down-test ker-host-readiness-echo \
  ker-host-readiness-high-rate-test \
  ker-host-readiness-source-test ker-host-readiness-mod-failure-test \
  ker-host-mmap-fatal-debug-test ker-host-mmap-fatal-release-test \
  ker-host-mmap-return-control-test ker-posix ker-io-worker ker-app
ctest --test-dir build --output-on-failure \
  -R '^(native-fstack-(caller-clock-|host-(readiness-|mmap-fatal-))|fstack-(caller-clock|host-readiness|host-mmap)-original-import)'
```

All 16 checks must pass. Missing namespace/runtime/PMD support fails rather than
skipping qualification.
