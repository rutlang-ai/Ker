# Native current-time contract

`ker_posix_get_current_time(int64_t *seconds, long *nanoseconds)` reads the active
original-Linux `CLOCK_REALTIME` once. Either output may be NULL; both NULL still
performs a real kernel read. It returns0 or-1/errno, leaving supplied outputs
unchanged on failure. An inactive instance returns ENETDOWN before a syscall.
Callers must quiesce before native shutdown, as for the native socket APIs.

Seconds are Unix epoch seconds and nanoseconds are0..999999999. Native startup
synchronizes the private Linux clock with the host epoch. Reads use that private
clock and do not substitute host time, synchronize it on each call, or create a
second Ker timestamp cache. Realtime can move backwards when its clock is set;
use monotonic time for elapsed-time measurements. Protocol scheduling continues
to use the existing original-Linux monotonic clock and host callback.

`native-fstack-current-time-optional` qualifies the two pinned F-Stack optional
output scenarios with actual Linux. It deliberately sets the private clock to
an old epoch and brackets an adapter sample with direct kernel reads, then
synchronizes the epoch and checks each optional output. The error test injects
one caller-thread syscall failure for each output combination; even a partial
write to the temporary kernel result cannot change caller outputs. The following
real syscall must recover. Startup/shutdown lifetime checks issue no syscall.

This is scenario adaptation, not the F-Stack cached timestamp or fatal-assert
ABI. Successful paths execute the production adapter and original Linux;
standalone bootstrap supplies only the active-instance gate. These tests do not
claim network delivery or wall-clock stability across external time changes.

`native-fstack-current-time-sockets` resolves the actual API from the preloaded
library under ker-run. It checks synchronized samples and independently optional
outputs during real original-Linux IPv4/IPv6 UDP exchanges. The app guard forbids
host INET fallback; strict family/source markers prevent partial coverage. After
explicit runtime teardown, reads fail ENETDOWN with unchanged outputs and the
kernel release query becomes unavailable. Worker acknowledgement and zero live
VMAs/guards/mbufs are required. The null PMD starts the runtime; payloads stay in
native loopback and do not claim external-wire interoperability. This adds no
new source-case completion count.

`native-fstack-current-time-parallel` adds four simultaneous readers over an
intentionally old private Linux epoch. Each reader exercises all four output
combinations for32 rounds; alternating pairs receive caller-thread EIO while
peers perform actual reads. Failed outputs remain unchanged, and every call is
followed by a real full sample bracketed by direct kernel reads. Exact per-thread
call/failure counts,512 recovery samples and256 errors detect shared injection,
output or errno state. All readers join before epoch restoration and shutdown;
concurrent shutdown and external clock adjustment are outside this test. This
is additional adapter evidence, with no new source-case completion.

`native-fstack-current-time-parallel-sockets` repeats the actual preload path
with four simultaneous application readers. Each owns its sockets and exchanges
unique reader/round payloads over both IPv4 and IPv6 for eight rounds. The runner
requires exactly64 family records and four distinct reader completions; each
exchange brackets two full samples and checks all optional-output combinations.
Reader errno values remain isolated, and all readers join before the existing
explicit shutdown/error checks. This extends the same two adapted cases without
claiming concurrent native shutdown, external-wire delivery or additional passes.
