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
