# Launcher failure boundaries

Runtime artifact failures return infrastructure status125 with a diagnostic.
The native library, selected worker and sibling application guard must resolve
to regular files; worker and guard must be executable before IPC channels are
created. A failed check starts no EAL worker or application. Configuration
validation retains its separate status2 convention.

`native-ker-run-boundaries` uses actual local pipes and executable coordinator
fixtures to verify failures and recovery. These fixtures exercise launcher
ownership and control records, not Linux/DPDK packet behavior or additional
F-Stack scenario completion. Imported upstream sources are unchanged.

Primary IPC allocation transfers ownership as one bundle. Descriptor exhaustion
at any socketpair or pipe allocation closes every earlier channel before
returning125; no worker or application starts. Fault tests enumerate all five
allocation positions, compare actual open descriptors, then launch successfully.

Primary and additional worker startup use a deadline for the complete newline
record, with a64KiB bound. A writer that emits a prefix then stalls cannot bypass
the startup timeout. EOF with a partial record is an error. The reader consumes
only that record, preserving later completion bytes for shutdown collection.

READY records must be objects with a MAC string and integer TX features accepted
by the native virtio consumer. Invalid records stop startup before application
execution; unrelated telemetry fields remain available. The same validation is
used for primary and additional workers.

A primary DONE payload must be a JSON object with a nonnegative integer
outstanding count. Malformed records, including boolean/string/floating counts,
are infrastructure failures after the worker is reaped; they cannot escape as
tracebacks or turn failed ownership evidence into successful shutdown.

Each worker emits one completion snapshot. Duplicate DONE records are failures,
including two zero-count snapshots; a later zero must not hide an earlier
outstanding-object count. A startup-consumed DONE snapshot counts toward the
same per-worker limit.

Primary worker collection errors return status 125, reap the primary child and continue auxiliary teardown. A failed collection cannot abandon the remaining workers.

Auxiliary completion records use the same object and outstanding-count validation as the primary worker. Malformed records fail teardown after reaping and do not escape as tracebacks.

Auxiliary workers finish concurrently during final cleanup. One cleanup exception is reported as infrastructure failure while every peer still receives its bounded reap.

Optional native statistics must be a single JSON object of nonnegative integer counters. Invalid or duplicate records fail the launch without bypassing auxiliary cleanup.

Explicit run-stop requests receive OK only after exactly one READY, STOPPING and DONE in that order, with no INCOMPLETE or unknown markers. Invalid sequences still stop and reap workers but receive FAIL.

An I/O error while draining final native status is reported as status 125; the status descriptor closes and application, primary and auxiliary children still finish cleanup.

Statistics reports are serialized before writing and atomically replaced from a temporary file in the same directory. Output failures return status 125 after child cleanup, preserve the previous report and remove temporary files.
