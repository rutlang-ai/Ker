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
