# Host and native Linux descriptor coexistence

Ker uses descriptor ownership, rather than F-Stack's global
`[stack] kernel_coexist` boolean. Normal `socket(AF_INET/AF_INET6, ...)` calls
under the preload create sockets in original native Linux. Other socket
families and unregistered host descriptors remain host objects. A caller that
explicitly needs a host INET socket can create it with the host `SYS_socket`
syscall; subsequent ordinary POSIX operations dispatch by that descriptor's
actual ownership. This does not select a stack based on a numeric fd offset.

[src/posix/fd-table.c](../src/posix/fd-table.c) reserves real host placeholders
for exported native fds, keeps references through duplication/replacement and
separates native and host object lifetimes.
[src/posix/posix-socket.c](../src/posix/posix-socket.c) sends unregistered host
fd operations to host syscalls and registered operations to original LKL.
Mixed readiness is handled by the existing poll/epoll adaptation. An external
raw syscall must target an actual host fd, not bypass registration for a native
placeholder.

## Executable ownership evidence

`native-fstack-fd-map` creates a real host UDP socket and a native TCP socket
with the same internal numeric fd, exports the native object to a distinct
reserved application fd, verifies host datagrams and both close orders, and
checks independent object identity and cleanup.

`native-fstack-socket-contracts` adds a production-preload scenario:

- A raw host UDP socket binds a real host loopback address and dynamic port.
  A normal native UDP socket then binds the identical address and port without
  reuse flags. Accidental same-kernel fallback would fail this bind.
- Distinct byte strings travel simultaneously through each kernel's own
  loopback path. Ordinary bind, sendto, recvfrom, fcntl and close calls must
  dispatch correctly for both descriptors; each received peer tuple is exact.
- A single exported epoll watches both sockets, preserves distinct full64-bit
  user tags and reports only the appropriate readable descriptor. After drain,
  both descriptors return EAGAIN rather than cross-delivering bytes.
- Repeat with each close order. Closing one side must not prevent the survivor
  from sending, becoming readable and receiving its own bytes. Closing both
  leaves no epoll event.
- The native runner requires the explicit success marker and exactly3 original
  Linux UDP sends/receives. Host loopback datagrams must not increment those
  native counters. Native TCP opens and zero worker-owned mbufs remain required.

The host-reference binary instead requires the second same-kernel UDP bind to
fail EADDRINUSE and verifies the original host socket remains usable. No
successful socket, readiness or kernel operation is mocked. These UDP checks
use the two kernels' loopback devices; separate active/passive original-Linux
TCP interoperability in the same runner exercises the real DPDK wire path.
They do not claim host UDP traverses the DPDK device.

## Exact source configuration differences

The unchanged pinned
[test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c) has
four `FF_KERNEL_COEXIST`-gated tests that inspect
`ff_global_cfg.stack.kernel_coexist`. Their assertions concern that global
configuration field, rather than any simultaneous socket traffic:

| Source case | Pinned assertion | Ker boundary |
| --- | --- | --- |
| `test_ff_load_config_stack_coexist_enabled` | Fixture value1 produces field1. | `[stack]` is unsupported and rejected before startup. Existing descriptor coexistence is not proof that the flag parsed. |
| `test_ff_load_config_stack_absent_defaults_disabled` | Missing section produces field0. | Missing section is accepted, but host/native descriptors still coexist. Ker has no synthetic disabled global field. |
| `test_ff_load_config_stack_garbage_defaults_disabled` | Garbage silently produces field0. | A supplied `[stack]` section, including garbage, fails explicitly; no silent false default is introduced. |
| `test_ff_load_config_stack_coexist_disabled_explicit` | Fixture value0 produces field0. | Explicit0 is rejected along with1; it does not disable host fd handling. |

The launcher configuration regression checks1,0 and garbage all fail with
status2 before library/worker resolution or application entry, without an app
marker/statistics file. The no-section runtime performs the real simultaneous
traffic described above. No successful no-op boolean or unused mode flag is
added. A global switch that reinterprets existing fds would require a separate,
precise lifetime and inherited-descriptor contract.

[Issue #228](https://github.com/rutlang-ai/Ker/issues/228) retains all four
source cases as blocked with these explicit differences. This documents and
qualifies the actual Ker boundary; it does not count the source flags as passed
or waive the remaining migration work. Inventory stays179 scenario-adapted,
19partial,167blocked,13architecture-specific,55harness-only out of433;
186blocked/partial cases remain incomplete.
