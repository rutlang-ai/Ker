# Original reload message boundary

The optional installed `ker::reload` component wraps unchanged pinned F-Stack
`lib/ff_reload.c`, using its original configuration and message layouts. It
initially exported six Ker entrypoints for caller storage, borrowed-state
lifetime and message fill/parse. The later [polling adapter](fstack-reload-polling.md)
adds twelve public poll/control APIs; other compiled runtime helpers remain private;
their presence is not qualification of their behavior. No original Linux or
DPDK source is patched, and no protocol state machine is implemented here.

This component is separate from Ker's authenticated resident control protocol.
Its callers cooperate in a trusted EAL namespace and retain ownership of their
state, queues, pools and EAL. `ker_reload_state_size` gives the original block
size; initialize suitably aligned caller storage with `ker_reload_state_init`,
then borrow it with `ker_reload_bind_state`. Quiesce all users before unbinding
and releasing storage. Calls are process-global and must be serialized. Binding
another state or reinitializing the borrowed state fails `-EBUSY`. Invalid size,
alignment, header or coordinate fails `-EINVAL`. The current entrypoint installs
no generation directory and does not authorize hardware ownership.

`ker_reload_message_fill` invokes the original helper: it sets type/result and
reload fields, samples the active coordinate and preserves transport PID/cookie
and payload ownership. NULL fill is the original no-op. Parse rejects NULL,
wrong type and unknown subcommands with original `-1`; each output is optional.
Successful parse establishes a recognized encoding, not an implemented command.

[`reload-query.c`](../examples/reload-query.c) is a real caller-owned EAL/pool/ring
consumer. Its provider uses the borrowed original runtime state to answer
read-only QUERY; other commands return `-EOPNOTSUPP`. An installed consumer uses
`find_package(ker CONFIG REQUIRED)` and links only `ker::reload`.

## Source acceptance

`tests/unit/test_ff_config.c::test_ut_nr_14_reload_msg_serdes` previously had only
partial authenticated-envelope evidence. `fstack-reload-message-serdes` now
checks every original assertion: DRAIN_DONE fields and roundtrip, all seven
known commands including QUERY, wrong message type, zero/out-of-range commands,
NULL input rejection and independently optional outputs. Additional assertions
check failed-parse output preservation, state borrowing and PID/cookie/payload
ownership across fill and unbind. `fstack-reload-import` verifies source Git
blobs and SHA256 values at the fixed revision.

The real multiprocess fixture transports all seven encodings through original
EAL primary/secondary shared rings. The same provider parses QUERY and fills its
reply from a bound original block with active generation 1 and epoch 2. Other
commands retain their fields and explicitly return unsupported. The rightful
caller parses the actual returned object, checks its fields and payload, frees
it, and proves a full pool census. No helper-only or skipped result substitutes
for this acceptance.

Debug/static and Release/shared CTests passed. At message qualification the shared library exported only the six message/lifetime
APIs. The current polling extension adds its documented twelve Ker APIs. A separately configured installed consumer completed actual
EAL/queue/pool lifetime and coherent QUERY response.

## Isolated guest evidence

Candidate `293203dacfedab1aa6d1a366372de406e51b2dd7` passed the source acceptance
in the networkless shared-hugepage guest. It reran all 15 IPC/naming/message
source phases with 22 distinct original-EAL secondary PIDs, reclaimed 64/64
objects, completed both examples with exit 0, then powered down normally with
QEMU exit 0. The host CTest's skip77 without shared hugepages is not completion.
Artifact directory:
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest3`.

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `0ce7253c97137accede048ae9332d9f2e119c2536b2e119e68ae92d0424d5bb8` |
| `package-manifest.json` | `138bba6cf800a5bca386a0162609210e7f3d7b7fae5be36be59966d209f8e963` |
| `initramfs.cpio.gz` | `69f12a46d5149aac9f52178061f6b9b1c7774f2ecd6b05ab16c5a29886483f33` |
| `serial-attempt1.log` | `7c333a24d34a262741204551f88f4ac899918868fa2662eded14fe6ceb84e177` |

The package binds candidate source and executable hashes; actual-result
validation requires every source marker, all distinct secondary lifetimes,
complete reclamation, both example exit codes and normal power-down. Inherited
guest files do not imply rerunning unrelated historical suites.

This completes exactly one baseline-partial source case. The baseline delta is
24/50 at message qualification. Later polling progress is recorded in
[the polling contract](fstack-reload-polling.md). Directory arbitration, hardware
users, cross-master generation handover, external
packet delivery, command execution and full application reload remain separate
unqualified contracts.
