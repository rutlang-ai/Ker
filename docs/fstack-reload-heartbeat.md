# Target heartbeat, READY and round observations

The optional `ker::reload` adapter now connects the original target-generation
heartbeat to actual poll passes. The target ticks while a round is open,
including passes denied by the RX gate. Observers supply consistent monotonic
sample/timeout units, such as original DPDK timer cycles. Timeout 0 disables
sampling. A stall reports liveness only: it does not transfer RX ownership.

Ten public APIs extend the previous eighteen: original shared-block validation,
individually atomic runtime observations, controller begin/finish, heartbeat
configuration/tick/sample/evaluation and READY publication/matching. The original
source and block layout remain unchanged. The observation-owner field mirrors
the original KNI-owner generation value; it does not establish KNI operations.

The caller serializes operations within a process, owns all shared storage and
coordination, and quiesces affected callbacks before commit or abort, which may
restore RX ownership. A new open round rejects re-entry. Poll ticks automatically;
other event loops may explicitly tick, but cannot recursively tick or sample
inside a poll callback. READY records correlate a trusted caller's slot, PID and
round; they are not authentication or proof of a listening application socket.
Unbind requires quiescence; a new bind resets local sampler bookkeeping.

## Source assertions and actual consumer

`fstack-reload-heartbeat` maps exactly
`tests/unit/test_ff_config.c::test_ut_nr_22_heartbeat_and_rx_return`:

- Counter advance, within-window, exact timeout, disabled timeout, backwards
  clock and NULL evaluation arguments use the original helper.
- Original magic/version/size validation rejects invalid blocks and accepts the
  valid original layout.
- Begin selects epoch 1/target 1; target ticks advance the shared counter and the
  old generation observes one stall followed by rebase.
- READY checks slot/PID/epoch correlation and out-of-range slots.
- Complete updates active/observation-owner values, closed windows stop ticks,
  abort preserves the active generation, and unbind restores default views.

Both Debug/static and Release/shared tests passed. The actual original-EAL
net_ring fixture also consumes the same APIs. A denied target poll advances the
original counter without entering the packet callback. The parent SIGSTOPs the
exact target child and verifies its stopped status using `waitpid(WUNTRACED)`.
The old worker samples actual original DPDK timer cycles until it reports one
stall, then verifies immediate rebase at the same observed monotonic stamp.
The shared RX owner remains 0. SIGCONT resumes target progression and live sampling.

The actual target PID publishes READY under round 1; wrong PID, epoch and slot
are rejected. The controller completes only after the already-qualified park,
release and claim sequence, with no callbacks in flight. Closed-window polling
leaves the counter unchanged. A second begin/abort retains active generation 1.
The existing transfer, reversal, same-slot successor, four original PMD RX/TX
records and 63/63 mbuf reclamation still pass.

The repository program and an independently configured installed-package
consumer each ran the whole profile. Their C/check source bytes were checked
against the candidate. Original IPC/naming/message 15 source phases and both
examples were rerun. The shared library exports only 28 documented Ker APIs.

## Evidence

Candidate `f169cd149ab15a74cac8bd6a7420cfc4dc246be0` passed in the isolated
networkless shared-hugepage guest. Each polling profile used four distinct
original-EAL secondary PIDs and recorded the exact stopped target, stall result 1,
rebase 0, owner 0, stalls 1, READY round 1, completion tick suppression and abort
active 1. Original PMD `ipackets=4`, `opackets=4`, no in-flight callback, empty
queues and full pool reclamation passed. All child/EAL exits, both examples,
normal power-down and QEMU exit 0 passed. Host skip77 is not completion evidence.

Artifact directory:
`/home/hurricane/.local/state/ker-compat-work/fstack-unfinished-ipc-guest5`.

| Artifact | SHA256 |
|---|---|
| `actual-result-attempt1.json` | `bc876708fe0d3cb91f883f1abcebdf196271f38a84e9a11a7f08fafd66dae753` |
| `package-manifest.json` | `fbb9361c53c57f125d80bdd3b85b689f6b0d34dc1b91eea22b064b887e59f0f9` |
| `initramfs.cpio.gz` | `58b75728253eed84de79f933cdd2691df92d7ddcc72e5fe1e3ce0522092f7df3` |
| `serial-attempt1.log` | `080c10e6f555142ea7f0c3b52bd5d602afd8367e34ff158e07e663a529f5317a` |

The result binds candidate source, executable, installed-source, package and
serial hashes. Exactly one baseline-blocked case is newly complete, bringing the
baseline delta to 27/50 at heartbeat qualification. Later caller-policy progress
is recorded in [the controller contract](fstack-reload-controller.md).
Cross-master directories, hardware-user proof, automatic
takeover, imported-Linux networking and complete application reload remain
separate unqualified contracts.
