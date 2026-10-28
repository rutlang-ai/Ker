# Cross-master directory adaptation in progress

This work has **not** qualified any additional upstream source case. The
baseline-to-current completion count remains **31/50**, with 19 still required.
Directory source cases retain their blocked/partial catalog status until their
full assertions and actual cross-master EAL/PMD and installed-consumer evidence
are complete.

`ker::reload` now builds the pinned original `lib/ff_reload_gendir.c`, alongside
the already imported `lib/ff_reload.c`. Both sources, the original configuration
layout and `ff_log.h` remain byte-for-byte unchanged. `UPSTREAM.json` records
GitHub-verified original Git blobs and SHA256 hashes. The compatibility layer
maps original logging to the registered `ker.reload.directory` DPDK log category;
it does not suppress or simulate logging.

The explicit APIs in `ker/reload-directory.h` borrow the caller's initialized
EAL and state storage. Primary reserves the original directory memzone;
secondaries look it up. The original backend derives secondary identity from
the real parent PID, assigns an epoch-derived slot, and retains fatal startup
refusal for missing/incompatible directories and conflicting slots. Primary
cannot poll hardware through this adapter. Attach fixes the generation and
worker slot for that process; detach releases both original local pointers.

Every secondary starts with an original STOPPED registration, so an attached
worker that has not polled is also tracked during orphan retirement. Polling
registers an original ACTIVE hardware-user lease before entering the
original ownership gate. A denied pass acknowledges STOPPED only after the
previous callback returns. Callback return alone leaves the lease ACTIVE.
Explicit stop/release require the caller to keep hardware work quiescent.
Release is terminal for the attachment; subsequent poll/transfer/reclaim/new
ring admission are refused until detach and a fresh attachment. Stop alone
permits a later poll.
Foreign ownership moves through the original proof-bearing release/reclaim
operations; implicit mirroring is suppressed while a foreign coordinate owns
RX. The adapter continues the original peer observation and liveness stamping
while that mirror is suppressed. Concurrent first claimants use the original
CAS reclaim operation before any mirror publishes. No protocol implementation
or automatic process supervisor is added.

Ring registration, census and purge locking expose the original runtime
operations. The application still owns resource initialization and purge:
serialize recycled-slot startup, hold the purge lock across census and dequeue,
leave slots with live users alone, drain all old objects before admitting a
recycled slot, and return every mbuf/message to its original pool. The recycled
flag in the view is observational and is not consumed by the view operation.
These primitives do not themselves prove that a ring has been drained.

Detach refuses this process's remaining registrations or purge lock. Departing
orphans preserve LIVE epoch state while other registered processes still borrow
that epoch. Destroy is primary-only and additionally refuses visible live
foreign masters and users. The caller must first prove that **all** other EAL
participants have exited, including unregistered observers. After detaching,
destroy frees the original memzone; a failed free reports an error and leaves
the local attachment detached. EAL cleanup and all other resources stay caller
owned. The component exposes 44 public APIs including the previous 28; original
helpers remain hidden.

`fstack-reload-directory-foundation` compiles the actual production translation
unit with private fixture access. It reproduces every assertion in upstream
`test_p2_hw_user_proof` and `test_ut_nr_m5_probe_epoch_fallback`, including an
actually exited/reaped PID, STOPPED versus disappearance, coordinate isolation,
and explicit-active-word priority. Raw field mutation exists only in this
noninstalled fixture.

`fstack-reload-directory-primary-eal` links the exported production library and
uses a real private single-process EAL with `--no-huge --no-shconf`. It checks
preconditions, primary nonownership, the actual original memzone, lock lifetime,
detach refusal, free and fresh recreation. This profile cannot prove secondary
attachment or shared hugepage behavior. The next qualification must use distinct
actual master parents, original shared EAL memory and original net_ring PMD
traffic, with held callbacks, live/dead/orphan user proofs and full reclamation.
