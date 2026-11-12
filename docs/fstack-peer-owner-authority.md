# Supervisor-authorized old-owner relay binding

The C31 relay consumer now has an opt-in, finite peer-binding protocol. It no
longer needs a prepopulated peer struct: an authenticated supervisor can
delegate the old owner's pidfd and packet channel, and the consumer enables
the transport only after the old worker independently acknowledges that exact
application/run identity. The existing single-owner launch path still drops
PEER. Production `graceful_reload=1` remains fail-closed.

## Authority and ordering

1. Complete the current candidate's existing OWNER_AUTH and worker-channel
   authentication. Its role must be candidate (1). Preserve its exact live
   PID/TID/start identity, slot device/inode and cookie in the consumer.
2. The supervisor validates both READY proofs and delegates an AUTH_PEER record
   over the already authenticated control channel. It contains the old initial
   owner's proof (role 0), the exact current candidate proof and a caller-chosen
   absolute monotonic authority deadline, no more than 300 seconds away.
   Exactly two descriptors accompany it: old pidfd and the application side
   of the old worker's Unix packet channel.
3. The consumer checks real supervisor credentials/lifetime, both live process
   identities, distinct owner/slot/cookie identities, exact candidate context,
   the deadline and descriptor types. It installs a pending binding, not a
   forwarding authorization. Duplicate or replacement bindings are rejected.
4. The supervisor sends the existing APP_AUTH bootstrap directly on the old
   channel with application/supervisor pidfds. The old module requires actual
   supervisor credentials; the application cannot bootstrap it itself. The
   supervisor enables `SO_PASSCRED` before the old worker can enqueue its ACK.
5. The consumer validates the old worker's own credentials, PID/TID/start,
   pidfd, application/supervisor identity and run context in AUTH_ACK. Only then
   does it emit AUTH_PEER_ACK to the supervisor and enable forwarding. A missing
   ACK is bounded by five seconds and by the authority deadline.
6. The supervisor validates the consumer's ACK and process lifetimes before
   starting traffic handoff. Successful delegation closes its own copy of the
   peer channel. Each later PEER hop checks live supervisor/current/old owners
   and the finite authorization both before and after the transport operation.
   Expiry means DROP, never renewal or implicit rebind.

The private record is 144 bytes: the unchanged 96-byte owner proof followed by
current PID/TID, start ticks, slot device/inode, cookie and authority deadline.
Record types 3/4 identify peer AUTH/ACK; existing types 1/2 and their ABI remain
unchanged. ACKs carry no descriptors and must match the entire request context.
The current worker's channel ACK also now checks application start ticks and
the supervisor PID/start fields, in addition to its existing owner/run checks.

`rx_owner_peer_auth()` in `tools/ker-run.py` is the private supervisor operation.
The consumer's `KER_RX_OWNER_PEER_AUTH_ENABLE=1` is for a dedicated controller
that retains the authenticated control endpoint. The legacy single-companion
launcher closes that endpoint after its original OWNER_AUTH, so it deliberately
does not activate this protocol. There is no claim that setting the environment
flag alone creates a complete two-owner launcher.

The caller must retain reload-window authority until all pending decisions
settle, or quiesce the owners before ending it early. This protocol does not
provide live renewal, replacement, an early-revocation ACK or repeated-generation
slot retirement. An accepted finite binding retains its descriptors until
consumer teardown; expiry disables forwarding. Those lifecycle contracts and
real two-Nginx source-classifier/old-stream qualification remain subsequent work.

## Validation boundary

`rx-owner-peer-authority-python` runs the actual C consumer registration and
transport code, plus the supervisor operation, across independent processes.
The workers model READY and relay wire messages only; they are not Nginx,
classifier or TCP implementations. The suite covers a delegated one-hop
LOCAL/DROP result, candidate-pair correlation, a foreign sender, malformed
records/rights, bad owner ACKs, duplicate binding, authority expiry, absent ACK,
and descriptor conservation. Real Unix slot-shaped sockets supply distinct
device/inode/cookie test identities, not broker/Nginx slot qualification.

All 26 controls passed with GCC, Clang and ASan/UBSan. The existing owner AUTH
suite and four real Nginx source flow-map/admission/revoke/PREPARED-failure
CTests also passed, preserving the default unbound PEER-to-DROP boundary.

```sh
ctest --test-dir <build> --output-on-failure \
  -R '^(rx-owner-peer-authority-python|rx-owner-relay-auth-python)$'
```

The migration catalog remains 362 adapted, zero partial and one blocked. This
is a concrete paired registration prerequisite, not completion of the original
reload FSM or `test_graceful_reload.sh::entrypoint`.

The subsequent [two-real-Nginx continuity qualification](fstack-peer-nginx-continuity.md) exercises this opt-in receiver with actual staged owner slots, original classifiers and native Linux TCP. It retains the full original reload shell/FSM boundary.
