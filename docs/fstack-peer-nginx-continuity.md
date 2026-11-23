# Original-classifier PEER handoff with two real Nginx owners

`native-nginx-companion-rx-source-peer-continuity` exercises the paired authority
receiver with two separately contained pinned Nginx masters and their real FF
owner workers. The application TCP sockets use the common original Linux/LKL
stack. No copied-frame TCP proxy or Ker TCP state machine is involved.

The test supervisor starts the authenticated native worker/runtime service and
C31 consumer, retains its AUTH endpoint, and receives two staged owner slots
from the existing owner-group controller through authenticated descriptor
transfers. The companions independently validate the pinned executable,
configuration, module and worker READY identity. The initial owner reports role
0 and the candidate role 1, with distinct real slot device/inode/cookies.
Only then does the supervisor send primary AUTH and the finite paired old-owner
record. The old module receives APP_AUTH directly from that same supervisor;
C31 validates the old module's independent ACK before acknowledging the pair.
Authority is nonrenewable and limited to 120 seconds in this test.

The alias qualification DSO includes the checksum-pinned original
`ngx_ff_module.c` without editing it. Both private source-created reload blocks
are advanced to epoch 3 through the original `ff_reload_master_begin`,
`ff_reload_set_epoch` and `ff_reload_master_complete` APIs. The old generation's
original arm executes in its preceding target-0 window and remains registered
when the next target becomes 1. Its unchanged original callback therefore
returns LOCAL as the previous generation. The candidate uses its existing real
source-map admission adapter in the target-1 window: an old tuple absent from
that map returns the original `FF_DISPATCH_PEER` result. These are prepared
qualification windows, not a claim that two masters share the original master
reload FSM or that its signals and phase transitions have been migrated.

A synchronous PEER transport cannot run inside this broker reactor: the old
Nginx worker needs broker owner-loop RPCs to progress and consume the relay.
The exercised begin/poll form sends once and returns to broker scheduling while
waiting. Each poll retains the original C31 packet ID and deadline, validates
the exact old owner and unchanged snapshot, and settles LOCAL or DROP without
extending the lease. There is no second hop. The original packet, rather than
the snapshot, enters native Linux after LOCAL.

The test requires all of the following:

- One host keepalive TCP connection returns `old-nginx` before cutover.
- A SYN queued during the native owner-group cutover cannot complete before
  COMMIT; afterward it returns `new-nginx`.
- Another GET on the same old TCP socket still returns `old-nginx` after COMMIT,
  while a fresh connection returns `new-nginx`.
- Real old-tuple GET payload frames before and after COMMIT correlate by packet
  ID with candidate PEER, old-owner LOCAL, and successful C31 handoff. Captured
  full-frame hashes, lengths, IPv4 addresses and TCP ports must agree.
- The host half-closes the old stream and checks orderly EOF. Raw native TCP
  census snapshots confirm both members have no remaining live connections
  (TIME_WAIT is allowed) before owner shutdown. Both companions settle; the original listener is retired while the candidate
  remains alive, census confirms listener closure, and the controller releases
  all remaining capabilities.
- Native Linux reports at least three passive opens, the native shutdown marker
  sequence completes normally, the runtime-service lease is released, and the
  DPDK worker exits with zero outstanding ownership.

The transport unit executable runs 28 controls in both synchronous and reactor
forms (56 controls). The reactor LOCAL control withholds the owner's reply,
requires a nonblocking EAGAIN, rejects a concurrent send, then releases the exact
reply. Both forms preserve identity, expiry, malformed-reply, no-loop and file
descriptor conservation controls.

```sh
ctest --test-dir <native-build> --output-on-failure \
  -R 'native-nginx-companion-rx-source-peer-continuity|rx-owner-relay-peer'
```

The test prints its retained evidence directory, including the JSON receipt,
C31 log, each Nginx runtime trace/error log and supervisor/controller logs. The
receipt records owner identities, matched packet IDs, old request payload
handoff times, native counters and final I/O ownership. The upstream Nginx
module SHA-256 remains
`d33fd03ea7a9626130a6029a03505dce54f9ee74d863f3d648f31903a0307f14`.

This qualifies one IPv4/TCP queue, one initial/candidate pair and one cutover
with real original-classifier PEER handoff. The full original same-master
reload FSM, its complete original shell entrypoint, multiworker/USR2 and
additional generations remain outside this batch. The migration inventory
stays at 362 adapted, zero partial and one blocked; the original shell case
must retain its blocked status until its own complete evidence exists.
