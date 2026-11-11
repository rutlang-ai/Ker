# Original source-map admission relay qualification

This focused qualification connects the existing C16 staged SYN-admission
broker task to the unchanged original `ff_flow_map_*` implementation in the
authenticated candidate Nginx worker. The C16 task requests admission through
the broker; the source-map adapter invokes the original unprefixed map API on
the authenticated Nginx worker thread. The original dispatcher then observes
that created entry through the same process-local map, and the matching
relayed frame receives the original LOCAL result. A distinct unadmitted tuple
reaches the original PEER result and is explicitly dropped by the current C31
relay; it is not forwarded to another generation.

The source-admission profile is an opt-in qualification adapter. The normal
`graceful_reload=1` startup path remains fail-closed, and this test does not
qualify the original same-master reload FSM, repeated generations, peer-ring
forwarding, or preservation of established streams. It also does not claim that
the pinned production Nginx binary populates the source map: the test builds the
unchanged pinned source module into a Ker-owned qualification module and checks
that its original classifier uses the unprefixed runtime map. The namespaced
candidate map remains separate.

## Focused cases

The CTests below require the pinned native Linux/DPDK/Nginx inputs configured
by the native build. Run them individually when investigating a failure:

```sh
ctest --test-dir build --output-on-failure -R '^native-nginx-companion-rx-source-admission$'
ctest --test-dir build --output-on-failure -R '^native-nginx-companion-rx-source-admission-revoke$'
ctest --test-dir build --output-on-failure -R '^native-nginx-companion-rx-source-admission-prepared-failure$'
```

`native-nginx-companion-rx-source-admission` proves an actual C16-created map
entry, exact tuple and owner-thread correlation, HTTP success, a foreign
unadmitted PEER-to-DROP result, and settled C31 accounting.

`native-nginx-companion-rx-source-admission-revoke` exercises expiry and
revocation of each created map entry. It verifies that the same tuple misses
the original map afterward and receives PEER-to-DROP. Retransmitted SYNs may
create multiple entries; every created entry must have a matching revoke.

`native-nginx-companion-rx-source-admission-prepared-failure` injects failure
after candidate listener preparation but before source activation/READY. The
candidate worker must die, the broker must release its exact admission task,
and dead-plan recovery must preserve the original listener cookie. Ker-run
then remains explicitly UNRESOLVED because the owner failed before READY; the
test records retained native actors and performs forced cleanup using only
captured test-owned pidfds. This case does not claim normal native shutdown or
zero-outstanding settlement.

The activated initial-listener helper mode is used only by the source-admission
dead-plan-recovery case. Other staged-admission tests keep their existing
publish-initial behavior. Server-side recovery preconditions are unchanged.

Receipts are written under `build/Testing/Temporary/` as
`rx-source-admission-qualification.json`,
`rx-source-admission-revoke-qualification.json`, and
`rx-source-admission-prepared-failure-qualification.json`. The prepared-failure
receipt distinguishes successful broker dead-plan recovery from the later
unresolved launcher and test-forced cleanup.
