# F-Stack directory admission adapter

This evidence covers five source-shaped P1 directory scenarios in the pinned
F-Stack test_ff_dpdk_if.c suite. The production boundary is Ker's real
secondary EAL startup: session_directory_lookup_validate() looks up the
resident-created DPDK memzone and validates its complete header and the
authenticated ticket before any pool/ring lookup or ATTACHED.

## Scenario-adapted cases

- test_p1_directory_missing: an actual independent EAL primary creates a
  namespace without a Ker directory. A real secondary reserves through the
  Ker resident, joins that EAL namespace, and is rejected before ATTACHED.
- test_p1_directory_invalid: a test-gated real secondary is released into EAL
  only after the resident mutates one shared-header field. Bad magic, version,
  size, session, generation geometry and capacity each fail before ATTACHED.
  The test restores the header and compares the resident directory, pool,
  PMD identity, slots, leases and peer mirrors.
- test_p1_directory_full: one real original ring-PMD owner and two live
  control-only standbys fill Ker's three master slots. Two fourth-master
  requests are denied, and the same resident state is compared before and
  after. Exception endpoint state is zero in this ring-PMD case.
- test_p1_directory_primary_slot_busy: a second original DPDK EAL primary
  using the live resident's file prefix is refused, with the original primary
  identity and directory state unchanged.
- test_p1_directory_success: in the default-off production configuration, a real
  secondary registers while the generation directory is absent and the generic
  control memzone remains present. In a separate generation-rings-enabled EAL
  namespace, the generation directory exists, the real secondary attaches, and
  a BUILD_TESTING-only action repeats the production attach lookup and confirms
  the same directory and all eight RX/TX ring pointers. Exact child cleanup
  restores pool, PMD, lease and peer state. This is a scenario adaptation, not a
  literal `graceful_reload` switch or F-Stack ABI equivalence.

The corresponding CTests are native-fstack-session-registration and
native-fstack-session-standby. The isolated guest run bound to runtime candidate
005f368fea6b8325730486b8025e4df633839963 passed both suites, including normal
poweroff, all 511 objects restored, and exact test-owned hugepage cleanup. The
result manifest is `/home/hurricane/.local/state/ker-compat-work/fstack-followups/session-directory-disabled-guest4/result-attemptdirectoryDisabled4.json` (SHA-256 `40e67429eee326cd2253832b06bd7418c010e33ac5212eda5dfc4a4388ab4523`); package and image SHA-256 are `eec8f41a68145442a18748da33d00e6ab6f3a40741715f5be83282dbb9a849c2` and `cb0c73789ed9c0c2e6b87b50386fd0529c37370f685161b6a67d479b5e87e04d`.

The latest integrated candidate `0ac28b8973b1f79e5fdbb9a86335531d9f71fd14` reran both
registration profiles within the 13-suite original-DPDK guest, including default-off absence
and same-domain enabled attach/replay. Its actual-result manifest SHA-256 is
`30f449b0762efa5fd0f953103aed2ee3c7f11368cf72b4ec624b9cef67e51571`, package SHA-256
`4d87ed42fe94ed1c45736a62701779fe2683511dd933115105c5d07d4bd45cbb`, image SHA-256
`32750d8b2c2648edf6abe56287d18723b030cad79a7879ebf954d2a9ed5d6149`, and serial SHA-256
`d2c258cc7feedca27e0becc0a83d17bf901dcb29763fef6e93106898b6022d44`. The standalone guest4
record above remains historical; this is the latest combined evidence.


## Remaining source boundaries

test_p1_directory_live_slot remains blocked. F-Stack refuses an occupied
epoch-derived slot without fallback, while Ker's resident selects any free
slot. A duplicate reservation or full-directory denial does not establish the
same slot-selection rule.

No fixed F-Stack directory layout, wire ABI, physical PMD mode, exception-TAP
routing or complete graceful reload is claimed.
