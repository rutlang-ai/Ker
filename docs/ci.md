# CI coverage

The hosted workflow checks the exact checkout GitHub supplies for the event; it
does not pin a separate migration branch or commit.

## Jobs

- `linux-core` builds with GCC and Clang, with `BUILD_TESTING` both enabled and
  disabled. It runs the registered core CTests and any `tests/unit/test_*.py`
  suite. When native migration sources are present, an empty Python unit-test
  directory is an error. A checkout without those sources reports that the
  migration suite is not present; it does not claim a migration result.
- `pinned-dpdk-build` verifies the DPDK and Linux submodule gitlinks and builds
  the pinned DPDK drivers and Linux/LKL runtime. For native source snapshots
  carrying the TAP retry adapter, it archives the exact pinned DPDK commit to
  a separate temporary tree, applies the checked-in compatibility patch there,
  validates the patch/source hashes and adapter ABI manifest, and builds that
  isolated tree without modifying the submodule. A native migration checkout
  missing that adapter fails; a checkout with no native migration sources builds
  the pinned DPDK dependency unchanged and reports native runtime coverage as
  unavailable. When native sources are
  present, every Ker target is built with strict warnings in `BUILD_TESTING=ON`
  and `OFF` configurations. The testing build runs the complete registered
  CTest graph serially (the session packet matrix is run separately with its
  longer timeout) and saves JUnit. Hosted-safe tests, all session-labeled tests,
  and the six software datapath tests below must appear and pass without a skip.
  Any unreviewed skip, CTest failure, or nonzero CTest result fails the job.
- The six mandatory software datapath tests are
  `native-fstack-tap-offload-retry`,
  `native-fstack-virtio-kernel-offloads`, `native-fstack-native-buffers`,
  `native-fstack-typed-vdev`, `native-fstack-rx-lcores`, and
  `native-fstack-rx-queues`. The DPDK build enables the TAP, virtio, and vhost
  PMDs and their required libraries. The job loads `vhost_net`, verifies that
  `/dev/vhost-net` is a character device the test user can open, checks that two
  CPUs are allowed, and confirms all three installed PMDs resolve inside the
  pinned DPDK prefix before CTest starts. Missing capabilities fail the job;
  CTest skip codes do not count as coverage.
- The same job provisions TUN, unprivileged user/network namespaces, and a
  hugetlbfs mount backed by 256 requested 2 MiB pages. It fails unless at least
  64 pages remain free and an actual TAP interface can be created and closed
  inside `unshare -Urn`. It then runs
  `tests/posix/session-native-packets.py` directly with the full negative handoff
  profile set under a 900-second timeout. Verification derives the profile set
  from the checked-out fixture, requires the positive/frame/non-FRAME profiles
  and all 16 negative profiles, and requires the full eight-profile recovery
  set whenever that code is present. Each profile must emit exact EAL-channel
  and private-hugepage-cleanup records. The expanded 27-profile fixture also
  emits structured records with content-verified capture digests. CTest JUnit
  and the direct session log are uploaded as CI artifacts.

The native checks are capability-detected from the current source tree. A
source tree with only part of the native backend fails instead of silently
skipping its build. On an older checkout with none of the native files, the
workflow summary says that native validation is unavailable in that checkout.
That result is not evidence that the native backend built or ran.

The hosted session matrix is a privileged host run, not a KVM guest run. It
does not claim the separate immutable KVM guest qualification. Native backend
validation is reported as unavailable only when all native migration sources
are absent from the current checkout; partial native source presence is an
error, and a migration checkout must execute the required native tests.

## Pull request bases

GitHub selects pull-request workflows from the PR's base branch. Stacked
migration PRs whose bases do not contain `.github/workflows/ci.yml` will not
receive these checks just because a separate PR adds the workflow to `main`.
After the CI bootstrap is integrated, rebase or retarget the migration stack so
its base lineage contains that workflow. The build then tests GitHub's current
PR merge checkout and its submodule gitlinks; it must not name a foreign head
SHA in the workflow.
