# TAP rejected-offload ownership compatibility

Upstream baseline: `d129414711aa7c4954f997acf4c54338574a7d92`.
Tracking: https://github.com/rutlang-ai/Ker/issues/244.

The original TAP checksum path allocates a header, advances the caller's mbuf,
chains it behind that header, then replaces only a local root. If `writev` fails,
ethdev returns zero accepted packets with an advanced caller chain and an
unreachable allocated header. Original GSO also clears the input's TSO flag
before a later write can reject it. A public ethdev wrapper cannot recover the
private lost pointer. This is the reason for the isolated upstream exception.

`tap-tx-retry.patch` makes checksum writes use a private complete packet copy,
frees that copy on success and rejection, and restores caller offload flags when
GSO or transmission rejects the input. Original DPDK still computes checksums
and segments TCP; original Linux owns TCP state and retransmissions. Extra
copies and allocations are intentional; no performance equivalence is claimed.
An unsuccessful GSO burst may already have emitted a segment prefix. Resending
the retained complete input may duplicate that prefix; original Linux TCP handles
sequence numbers and duplicates. This does not provide atomic on-wire bursts.

`ker_dpdk_tap_tx_retry_abi(port)` returns 1 only if that port uses this patched
module's device operations. Workers allow TAP offload retries only with that
per-port qualification. Unmodified or unrelated drivers cannot opt in merely
because another shared object exports the marker. Original TAP continues to
fail closed on offload rejection. No change is made to default offload policy.

Prepare a new directory outside both source trees and use a separate prefix:

```sh
python3 tools/prepare-dpdk-tap-retry.py \
  --source /path/to/original/dpdk \
  --output /external/dpdk-tap-retry-source
KER_DPDK_SOURCE_DIR=/external/dpdk-tap-retry-source \
KER_DPDK_BUILD_DIR=/external/dpdk-tap-retry-build \
KER_DPDK_PREFIX=/external/dpdk-tap-retry-install \
KER_DPDK_LIBS=eal,ring,mempool,mbuf,ethdev,gso \
KER_DPDK_DRIVERS=mempool/ring,net/tap,net/null,bus/pci,bus/vdev \
  bash tools/build-dpdk.sh
```

Preparation archives the exact pinned commit and applies the checked-in patch,
recording source and patch hashes in `ker-tap-retry-provenance.json`. It never
edits the dependency checkout. Select the resulting pkg-config directory in
CMake and preload its TAP PMD for tests, as with the original shared PMD.

`native-fstack-tap-offload-retry` requires exact caller descriptor/chain/data
preservation, temporary allocation balance, and successful retries after injected
copy/write failures and real pool exhaustion. It skips on an unpatched PMD.
`native-fstack-tx-offloads` additionally verifies actual native TCP/UDP traffic,
independent full-stream payload and wire checksums after failures. Original
PMDs retain their explicit failure characterization in that test. Physical-NIC
acceptance, TAP IPv6 TSO and performance remain outside this evidence.
