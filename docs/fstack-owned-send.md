# Owned-frame send failure and disposal

This qualifies exactly two pinned F-Stack cases:

- `tests/unit/test_ff_dpdk_if.c::test_ff_dpdk_if_send_null_ctx_with_mbuf`
- `tests/integration/test_ff_dpdk_if_integration.c::test_ff_dpdk_if_send_copydata_fail`

The complete source functions and complete original `ff_dpdk_if_send` body are
retained byte-for-byte at revision `646a641cfff77f4815e1e29829a09e1ed15a2999`.
`fstack-owned-send-original-import` verifies the functions, full retained source
hash, metadata declaration/header hash and upstream license. The original
context/configuration declarations are supplied by the retained headers.
Private names and dependency adapters compile that unchanged body in a caller
library, outside Ker's libraries and exported APIs. Input chains use the unchanged
production `ker_worker_mbuf_from_bytes` packing adapter; no duplicate packet
representation or packing implementation is introduced.

## Actual ownership boundary

F-Stack's send consumes an owned packet, including on NULL context and copy
failure. Ker's original-Linux netdev callbacks borrow iovecs and preserve those
vectors on error. The new caller does not modify that callback or transfer its
borrowed buffers. It instead owns actual original DPDK mbufs and passes them to
the retained conversion function. Its free dependency calls `rte_pktmbuf_free`;
its read dependency calls `rte_pktmbuf_read`, copying a returned contiguous view
when needed. The original function allocates its actual output head/segments,
handles failed reads, frees the input and submits a successful output.

The source stack sentinel and `0x1` token are harness identifiers only: the host
adapter supplies a real owned mbuf, never dereferences/frees those identifiers,
and calls the unchanged send function. The original copy-failure flag selects
a real 127-byte input for the original 128-byte request. It does not replace
copydata with a canned error: the actual DPDK read fails its bounds check and
the original error branch runs. A later 1024-byte input/1536-byte request fails
the third copy, after three output segments have been allocated/linked.

Each complete source function runs five times. The NULL guard returns -1,
drops exactly one packet per call, frees the input and makes no copy or PMD
send. The copy guard returns -1, records the actual failed copy and releases
both its allocated output and owned input. Every iteration requires no queued
output, zero PMD TX/RX and all 511 pool objects available. Recovery then uses
the same sender, pool and started PMD to send and receive an exact 128-byte
frame. Finally all 511 objects are allocated simultaneously, checked for unique
pointers, exhausted exactly and freed. Mere count restoration cannot mask a
duplicate object. Unsupported offload input is consumed with ENOTSUP before the
original metadata/offload path, with no PMD output and complete pool recovery.

Two separate linker mutations demonstrate rejection: suppressing the original
input-free dependency fails pool conservation; replacing failed copydata with
success fails the original `rv == -1` assertion. They are test-only executables;
the ordinary library contains neither mutation. EAL/PMD startup failure cannot
skip the tests or satisfy their exact failure markers/assertions.

## Real and installed consumers

`ker-owned-frame-forwarder [EAL options] -- input.bin output.bin` consumes an
Ethernet frame file, creates a real original net_ring device, converts the owned
input through the retained function and receives the output through that PMD.
It writes the received bytes to the output file. Each invocation uses its own
EAL namespace and a 511-object pool with 384-byte usable segments. The independent
host driver supplies exact 64/4096/9014-byte experimental-EtherType frames and
compares every output byte. PMD counters must be TX1/RX1; input disposal, output
segment count and pool restoration must agree. The installed example repeats
all three exchanges from a separate prefix, with the original license verified.
This is real software-PMD frame I/O, not physical NIC or TCP/UDP interoperability.

The supported caller is serialized on its primary EAL lcore, with a started
port, configured queue and pool kept alive by its owner. Its ownership query
checks the actual EAL role/lcore; pool and queue selection use the actual bound
sender. The no-offload metadata adapter accepts only genuinely zero metadata.
Page-array mode is a build error; parked-generation diversion is an explicit
unsupported fatal boundary. Offloads, FreeBSD mbuf layout, reload epochs,
physical NIC behavior and any protocol stack are outside this qualification.
Linux/F-Stack/DPDK function bodies remain unchanged; no Ker protocol or mbuf
substitute is introduced.

## Validation

GCC and Clang with ASan/UBSan each passed all seven source, mutation, consumer,
installed-consumer and import checks. Sanitizer runs use
`ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1`; expected early-failure
mutation executables do not run orderly EAL/application cleanup. The explicit
511-object ownership audits apply to normal profiles independently of sanitizer
leak checking. The 21 inventory mutation/regression tests also pass. One test
fixture now places its selected partial case first so another blocked case in
the same follow-up group cannot mask the intended disposition error.

With the pinned Linux dependency available and DPDK configured:

```sh
cmake --build build --target ker-owned-frame-forwarder ker-owned-send-source-test \
  ker-owned-send-no-free-test ker-owned-send-copy-success-test
ctest --test-dir build --output-on-failure -R '^fstack-owned-send-'
python3 tests/fstack_migration.py
```

Native Linux/LKL startup is not required for these packet-memory contracts.
Existing native callback/traffic qualification remains separate. Missing EAL,
PMD, installation or source integrity is a failure, not a compatibility pass.
