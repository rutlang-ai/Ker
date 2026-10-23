# Original Linux buffer mappings and send completions

`ker_posix_buffer_alloc(size)` allocates zero-initialized, native-page-aligned
memory with the pinned original Linux anonymous `mmap` syscall. Linux registers
the VMA and owns the pages. `ker_posix_buffer_free(base)` unmaps that exact
allocation through original Linux. These optional `ker::posix` APIs require an
active native instance; allocation sizes must be 1 through INT_MAX. A failed
allocation returns NULL/errno. Unknown, interior, NULL and duplicate frees return
EINVAL without freeing another allocation. Do not use libc free or host munmap
on these addresses, and do not race access/free/shutdown.

This addresses a real boundary in the pinned LKL NOMMU runtime: host malloc and
host mmap storage are not registered native VMAs. They cannot be passed to
original Linux page lookup as native user pages. Native mapped storage can be
used by original Linux MSG_ZEROCOPY; it does **not** eliminate the copies in the
Unix packet channel and worker mbuf construction.

## Socket contract

Enable SO_ZEROCOPY on a native TCP/UDP socket and send mapped ranges with
MSG_ZEROCOPY. Each nonempty iovec must fit inside one allocation; multiple
allocations may be sent using multiple iovecs. Foreign or out-of-range payloads
return EFAULT before native page lookup. Other socket data/control structures
remain ordinary caller-owned POSIX structures.

When SO_ZEROCOPY is disabled, original Linux ignores MSG_ZEROCOPY and performs
ordinary copying; host malloc storage remains valid for that operation.
Unflagged copying sends remain available even while SO_ZEROCOPY is enabled.
Host-domain sockets continue using the host syscalls.

The adapter serializes SO_ZEROCOPY updates with flagged sends using the original
socket's SO_COOKIE, including dup aliases. Unrelated sockets and memory
allocations do not wait for a blocking send's socket-option guard. Registered
range checks protect the NOMMU page boundary; they do not create an application
buffer ownership transfer or permit concurrent free while a send is using it.

Original Linux chooses the accepted byte count, GUP/page references, TCP state,
segmentation, retransmission and completion notifications. With sendmmsg, the
adapter validates and invokes original Linux one message at a time for flagged
batches, preserving accepted-prefix and msg_len behavior if a later message has
invalid memory. It does not implement a transport or claim unchanged batch-call
performance.

A positive return alone does not allow buffer modification or reuse. Consume
MSG_ERRQUEUE control messages with SO_EE_ORIGIN_ZEROCOPY and track every completed
inclusive ee_info..ee_data ID range. Treat SO_EE_CODE_ZEROCOPY_COPIED as an explicit
copy fallback. Code zero is the original socket completion classification, not
proof that later segmentation, the device or the packet transport made no copy.
The pinned UDP path can allocate an ID even for a zero-payload datagram. Keep
referenced bytes unchanged until all corresponding successful-send IDs complete.
A failed/unsent suffix remains the caller's responsibility.

`tests/posix/native-buffer-test.h` exercises actual completion ranges, including
merged ranges, copying fallbacks, scatter/gather across VMAs, batch-prefix
failure and concurrent option changes through a socket alias.

## Shutdown and evidence

Before native shutdown, quiesce native users as required by ker_posix_run.
Shutdown closes/drains sockets, unmaps residual registered allocations and then
removes devices and halts original Linux. Every returned pointer is invalid
afterward. Late allocator/free calls return ENETDOWN without dereferencing stale
addresses. Explicitly released allocations and shutdown reclamation are reported
in native.buffer_allocations, buffer_releases and buffer_shutdown_releases.
buffers_live and buffer_bytes count registered mappings, not physical pages or
DPDK buffers; buffer_option_guards_live must be zero after quiescence.

Worker rx_shutdown_discarded separately counts a retained RX suffix reclaimed
once native delivery has stopped. Per-queue accounting includes that suffix;
zero runtime drops is distinct from shutdown disposal. This closes the accounting
gap exposed by explicit run teardown after the buffer test's final TCP ACK.

`native-fstack-native-buffers` uses an independent host TCP/UDP peer and raw wire
capture over original virtio-user/vhost-kernel. Five off/checksum/TSO profiles
transfer exact nonperiodic 512 KiB TCP streams and UDP boundary payloads in both
IP families. Completion ranges cover every submitted payload byte; non-COPIED
TCP completions are observed with checksum/TSO support, and UDP copying fallback
is required without SG. Wire payload coverage, checksums, MTU, capture drops,
VMA/guard reclamation and EAL teardown acknowledgement are checked separately.
The test includes concurrent allocation/free in four threads, cross-thread
mapping release, invalid memory guards, alias option races, persistent TAP flag
restoration and an intentionally retained mapping reclaimed by run shutdown.

## F-Stack migration boundary

The pinned F-Stack unit suite is an algorithm mirror, not its compiled network
implementation. Its real ff_zc_mbuf_get/write code constructs FreeBSD mbuf chains,
copies initial data into them and updates M_PKTHDR/m_pkthdr.len. ff_zc_send hands
the owned chain to kern_zc_sendit/sosend. Native Linux mappings and MSG_ZEROCOPY
retain a different ownership/completion API and do not implement those fields.

All 13 source cases remain blocked under issue225 pending case-specific mapping
of the owned-chain, write-cursor and validation contracts. New Linux socket
operations are not proof of FreeBSD header-field or ownership assertions.

The real upstream default ff_dpdk_if_send path also calls ff_mbuf_copydata to
copy into DPDK buffers; FF_USE_PAGE_ARRAY is a separate optional path. Removing
Ker's packet transport copies is a distinct stronger milestone, not an invented
prerequisite for these socket-fast-path unit cases. Such a milestone would need
producer/consumer release acknowledgements, backpressure, retained suffixes,
process-failure and teardown proof. Neither code-zero completions nor passing
the source algorithm mirror demonstrate end-to-end zero-copy.

Source references: pinned F-Stack
[ff_veth.c](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_veth.c),
[ff_syscall_wrapper.c](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_syscall_wrapper.c), and
[ff_dpdk_if.c](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_dpdk_if.c).
Original Linux/LKL pins are recorded in [native-linux.json](../config/native-linux.json).
