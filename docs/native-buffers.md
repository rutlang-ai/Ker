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

## Resizing registered memory

`ker_posix_buffer_realloc(base, size)` grows or shrinks a registered allocation.
Original Linux creates the replacement VMA; the adapter copies
`min(old_size, size)` bytes and then unmaps the old VMA. New bytes are zero.
The returned base can change even when shrinking. Use a temporary return value:

```c
void *replacement = ker_posix_buffer_realloc(buffer, wanted);
if (replacement) buffer = replacement; /* old buffer survives failure */
```

Nonzero sizes must be <=INT_MAX; NULL with nonzero size allocates. Exact live
bases are required for nonzero resizes. Foreign, interior and stale bases fail
EINVAL. ENOMEM or failure releasing the old mapping leaves that original mapping
valid. If rollback release also fails, the replacement stays registered for
shutdown cleanup; the failed call does not hand it to the caller.

Zero size deliberately follows the pinned F-Stack helper's pointer-identity
contract rather than libc realloc: it returns the input unchanged, including
NULL or a foreign sentinel, without allocating, freeing, dereferencing or
registering it. This no-op needs no active instance and preserves errno. It
never makes a foreign pointer suitable for MSG_ZEROCOPY.

Consume all original send completions before resizing, just as before freeing.
Do not race access, resize, free or native shutdown. Live allocations require an
active native instance; positive resize after shutdown fails ENETDOWN. This
memory adapter does not add an owned-chain writer or transfer ownership to a
socket. Resizing itself copies bytes and is not a zero-copy operation.

`native-fstack-buffer-resize` boots original Linux and exercises these paths,
including individually injected mmap ENOMEM, old-mapping munmap EIO and failed
rollback munmap. Every successful syscall reaches original Linux, and final
allocation/release counts and live bytes must balance. The existing five
virtio/vhost-kernel profiles additionally send from grown buffers and shrink /
regrow midway through IPv4/IPv6 TCP512KiB, after actual completion ranges, with
full independent wire payload validation.

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

At PR #248, all 13 source cases remained blocked under issue225 pending case-specific mapping
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

The subsequent [case-specific contract audit](fstack-zc-contracts.md) qualifies
four allocation/send validation scenarios with `native-fstack-zc-validation`.
Two FreeBSD header-field cases are architecture-specific; seven empty-chain,
write-cursor and zero-send cases remain blocked under issue225. These source
scenarios do not establish ff_zc ABI equivalence or copy-free transport.

`ker_posix_buffer_write(base, offset, data, length)` 在已登记的原版 Linux VMA
请求范围内写入，返回复制字节数或`-1/errno`。必须提供精确base、非NULL且可读的
source和合法offset/length；检查使用减法，拒绝size_t加法溢出和page-rounded余量。
支持memmove重叠语义，合法零长度调用返回0且不改变字节。拒绝返回EINVAL且不
修改字节或登记，native未启动/已关闭时返回ENETDOWN。它不改变分配长度，不维护
packet header或隐式写游标；调用者仍须在写入被zerocopy引用的字节之前等到全部
完成通知，并同步直接访问、send、resize、free与shutdown。

三个standalone原版Linux测试分别覆盖容量拒绝、NULL数据拒绝和实际多页/重叠/
零长度写入；不是网络、PMD、mbuf链或端到端零拷贝证据。

动态库集成测试通过dlsym获取有界写入接口，先用它填充登记VMA，再用已连接的
原版Linux loopback UDP socket验证非法写入不投递datagram、不产生zerocopy
completion且不改变字节。有效后继发送收到精确数据，首个completion ID仍为0；
另一个由有界写入准备的VMA参与8192字节scatter-gather传输。显式runtime退出后
write返回ENETDOWN，所有映射、option guard和worker mbuf必须清零。
`native-fstack-zc-validation`的六项source marker必须完整且唯一，不能用少跑或
重复marker掩盖缺失。null PMD仅负责启动真实runtime，loopback结果不计外部wire；
完整`native-fstack-native-buffers` virtio软件数据通路回归另行验证。
