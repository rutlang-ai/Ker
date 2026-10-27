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

跨线程扩展`native-fstack-buffer-write-parallel/handoff`通过真实pthread与原版
Linux VMA验证独立buffer的写入/错误码隔离，以及生产者join后转交消费者、扩容、
旧base拒绝和后续写入释放。parallel没有共享可写buffer；handoff明确先同步，
不作为未同步write/free/send竞争安全的承诺。两例均检查全部分配/释放及残留映射
shutdown回收；没有网络或FreeBSD隐式cursor/mbuf ABI证明。

`ker_posix_buffer_writer_create/append/view/destroy` 提供有所有者的单VMA写入游标。
create容量为0..INT_MAX；零容量拥有最小一字节backing，逻辑容量和已写长度仍为0，
不改变raw buffer_alloc(0)的EINVAL。append成功后才增加逻辑长度，溢出/NULL拒绝
保留游标和字节，合法零长度不改变状态。view返回借用的只读指针及可选长度/容量；
失败不改变输出。owner就是登记记录。destroy成功时立即释放VMA，但为防止分配器
复用登记地址后让stale handle指向新owner，会把已销毁登记元数据保留到native
shutdown；这是有意的per-runtime内存开销。unmap失败保留owner供重试，runtime
shutdown也回收未销毁owner。

writer数据的raw free/write和非零realloc返回EBUSY；view只能按已写长度发送，
修改/销毁前必须等待全部zerocopy completion并同步owner访问/交接。它不提供
FreeBSD M_PKTHDR、m_next/per-node m_len，也不改变Linux零字节UDP的行为。

Writer动态集成在原版Linux IPv4/IPv6 loopback上验证空owner、累计append、失败
保留、raw bypass拒绝及完成后的再次append。零append无datagram/completion，
普通Linux零字节UDP仍产生真实datagram与ID0；后续4/8字节发送保留准确编号及
scatter-gather字节。销毁发生在完成之后；runtime退出同时回收raw残留和空writer，
因此这些app场景的buffer_shutdown_releases必须为2。九个source marker完整且唯一。

Writer故障扩展`native-fstack-buffer-writer-constructor/retry`只定点注入当前线程的
登记malloc ENOMEM、mmap ENOMEM或munmap EIO，正常路径始终调用原版实现。
构造失败不污染已有owner，mmap失败释放临时登记；销毁失败保留owner供查询、
同步交接及后继append，另一个owner不受影响，真实重试成功后不能重复unmap。
精确回收全部VMA和一个残留空owner，不计FreeBSD分配器ABI或无同步访问证明。

`ker_posix_buffer_writer_send(owner, fd, offset, length, flags)`发送已写payload的
非空范围，长度0、NULL owner、INT_MAX/范围溢出在发送前返回EINVAL。只接受
imported native socket，host fd返回EBADF、native非socket返回ENOTSOCK；数据进入
与普通sendto共用的原版Linux/zerocopy guard/SIGPIPE适配路径，无host fallback。
返回实际接受字节数或原版Linux错误，flags不改写，短发送由调用者推进offset。
成功和失败均保留writer/cursor，调用者必须等待completion后才append/destroy。
普通send的零字节UDP行为不变；这里是显式owned-payload入口的非空合同。

`ker_posix_buffer_writer_create_segmented(capacity, segment_capacity)` 提供多VMA
owned writer，两个参数必须为1..INT_MAX且节点数不超过IOV_MAX。append按顺序填充
各段，单次输入先快照以保留跨段别名语义；分配失败、越界和NULL不改变字节或总游标。
`ker_posix_buffer_writer_segment`按索引返回借用视图、每段已写长度/容量和总已写长度。
单VMA view/send对分段owner返回EOPNOTSUPP，调用者可以用这些段构建native sendmsg。
这些视图不能跨未同步append/destroy/shutdown或尚未完成的zerocopy引用使用。

销毁先释放子段再释放owner段。首个unmap就失败时仍允许访问；部分释放后若失败，
所有视图/append返回EBUSY，destroy重试仅处理剩余段。所有登记描述符身份保留到
shutdown，避免旧handle冒充新owner；VMA本身成功unmap后立即释放。构造失败的
rollback unmap若失败，登记仍保留给shutdown回收，不伪造成功。

`native-fstack-buffer-segments-layout/failures`使用真实LinuxVMA验证128+50字节
源布局、跨段追加、输入别名、错误原子性、旧handle、部分销毁及精确回收；失败探针
只替换指定malloc/mmap/munmap。此证据不包括socket/PMD传输和全链路无复制。

分段socket集成通过dlsym解析实际动态库API，分别在原版LinuxIPv4/IPv6 UDP上
验证128+50字节节点、总游标178、sendmsg精确接收及真实completion。拒绝单视图
send、溢出append或非法节点不会投递数据或消耗完成编号；实际完成后追加78字节
填满尾段，再发送跨节点100字节子范围。两次completion后才销毁owner，并验证
旧handle无法操作replacement。runtime退出时所有VMA/guard/worker mbuf清零。
zc-validation必须包含全部11个唯一source marker；null PMD下payload仍是Linux
loopback，完整virtio软件数据通路回归另行执行相同owner场景，不宣称全链路无复制。

`native-fstack-buffer-segments-parallel/handoff`补充线程生命周期：四个pthread各自
拥有独立8195字节owner，跨4096/4096/3字节节点追加，验证每段字节/长度、失败
保留、replacement创建后的旧handle拒绝及errno隔离。同步交接用producer join、
consumer join、releaser join明确转移owner；不承诺未同步共享owner访问。计数分别
要求99/9个VMA完整释放，含3个shutdown残留回收。仅扩展已有源场景，不新增计数。

`native-fstack-buffer-segments-constructor-matrix/destroy-matrix`逐一验证四节点
owner的mmap失败位置、三种构造rollback unmap失败，以及全部销毁失败位置
（包含最后的root）。失败只注入调用线程的指定调用，正常syscall仍为原版Linux。
活跃sentinel的字节/节点/游标全程不变；成功syscall增量证明rollback只残留一个
节点，shutdown回收全部三种残留。部分销毁后重复失败仍保持EBUSY，后继成功
只unmap剩余节点；旧handle不能碰replacement。最终19/36次分配释放与5/2个
shutdown残留精确匹配，不以全零最终计数掩盖中途多释放或遗失。

Segmented writers can send any nonempty written range directly with `ker_posix_buffer_writer_send`, including ranges crossing VMA boundaries. The adapter snapshots registered iovecs and submits original Linux sendmsg; it never flattens payloads or changes the writer cursor. Callers retain ownership and await zerocopy completion before mutation or destruction.

`ker_posix_buffer_writer_sendto` supplies an explicit original-Linux destination for an owned range on an unconnected UDP socket. It shares the range and zerocopy ownership checks, preserves the socket association and writer cursor, and requires completion before reuse just like connected sends.
