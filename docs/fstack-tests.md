# F-Stack 测试场景迁移

全量范围、源快照、433 项清单及未完成项见 [全量迁移清单](fstack-migration.md)。
下表仅列既有场景适配，不能作为上游全部测试迁移完成的声明。

F-Stack 的 tests/unit 和 tests/integration 主要针对 lib/ff_* glue layer；
unit 使用多种 stub/wrap，部分 integration 启动实际 EAL，但也用 stub 替代
FreeBSD mbuf/veth。这不是可直接搬入 Ker 的 Linux TCP/IP 一致性套件。
当前迁移固定到 F-Stack dev commit 646a641cfff77f4815e1e29829a09e1ed15a2999。

适配场景由下表逐项列出，各自运行独立 CTest。测试实现重新编写，使用 Ker CHECK
harness 和真实 EAL/mempool，不将 ff_* glue、
FreeBSD 栈或 cmocka mock/stub 当作 Ker 实现。上游测试和脚本另存为完整只读快照，
用于来源审计，不自动运行或计为 Ker 通过。没有通过宿主机 socket 的结果
冒充 Ker 网络栈通过，也不因 EAL 初始化失败跳过用例。

| Ker CTest | 上游场景 | 适配边界 |
|---|---|---|
| native-fstack-idle-wait | test_ff_load_config_valid_minimal_ini 的 idle_sleep 子集 | INI/CLI 微秒等待、实际 ppoll 超时计数、静默后独立宿主 TCP/UDP 和控制关闭；默认保留 Ker 1ms，完整配置合同仍 partial |
| native-fstack-promiscuous | test_ff_load_config_valid_minimal_ini 的 promiscuous 配置子集 | 真实 PMD 开关/回读、INI/CLI、外来 MAC 帧 RX 抓包与原始 Linux socket 过滤；完整最小配置合同仍 partial |
| native-fstack-ipv4-vlan-route | valid_vlan_vip.ini 的 VLAN gateway（相关扩展） | 原始 Linux VLAN IPv4 主表默认路由；独立路由器和远端双向 TCP/UDP、TTL、tagged PCAP/ARP、INI/CLI 及 off-link 失败回收。不是多表/多默认网关迁移 |
| native-fstack-ipv6-vlan-route | valid_inet6.ini 的 VLAN gateway6（相关扩展） | 原始 Linux VLAN IPv6 默认路由；独立路由器与远端 TCP/UDP、hop limit、tagged PCAP/NDP、INI/CLI 和启动失败回收。源 INET6-disabled ignore 用例仍 blocked |
| native-fstack-ephemeral-ports | test_ff_rss_tbl_set_portrange_inverted_range（partial） | 配置通过原始 Linux sysctl 生效；IPv4/IPv6 TCP/UDP 分配、耗尽/复用、保留端口和独立 IPv4 对端验证。RSS 队列专属端口表仍未迁移 |
| native-fstack-config-lifecycle | test_ff_config.c 的 6 项配置加载场景 | 8 个独立检查验证 CLI/INI、缺失文件和加载隔离；3 项适配、3 项部分覆盖，未知节/完整 schema 差异保留。仅配置层证据，不计 NIC/内核互通 |
| native-fstack-launcher-config / native-fstack-launcher-config-interop | test_ff_ini_parser.c：18 项场景适配，1 项多行部分覆盖 | 实际 launcher 的标准库 INI 解析、类型校验、CLI 覆盖和配置文件相对路径；真实 DPDK/原始 Linux TCP 双角色及日志/capture 验证。不是 F-Stack config schema/callback ABI 兼容层。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-worker-log / native-fstack-worker-log-interop | test_ff_log.c 的 13 项场景 | 真实 DPDK 日志文件、追加、实例文件名、流切换、级别过滤、格式与返回值；检查 flush/close 失败。Ker 使用自身分类，不模拟 FreeBSD 分类；独立 Linux TCP 对端验证实际 worker 和 launcher 错误传播。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-thread-runtime | test_ff_pthread_create_arg_passed / test_ff_pthread_create_malloc_failure；basic / join_retval 部分覆盖 | LKL 真实线程、参数和分配失败，扩展验证 TLS/析构/回收、信号量、互斥、join 错误恢复与当前线程 detach 边界；真实 Linux 启停确认线程回调被调用。FreeBSD pcurthread 继承和返回值槽仍未迁移。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-host-runtime | test_ff_malloc_normal / test_ff_free_null / test_ff_clock_gettime_monotonic / test_ff_clock_gettime_ns_advances / test_ff_mmap_munmap_roundtrip / test_ff_mmap_prot_writeonly / test_ff_mmap_prot_readonly | 直接验证原生 LKL 主机回调的内存、单调时钟和映射权限；碰撞不得破坏原有映射。LKL 使用精确地址，区别于 F-Stack 的 NULL 地址分配接口。真实 Linux 启停确认内存/时钟回调被使用；固定地址 mmap 由回调测试覆盖，当前非 MMU 内核启动不走该路径。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-message-io | test_ff_host_msg_name_shutdown_bridges / test_ff_host_readv_writev / test_ff_host_ioctl_fionbio / test_ff_host_dup / test_ff_host_dup2 | 6 个公共 POSIX 场景分别在宿主 Linux 与完整导入内核运行：message/vector I/O、地址查询、半关闭、FIONBIO、dup/dup2；Ker 扩展覆盖零长度 iovec、短读、PEEK/DONTWAIT、FIONREAD、共享状态与跨后端 fd 替换。原生连接计数必须增长；UNIX socket 明确走宿主透传。上游场景只测试 FF_KERNEL_COEXIST 宿主桥接，本适配不声称上游已验证用户态 TCP。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-stream-io | test_ff_host_msg_name_shutdown_bridges / test_ff_host_readv_writev | Ker-specific 独立对端扩展：vector、message、batched-message 三种 API × 原生客户端/服务端，共六种组合；每方向校验 256 KiB + 13 字节、非阻塞进度、半关闭和 EOF，逐实例断言 DPDK TX/RX、原生 open 和回收。上游只有小型宿主桥接，不覆盖本测试的原生 TCP、DPDK 或 sendmmsg/recvmmsg 扩展。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-udp-interop | test_ff_dpdk_if_send_udp_csum；adapter/syscall/main_stack_udp.c（示例） | Ker-specific 原生 UDP socket 扩展：三种 API × 原生客户端/服务端，对独立宿主 Linux 验证 0/1/33/257 字节 datagram、epoll、peer tuple、peek/truncation、connected UDP 和 batch。原生 UDP SNMP 计数及 DPDK 收发/回收必须通过。上游 checksum 用例只验证 TX offload，UDP 示例不是自动测试；本批调用完整原始 Linux UDP，不走基础报文构造路径。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-epoll | test_ff_epoll_create_returns_fd / test_ff_epoll_ctl_add_event / test_ff_epoll_ctl_mod_event / test_ff_epoll_ctl_del_event / test_ff_epoll_wait_* / EPOLLET / EPOLLONESHOT cases | 8 个真实 POSIX TCP 场景分别在宿主 Linux 与完整导入内核上运行并比较结果，覆盖参数、ADD/MOD/DEL、64 位 userdata、LT/ET、oneshot 重置、仅写就绪、半关闭 EOF 与 RST/ERR/HUP；原生连接计数和 mbuf 回收必须通过。同一 CTest 还运行独立宿主对端的 DPDK 互通。上游用 cmocka 合成 kqueue 事件，本适配不复制 stub/FreeBSD 行为；Linux 的 create(0) 返回 EINVAL，半关闭检查 RDHUP，未声称覆盖无效指针和未知 kqueue filter。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-readiness / host-fstack-readiness-reference | test_ff_host_kqueue_ctl_poll / test_ff_host_ioctl_fionbio | Ker-specific poll/select 扩展：同一公共 POSIX 程序在宿主基线和原生内核分别检查 8 个场景，包括监听、混合 pipe/TCP、计数、无效 fd、带外数据、低水位及 EOF。原生连接计数与回收须通过。上游仅为 FF_KERNEL_COEXIST 宿主 readiness/FIONBIO 桥接，本批不声称上游已有这些 poll/select 测试。需 KER_WITH_NATIVE_TCP=ON |
| native-fstack-socket-contracts / host-fstack-socket-contracts-reference | test_ff_host_msg_name_shutdown_bridges / test_ff_host_ioctl_fionbio / test_ff_host_dup | Ker-specific TCP socket 契约扩展：6 个宿主/原生场景覆盖创建与 accept 标志、地址长度截断、socket option 错误恢复、bind 冲突和重复 fd 的 fstat 身份/生命周期。上游仅测试 host bridge，本批以 Linux 语义断言，不复制 FreeBSD 行为。原生 open 与回收计数必须通过。需 KER_WITH_NATIVE_TCP=ON |
| flow-icmpv4 | test_ff_dpdk_if_send_multiseg | Stateless ICMP quotation parsing extracts the quoted UDP flow key for generic packet steering. Segmentation, truncation, length, options and fragment boundaries preserve input ownership; it creates no connection or send evidence and is not an F-Stack ICMP or NIC/RSS test |
| fstack-mbuf-release | test_ff_dpdk_pktmbuf_free_basic | 实际 Ker packet pool alloc/free，验证可用对象数恢复 |
| fstack-clock-monotonic | test_ff_get_tsc_ns_monotonic | Ker CLOCK_MONOTONIC ns，验证非递减，不复制 TSC 算法 |
| fstack-empty-export | test_ff_dpdk_if_send_zero_total | 空 skb copy-export，断言长度和所有权，不宣称网卡发送 |
| fstack-null-context | test_ff_dpdk_if_send_null_ctx_no_crash | Ker allocation 拒绝 null context，输出不变 |
| fstack-arp-chain-feedback（first-contact discovery） | test_ff_dpdk_if_send_basic | Ker-specific 首次邻居解析：显式 IPv4 peer、无预设 MAC，从 NUD_NONE 经原生 ARP 排队/回复后发送；验证创建回滚、生命周期和失败恢复。不代表完整 Linux 邻居创建子系统、路由、一般 ARP learning 或 NIC 发送 |
| neighbor-timer（known-peer resolution） | test_ff_dpdk_if_send_basic | Ker-specific Linux 邻居重新解析：已有受监控 peer 从 FAILED 进入 INCOMPLETE，原生有界队列暂存数据、ARP callback 构造探测包、有效回复触发原生 FIFO flush，覆盖淘汰、超时释放与取消；不是 F-Stack 上游 ARP 测试，不代表未知邻居发现、路由或 NIC 发送 |
| neighbor-timer（resolved output） | test_ff_dpdk_if_send_basic | Ker-specific Linux 原始 `neigh_resolve_output` 移植：已有 MAC 的受监测 IPv4 邻居重建 Ethernet 头并交给有界 TX exporter，覆盖 NUD 状态、更新后的 MAC、所有权及背压；原始 Linux 函数另由 `neighbor-output-import` 校验来源。不代表 F-Stack 邻居测试、未知邻居解析、路由或 NIC 发送 |
| fstack-packet-export | test_ff_dpdk_if_send_basic | 实际字节复制；原始 backing 释放后 copy 仍可读取 |
| fstack-multiseg-boundary | test_ff_dpdk_if_send_multiseg | skb adoption API 仍 fail-closed；独立的 TX exporter 将受支持 skb 复制为 DPDK 段，并由 `ethdev-tx` 用真实 net_ring PMD 验证正向发送 |
| ethdev-tx | test_ff_dpdk_raw_packet_send_basic / test_ff_dpdk_raw_packet_send_multiseg; test_ff_dpdk_if_send_tcp_csum / test_ff_dpdk_if_send_udp_csum | Ker-owned bounded TX adapter borrows a caller-configured/started DPDK ethdev queue. A pinned DPDK `net_ring` PMD receives and exposes exact 64-byte and 4096-byte multisegment packets; the test also verifies FIFO, ring-full retry, pool exhaustion and PMD `opackets`. The test also checks private opt-in software TCP/UDP checksum completion against an independent wire oracle, including standard folded-zero UDP mangling and caller-selected exact folding over a segment boundary; the old init mode still rejects partial-checksum skbs. The upstream checksum cases exercise hardware-offload metadata, not this software completion; this adds no hardware offload, NIC, or full-stack support. |
| ethdev-rx | test_main_loop_one_iteration_then_stop | Ker-specific borrowed ethdev RX adapter feeds the existing Ethernet classifier and worker receive dispatcher. A real pinned DPDK `net_ring` PMD injects segmented frames; the test covers one-packet worker budgets, FIFO, pool-pressure retry/cancel, and binding exclusion. Opt-in immutable-reference profiles test direct shared segments, actual DPDK clones and attached external-buffer clones with callback lifetime. Pinned F-Stack free/fanout cases do not test clone or external-buffer RX. The upstream case only motivates the worker-loop boundary; no NIC/RSS/full-stack support is claimed. |
| ethdev-external-lifetime | test_ff_dpdk_pktmbuf_free_basic | Ker-specific RX 最后引用生命周期扩展：真实 `net_ring` 接收 external/direct/external 混合链，不保留 parent/sibling；DPDK 释放回调覆写并暂存源缓冲区，验证上层保留的 owned skb 在源数据覆写及实际释放后均完整。覆盖重复 ENOMEM、部分预算完成后的 FIFO 恢复、取消转交、transformed metadata 丢弃、精确回调次数和双 pool 回收。仅测试既有 copy/classify/dispatch 适配，不验证 IPv4/TCP/UDP 协议行为；上游只释放基本 mbuf，不含外部缓冲区 RX、NIC 或硬件 offload 场景。 |
| ethdev-rx-capacity | test_ff_dpdk_if_send_multiseg | Ker-specific RX 线性复制容量边界：真实 `net_ring` 将小源池的多段帧复制到独立目标池，验证容量前一字节、恰好容量和超出一字节；覆盖三种 headroom、非缓存行对齐的 data room 与 Linux shared-info 预留。目标池耗尽时，永久超限帧仍以 ENOSPC 消费/drop，后续可容纳帧以 ENOMEM 保留，释放一个 backing 后按 FIFO 恢复；逐字节检查并确认双 pool 回收。负载保持 opaque，不声明 IPv4/TCP/UDP 协议、jumbo MTU 协商、NIC 或非线性 skb 支持；上游只提供多段 TX 场景动机。 |
| ethdev-rx-fanout | test_main_loop_one_iteration_then_stop / test_ff_dpdk_pktmbuf_free_basic | Ker-specific Linux `packet_type` 分发与所有权扩展：真实 `net_ring` 分段帧通过 worker、原始 Ethernet 分类器和导入的 Linux ptype delivery，验证全局/设备 handler 顺序、各自 descriptor 引用、最终 handler 状态、非法返回值和无 handler 丢弃。保留 skb 并克隆，在目标池耗尽时验证 COW 回滚、恢复后的头部/负载隔离、两种释放顺序及完整回收。上游只提供 worker iteration 和基本 mbuf 释放动机，不含 Linux fanout/COW 场景；负载保持 opaque，不声明 IP/transport 协议、F-Stack RX 或 NIC 支持。 |
| ethdev-rx-metadata | test_ff_dpdk_if_send_tcp_csum / test_ff_dpdk_if_send_udp_csum | Ker-specific RX trust-boundary extension: real `net_ring` bursts pass TCP/UDP frames through the worker, original Ethernet classifier and existing transport packet views. GOOD/BAD/UNKNOWN checksum hints never bypass software checksum validation; deliberately corrupted IPv4/TCP/UDP checksums are dropped, while valid bytes pass despite BAD hints. NONE and transformed VLAN/LRO/security metadata are rejected, with valid successors proving FIFO progress and pool reclamation. The upstream cases cover TX checksum-offload metadata only; this is not hardware-offload or NIC RX coverage. |
| ethdev-rebind | test_ff_dpdk_register_deregister_roundtrip | Ker-specific borrowed ethdev RX lifecycle extension: a real started `net_ring` port retains a queued frame behind a pending packet across adapter/device/runtime teardown, then a fresh callback generation rebinds the same queue and consumes it in FIFO order. The test also covers pending-packet cleanup exclusion, exact cancellation, invalid rebind rollback, and pool reclamation. The upstream registration roundtrip motivates lifecycle testing only; neither test promises that queued PMD frames are flushed or implements full F-Stack device registration. |
| ethdev-duplex | test_main_loop_one_iteration_then_stop; test_ff_dpdk_if_send_tcp_csum / test_ff_dpdk_if_send_udp_csum | Ker-specific composition test cross-connects two actual pinned DPDK `net_ring` ethdev ports. Both workers poll the existing TX and RX adapters through their shared callback argument; separate pools carry multisegment software-checksummed TCP/UDP frames through the original Ethernet classifier and transport views. Independent wire checksum checks, FIFO, TX ring-full retry, destination-pool pressure retention, callback drop, and reclamation are verified. These upstream cases motivate the worker/send/checksum boundaries only; this is not full F-Stack, hardware offload, NIC, or application-protocol coverage. |
| ethdev-multiqueue | test_ut_nr_19_drain_ring_sp_sc | Ker-specific multi-EAL extension: two owner workers on distinct EAL lcores use separate bounded `net_ring` ethdev queues, pools, contexts, and existing TX/RX adapters. It verifies worker-dispatched TCP/UDP payloads and checksums, FIFO, queue-0 backpressure while queue 1 progresses, queue-0 recovery, and wrong-owner rejection. The upstream case motivates queue isolation only; this does not test ring reload, RSS, multiprocess, physical NICs, or full F-Stack. |
| fstack-queue-isolation | test_ut_nr_19_drain_ring_sp_sc | 两个本地 Linux skb FIFO 隔离，不等价于多进程 generation/ring |
| fstack-queue-full-ownership | 同上 | 满队列不消费调用方引用，可用 pool 对象数不变 |
| fstack-export-exhaustion-retry | test_ff_dpdk_if_send_copydata_fail | 真实 pool 耗尽时输出槽和 skb 所有权不变；释放一个 mbuf 后重试成功，不模拟 copydata 错误 |
| fstack-offload-metadata-rejection | test_ff_dpdk_if_send_ip_csum / test_ff_dpdk_if_send_tso | Ker 当前明确拒绝无法执行的 checksum/GSO 元数据，验证对象不变并在清除标记后成功导出；不宣称正向 offload |
| fstack-software-checksum-completion | test_ff_dpdk_if_send_ip_csum | Ker-specific software completion extension：复制线性 CHECKSUM_PARTIAL skb，并以 Linux Internet-checksum primitives 在副本上完成 UDP/TCP pseudo-header-seeded checksum；CRC32C（当导入 skb layout 暴露该标志时）、GSO 与普通 export 仍 fail-closed，输出无 TX offload flag，不代表 F-Stack 网卡 offload |
| fstack-headroom-export | test_ff_dpdk_if_send_basic | 显式 headroom 转为 mbuf data_off，检查字节和 skb 释放后的副本生命周期 |
| fstack-multiseg-copy | test_ff_dpdk_if_send_multiseg | 真实多段 DPDK 输入复制并合并到线性 Linux skb，检查零长度段、源链所有权和释放源链后的数据；不代表上游分段 TX 或 Linux nonlinear skb 支持 |
| fstack-multiseg-ethernet-ingress | test_ff_dpdk_if_send_multiseg | 将目的/源 MAC 和 EtherType 拆分到真实 DPDK 段中，经 Ker copy adapter 线性化后调用原始 Linux Ethernet 分类器，并经现有 raw packet-view dispatch；方向改为 ingress，不宣称 F-Stack TX、NIC/offload 或 Linux nonlinear skb |
| fstack-flow-owner-receive | test_ff_dpdk_if_send_multiseg | Ker-specific owner 接收适配器：分流后进入有界本地队列，由 worker service 执行 copy/classify/dispatch；目的包池耗尽保留 pending、允许 TX 释放缓冲区并按 FIFO 重试，队列满显式释放并计数丢弃。验证恢复、取消、生命周期 pin 和初始化回滚；不代表无损背压、NIC/RSS、socket 或 TCP 状态 |
| fstack-flow-concurrent-receive | test_ff_dpdk_if_send_multiseg | Ker-specific 跨 CPU 完整 flow 接收链路：真实 source ring 经 ingress worker 的 flow-ring 分流到另一固定 CPU 的 owner，再用其独立 pool/context/device 执行 Ethernet 和 TCP/UDP 校验。验证 immutable 期望包、确定性 inbox 背压及 FIFO、checksum 丢弃、owner pool 耗尽/恢复与清理；少于两个可用 CPU 时明确 skip。上游仅是 segmented TX 场景，不代表 NIC/RSS、socket 或 TCP 状态实现 |
| fstack-flow-receive | test_ff_dpdk_if_send_multiseg | Ker-specific steering/ingress extension：segmented IPv4 TCP/UDP 经真实 source ring 和 worker RX 的 flow-ring adapter，再经固定 flow owner 分流、worker handoff、owner 独立 pool/context/device 和原始 Ethernet 分类后进入 transport checksum 校验。覆盖 IHL 5–15 的全部 IPv4 options 长度、options 区域 checksum 损坏、本地/远端、capacity-one 背压 pending/FIFO 重试、坏 checksum drop，以及 owner pool 耗尽时显式消费/drop 和恢复。flow-chain 另覆盖 IPv4/IPv6 分段解析与链所有权，flow-ip-options 检查可变 IHL 与截断/长度边界；options 保持 opaque，不处理 source-route 等语义；上游是 TX 场景，不是 flow/RSS 或 ingress 测试；这里不实现 NIC、socket、TCP 状态或 IPv6 transport |
| fstack-arp-chain-feedback | test_ff_dpdk_if_send_multiseg | Ker-specific integration extension：将有效 ARP reply 的以太网和 ARP 字段拆分到 DPDK chain，经 copy/classify、原始 ARP decoder 和实际 worker RX poll，验证 scoped neighbor feedback 从 DELAY 更新至 REACHABLE，以及启用 known-peer resolver 后从 INCOMPLETE 接受回复、发送排队数据和 TX 满时消费/drop；无效广播回复保留待解析队列。该场景不是 F-Stack 上游测试，不代表一般 ARP learning 或 NIC 收发 |
| arp-configured | RFC 826 §2 (format reference; Ker-specific test) | 使用显式静态 IPv4 address 和调用方 MAC tuple 调用原始 ARP request/reply constructor；按42个wire bytes验证broadcast/zero-THA request、reply与旧 raw adapter 等价，并覆盖失败回滚。既有 arp-receive 测试另覆盖 DAD、Ethernet padding、malformed fields、copied-message lifetime 和 callback ownership。无 neighbor lookup、自动应答、路由或 NIC 收发 |
| fstack-icmp-echo-service | test_ff_dpdk_if_send_basic / test_ff_dpdk_if_send_multiseg | Ker-specific 单个显式 peer 的自动 echo 回复：现有 transport receiver 校验后进入服务，回复经原生有界邻居解析、ARP responder 和 scoped feedback，从真实 ring 返回对端。保留 UDP/TCP/type-0 回调；不代表 F-Stack ping/socket、完整 Linux ICMP、路由或 NIC。详见 [服务边界](linux-icmp-echo-service.md) |
| arp-responder | test_ff_dpdk_if_send_basic / test_ff_dpdk_if_send_multiseg | Ker-specific 本地 ARP 自动应答与双端首次通信：生产 responder 构造回复，经真实 DPDK ring 和 worker RX 驱动 discovery、邻居队列发送和 UDP 校验交付；覆盖请求筛选、应答分配/入队失败及 exporter 重试。不代表完整 arp_process、通用邻居学习、路由或 NIC 收发 |
| arp-ring | test_ff_dpdk_if_send_multiseg | Ker-specific bounded-ring integration：configured ARP request/reply 被 worker TX exporter 复制为真实 segmented DPDK chains，经容量受限ring进入实际 worker RX poll、Ethernet classifier 和原始 ARP receiver；覆盖重试、bad-reply feedback拒绝、短帧drop及pool-pressure取消/FIFO恢复。F-Stack源用例不是ARP测试；不代表ARP学习、自动应答、NIC/RSS或F-Stack RX |
| arp-concurrent-ring | test_ff_dpdk_if_send_multiseg | Ker-specific same-process SP/SC扩展：独立EAL producer/consumer worker通过capacity-one ring发送192个逐个可区分的configured ARP request/reply，consumer使用自身pool/context/device和worker RX dispatcher验证原始消息及FIFO次序。上游用例仅提供segmented-ring动机；不声称MPMC、多进程、NIC/RSS或通用ARP协议栈 |
| fstack-ipv4-ingress-validation | test_ff_dpdk_if_send_multiseg / test_ff_dpdk_if_send_ip_csum | Ker-specific ingress extension：真实 EAL segmented Ethernet/IPv4 frame 经 copy/classify 后，以原始 `ip_fast_csum` 检查 IPv4 base/options header，验证长度、padding、fragment 字段和失败所有权。Pinned F-Stack 两个用例都是 TX 路径，没有 IPv4 ingress/header-validation case；本测试不模拟 `ip_rcv`、路由、reassembly、transport/socket 或 NIC delivery |
| fstack-udp-ingress-validation | test_ff_dpdk_if_send_udp_csum | Ker-specific ingress extension：真实 EAL segmented UDP/IPv4 datagram 经已有 IPv4 view 后，用原始 Linux pseudoheader checksum helpers验证偶数/奇数payload、checksum零值语义和长度/fragment/协议失败。Pinned F-Stack case仅设置TX UDP checksum offload并调用 send；不覆盖UDP ingress，也不代表socket、路由、reassembly、ICMP、NIC或TX offload |
| fstack-udp-minimal-boundaries | test_ff_dpdk_if_send_udp_csum | Additional Ker-specific real-EAL regression：minimum 8-byte UDP headers with zero/nonzero checksum, both ports zero, even payload and Ethernet padding exclusion; independent checksum oracle plus source/copy lifetime checks. Upstream case remains TX-only |
| fstack-tcp-ingress-validation | test_ff_dpdk_if_send_tcp_csum | Ker-specific ingress extension：真实 EAL segmented IPv4/TCP，经原始 IPv4 view 后校验完整 TCP pseudoheader checksum、20–60 byte header/data offset和opaque options。Pinned F-Stack case只覆盖TCP TX checksum offload。本测试不解释 TCP options、不实现连接状态、routing、reassembly、socket或NIC delivery |
| transport-receive | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific actual-worker RX integration：ETH_P_IP handler 验证 IPv4 后同步交付 borrowed IPv4/UDP/TCP views；分段源链在 dispatch 前释放，验证 checksum/fragment/protocol rejection、callback DROP/invalid status、回调期 unregister/cleanup EBUSY 和多 handler fanout 对共享 skb descriptor 的 fail-closed `-EBUSY`。Views 只能在同步 callback 内读取，不得保留、修改或释放；共享 descriptor 不交付。ICMP echo request/reply 后续在独立 `icmp-echo` case 覆盖。上游场景是 TX offload；此用例不代表 socket、routing、reassembly、TCP state 或 NIC delivery |
| icmpv4-service | test_ff_dpdk_if_send_basic / test_ff_dpdk_if_send_multiseg | Ker ICMPv4 service/parser adapters and generic control events; no TCP/UDP endpoint table or protocol state machine. Scope and unsupported IPv4 subsystems are documented in [control service](linux-icmpv4-control.md) |
| icmp-echo | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific ICMPv4 echo extension following [RFC 792](https://www.rfc-editor.org/rfc/rfc792.html): constructs explicit-address Ethernet/IPv4 echo request/reply packets with opaque IPv4 options and full ICMP checksum, then validates echo type/code/checksum through immutable views and the actual worker transport receiver. ICMP checksum zero is retained as computed; this is not automatic reply, ICMP error handling, ping, routing, reassembly, socket or NIC support. The pinned F-Stack cases cover UDP/TCP TX offload, not ICMP |
| ipv4-field-profiles | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum / test_ff_dpdk_if_send_multiseg | Ker-specific UDP/TCP/ICMP echo constructor extension: copies an opaque IPv4 DS byte and wire-order identification, permits only fragment field zero or DF, and checks IPv4 and transport checksums with independent byte oracles. Permanent-neighbor variants snapshot the configured source and neighbor MAC; a concurrent 192-packet three-protocol TX/RX case checks copied fields on real worker threads. RX-ring tests also preserve a DF profile through exact software checksum completion, allocation-pressure cancellation and FIFO recovery. This does not change RX handling of the raw IPv4 reserved fragment bit. Existing constructors remain byte-identical zero-profile wrappers. The pinned cases do not test these IPv4 fields; this adds no DSCP/ECN policy, ID generation, fragmentation, PMTU, routing or NIC behavior |
| icmp-neighbor-create | test_ff_dpdk_if_send_udp_csum | Ker-specific extension builds ICMP echo packets from one configured local address/device and an existing permanent neighbor, releases the lookup reference before allocation, and verifies options/checksum through TX retry and worker RX. The upstream case does not test ICMP or neighbor selection; no ARP resolution, routing, automatic reply, ICMP errors, ping, socket or NIC behavior is claimed |
| icmp-chain-exact-fold | test_ff_dpdk_if_send_multiseg / test_ff_dpdk_if_send_udp_csum | Ker-specific opt-in software checksum completion preserves a folded zero in a copied DPDK chain and verifies it through actual worker RX with ring backpressure. The legacy checksum mode continues its existing zero-mangling behavior. This is not hardware offload and does not define other protocols' zero policy |
| udp-create | test_ff_dpdk_if_send_udp_csum | Ker-specific software packet-construction/roundtrip extension：显式地址/端口构造 Ethernet+IPv4+UDP owned skb，Linux checksum primitives 生成 IP/UDP checksum，再 copy-export、拆段并经实际 worker transport receiver 校验。输入 payload 被复制；不代表上游 TX offload、路由、地址策略、socket 或 NIC发送 |
| udp-configured-create | test_ff_dpdk_if_send_udp_csum | Ker-specific extension snapshots source IPv4/MAC from one live configured address and uses caller-supplied destination MAC/IP literally; independent IP/UDP wire checks cover opaque IPv4 options and zero/DF field profiles. It preserves the raw constructor APIs and performs no neighbor lookup, subnet selection, FIB, routing, socket delivery, or NIC transmission |
| tcp-configured-create | test_ff_dpdk_if_send_tcp_csum | Ker-specific configured-source TCP constructor extension snapshots source IPv4/MAC from one live address/device and uses literal destination MAC/IP; independent wire oracles cover opaque IPv4/TCP options, copied zero/DF fields and TCP checksum behavior including a valid zero result. The upstream case is TX checksum-offload only; this adds no neighbor lookup, routing, TCP state, socket, NIC, or hardware offload |
| icmp-echo-configured-create | test_ff_dpdk_if_send_udp_csum | Ker-specific configured-source ICMP echo request/reply constructor extension; independent byte oracles verify full IPv4 and ICMP checksums (including folded zero), option copying and zero/DF fields. It also cross-checks UDP/TCP/ICMP address-association rollback. The pinned upstream case is a UDP checksum TX scenario, not ICMP; this adds no automatic reply, neighbor resolution, routing, ICMP errors, socket, or NIC behavior |
| udp-ip-options | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_multiseg | Ker-specific extension adds opaque IPv4 option bytes to explicit Ethernet/IPv4/UDP construction, checks the variable-IHL IPv4 and UDP pseudoheader checksums, then exports and receives a segmented copy through the actual worker path. Options are copied byte-for-byte but not interpreted; the upstream cases motivate checksum and segmented-buffer coverage, not IPv4 options behavior. No routing, source-route processing, socket delivery or NIC transmission is claimed |
| udp-neighbor-create | test_ff_dpdk_if_send_udp_csum | Ker-specific extension derives the source IPv4/MAC from its configured address/device and destination MAC from an existing permanent neighbor entry, releases the lookup reference before allocation, then exercises TX retry and segmented worker RX. It does not perform ARP resolution, FIB lookup, routing, source selection, socket delivery or NIC transmission |
| udp-neighbor-ip-options | test_ff_dpdk_if_send_udp_csum | Ker-specific neighbor-backed UDP constructor extension copies opaque IPv4 options, verifies variable-IHL/IP and UDP checksums, reference release, rollback and worker RX retry. No upstream neighbor/options scenario, ARP resolution, routing, source fallback, socket or NIC behavior is claimed |
| tcp-create | test_ff_dpdk_if_send_tcp_csum | Ker-specific explicit-address Ethernet/IPv4/TCP construction and worker receive-roundtrip extension: software checksums are checked by an independent byte oracle, a TX sink backpressure retry exports a copy, and the accepted copy is segmented before native Ethernet classification and TCP view delivery. This does not implement TCP connection state, sockets, routing, NIC transmission or hardware offload |
| tcp-options | test_ff_dpdk_if_send_tcp_csum | Ker-specific extension constructs TCP headers with copied opaque 0–40-byte aligned options and verifies the complete checksum after TX retry, segmentation and worker receive. The pinned F-Stack case is TX checksum-offload only; Ker does not interpret options or add TCP state/socket/NIC support |
| tcp-ip-options | test_ff_dpdk_if_send_tcp_csum / test_ff_dpdk_if_send_multiseg | Ker-specific extension constructs IPv4/TCP packets with independently supplied opaque IPv4 and TCP option bytes, checks both header checksums with independent wire oracles, then exports a real segmented copy through worker TX/RX. Existing no-IP-options APIs remain zero-option wrappers. The F-Stack cases motivate checksum/segmentation coverage, not option semantics; no routing, source-route processing, TCP state, socket or NIC behavior is claimed |
| tcp-neighbor-create | test_ff_dpdk_if_send_tcp_csum | Ker-specific extension derives source IPv4/MAC from one configured address/device and destination MAC from an existing NUD_PERMANENT neighbor, releasing the lookup reference before allocation. It tests TCP options/checksum through TX retry and segmented worker RX; upstream does not test neighbor selection or ARP. No unresolved queue, FIB, routing, source fallback, TCP state, socket or NIC transmission is claimed |
| tcp-neighbor-headers | test_ff_dpdk_if_send_tcp_csum | Ker-specific combined neighbor constructor copies independent opaque IPv4/TCP options (including 40-byte areas), verifies both checksums and lookup-reference release before allocation, then exercises worker TX/RX retry. Existing TCP neighbor API/error precedence stays unchanged; no option interpretation, ARP resolution, routing, TCP state, socket or NIC transmission is claimed |
| fstack-chain-export | test_ff_dpdk_if_send_multiseg | Ker-specific positive copy extension: copy a supported linear UDP/TCP constructor skb into a caller-owned direct DPDK chain, release the source, then receive the chain through existing copy/classify and worker transport validation. This is not native Linux nonlinear skb support, upstream F-Stack TX, NIC transmission or offload |
| tx-chain-export | test_ff_dpdk_if_send_multiseg | Ker-specific worker TX retry extension: opt-in `CHECKSUM_NONE` mode copies a supported linear skb to a direct DPDK chain; sink acceptance transfers the whole chain, while rejection frees the copy and retains the original FIFO skb for retry. Legacy single-mbuf software-checksum export remains separate. This is not F-Stack/NIC transmission, nonlinear Linux skb support, or hardware offload |
| fstack-chain-software-checksum | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific software-completion extension: completes a linear `CHECKSUM_PARTIAL` skb using Linux checksum semantics, copies it into direct DPDK segments even when the checksum word crosses a segment boundary, then validates UDP/TCP through native Ethernet classification and the actual worker receiver. Coverage includes variable IPv4 IHL with checksum start after the full options area. The pinned F-Stack cases exercise TX checksum offload; this does not claim NIC/hardware offload, nonlinear Linux skb support, sockets or TCP state |
| tx-ring-drain | test_ff_dpdk_if_send_multiseg | Ker-specific application-ring transport extension: worker TX copies into a bounded exact-capacity DPDK pointer ring with SP/SC flags; a single consumer drains whole chains and feeds the existing copy/classify worker RX path. Ring-full returns EAGAIN so the TX exporter retains the original skb for retry. This does not implement an ethdev, NIC/RSS, multi-process sharing or F-Stack TX |
| rx-ring-drain | test_ff_dpdk_if_send_multiseg | Ker-specific worker RX extension over the application ring: one attached consumer copies accepted direct chains into owned Linux skbs and dispatches them through the existing Ethernet and IPv4 transport receive path. Allocation pressure retains the popped chain for retry; option-bearing UDP/TCP frames preserve FIFO order through retry and cancel; ICMP echo is delivered and a bad ICMP checksum is consumed as a drop without callback. This does not implement ethdev RX, NIC/RSS, NAPI polling or sockets |
| fstack-concurrent-ring | test_ff_dpdk_if_send_multiseg / test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific concurrent same-process SP/SC integration: a capacity-one ring is filled before its registered EAL consumer starts, forcing TX-export retry, then producer A and consumer B overlap for 192 alternating UDP/TCP/ICMP echo chains across repeated ring wraparound. IPv4 and TCP option lengths vary and are checked byte-for-byte after RX. The consumer uses its own worker, memory context, pool, device and actual RX dispatcher. It does not claim MPMC, multiprocess/RSS, NIC I/O or F-Stack RX |
| configured-ring | test_ff_dpdk_if_send_multiseg / test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific configured-source worker integration: UDP, TCP and ICMP echo frames are built from one configured address and pass through normal or exact software checksum export, a bounded DPDK ring, Ethernet classification and the actual worker protocol receiver. It checks IPv4/transport checksum and fragment/protocol rejection, pool-pressure cancellation with FIFO recovery, and ARP plus IPv4 handlers sharing the configured device/runtime registration lifetime. This is not automatic ARP, routing, a socket stack, NIC I/O or F-Stack ingress |
| cross-worker-ring-rx | test_ff_dpdk_if_send_multiseg | Ker-specific same-process SP/SC extension: an EAL worker A exports UDP/TCP chains into a DPDK ring and a distinct worker B uses its own pool, context, device and actual worker RX poll to classify and validate them. Pool pressure preserves FIFO pending ownership for retry. Producer/consumer lifecycle changes require external quiescence; this does not claim RSS steering, multiprocess rings, NIC I/O or F-Stack RX |
| tx-chain-software-checksum | test_ff_dpdk_if_send_udp_csum / test_ff_dpdk_if_send_tcp_csum | Ker-specific worker TX extension: the opt-in chain exporter accepts ordinary `CHECKSUM_NONE` and supported Internet `CHECKSUM_PARTIAL` packets. It completes each partial checksum in an independent chain copy; sink rejection frees that copy and retains the unchanged original for FIFO retry. Existing CHECKSUM_NONE-only chain mode and legacy single-mbuf completion remain separate. This does not claim NIC/hardware offload, nonlinear Linux skb support, sockets or TCP state |
| tx-copy-export-retry | test_ff_dpdk_if_send_udp_csum | Ker-specific worker TX copy/retry extension: bounded owner-worker FIFO retains the original skb until a synchronous application sink accepts its copied mbuf; allocation and sink backpressure preserve the pending head, and cancellation returns it before later FIFO entries. The sink is not an ethdev/NIC, and this does not implement F-Stack hardware offload or transmission |

逐例上游路径、case 名、固定版本和原始文件 SHA256 记录于
[provenance](../tests/fstack-provenance.json)。源链接固定到具体 commit；这是
场景追溯记录，不宣称生成或逐字执行原始 suite，也没有把上游 README 的测试
数量/覆盖率数字当成 Ker 的实测结果。

运行：

```bash
ctest --test-dir build -R '^fstack-' --output-on-failure
```

这些用例仅随 KER_WITH_DPDK 启用。每例独立进程，使用现有无 hugepage/无 PCI
EAL 测试初始化，显式检查全部 descriptor、queue 和 pool 回收。DPDK 沿用
项目固定 submodule 版本，不替换成上游 Makefile 的主机版本。

## 后续迁移顺序

- 新增的 `ker_skb_copy_from_mbuf_chain` 仅将经校验的独占 direct DPDK 输入链复制成线性 skb；`ker_skb_from_mbuf` 仍拒绝多段 adopt，且此适配不保留 DPDK 分段边界。下一步若实现 Linux skb 非线性片段语义及相应 DPDK 引用生命周期，再测试原生分段 skb 导出；当前用例不宣称上游多段 TX 正向支持。
- `ker_skb_to_mbuf_chain_copy` 为受支持的 owned 线性 skb 创建独立 direct DPDK chain，首段保留 skb headroom、后续段用默认 headroom，并在失败时释放所有部分分配；既有单段 `ker_skb_to_mbuf` 不变。它仅提供显式复制，不暴露 Linux skb fragment/list 语义，也不代表 NIC/offload 或 F-Stack 原生发送路径。
- 新增的 `ker_eth_receive_copy_chain` 在 copy-in 后调用未修改的 `eth_type_trans`，并允许既有packet-view adapters 处理分类后的 skb；源 mbuf 链仍由调用者持有。Ethdev TX 已有真实 `net_ring` 适配器；硬件 offload、物理网卡及完整 F-Stack TX 路径仍未接入。
- `ethdev-tx` 现有显式软件 checksum mode 只完成受支持的 Internet CHECKSUM_PARTIAL 副本；它不协商或启用 NIC checksum offload，也不提供 TSO/GSO。将来若接入硬件 offload，必须单独协商能力并验证真实设备路径，不能把本软件 completion 用例当作硬件 offload 覆盖。
- `ker_skb_to_mbuf_software_checksum` 仅为线性 Internet-checksum CHECKSUM_PARTIAL skb 提供软件 completion 副本；当导入的 skb layout 暴露 `csum_not_inet` 时会拒绝 CRC32C，且始终拒绝 GSO。它与 F-Stack 原用例的 NIC offload path 不同，也不改普通 `ker_skb_to_mbuf` 的 fail-closed 约束。
- `ker_skb_to_mbuf_chain_software_checksum_exact` 和对应显式 TX mode 保留折叠结果为零的字节；旧 checksum API 仍将 Internet checksum 的零映射为 `CSUM_MANGLED_0`。`CHECKSUM_NONE` 仍按普通复制处理。调用方负责选择协议要求的零值策略；此选项不宣称 NIC/offload。
- `ker_ipv4_packet_view_init` 只验证owned/classified linear IPv4 skb的完整header/options、total length和原始checksum，并借出只读view；不改变 skb 长度，padding留在原位置，fragment字段只是原始wire-order值。此项是Ker-specific extension，非上游IPv4 ingress场景，无fragment reassembly、FIB、netfilter、L4或socket处理。
- `ker_udp_packet_view_init` 进一步验证 unfragmented IPv4 UDP 的完整固定头、精确匹配的UDP/IP长度及伪首部checksum；合法IPv4 UDP零checksum按协议作为checksum omitted接受。UDP头/负载以只读borrowed pointers返回，保留wire-order字段，不修剪padding、不送socket，也不信任RX checksum元数据跳过软件校验。该场景由TX-only F-Stack UDP checksum用例启发，属于Ker-specific ingress扩展。
- `ker_tcp_packet_view_init` 进一步验证unfragmented IPv4 TCP segment、完整 TCP pseudoheader checksum、最小/最大data offset及完整segment bounds；TCP checksum字段值零不作为省略标志，只按同一校验算法验证。Header options保持opaque，不做解释；不修改skb、不做routing、reassembly、TCP状态机或socket处理。此 ingress view 是受 F-Stack TX checksum案例启发的Ker-specific extension。
- 固定 hash/bucket 分流与有界跨 worker 转发已建立；现在可接收合法 segmented
  mbuf，并通过 `fstack-flow-receive` 验证 owner 的 IPv4 transport packet-view 校验路径。
  该桥接测试在单个 EAL thread 上使用独立逻辑 worker，不替代现有跨 CPU 测试。
  RSS、在线 flow-map 更新、drain/reload、多进程和状态迁移仍需独立实现与测试。
- 有 Ker socket/epoll API 后，再引入 TCP/UDP 应用互通、连接回收、超时等黑盒
  场景。FreeBSD kqueue/内部 mbuf 的白盒测试不直接用于原始 Linux 布局。
- 在实际移植配置、日志、pcap 或 IPC 模块后，再选择对应 ff_* glue 用例；
  当前项目没有这些接口，不能靠空 stub 建立虚假覆盖。

该套件是外部场景驱动的补充，既有 Linux 原始代码、DPDK 所有权和失败回滚
测试继续保留。当前公共网络 capability 仍仅为 checksum。

## poll/select 就绪语义扩展

`host-fstack-readiness-reference` 与 `native-fstack-readiness` 分别运行同一套
8 个公共 POSIX 场景：监听接入和 accept 后恢复空闲、重复 poll 条目与 select
多集合计数、宿主 pipe/原生 TCP 混合等待、负数/已关闭 fd、带外数据
`POLLPRI/exceptfds`、`SO_RCVLOWAT`、缓冲数据后的 EOF、零值/非法 timeout。
`pselect` 的 timeout 必须保持不变，原生场景必须记录 imported-kernel TCP open
并回收 packet buffers。数据到达通过有界等待同步，不把 send 返回当作对端已就绪。

这些是受固定 F-Stack host readiness/FIONBIO 桥接场景启发的 Ker 扩展，
上游没有用这些案例验证 poll/select 或原生 TCP。宿主基线单独列出，不冒充
用户态栈通过；原生 CTest 另行执行独立宿主对端的 TCP/DPDK 互通和启动失败检查。
本批不修改协议实现，也不作性能或 io_uring 支持声明。

```sh
ctest --test-dir build-native-tcp -R '^(host-fstack-readiness-reference|native-fstack-readiness)$' --output-on-failure
```

## 完整原生 Linux 的 epoll 场景

`native-fstack-epoll` 将固定版本 `tests/unit/test_ff_epoll.c` 的 API 场景迁移为
真实连接测试，区别于上表中基础库的报文 view 与 adapter 测试。C 程序仅使用公共
POSIX 接口；先以宿主 Linux 为基线，再由 `ker-run` 在独立原生内核运行。两个后端的
8 项断言必须分别全部通过，输出也必须相同；不能用基线结果代替原生结果。
原生运行记录至少 8 次 active/passive open 和 `outstanding=0`。这部分 loopback
连接不会经过 DPDK；同一测试中的主动/被动 1 MiB 独立宿主对端互通另行验证
DPDK TX/RX 与原生连接计数。

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-epoll$' --output-on-failure
```

F-Stack 的原始测试检查 FreeBSD kqueue 转换和 mock 调用；这里检查原始 Linux
的运行行为。Linux 的 `epoll_create(0)`、半关闭及错误标志按 Linux 语义断言，
不强行匹配上游 stub 的结果。完整来源、原始文件 SHA-256、具体案例及未覆盖项
见 [provenance](../tests/fstack-provenance.json) 的 `native-fstack-epoll`。

## TCP socket 契约扩展

`host-fstack-socket-contracts-reference` 和 `native-fstack-socket-contracts`
分别用同一公共 POSIX 程序运行 6 个场景。检查创建时的 NONBLOCK/CLOEXEC、
SO_TYPE/DOMAIN/PROTOCOL，普通 accept 不继承监听 fd 的非阻塞/close-on-exec
标志，而 accept4 按显式参数设置它们。

地址查询用 0 字节和仅够 sa_family 的缓冲区，必须返回完整地址长度且保持尾部
sentinel 不变；双端 getpeername/getsockname tuple 必须一致。Option 测试覆盖
KEEPALIVE、NODELAY、KEEPIDLE、错误值/未知 option 以及随后正常 I/O。
bind 冲突后监听者继续接受连接；F_DUPFD_CLOEXEC 的 alias 必须保留同一 socket
inode，关闭原 fd 后仍可传输，并验证 dup2/dup3 同号参数的不同规则。

这些是固定 F-Stack host bridge 场景的 Ker 扩展，预期结果依据 Linux 契约，
不声称上游案例或 FreeBSD 已有相同覆盖。局部契约用 loopback 检查，原生 CTest
另行执行既有独立宿主 TCP/DPDK 互通、原生计数、回收和启动失败检查。

```sh
ctest --test-dir build-native-tcp -R '^(host-fstack-socket-contracts-reference|native-fstack-socket-contracts)$' --output-on-failure
```

## Message/vector I/O 与描述符桥接

`native-fstack-message-io` 迁移固定版本 `test_ff_host_interface.c` 中
`FF_KERNEL_COEXIST` 下的五个宿主桥接测试，并加入 Ker 兼容性边界检查。
6 个场景仅调用普通 POSIX API，分别在宿主 Linux 和 Ker 原生 Linux 上执行，
比较结果并检查至少 6 次原生 active/passive open。AF_UNIX socketpair 的
vector roundtrip 明确验证宿主透传，不计作原生 TCP 覆盖。

覆盖 `sendmsg/recvmsg`、`readv/writev`、四个端点地址查询、半关闭后反向发送，
以及 `FIONBIO/FIONREAD`、`MSG_PEEK/MSG_DONTWAIT`、dup 共享的 `O_NONBLOCK`、
独立的 `FD_CLOEXEC` 和 host/native 双向 `dup2` 替换。Vector 接收循环允许合法
TCP 短读；message 接收的小缓冲区必须保留后续流数据，不能按 datagram 截断。
这些附加检查是 Ker 扩展，不冒充上游原始用例。

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-message-io$' --output-on-failure
```

这些局部连接使用 loopback，不经过 DPDK；同一 CTest 另行执行现有的独立
宿主对端双向 TCP/DPDK 互通，并验证 TX/RX、原生连接计数和 mbuf 回收。
本批未增加 ancillary data、IPv6、零拷贝、fork 或 io_uring 支持。

## 独立宿主对端的 message/vector stream I/O

`native-fstack-stream-io` 将消息/vector 桥接场景推进到真实 DPDK `net_tap`、
veth 和独立宿主 Linux TCP 对端。原生客户端和服务端各运行三种模式：
`writev/readv`、`sendmsg/recvmsg`、`sendmmsg/recvmmsg`，共六种组合。
每方向以不同 seed 校验 256 KiB + 13 字节，使用小发送缓存和非阻塞 socket，
处理短进度、EAGAIN、半关闭及 EOF；输出实际 short/retry 计数，不把次数固定为
调度或性能要求。TCP batch 不保证消息边界，接收按实际 msg_len 重组字节流。

客户端和服务端都必须报告校验成功；每个原生实例独立断言对应 active/passive
open、DPDK TX/RX 非零和 `outstanding=0`。这区别于已有
`native-fstack-message-io` 的局部 loopback 场景，不能用宿主桥接成功替代原生结果。
固定上游来源仍为小型 host-only message/vector 桥接；batch 与大流量独立对端
属于 Ker 扩展，不声称 F-Stack 原始案例已有相同覆盖。

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-stream-io$' --output-on-failure
```

## 原生 UDP socket 的独立对端验证

`native-fstack-udp-interop` 使用完整导入内核的 UDP，验证现有 POSIX 转换层的
UDP socket 路径，区别于基础库的 UDP packet view/constructor 测试。固定上游
checksum 场景仅提供 UDP 动机；额外记录的 UDP/epoll 示例也不是自动化验收，
不能将它等同于本批测试覆盖。

验收分为 sendto/recvfrom、sendmsg/recvmsg、sendmmsg/recvmmsg 三种模式，
每种交换原生客户端/服务端角色，并要求独立宿主 Linux 对端参与。零长度报文
必须接收并回复，随后同一 socket 继续处理非空报文。原生计数来自 Linux 的
`/proc/net/snmp`，不能用宿主 socket 或 DPDK 包计数代替原生 UDP 收发证据。
详细断言与边界见 [UDP 验证说明](native-udp-validation.md)。

原生启动与设备集成：`ctest --test-dir build -R '^native-fstack-startup-lifecycle$' --output-on-failure`。
使用真实 DPDK/net_tap 和原始 Linux，检查启动诊断、接口地址/状态/MTU、双角色流量、清理及启动失败不执行应用。
F-Stack run/stop 回调 ABI 和自然内核内部故障仍未覆盖；初始化/启动/接口错误注入见 startup-failures。

宿主失败路径：`ctest --test-dir build -R '^native-fstack-host-(failure-.*|runtime)$' --output-on-failure`。
同一时钟/panic 适配器分别以断言开启和 `NDEBUG` 编译，真实时钟正常前进；注入时钟失败及 panic 均须 SIGABRT。
原生内核启动/关闭测试确认使用安装后的实际时钟回调，上游源码保持不变。

空 UDP 可读性：`ctest --test-dir build -R '^native-fstack-(epoll|udp-interop)$' --output-on-failure`。
前者对照宿主/原生内核，覆盖 IPv4/IPv6 回环、LT/ET/ONESHOT 和三种 wait 接口；
后者通过独立 IPv4 宿主验证包含空报文的流量均无 HUP/EOF。

Jumbo MTU：`ctest --test-dir build -R '^native-fstack-(jumbo-mtu|launcher-config|startup-lifecycle)$' --output-on-failure`。
配置 `--mtu 9000` 或 `[network] mtu=9000`，对端及所有中间链路也需配置为 9000。
测试通过实际双向 9014 字节以太网抓包验证 jumbo 收发，保持原始内核协议实现。

TCP ECN：`ctest --test-dir build -R '^native-fstack-(tcp-ecn|launcher-config)$' --output-on-failure`。
`--tcp-ecn off|passive|on` 或 `[network] tcp_ecn` 控制私有原生内核；未配置保留 Linux 默认策略。
测试比较实际宿主握手、TCP_INFO 及 SYN/SYN-ACK 抓包，CE 拥塞响应与外部 IPv6 ECN 尚未覆盖。

`native-fstack-fd-map` 对应 `test_ff_native_fd_map`，使用真实 Linux socket 和实际 Ker fd 表验证映射生命周期、固定位置替换、引用及边界。无需网络设备，需 `KER_WITH_NATIVE_TCP=ON`。
`native-fstack-errno` 对应 `test_ff_os_errno_mapping`，覆盖 81 项 Linux/LKL 到宿主 errno 的符号映射、未知错误及成功值，使用生产转换函数和真实内核调用。需 `KER_WITH_NATIVE_TCP=ON`。

`native-fstack-lcore-mask` 对应六个 lcore mask 源场景，结合 `native-fstack-launcher-config` 验证提前拒绝、CLI 优先级及真实 EAL 选核。
INI 双核/CLI 单核均运行原始 Linux 对独立宿主 TCP，检查 lcore_count、main_lcore、main_cpu 和资源回收；需要两个可用且 ID 小于 128 的 CPU。

`native-fstack-worker-traffic` 对应 `test_ff_get_traffic_zero_init` 和 `test_ff_dpdk_stop_smoke`。
在私有 namespace 中通过实际 net_tap/AF_PACKET 验证空闲零统计、双向精确帧/字节计数、非法 TX 长度方向计数、重复停止和 mbuf 回收。
测试用 SIGSTOP/SIGCONT 作为排程屏障，在 worker 读取前写入两个控制字节并关闭管道；实际停止仍由控制通道和 EOF 驱动。

`native-fstack-entropy` 对应 `test_ff_arc4rand_buf_filled` 和 `test_ff_arc4random_distribution`。
直接运行真实 Linux RNG，覆盖宿主熵注入、非阻塞读取、失败和短读/EINTR、重复种子注入及私有临时节点清理；需 `KER_WITH_NATIVE_TCP=ON`。

`native-fstack-realtime` 对应 `test_ff_clock_gettime_realtime`，使用真实 Linux 校验启动同步的 epoch、纳秒、前进和单调时钟隔离，并注入宿主/原生错误验证失败传播与恢复。

`native-fstack-worker-clock` 对应 `test_ff_get_tsc_ns_basic` 的单调纳秒场景，测试实际 worker 适配器的真实时钟前进、换算边界和失败传播。
`native-fstack-worker-clock-interop` 在真实 DPDK net_tap worker READY 后注入一次 EIO，检查失败退出及 mbuf/EAL 清理；不改变协议定时器，不声称 TSC API 等价。

`native-fstack-startup-failures` 验证正常启动、原生 realtime EIO、原始 Linux 网关拒绝和 worker ethdev 查找失败。
所有失败均需返回 125、阻止应用 main、回收 worker mbuf 并完成真实 EAL cleanup。
测试专用链接库包装 LKL init、netdev add、kernel start 和 if up，分别注入 EIO，
以精确阶段记录验证真实前置调用、失败位置以及后续阶段未执行；
成功控制调用真实激活函数，生产库无 hook。这不是自然硬件故障或完整 F-Stack ABI 等价。

`native-fstack-packet-device` 对应设备上下文创建/释放两个源场景，连接生产 packet-device 回调，检查真实 fd/eventfd 生命周期、内存失败回滚、scatter/gather、背压、截断及停止唤醒。
不依赖 DPDK 设备或运行内核；需原生构建提供的 LKL 头文件，以及可读取自身线程 syscall 状态的 Linux `/proc`。

`native-fstack-vip-addresses` 验证真实主地址/VIP 安装、掩码、未配置地址拒绝、三个目的地址入站 TCP 和两个 VIP 源地址出站 TCP。
结合 `native-fstack-launcher-config` 验证 `[network] vip_addresses`、重复 `--vip-address`、CLI 替换、32 项上限及非法输入在启动前返回 2。

`native-fstack-launcher-config` 验证独立 `max_mtu`、相等边界、9000/2000 拒绝和 CLI 覆盖。
`native-fstack-jumbo-mtu` 先验证低上限在启动前拒绝，再覆盖到 9000 执行真实 jumbo TCP/UDP、DF 和抓包检查，补齐 `test_mtu_port_over_max_fails`。


`native-fstack-ipv6-vip` 将固定 IPv6 fixture 的 VIP 功能需求适配为同一原生 Linux
接口上的多地址配置。五次真实 net_tap 启动验证 INI、CLI 替换、省略/继承值清理、
32 个 VIP 上限，以及由 Linux DAD 拒绝宿主已占用 VIP。
主地址和两个 /128 VIP 均验证双向 TCP/UDP、显式源地址、宿主 NDP、内核计数及 mbuf 清理。
`test_ff_load_config_inet6_fixture_ignored` 仍 blocked，因为其 INET6-disabled 语义与此不同；
不增加 adapted/partial 计数。IPv6 VLAN 另见后续测试；RA/SLAAC 和独立 FreeBSD VIP 接口仍未迁移。


`native-fstack-ipv6-vlan` 以真实 original Linux VLAN 100/200 和独立宿主 peer 验证
双向 IPv6 TCP/UDP、VLAN VIP、混合 IPv4、设备绑定与 IPv6 packet metadata。
INI/large、CLI/scatter、16×8 地址上限和重复地址拒绝共四次原生启动，
含完整帧、标签、UDP checksum、NDP、原始内核计数及 mbuf 清理证据。
错误 VLAN/untagged UDP 先通过 worker RX，再以实际 socket 收包验证未被交付。
固定 `test_ff_load_config_inet6_fixture_ignored` 仍 blocked，不增加迁移通过计数。


`native-fstack-thread-runtime` 的 TLS 失败路径扩展使用实际 Ker 回调，分别在默认、
DEBUG 和 NDEBUG 构建中验证 key 创建的 EAGAIN/ENOMEM、设置的 ENOMEM，
以及删除失败时的显式终止。创建失败需回收包装对象并允许下一次真实创建；
设置失败需保留空槽或旧值，之后真实替换、清空及删除仍成功。
删除失败由链接包装器注入，不向 pthread 传递失效 key；void 回调不能报告错误，
因此必须中止，不能把仍注册的 key 当作已释放。故障仅作用于测试调用线程，
原始 Linux 启停和实际 TCP/UDP 回归在故障关闭时执行。
这是线程适配层的 Ker 扩展，不改变上游源案例迁移计数或 FreeBSD 上下文边界。


宿主定时器适配由 Ker 持有 opaque timer_t 包装对象，保留 pinned LKL 的
相对 CLOCK_REALTIME/SIGEV_THREAD 行为和原始 Linux clock-event 实现。
分配或 timer_create 失败返回 NULL，保留 errno 并完整回收存储；
timer_settime 失败直接返回错误；void timer_free 无法报告删除失败，因此明确
abort，不能静默释放仍有效的 handle。0 纳秒解除定时，interval 始终为0。

`native-fstack-host-timer-debug/release` 使用真实 POSIX timer 验证失败恢复、
秒/纳秒换算、通过 timer_gettime 检查解除定时，以及把100秒期限重新设为1纳秒后的真实单次回调。
删除失败的子进程在父进程创建任何线程或 timer 之前 fork；成功路径不模拟。
原始 Linux 必须实际分配、设定、触发和释放这些 timer，并唤醒一次带超时 poll。
另以实际 DPDK TCP/UDP 和启动生命周期做回归。固定 F-Stack clock 案例仅为来源
动机，本批是 Ker 适配扩展，不增加迁移来源案例数，也不修改上游源码。
不宣称 timer_delete 等待已经执行中的 SIGEV_THREAD 回调结束；墙钟调整、周期
定时器、回调静止保证、精确延迟和性能仍未验证。

宿主页内存扩展：`native-fstack-host-pages-debug/release` 在现有 host-interface
映射场景上覆盖分配失败恢复、固定地址回退清理与 page_free 失败边界；
成功操作始终执行真实 mmap/munmap，失败的 void 释放回调明确终止。
两项扩展不增加来源案例计数，具体边界见 native-tcp.md。

宿主线程栈扩展：现有 `native-fstack-thread-runtime` 三种构建变体验证主/子
线程真实栈范围、可选 size、查询失败后的属性清理和恢复。它是现有线程场景的
Ker 扩展，不增加来源案例计数，也不宣称已运行 KASAN 内核。

INI 重复键：`native-fstack-config-lifecycle` 与
`native-fstack-launcher-config-interop` 共同适配
`test_ff_load_config_repeat_keys_no_leak`；最终值生效、CLI 优先、重复加载隔离，
并验证真实 DPDK/Linux 的最终地址与 EAL 参数。该来源项从 blocked 转为
scenario-adapted（126 adapted、224 blocked、20 partial）。

描述符共存：`native-fstack-fd-map` 进一步覆盖相同内部 fd 数值的宿主 UDP/
原生 Linux TCP 对象、Ker export/lookup 往返和两种关闭顺序；使用真实
宿主 socket、原生 socket 和 fd 预留，来源 `test_ff_kernel_fd_encode_roundtrip`
按映射表架构适配，固定偏移编码 ABI 不在覆盖范围。清单为 127 adapted、
223 blocked、20 partial。

TCP_CORK/MSG_MORE 扩展：`native-fstack-tcp-cork` 验证双向暂缓、dup 共享选项、
解除后的完整字节流与普通写入恢复；宿主参考及原生两种角色均运行。
这是已有 socket/dup 场景的 Linux 功能扩展，不增加已迁移来源案例数。

TCP MSS 扩展：`native-fstack-tcp-mss` 验证连接前 TCP_MAXSEG、监听继承、
错误后恢复和双向完整字节流；实际抓包检查握手 MSS 与原生发送分段上限。
来源案例数不变，剩余仍为 223 blocked + 20 partial。

INI 长键名：`native-fstack-launcher-config` 与 `native-fstack-network-sysctl`
适配 `test_ini_parse_stream_long_key_name` 的完整名称保留，覆盖 60 字符、
128/129 字符边界、重复/CLI 顺序及真实内核未知键失败后的回收。清单更新为
128 adapted、222 blocked、20 partial，剩余 242 项。


TCP keepalive 扩展：`native-fstack-tcp-keepalive` 检查选项共享与监听继承、
无效参数恢复，并通过原生发送抓包验证空闲探测及后续收发。它扩展已有 socket
迁移场景，不增加源案例迁移数；当前仍有 222 个 blocked、20 个 partial。


SO_PEEK_OFF 扩展：`native-fstack-tcp-peek-offset` 探测宿主支持，仅在宿主明确返回
`EOPNOTSUPP`/`ENOPROTOOPT` 时跳过宿主参考；原生客户端和服务器的游标断言始终必跑，
宿主对端仍验证普通 peek、精确字节和 EOF。测试验证偏移预览、dup 共享游标、
消费后的回退、重置和完整字节流恢复。这是已有 socket 场景的 Linux 扩展，
未新增源案例迁移数；仍有 222 个 blocked、20 个 partial。
