# F-Stack 全量测试迁移清单

固定上游版本：`646a641cfff77f4815e1e29829a09e1ed15a2999`。

本清单覆盖整个上游 `tests/`：105 个文件，加原始 LICENSE 共 106 个文件，
保存在 [只读源快照](../tests/upstream/fstack)。保留原始内容、执行位、Git blob SHA-1
及 SHA-256；不是把快照作为 Ker 实现或自动执行上游脚本。

从实际注册代码得到 378 个 CMocka 用例、53 个 Python unittest 方法、
1 个 reload shell 入口和 1 个 MTU 手工检查入口，共 **433 项**。
上游 README 的 189+8 统计与此固定版本实际内容不一致，不能用作分母。

## 当前完成程度

| 状态 | 数量 | 含义 |
|---|---:|---|
| scenario-adapted | 136 | 有现存 Ker CTest 和来源映射；是场景适配，不是 API/实现等价认证 |
| partial | 21 | 有相关场景，但未满足完整源用例合同；remaining 字段记录缺口 |
| blocked | 213 | 没有完整可执行的 Ker 对应项；明确保留缺口，不计为通过 |
| architecture-specific | 8 | FreeBSD callout/内部 kqueue filter 断言，不适用于 Linux 内部结构 |
| harness-only | 55 | 53 个 F-Stack reload 工具链自测及 2 个 CMocka smoke；不计 Ker 网络覆盖 |

**全部原始测试已纳入；全部行为迁移尚未完成。**
完整逐项 ID、处置理由和 CTest 链接在 [机器清单](../tests/fstack-migration.json)。
一个 Ker CTest 可以适配多项上游场景；Ker 来源条目中还包含大量
Ker 自有扩展，不能把这些扩展数量当作已迁移上游用例数。

本批补齐 `valid_inet6.ini` 中 VLAN IPv6 网关的相关功能，通过
`native-fstack-ipv6-vlan-route` 验证单一默认网关、全局/link-local 下一跳、
原始 Linux 路由失败边界及独立路由器后的双向 TCP/UDP。来源注册用例
`test_ff_load_config_inet6_fixture_ignored` 断言的是 INET6-disabled ignore，
仍保持 blocked；新增功能证据不改变上表计数，也不声称完整 fixture 等价。

另补齐 `valid_vlan_vip.ini` 中 VLAN IPv4 gateway 的相关运行能力，
`native-fstack-ipv4-vlan-route` 验证原始 Linux 主表默认路由、ARP 下一跳和
路由器后的双向 TCP/UDP。它扩展已适配配置场景的运行证据，未将白盒 config
合同或完整 F-Stack 多接口路由语义记为完成，计数保持不变。

新增 `dpdk.promiscuous` / CLI 开关及真实 PMD/native 验证，补齐最小配置用例中
promiscuous 的运行子集。默认省略保留 PMD 状态，明确区别于 F-Stack fixture 的
显式开启值。完整 config ABI/布局仍
未实现，该源用例继续 partial，计数不变。

`dpdk.idle_sleep` / `--idle-sleep-us` 进一步补齐该最小配置场景的空闲等待子集，
以宿主 `ppoll` 实现 Ker I/O 等待，保持 Linux 协议定时器独立。五个真实实例验证
默认、20 微秒、零等待和上限配置下的实际超时及 TCP/UDP/控制关闭。该源用例的
其他缺口继续保留，计数不变。

## 剩余案例的 issue 追踪

持续迁移以固定版本的 433 项源案例为准。未完整适配的 297 项记录均在
[后续清单](../tests/fstack-followups.json) 中关联一个具体 issue：其中 234 项是
21 partial + 213 blocked，另有 8 项架构专用和 55 项上游工具链自测。
**建单不是迁移通过，也不会解除 `--require-complete` 的失败。**

后续清单将案例分为需要适配器实现、合同差异待决策、架构专用和上游工具链专用。
需要适配器的继续移植；合同差异必须逐项核对，不能为了减少计数加入无实际调用方的
API，或改写原版 Linux 协议实现。不适合直接移植的案例保留精确源 ID、理由、issue
和可接受的替代/排除边界；不把原始 helper 的成功、软件 checksum、普通 FIFO 或
额外 socket 功能测试冒充硬件 offload、跨代 reload 或原始 ABI 合同通过。

| 工作组 | 源案例数 | 处置类别 | issue |
|---|---:|---|---|
| Design generation-aware reload, IPC and drain ownership | 81 | 需要适配器实现 | [#218](https://github.com/rutlang-ai/Ker/issues/218) |
| Define a supported host exception bridge and KNI policy adaptation | 38 | 需要适配器实现 | [#219](https://github.com/rutlang-ai/Ker/issues/219) |
| Qualify RSS steering and queue-aware source-port contracts | 31 | 需要适配器实现 | [#220](https://github.com/rutlang-ai/Ker/issues/220) |
| Add positive hardware checksum and TSO acceptance coverage | 4 | 需要适配器实现 | [#221](https://github.com/rutlang-ai/Ker/issues/221) |
| Define packet-dispatch and PCB callback adaptation boundaries | 7 | 合同差异待决策 | [#222](https://github.com/rutlang-ai/Ker/issues/222) |
| Resolve device/run lifecycle and upstream fault-injection contracts | 4 | 合同差异待决策 | [#223](https://github.com/rutlang-ai/Ker/issues/223) |
| Adapt typed vdev, bond and multi-port configuration | 6 | 需要适配器实现 | [#224](https://github.com/rutlang-ai/Ker/issues/224) |
| Define a Linux-native zero-copy send and ownership contract | 13 | 合同差异待决策 | [#225](https://github.com/rutlang-ai/Ker/issues/225) |
| Resolve remaining typed configuration and intentional schema differences | 18 | 合同差异待决策 | [#226](https://github.com/rutlang-ai/Ker/issues/226) |
| Decide F-Stack primary/secondary and thread-mode compatibility | 6 | 合同差异待决策 | [#227](https://github.com/rutlang-ai/Ker/issues/227) |
| Document and qualify host/native stack coexistence configuration | 4 | 合同差异待决策 | [#228](https://github.com/rutlang-ai/Ker/issues/228) |
| Resolve unmapped host memory, time, environment and kqueue helpers | 13 | 合同差异待决策 | [#229](https://github.com/rutlang-ai/Ker/issues/229) |
| Resolve INI callback, userdata and section semantics | 6 | 合同差异待决策 | [#230](https://github.com/rutlang-ai/Ker/issues/230) |
| Resolve FreeBSD thread context and join-result assertions | 3 | 合同差异待决策 | [#231](https://github.com/rutlang-ai/Ker/issues/231) |
| Record nonportable callout and internal kqueue filter assertions | 8 | 架构专用 | [#232](https://github.com/rutlang-ai/Ker/issues/232) |
| Disposition upstream reload-tool self-tests and CMocka smoke cases | 55 | 上游工具链专用 | [#233](https://github.com/rutlang-ai/Ker/issues/233) |

默认审计还检查：每个非 `scenario-adapted` 案例都恰好出现一次、issue 必须是
Ker issue 链接、固定版本一致、分组有理由及验收条件。它不联网判定 issue 关闭
与否；issue 的存在和状态需通过 GitHub 核对，关闭 issue 也不能自动改写覆盖状态。
新增可运行适配后，应同时更新源案例映射、provenance、issue 证据和后续清单。

MTU 手工清单的五步已由静态及动态 ICMP 测试完成适配（[#234](https://github.com/rutlang-ai/Ker/issues/234)）；
下一步推进适配器生命周期、vdev/bond、多队列/RSS、异常桥接和跨代 reload。正向硬件
checksum/TSO 验收保留对实际支持设备与独立抓包环境的要求。

## 自动检查

```sh
python3 tests/fstack_migration.py
python3 tests/fstack_migration.py --require-complete
ctest --test-dir build -R '^fstack-migration-' --output-on-failure
ctest --test-dir build -R '^native-fstack-epoll$' --output-on-failure
```

默认检查只验证快照完整性、全部注册项没有遗漏、处置理由存在，以及适配项关联真实
CTest、精确源文件/用例 provenance 和 provenance 条目声明的 Ker CTest 绑定。它通过不代表
433 项行为通过。
`--require-complete` 在仍有 blocked 或 partial 项时返回 2，目前必须失败。
17 个 mutation/门禁用例验证快照与目录完整性、适配状态、存在且匹配来源的 CTest、源文件和源用例对应关系、provenance 到 Ker CTest 的显式绑定（包括拒绝无关现存 CTest、缺失绑定和无效绑定类型），以及未完成门禁；CI 将清单校验标为 provenance。

## 本批实际迁移与修复

补齐 `test_ff_epoll_ctl_null_event_non_del` 的 Linux 场景：ADD/MOD 的 NULL event
应返回 EFAULT（上游 F-Stack wrapper 为 EINVAL），失败不能破坏已有注册，
DEL 的 NULL event 合法。宿主参考先通过；native 修复前退出 139，修复后通过。
修复仅在 Ker epoll 适配层阻止 NULL 进入 LKL 的同地址空间 user-copy；
Linux/FreeBSD/DPDK 原始实现均不修改，不宣称支持任意坏指针。
既有 write-only、zero-maxevents、空 FIN 和零长度 UDP 场景补齐相应来源映射。

## 阻塞分类与边界

- 配置/INI、日志、IPC：当前没有对应 Ker 接口，不能把 F-Stack 库自测当作 Ker 已实现这些模块。
- KNI、RSS/源端口调整、完整设备注册、generation/epoch/热重载：需要实际适配器与运行环境；本地 FIFO 或 borrowed ethdev 用例只覆盖各自明确的子集。
- FreeBSD TLS、callout 和 mbuf 镜像：迁移必须尊重原始 Linux 结构和协议实现，不能为通过白盒测试复制 FreeBSD 协议算法。
- reload Python 工具自测：源文件保留，不自动导入/执行，不把工具链断言记为网络协议覆盖。
- `test_mtu.sh` 实际只打印手工步骤及无条件 ALL PASS 摘要；执行它不构成 jumbo、动态 MTU 或 IPv6 互通证据。

后续每完成一项，先提供真正的适配和测试证据，再修改该项状态；完整迁移门禁
继续显示未完成，直至全部阻塞都有明确实现或经过审阅的架构处置。

## 按源文件统计

| 上游入口 | 总数 | 场景适配 | 部分覆盖 | 阻塞 | 架构特有 | 工具自测 |
|---|---:|---:|---:|---:|---:|---:|
| [integration/test_ff_dpdk_if_integration.c](../tests/upstream/fstack/tests/integration/test_ff_dpdk_if_integration.c) | 20 | 14 | 6 | 0 | 0 | 0 |
| [integration/test_ff_gendir_mp_integration.c](../tests/upstream/fstack/tests/integration/test_ff_gendir_mp_integration.c) | 7 | 0 | 0 | 7 | 0 | 0 |
| [integration/test_ff_kni_integration.c](../tests/upstream/fstack/tests/integration/test_ff_kni_integration.c) | 8 | 0 | 0 | 8 | 0 | 0 |
| [integration/test_ff_reload_integration.c](../tests/upstream/fstack/tests/integration/test_ff_reload_integration.c) | 7 | 0 | 0 | 7 | 0 | 0 |
| [integration/test_graceful_reload.sh](../tests/upstream/fstack/tests/integration/test_graceful_reload.sh) | 1 | 0 | 0 | 1 | 0 | 0 |
| [integration/test_mtu.sh](../tests/upstream/fstack/tests/integration/test_mtu.sh) | 1 | 1 | 0 | 0 | 0 | 0 |
| [unit/test_ff_callout.c](../tests/upstream/fstack/tests/unit/test_ff_callout.c) | 6 | 0 | 0 | 0 | 6 | 0 |
| [unit/test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c) | 96 | 26 | 9 | 61 | 0 | 0 |
| [unit/test_ff_config_pa.c](../tests/upstream/fstack/tests/unit/test_ff_config_pa.c) | 2 | 0 | 0 | 2 | 0 | 0 |
| [unit/test_ff_dpdk_if.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c) | 67 | 6 | 2 | 59 | 0 | 0 |
| [unit/test_ff_dpdk_kni.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c) | 25 | 0 | 0 | 25 | 0 | 0 |
| [unit/test_ff_dpdk_pcap.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_pcap.c) | 9 | 9 | 0 | 0 | 0 | 0 |
| [unit/test_ff_epoll.c](../tests/upstream/fstack/tests/unit/test_ff_epoll.c) | 21 | 19 | 0 | 0 | 2 | 0 |
| [unit/test_ff_host_interface.c](../tests/upstream/fstack/tests/unit/test_ff_host_interface.c) | 34 | 22 | 0 | 12 | 0 | 0 |
| [unit/test_ff_ini_parser.c](../tests/upstream/fstack/tests/unit/test_ff_ini_parser.c) | 25 | 19 | 1 | 5 | 0 | 0 |
| [unit/test_ff_init.c](../tests/upstream/fstack/tests/unit/test_ff_init.c) | 6 | 5 | 1 | 0 | 0 | 0 |
| [unit/test_ff_ipc.c](../tests/upstream/fstack/tests/unit/test_ff_ipc.c) | 12 | 0 | 0 | 12 | 0 | 0 |
| [unit/test_ff_log.c](../tests/upstream/fstack/tests/unit/test_ff_log.c) | 13 | 13 | 0 | 0 | 0 | 0 |
| [unit/test_ff_thread.c](../tests/upstream/fstack/tests/unit/test_ff_thread.c) | 5 | 2 | 2 | 1 | 0 | 0 |
| [unit/test_ff_zc_send.c](../tests/upstream/fstack/tests/unit/test_ff_zc_send.c) | 13 | 0 | 0 | 13 | 0 | 0 |
| [unit/test_hello.c](../tests/upstream/fstack/tests/unit/test_hello.c) | 2 | 0 | 0 | 0 | 0 | 2 |
| [unit/test_reload_harness.py](../tests/upstream/fstack/tests/unit/test_reload_harness.py) | 53 | 0 | 0 | 0 | 0 | 53 |

## NULL epoll 等待缓冲区适配

`native-fstack-epoll` 新增三个等待接口的 NULL 输出缓冲区场景，
覆盖无事件返回零、无效 maximum 返回 EINVAL、就绪后返回 EFAULT，以及
错误后 ET/ONESHOT 事件仍可读取。混合 epoll 中的宿主 pipe 也检查错误恢复。
这是 Linux POSIX 语义适配：上游 F-Stack 包装器对 NULL 一律返回 EINVAL。
任意不可访问指针及并发消费者竞争仍不在本次覆盖范围内。

## PCAP 抓包适配

新增 `native-fstack-pcap`，将 PCAP 文件创建、NULL 目录、禁用、打开失败、
微秒/纳秒精度、十文件滚动、追加、多段截断共九项源场景适配到 Ker 抓包器。
测试使用实际 DPDK mempool/mbuf，逐字段解析文件，检查内容及所有权不变。
`native-fstack-pcap-interop` 另行验证真实原始 Linux TCP 经 DPDK 的双向抓包。
文件名、错误处理和滚动触发点采用 Ker 语义，详见 [抓包说明](packet-capture.md)。

## V6ONLY 与 IPv4-mapped socket

`native-fstack-dualstack` 适配 `test_ff_host_set_v6only`：验证同端口绑定隔离、
双栈绑定冲突、IPv6 loopback、独立宿主对端的 IPv4-mapped TCP、epoll 和 EOF。
`native-dualstack-drain` 使用实际内核分别填满 IPv4/IPv6 发送队列，验证排空超时
及读取后的恢复，避免 IPv6 socket 被关闭流程遗漏。内核只启用原始 IPv6 配置；
未修改协议源码。外部 IPv6 地址、路由和 NDP 接收部署尚未验收。

## 主机内存与时钟回调

`native-fstack-host-runtime` 适配 7 个 `test_ff_host_interface.c` 场景，直接调用
Ker 原生内核所用的 `lkl_host_ops`，检查分配区可写、释放 NULL、单调纳秒时钟、
匿名映射读写权限和解除映射。读写区逐字节校验；只读区在内核启动前的子进程中
验证写入触发 SIGSEGV，并关闭 core dump。还验证页分配对齐与释放。
随后真实启动和关闭固定版本 Linux，通过计数转发回调确认内核使用主机内存和时钟。

LKL 的 `mmap` 回调要求精确地址，与 F-Stack 的 NULL 地址分配接口不同。
碰撞回归发现固定 LKL POSIX 回调在失败时会解除原有地址，访问原有内容导致崩溃。
Ker 在 `src/posix/host-memory.c` 安装安全回调：失败保持原映射；若老宿主忽略
`MAP_FIXED_NOREPLACE` 并返回其他地址，只释放新返回的映射并报告失败。
原始 LKL 源码保持不变。当前非 MMU 内核通过 `page_alloc` 获取启动内存，
固定地址回调由测试直接验证，不声称内核启动已走该路径。

这些是运行时适配证据，不增加 TCP/UDP 协议覆盖。共享或文件映射、calloc/realloc、
随机数、实时时钟等剩余主机接口仍保留未迁移状态。

## 主机线程与 TLS 回调

`native-fstack-thread-runtime` 适配 `test_ff_thread.c` 的参数传递和分配失败场景。
线程失败使用 LKL 的零 handle 表示，区别于 F-Stack 的负 errno 返回值；测试通过
链接器只注入一次 malloc 失败，线程创建与同步始终使用真实 LKL 主机回调。
四个真实线程验证参数、identity、join 完成、信号量阻塞、互斥计数、TLS 隔离、
析构和 key 回收复用。随后真实 Linux 启停，并确认内核创建了主机线程。

测试发现固定版本的 `tsd_alloc` 在 malloc 返回 NULL 后仍解引用，修复前触发
SIGSEGV。Ker 在 `host-thread.c` 提供完整且私有的 pthread TLS key 适配，
分配失败返回 NULL；pthread key 用尽时释放中间分配并报告 EAGAIN。
真实 key 耗尽测试检查所有分配回收。上游 LKL 源码保持不变。

`test_ff_pthread_create_basic` 和 `test_ff_pthread_join_retval` 只计部分覆盖：
LKL 不继承 FreeBSD 的 pcurthread，且 void 线程入口和无返回值槽的 join 无法表达
F-Stack 丢弃非 NULL 线程返回值的断言。本批不模拟 FreeBSD 上下文，也不对应用的
pthread API 做拦截；cancel、detach 生命周期及析构重新设置 TLS 等仍未覆盖。

## DPDK worker 日志

`native-fstack-worker-log` 用真实、未 wrap 的 DPDK 日志 API 适配 `test_ff_log.c`
的 13 项场景：文件打开/追加、无效目录、非零实例文件名、打开和空状态关闭、
输出流切换、全局/分类级别、分类错误、可变参数与 va_list，以及实际输出字节数。
不复制上游任意 mock 返回值，也不创建虚假的 FreeBSD 日志分类。
Ker 使用 `ker.io` 分类及 `ker-io-<instance>.log`，worker 实例为其 PID。

`ker-run --log-dir DIR` 在现存目录中追加 worker 的 DPDK 日志；未启用时保持既有行为。
`--log-level 1..8` 在 EAL 启动后覆盖 DPDK 全局与 Ker 分类级别；启动期 EAL 消息
仍由 `--eal` 中的级别选项控制。只修改诊断输出，不修改包或协议处理。
DPDK 日志进入文件；应用输出和 worker 显式 stderr 错误仍在各自原有通道。

真实 `/dev/full` 测试验证 fflush 和缓冲关闭失败；Ker 会检查 DPDK 未传播的流错误，
关闭前把 DPDK 输出流恢复到 stderr。独立 Linux 对端的 TCP 主动和被动连接验证
文件内容、DPDK TX/RX、原生连接计数与零 outstanding，并确认实际 worker 日志
打开/写入失败最终返回 launcher 状态 125。文件为追加模式，本批不提供轮转或多进程共享 sink。

## Launcher INI 配置

`native-fstack-launcher-config` 适配 INI 基本语法、文件输入、注释/空白、空值、
UTF-8 BOM、无结尾换行、冒号分隔及错误拒绝等 18 项。生产 `ker-run --config` 和
测试使用同一个 Python 标准库解析路径；错误以异常/CLI 状态 2 表达，不复制
F-Stack 的 callback ABI 或整数返回码。无效配置在创建 packet channel 或子进程前拒绝。

多行值支持用于 EAL 参数，但合并为一个字符串；上游逐行 handler 调用序列尚未迁移，
该项只计 partial。另 6 项仍 blocked：无 section 的全局键、任意 handler 返回零与
userdata 传递、NULL FILE 指针入口，以及长 section/key 的固定长度截断。
Ker 使用自己的已知 section/option 配置 schema，不能直接读取任意 F-Stack 配置；
`test_ff_config.c` 的其他功能不会因此计为通过。

真实互通测试从文件加载 IPv4/EAL、相对日志与 capture 路径，验证主动/被动 TCP、
原始 Linux 连接计数、DPDK TX/RX、零 outstanding，以及命令行 port/stats 覆盖。
使用说明见 [原生运行文档](native-tcp.md)，示例见 [launcher INI](../config/native-launcher.example.ini)。

## 原生启动与设备集成

`native-fstack-startup-lifecycle` 使用真实 DPDK net_tap 和原始 Linux：
验证单端口、primary EAL、NUMA socket ID、链路状态，以及原生接口的地址、UP 标志和 MTU。
`ker-run --stats` 新增 `io` 启动诊断，保留原有流量与 native 统计。
`io.link_up` 在 PMD 无法查询链路时为 `null`；单端口 net_tap 测试要求它为 `true`。
双向 TCP 互通验证 TX/RX、内核连接计数和零 outstanding；配置文件缺失、EAL 参数错误及设备不存在均验证应用未执行。
配置错误退出 2，基础设施失败退出 125，区别于 F-Stack 的退出码 1。
新增 8 项场景适配，run/stop 仅部分覆盖实际 worker 停止与原生清理，未提供 F-Stack 回调 ABI。
接口激活返回错误已由 `native-fstack-startup-failures` 的测试专用链接包装覆盖；
内核初始化/启动返回错误已在同一测试中注入；完整 F-Stack 初始化 ABI 和实际内核内部故障仍未覆盖。
worker 明确拒绝 EAL secondary 进程；不宣称支持共享端口多进程。

## 主机时钟故障与 panic

`native-fstack-host-failure-debug` 和 `native-fstack-host-failure-release` 新适配 2 项上游场景。
固定 LKL POSIX 时钟回调未检查 `clock_gettime` 失败，可能将未初始化时间传给内核；
panic 只调用 `assert(0)`，在禁用断言的构建中可能返回。
Ker 在 `src/posix/host-clock.c` 安装检查时钟返回值并无条件 abort 的回调，保持原始 LKL 不变。
失败时钟没有可用的错误返回通道，因此不能伪造时间继续运行。
测试分别启用断言和定义 `NDEBUG` 编译同一实际适配器，在关闭 core dump 的子进程中
验证时钟失败及 panic 均产生 SIGABRT；正常时钟调用真实宿主并验证纳秒范围和前进。
原有 host-runtime 测试安装同一适配器，真实启动/关闭 Linux 并测量内核时钟调用。
这不包含实时时钟缓存失败、内核启动定点失败或新的网络协议覆盖。

## 空 UDP 数据报的可读性

`native-fstack-epoll` 新适配 `test_ff_epoll_wait_evfilt_read_data_zero_no_eof_yields_in`：
用真实空 UDP 数据报验证零字节可读事件，不复制合成 kqueue 事件或转换逻辑。
IPv4/IPv6 回环 × LT/ET/ONESHOT × 三种 epoll wait 接口共 18 个组合，均比较宿主 Linux 和原生 Linux。
验证 FIONREAD 为 0 时仍有 EPOLLIN，且无 HUP/RDHUP/ERR；PEEK 不消费；按触发模式重复或重装；
接收后 EAGAIN；后续普通数据报仍可接收。原生 IPv4 UDP 计数及零 outstanding 验证实际内核和清理。
`native-fstack-udp-interop` 同时强化独立 IPv4 宿主互通的无 HUP/EOF 断言，包含空报文。
IPv6 仅覆盖回环，不宣称外部 IPv6 部署完成。
此后 epoll 清单的 19 个可移植场景均有适配，剩余 2 项仍为 FreeBSD 内部结构专属，不能算 Ker 通过。

## 可配置 MTU 与 jumbo 互通

`[network] mtu` / `ker-run --mtu` 同时配置原生 Linux 接口和 DPDK 端口；默认 1500，范围 1280–9000。
较大 MTU 使用原始 LKL 已有的 virtio 合并接收缓冲能力；DPDK 单个 mbuf 包含帧、CRC 预留和 headroom。
不启用 checksum/segmentation offload，也不修改原始 Linux/LKL/DPDK。
设备不支持请求的 MTU 时启动失败，需由调用方预先配置对端链路 MTU。
`native-fstack-jumbo-mtu` 用真实 net_tap/veth 和独立宿主验证 9000 MTU、双角色 TCP/UDP、
8972 字节 DF UDP 有效载荷、8973 字节报文 EMSGSIZE、双向完整 9014 字节抓包及零 outstanding。
IPv6 jumbo 外部互通现由 ICMP 静态/动态清单验证；1280 下限保证默认双栈接口的配置范围。
`[network] max_mtu` / `--max-mtu` 提供独立部署上限（默认 9000，范围 1280–9000），请求 MTU 不得超过它。
9000 请求对 2000 上限在启动前拒绝；CLI 覆盖上限到 9000 后执行同一真实 jumbo 互通测试。
`test_mtu_port_over_max_fails` 已从部分覆盖转为场景适配；此上限不是硬件能力探测；动态 MTU 适配下，large pool 会按上限预留帧容量。
F-Stack mtu_enable 禁用分支及其内部配置 ABI 继续保留缺口。

## TCP ECN 策略

`[network] tcp_ecn` / `--tcp-ecn` 支持 `off`、`passive`、`on`，分别映射为原始 Linux 的 sysctl 值 0、2、1。
配置只写入应用私有原生 Linux 的 `/proc/sys/net/ipv4/tcp_ecn`；写入失败则启动失败，协议行为仍由原始内核提供。
未配置时不写 sysctl，保留固定 Linux 默认值 2（被动接受）。F-Stack/FreeBSD 的值 1 表示被动，
默认值 0 表示关闭，不能照搬数字或将“默认关闭”计为通过；该源用例仍为 partial，显式 `off` 可选。
`native-fstack-tcp-ecn` 覆盖默认及三种显式模式、两种原生角色，共 8 组独立 IPv4 宿主互通，另有宿主参考。
双方核对 `TCP_INFO` 协商结果和负载，抓包核对 SYN 的 ECE/CWR、SYN-ACK 的 ECE，
原生统计新增 `tcp_ecn` 有效策略，并检查连接计数和零 outstanding。
尚未验证 CE 标记后的拥塞响应、外部 IPv6 ECN 或 AccECN。
本批新增 1 项场景适配、1 项部分覆盖；FreeBSD 配置结构及 hz/mem_size 同级字段 ABI 不作等价声明。

`native-fstack-fd-map` 迁移原生 fd 映射场景，直接链接实际 Ker fd 表并启动原始 Linux。
验证建立、替换、清除、越界拒绝、失败时所有权释放、旧引用存活、重复 fd 独立关闭及 host 替换。
以真实 socket 类型和宿主/原生 fd 关闭结果作证据；不宣称兼容 FreeBSD fd 偏移编码或静默越界 setter。
`native-fstack-errno` 迁移完整 81 项符号错误码表及未知错误透传，直接验证 POSIX socket 包装和 fd 关闭共用的实际转换函数。
真实 Linux 启停及错误调用补充验证 EBADF、EINVAL、EAFNOSUPPORT、ENOTCONN；成功返回值和 errno 保持不变。
输入是 Linux/LKL 错误码，不宣称接受 FreeBSD 数字错误码 ABI。

`native-fstack-lcore-mask` 迁移六个配置解析/选核场景：大小写前缀、空白、多位掩码、非十六进制、空值及零掩码。
实际 DPDK 双核配置和单核 CLI 覆盖分别运行双向 TCP，检查 lcore 数量、主 lcore、宿主 CPU、原始 Linux 连接统计和零 outstanding。
这是 Ker/EAL 的核选择适配；不迁移 FreeBSD/F-Stack 的 nb_procs/proc_lcore ABI、多进程或 proc_id 语义。
CPU 是否可用及 DPDK 构建允许的最大 lcore ID 仍由原始 EAL 校验。互操作测试要求两个可用且 ID 小于 128 的 CPU。

`native-fstack-worker-traffic` 迁移流量零初始化和重复停止两个场景，使用真实 DPDK net_tap worker。
空闲快照所有计数为零；实际主机 AF_PACKET 与 packet channel 双向转发三帧，逐字节验证，计数各为 3 帧/1701 字节。
两条非法 TX 长度只增加 tx_dropped，聚合 dropped 保持一致；重复控制请求与 EOF 只产生一个成功 DONE，ethdev 关闭后零 outstanding。
不宣称 F-Stack 结构体/getter ABI，也不把这项裸 Ethernet 测试计为 Linux 协议覆盖。

`native-fstack-entropy` 迁移随机缓冲区填充和连续随机字变化两个场景。
运行时在原始 Linux 启动后、应用 socket 可用前，通过宿主 SYS_getrandom 系统调用（flags=0）获取 32 字节，交给原始 Linux RNG 并记入 256 位熵，再通过原始 reseed ioctl 立即更新已就绪 RNG。
测试启动真实 Linux，验证非阻塞随机读取、64 字节填充和 16 个字变化；EINTR/短读仍只使用真实宿主随机字节，读取失败/零读必须返回错误。
私有 random 节点即时 unlink，已有对象冲突保持不变，fd 关闭且所有返回路径显式清除种子缓存。
不实现自己的 PRNG，不声明 FreeBSD arc4random ABI/算法等价；输出变化阈值只作场景检查，不作密码学强度证明。

`native-fstack-realtime` 迁移实时时钟场景，复用 constructor 的实际同步适配器并启动真实 Linux。
先把私有内核时间设为旧的 2000 年 epoch，再验证同步后处于宿主前后采样区间、秒/纳秒有效且延迟后前进。
同步过程中原生单调时钟的前进量落在宿主单调时间前后采样窗口内，不随实时时钟跳变；宿主 EIO 和原生 EINVAL 均保持旧 epoch，仅返回错误。
恢复及重复同步同样验证。所有 settime 仅作用于私有 Linux；FreeBSD 缓存时间和 NULL 输出参数场景仍保留缺口。

### Worker 单调纳秒时钟

`native-fstack-worker-clock` 迁移 `test_ff_get_tsc_ns_basic` 的正值、非回退纳秒合同，
直接测试生产 worker 使用的宿主 `CLOCK_MONOTONIC` 适配器；额外验证精确换算、
有符号纳秒上界、无效采样、EIO、失败不写输出及恢复。
`native-fstack-worker-clock-interop` 运行真实 net_tap worker：正常控制通道停止能完成排空；
READY 后注入一次单调时钟 EIO 时必须失败退出，并记录零 outstanding、成功 EAL cleanup。
F-Stack 的 CPU TSC/频率换算和 `ff_get_tsc_ns` ABI 没有移植，不将此项当作实现等价。
原始 Linux 的协议时钟不变；这里只修复 worker 排空超时读取失败后的资源清理。

### 启动失败顺序与清理证据

`native-fstack-startup-failures` 运行真实 launcher、原生 preload/guard 和 DPDK net_tap。
原生内核启动后的宿主 realtime EIO 必须在 native READY 和应用 main 前终止初始化，
迁移 `test_ff_init_fail_freebsd_init` 的初始化失败顺序场景；不是 FreeBSD 初始化 API 等价。
原始 Linux 拒绝非本子网网关时也不能执行应用，但这只是 `test_ff_init_fail_dpdk_if_up`
的部分覆盖，直接 `lkl_if_up` 错误及 F-Stack 精确阶段顺序仍未测试。
另外测试未知 ethdev 的提前失败，保留其首行 DONE 快照供 `--stats` 使用。
正常及失败路径均检查实际 EAL cleanup 成功、零 outstanding，以及应用执行标记。

### Packet device 上下文与通道生命周期

`native-fstack-packet-device` 迁移 `test_ff_dpdk_register_if_returns_ctx`、
`test_ff_dpdk_deregister_if_frees` 的上下文创建/释放场景，直接连接生产适配器并运行
真实 datagram/eventfd，不替换 Linux/DPDK 协议实现。验证 fd 所有权、内存释放次数、
ENOMEM 与真实 EMFILE 回滚、64 次创建/释放后描述符余额。
额外 Ker 测试覆盖精确 scatter/gather 收发、截断丢弃、无效 vector 数、背压及 readiness，
在 `/proc` 确认线程阻塞于实际 ppoll 后验证 EINTR 重试与重复停止唤醒，先 join 再释放。
这些是适配层回调测试，不启动或验证原始 Linux 协议，不声明 FreeBSD softc/ifp、
`lkl_netdev_add/remove` 注册或 NULL context mbuf 所有权兼容；对应后者用例仍保留缺口。

### IPv4 VIP/附加地址

`native-fstack-vip-addresses` 迁移 `test_ff_load_config_with_vip_addr` 和
`test_port_cfg_handler_addr_parse`，通过 Ker 的 typed INI/CLI 配置安装主 IPv4 与 VIP。
生产 constructor 调用未修改的 LKL 地址接口向原始 Linux 增加地址，主地址保留。
真实 net_tap 下分别验证 INI 列表与 CLI 整体替换，读取实际地址/掩码并从独立宿主连接
主地址及两个 VIP；反向连接显式绑定各 VIP，检查宿主观察的源地址、原生 TCP 计数和资源清理。
配置检查覆盖重复/非法地址与 32 项上限；ambient VIP 设置不能改变 launcher 的配置。
这是地址配置场景适配，F-Stack 结构布局、VLAN VIP、VRRP 和故障切换仍未实现或验证。

## Linux 网络 sysctl 配置（部分适配）

`[sysctl]` 接受显式的 Linux `net.*` 名称；重复 `--sysctl KEY=VALUE` 按键覆盖 INI，
最后一个同名 CLI 值生效，其他 INI 键保留。最多 32 个不同键，键不超过 128 字节、
值不超过 256 UTF-8 字节；拒绝路径分隔符、空路径段、多行值和空值。
与 `[network] tcp_ecn` / `--tcp-ecn` 同时指定 `net.ipv4.tcp_ecn` 会报配置冲突。

```ini
[sysctl]
net.ipv4.ip_default_ttl=65
net.ipv4.tcp_keepalive_time=42
net.ipv4.tcp_keepalive_intvl=7
net.ipv4.tcp_keepalive_probes=4
net.ipv4.tcp_syn_retries=3
```

启动适配层在接口激活及 native READY 前写入私有原始 Linux 的 `/proc/sys/net/`，
内核负责值域校验；未知键或非法内核值返回 125，应用 main 不执行。
语法错误在创建 worker 前返回 2。配置不写宿主 sysctl；省略时保留 Linux 默认值，
并清除继承的内部环境配置。没有自动翻译 FreeBSD sysctl 名称。

`native-fstack-network-sysctl` 启动真实 DPDK net_tap，以 socket 选项读取上述五项实际默认值，
验证 INI、单键 CLI 覆盖、配置省略、未知键与非法 TTL，检查宿主参数不变、
应用启动顺序、实际 EAL 清理和零未释放 mbuf。
`test_ff_load_config_freebsd_boot_multi_entries` 从 blocked 调整为 partial：
多项网络配置已有运行证据，FreeBSD boot 参数和 boot/sysctl 内部链表仍未迁移，不计完整通过。

## IPv6 接口与同链路互通扩展

Ker 现在支持 `[network] address6` / `--address6 ADDRESS/PREFIX`，CLI 覆盖 INI，
与既有 IPv4 `address` 并存。IPv6 配置触发 DPDK all-multicast 接收以支持 NDP；
没有自行实现邻居发现或 TCP/UDP 协议。原始 LKL helper 经 rtnetlink 添加 IPv6 地址，
并等待原始 Linux 重复地址检测完成。配置省略时不添加显式 IPv6 地址，继承的内部变量会清除。

`native-fstack-ipv6-interop` 使用真实 net_tap，在 INI 和 CLI 覆盖两次启动中，
验证 IPv6 TCP/UDP 的双向字节一致、源/目的地址、未配置地址的 bind 拒绝、
宿主 NDP 解析到 worker MAC、IPv4 TCP 同时工作，以及原生 TCP 计数和零未释放 mbuf。
另以宿主已占用的 IPv6 地址验证 Linux DAD 拒绝，应用 main 不执行、worker 正常清理。
IPv6 VIP 见后续扩展；IPv6 VLAN 见后续扩展；RA/SLAAC 部署尚未验收；默认网关和跨网段验证见下文。

固定上游 `valid_inet6.ini` 包含 IPv6 地址、前缀、网关、VIP 和 VLAN；
但 `test_ff_load_config_inet6_fixture_ignored` 测试的是 **未启用 INET6 时忽略配置**，
不能用上述启用 IPv6 的互通测试替代。因此该源项仍为 blocked，当前 117 项 adapted、
16 项 partial、237 项 blocked 的计数不变。新运行测试是相关 IPv6 功能证据，
不声明已迁移 FreeBSD 条件编译语义或完整 fixture。

## IPv6 默认网关与跨网段互通

`[network] gateway6` / `--gateway6` 支持 global 或 link-local IPv6 下一跳，
要求配置 `address6`，CLI 覆盖 INI。省略时不创建默认路由，并清除继承的内部网关变量。
地址语法及前置条件错误在启动前返回 2；网关不在链路等内核路由校验错误返回 125，
应用 main 不执行。Ker 的 rtnetlink 适配层指定原生接口索引并等待 Linux ACK，
不使用 ONLINK 绕过内核规则、不建立自有协议实现，也不修改上游代码。

`native-fstack-ipv6-route` 使用原生 Linux、独立宿主 Linux 路由器和第三个远端
网络命名空间；两个子网分别为 `2001:db8:1::/64` 和 `2001:db8:2::/64`。
真实 DPDK net_tap 链路分别测试 INI global 网关与 CLI 覆盖成 link-local 网关。
双方验证 TCP/UDP 字节和源地址；UDP 接收端检查 hop limit 63（发送端设置 64），
同时要求路由器 IPv6 转发计数增加、原生 TCP 计数有效、worker 未释放 mbuf 为零。
额外验证无默认网关时 TCP/UDP 返回 ENETUNREACH，以及 off-link 网关的启动清理。

固定 F-Stack IPv6 fixture 的网关功能已有上述相关证据；
`test_ff_load_config_inet6_fixture_ignored` 仍保留 blocked，因为它的条件编译忽略语义、
独立 FreeBSD VIP 接口等未迁移；原生 IPv6 VIP 和 VLAN 地址见后续扩展。
尚未验收路由更新/故障切换、RA/SLAAC 和真实物理网卡。

## UDP 批量功能验收

公开 socket 的 IPv4/IPv6 合同、外部 IPv6 ancillary/错误队列/分片/分段/ASM/SSM、
IPv4 SSM 和 limited broadcast、真实路由器 PMTU、原始错包/倒序分片/重组超时，
现集中在 [UDP 验收矩阵](udp-acceptance.md) 和 `tools/validate-udp.py`。
25 个 UDP CTest 必须全部登记并实际执行；机器报告区分功能通过、已确认不支持与未验收。
宿主信号中断 native 阻塞 recvfrom 仍不兼容，专用边界检查不得算为兼容通过。
原始 Linux 的 IPv6 UDP/分片/重组计数补入诊断，作为真实数据路径的证据。
这些是 Linux 扩展验收，不增加固定 F-Stack 的 adapted 计数。


## DPDK scatter / multi-segment 存储模式

`ker-run --mbuf-mode scatter` 或 `[dpdk] mbuf_mode=scatter` 使用标准大小 mbuf pool，
启用原始 DPDK 的 RX scatter 与 TX multi-segment 能力；PMD 缺少任一能力时在 READY 前失败，
不静默回退。默认 `large` 继续使用可容纳 MTU 帧的连续缓冲，CLI 覆盖 INI。
其他 checksum、TSO、VLAN stripping 和 LRO offload 均保持关闭；协议仍由原始 Linux 处理。

发送适配器用真实 `rte_pktmbuf_chain` 构造完整帧；部分分配失败时回收整条链并保留 channel 中已读帧供重试。
PMD 只获得成功发送的链，RX 链通过已有 `rte_pktmbuf_read` 路径完整交给 Linux。
`tx_multiseg` 记录已交给 PMD 的链式帧，`rx_multiseg` 记录已成功交给 native channel 的链式帧。

`worker-mbuf` 验证真实 DPDK pool 的 14/2047/2048/2049/4096/9014 字节帧、跨段字节完整性、
pool 耗尽时部分链回收及最终可用数恢复。`native-fstack-mbuf-scatter` 在 net_tap 与独立宿主间执行
双角色 TCP/UDP；UDP 包含 8972 字节 DF 载荷、8973 字节 EMSGSIZE 边界、双向完整 9014 字节抓包，
要求双向多段计数、原始 Linux 计数及零 outstanding。large 模式对照要求多段计数为零。
这迁移了两项 MTU mode 配置场景及 multisegment send 场景；硬件 PMD、scatter 性能和跨进程共享不在本批验收范围。
清单现为 120 adapted / 15 partial / 235 blocked / 8 architecture-specific / 55 harness-only，共 433 项。


## 原始 Linux 802.1Q VLAN 与 VLAN VIP

内核构建配置启用 `CONFIG_VLAN_8021Q`，Linux/LKL/DPDK/F-Stack 上游源保持原样。
Ker 仅通过 rtnetlink 创建 `ker.ID` 子接口，再用原始 Linux 地址/链路 API 安装 IPv4 地址和 MTU。
配置示例：

```ini
[vlan.100]
addresses=198.19.100.2/24,198.19.100.3/24,198.19.100.4/24,198.19.100.5/24
[vlan.200]
addresses=198.19.200.2/24
```

也可重复 `--vlan 100=198.19.100.2/24,198.19.100.3/24`；CLI VLAN 列表整体替换 INI VLAN 列表。
最多 16 个 VLAN，ID 1–4094；每个最多 8 个地址，支持 IPv4/IPv6 混合；此处 IPv4 场景的首地址为主地址，其余为 VIP。
重复 ID、重复 IP、非法/空地址和未知字段在库/设备准备前拒绝。未显式配置时不继承宿主的 VLAN 环境变量。
Ethernet channel 为单层 802.1Q 标签保留额外 4 字节，未标记帧仍受原 MTU 限制。
DPDK VLAN stripping/filter offload 保持关闭，tag/demux 属于原始 Linux。

`native-fstack-vlan` 使用真实 net_tap、独立宿主 VLAN100/200、三个 VLAN100 VIP，
分别验证 INI + large 和 CLI 替换 + scatter。TCP/UDP 显式绑定 Linux VLAN 设备；IP_PKTINFO 检查接收设备与本地地址。
每个地址传输完整 1472 字节 UDP 载荷，抓包要求双向完整 1518 字节帧、正确标签/IPv4/UDP 校验和且无分片。
错误 VLAN200、未配置 VLAN300 和无标签探针须先经过实际 RX 抓包，且不能交给绑定 VLAN100 的 socket。
这依赖 Linux 的 SO_BINDTODEVICE 语义，不宣称把 Linux weak-host 行为改成 strong-host 防火墙。
每次要求 5 个原始 Linux passive opens、5 个 UDP input/output，以及零 outstanding。

迁移 `test_ff_load_config_dual_vlan` 与 `test_ff_load_config_vlan_vip_addr` 两个场景，
当前清单 122 adapted / 15 partial / 233 blocked / 8 architecture-specific / 55 harness-only。
本批仅验收 IPv4 单层 802.1Q，未实现每 VLAN 独立网关、QinQ、IPv6 VLAN、热变更或硬件 VLAN offload。

## 配置加载边界与恢复

`native-fstack-config-lifecycle` 通过实际 Ker loader 验证最小配置、空文件/无 DPDK
节、CLI 覆盖与 EAL 引号、缺失文件在库解析前拒绝、全部受支持配置节，以及
成功/失败交替加载后的状态隔离。8 个测试均为配置层证据，不运行 NIC 或内核。

本批新增 3 项场景适配和 3 项部分覆盖。固定源中名为
`test_vlan_cfg_handler_isolated` 的用例实际验证不存在的配置文件路径，
映射按函数体而非名称建立。F-Stack 忽略未知节；Ker 严格拒绝，故仍为 partial。
F-Stack 的完整 DPDK 字段、KNI/FreeBSD/bond/RSS/reload 配置未因此变为支持。
重复键测试明确验证 Ker 拒绝重复键；上游的 last-value-wins 用例仍 blocked。
多次加载不串状态不等同于 allocator 泄漏检测或热重载能力。

## 原始 Linux 临时端口策略

`native-fstack-ephemeral-ports` 验证 INI `[network] ephemeral_ports=40000-40007`
及 CLI `--ephemeral-ports 41000-41007` 对私有 Linux `ip_local_port_range` 的
实际作用。配置在应用启动前安装；未配置时保留 Linux 默认范围。与通用
`--sysctl net.ipv4.ip_local_port_range=...` 同时指定时拒绝，避免双重配置来源；专用
选项也不能与 `net.ipv4.ip_unprivileged_port_start` 组合。Linux 要求非特权端口边界
不高于端口范围下界。若需同时提高两者，只通过通用 sysctl，先写 `ip_local_port_range`
再写 `ip_unprivileged_port_start`；CLI 覆盖 INI 同名项时按 CLI 出现顺序重新应用，
其它 INI 项保持原顺序。真实测试使用边界优先的 INI 再以 CLI 按有效顺序覆盖两项，
覆盖范围50000-50007与边界50000。

真实 IPv4/IPv6 TCP/UDP socket 验证自动分配、唯一性、范围耗尽、释放及单一空闲
端口复用，并验证 Linux reserved-port 排除。独立宿主 TCP/UDP 对端确认实际
IPv4 源端口和负载，原始内核计数、DPDK 收发与回收均检查。宿主 sysctl 不变。
IPv6 部分为本地 socket 分配验证，不是 IPv6 线缆互通验证。

`test_ff_rss_tbl_set_portrange_inverted_range` 从 blocked 变为 partial：
倒置范围的拒绝及有效范围的原生分配已有证据；RSS 表、Toeplitz/RETA 与队列专属
端口选择仍未实现，不将原始 Linux 的端口范围误称为 F-Stack RSS 等价支持。


## IPv6 VIP 配置与互通

`[network] vip_addresses6` 接受逗号分隔的 IPv6 地址/前缀；可重复的
`--vip-address6` 替换整个 INI 列表。要求 `address6`，最多 32 个额外地址，
拒绝重复 IP（含主地址）、作用域后缀、未指定、多播、回环、IPv4-mapped 和非法前缀。
省略配置时清除继承的内部 VIP 环境变量。所有 VIP 加在既有原始 Linux 接口上，
通过未修改的 LKL rtnetlink helper 先添加全部地址，再通过原始 DAD helper 等待每个地址验证完成；
避免串行 DAD 在 32 个 VIP 时超出既有启动时限，不跳过重复地址检测。

`native-fstack-ipv6-vip` 使用实际 net_tap/veth 和独立宿主 Linux 对端，
分别验证 INI、CLI 列表替换、省略配置和 32 个 VIP 的实际启动与绑定。
主地址及两个 /128 VIP 均完成双向
TCP/UDP 字节和地址校验，检查宿主 NDP 的 worker MAC、原始 TCP/UDP6 计数和零未释放 mbuf。
额外的宿主占用 VIP 场景必须由原始 Linux DAD 拒绝，应用 main 不执行，worker 清理完成。
配置测试验证边界及错误在加载库或启动 worker 前被拒绝。

固定 F-Stack `valid_inet6.ini` 中的 `vip_addr6`/`vip_prefix_len` 是功能来源，
但 Ker 不复刻 `vip_ifname` 的独立 FreeBSD 接口；也不把“INET6 未启用时忽略配置”
测试标为通过。该源项仍 blocked，迁移计数不变。IPv6 VLAN 见后续扩展；RA/SLAAC 仍未验收。


## IPv6 VLAN 与混合地址

`[vlan.ID] addresses` / `--vlan` 扩展为 IPv4/IPv6 混合列表，保持 16 个 VLAN、
每 VLAN 八个地址的界限。原始 LKL 负责 rtnetlink 地址安装和 VLAN UP，
等待全部 Linux DAD 完成后应用才可启动；不修改 Linux/DPDK 上游源码。
VLAN 上存在 IPv6 时，即使主接口没有 `address6` 也自动启用 NDP 所需 multicast 接收。

`native-fstack-ipv6-vlan` 运行 INI/large 和 CLI 替换/scatter 两组真实 net_tap 互通：
VLAN 100 带 IPv4/IPv6 主地址与 /128 VIP，VLAN 200 为 IPv6-only。
独立宿主 VLAN peer 验证每个 IPv6 地址双向 TCP/UDP、1452 字节完整 UDP 载荷、
VLAN 设备绑定和 IPV6_PKTINFO，另检查 IPv4 共存、宿主 NDP、原始内核计数和零未释放 mbuf。
PCAP 两个方向都必须包含 VLAN 100/200 的完整 1518 字节帧与有效 IPv6 UDP 校验和。
VLAN 200/300/untagged 错误探测先经过 worker RX，不能交给绑定 VLAN 100 的 socket。
另两次启动验证 16×8 长 IPv6 地址（序列化超过原 4096 字节限制）以及宿主重复地址被 DAD 拒绝。

相关 F-Stack IPv6 fixture 测试仍为 blocked：它验证的是 INET6-disabled 忽略语义，
不是启用 IPv6 后的互通。计数不变；per-VLAN gateway、FreeBSD 独立 VIP 接口、
RA/SLAAC 和完整 fixture 等价性仍未迁移。


`dpdk.channel` / `--memory-channels` 进一步适配最小配置的 `nb_channel` 子集，
直接交给原始 EAL，并从 `rte_memory_get_nchannel()` 回读配置。五次真实 native 启动
验证省略、INI、CLI 覆盖及原始 EAL 长短参数，同时要求独立宿主 TCP/UDP 与清理证据。
仅验证 no-huge 模式下配置生效，不认证物理拓扑或性能；global layout
仍未覆盖，因此源案例保持 partial，迁移计数不变。


`dpdk.numa_on` / `--numa` / `--no-numa` 进一步适配最小配置的 NUMA 分配选择，
启用按 lcore socket 分配，关闭统一 socket 0。五次真实 worker 启动覆盖默认、INI 与
CLI 双向覆盖，同时检查 pool 元数据、原始 Linux TCP/UDP 和清理。
单节点环境不证明跨节点物理放置或性能，队列目标也不等同于驱动内存回读；
global layout 仍未覆盖，源案例保持 partial，迁移计数不变。


接口激活失败扩展使用不安装的 `ker-posix-startup-failure` 库：与生产库编译相同 Ker
适配源文件和原始 liblkl，仅在链接时包装 LKL 初始化、设备注册、内核启动和接口激活入口。成功控制必须真实激活 loopback
和设备；loopback 注入 EIO 后不得激活设备；设备 EIO 必须发生在真实 loopback 成功后。
宿主侧精确阶段记录、应用 marker 缺失、native READY 缺失、退出 125、实际 EAL cleanup
成功和零 outstanding mbuf 共同验证失败传播与资源回收。生产库不包含测试 hook。
源案例保持 partial：这里验证 Ker 适配器的注入错误，不等同于真实硬件故障或 F-Stack
FreeBSD 到 DPDK 的完整阶段/ABI，迁移计数不变。


启动失败扩展继续覆盖 `lkl_init`、`lkl_netdev_add`、`lkl_start_kernel` 的负返回值。
测试专用库的成功控制将真实 init/register/boot/loopback/interface 全部走通，
内核启动的变参命令行格式化后原样传给真实启动函数。每个注入 EIO 的实例要求阶段
记录恰好终止于目标调用，前置真实调用成功，并验证未发布 native READY、未执行应用、
退出 125 与实际 worker/EAL 清理。该证据适配初始化失败传播，不等同于内核内部自然故障
或 F-Stack/FreeBSD ABI；迁移清单计数不变，生产库无测试入口。


`native-fstack-tcp-lowwater` 在既有低水位场景上补齐两个转换：共享阈值从1重新升到64
后必须抑制已有17字节的 readiness，再降到1恢复；独立阶段先确认17字节排队且不就绪，
再允许对端补齐47字节，恰好达到64字节后 poll/select/LT epoll 才就绪，消费后清除。
额外检查非阻塞 peek 的内容、队列及 readiness 不变。复用原宿主参考和 native 双角色
双向互通，不增加重复测试或上游案例计数，不修改 Linux 协议或 Ker 适配器代码。


`dpdk.pkt_tx_delay` / `--tx-delay-us` 将最小配置的 TX 等待适配为 Ker 的有界32包批次。
0表示不主动等待，支持到100微秒；首包期限、满批、停止刷新与 PMD 部分接受后缀的所有权
均有聚焦验证。五组真实 native TCP/UDP 要求实际定时刷新，另有真实待发三帧stop/EOF
场景证明按序交付与零mbuf。受控部分接受测试与真实PMD背压证据明确区分。
不声称 F-Stack 周期TSC/多进程 ABI 或微秒调度/性能等价；完整配置布局仍缺失，源案例
保持partial，迁移计数不变，上游源码未修改。


`native-fstack-eal-memory` 补齐 `valid_dpdk_full.ini` 的 memory/no_huge 相关运行功能：
typed INI/CLI 转为原始EAL，回读真实内存字节数与页模式，五次实例验证32/64/128MiB和
独立宿主TCP/UDP，并验证 hugepages 不可用时明确失败。它不是该注册源测试的迁移通过：
`test_ff_load_config_dpdk_full` 主要断言 multi-port/bond/RSS，仍为blocked，ker_tests为空；
相关功能证据单独记录在 provenance，不改变清单计数，也不声称hugepage成功或硬件资格。


`native-fstack-eal-log-level` 继续补齐 full fixture 的 `dpdk.log_level` 相关功能，
将数值级别传给原始 EAL，在初始化后及 READY 时回读全局级别，并验证启动 INFO
日志过滤与现有运行级别覆盖的时间边界。它允许 typed 全局级别与原始 EAL component
pattern/regex 规则共存，并用七个实例走通原始 Linux TCP/UDP。
这仍是相关功能证据；源注册案例的 multi-port/bond/RSS 断言尚未迁移，保持
blocked，不增加迁移通过计数。


`test_ff_load_config_dpdk_extra_keys` 的 file_prefix 断言已有 typed 配置与真实 EAL
运行目录、同名 primary 排他、异名并发 native 生命周期和宿主 TCP/UDP 证据，
现标为 partial。其 base_virtaddr、vdev completion queues 和 bond down_delay
断言仍缺失；Ker 原样使用 prefix，不采用 F-Stack 的 container- 装饰。
未将源案例计为完整迁移，也不声称 shared hugepage/secondary 支持。


extra-keys 的 `base_virtaddr` 子集现有 typed 配置、真实 EAL 内存段地址回读和
五组宿主TCP/UDP证据，补充已有 file_prefix 子集。地址提示及16MiB对齐由原始
DPDK处理；不保证固定地址或地址冲突回退。源用例仍因 vdev completion queues、
bond down_delay 与配置 ABI 缺口保持 partial，清单计数不变。


`native-fstack-tcp-fastopen` 补齐原始 Linux Fast Open 的独立宿主互通与线路证据：
宿主参考、native client/server 均对比 MSG_FASTOPEN 和普通 connect，并要求抓包
观察到完整 SYN 数据。私有命名空间显式启用无 cookie 策略；不改变部署默认值。
这是 host message/name/shutdown 桥接场景的 Ker/Linux 扩展，非上游注册 TFO 用例，
不增加源用例迁移计数，不替代 cookie、重传或性能资格验证。


`native-fstack-tcp-fastopen-cookies` 补齐上一批保留的 cookie 协商/复用边界：
私有测试命名空间用原始 Linux 策略3，抓包关联初次 SYN cookie 请求、SYN-ACK
发放值及另一连接 SYN 对同一 cookie 的携数据复用，另有普通连接对照。
宿主参考与 native 双角色验证完全相同的流/EOF合同。该 Linux 扩展仍不计为
新增源注册用例迁移；无效 cookie、轮换、过期和非阻塞/丢包场景仍明确保留。

`native-fstack-tcp-fastopen-nonblocking` 补齐非阻塞 Fast Open 发起与无 cookie 回退：
宿主参考、native 客户端及 native 服务端三种角色均要求首次 O_NONBLOCK
MSG_FASTOPEN 返回 EINPROGRESS，经 POLLOUT 和 SO_ERROR=0 后由调用者重发完整请求；
另一连接复用 cookie 时必须立即接受正数字节。独立抓包要求 cookie 请求/返回、
新端口携 cookie 和完整请求的 SYN，以及普通 connect 空 SYN 对照。
发起完成后恢复阻塞模式验证精确流、peer、半关闭和 EOF，因此不宣称覆盖通用
非阻塞流读写。协议仍完全使用原始 Linux，未修改运行时或上游源码，来源案例计数不变。
无效 cookie、密钥轮换、缓存过期、丢包重传和 IPv6 仍待验证。

`native-fstack-tcp-fastopen-key-rotation` 补齐监听端更换密钥后的旧 cookie 回退。
测试通过原始 Linux TCP_FASTOPEN_KEY 设置并读回16字节密钥；首次连接收到请求后，
服务端先更换为另一个单密钥，再发送回显，以确定顺序而不依赖睡眠。
宿主参考、native 客户端和 native 服务端均依次完成首次协商、旧 cookie 发起、
新 cookie 发起和普通 connect 对照四条连接，检查精确流、peer、半关闭与 EOF。

独立抓包要求旧 cookie SYN 携带完整请求，但 SYN-ACK 只确认 SYN 并返回不同的
cookie；客户端在建立后的流中以相同起始序号重发完整请求。下一条连接必须
用新 cookie 携数据发 SYN，服务端须确认 SYN 加完整数据长度。native 角色同时
要求至少四次原始 Linux opens、DPDK TX/RX 和零遗留 mbuf。
这属于 F-Stack host bridge 场景的 Linux 扩展，不新增来源案例计数，也不修改
运行时或上游协议源码。仅覆盖不保留备用密钥的单密钥替换；双密钥重叠轮换、
缓存过期、丢包重传、IPv6 与性能仍未验证。

`native-fstack-tcp-fastopen-backup-key` 覆盖双密钥重叠轮换：监听端先设置 A，
用两个源地址建立独立的原始 Linux TCP Fast Open cookie 缓存后，改为主密钥 B
加备用 A，再移除备用 A 仅保留 B。每次 TCP_FASTOPEN_KEY 均读回检查精确内容和
16/32/16字节长度；密钥更改发生在发送上一连接回显之前，以确定后续连接顺序。
宿主参考、native 客户端和 native 服务端各完成六条精确流，并检查 peer、半关闭
和 EOF：两个缓存先各取得 A cookie；B 源地址在 B+A 重叠期间携 A cookie 发 SYN，
服务端确认全部 SYN 数据并返回 B cookie；移除备用 A 后，未刷新过的 A 源地址仍
携 A cookie 发 SYN。独立抓包必须观察到此 SYN 携带完整请求、SYN-ACK 只确认 SYN
并返回不同的 B cookie；客户端在建立后的流中须以 SYN 数据起始序号（原 SYN 序号
加一）重发完整请求。
B 源地址随后须用已缓存的 B cookie 携数据发 SYN并获得完整确认；另有普通连接
对照。native opens、DPDK TX/RX 与零遗留 mbuf 同样必须通过。这是 F-Stack host
bridge 场景的原始 Linux 扩展，不改变来源案例计数或运行时/上游协议代码。缓存
过期、丢包重传、IPv6 与性能仍未验证。

`native-fstack-tcp-fastopen-connect` 覆盖原始 Linux TCP_FASTOPEN_CONNECT。
宿主参考、native 客户端和 native 服务端均先用未缓存 cookie 的选项式 connect
协商 cookie，再用带缓存的新连接检查延迟 SYN，最后走普通 connect 对照。
两条选项式连接均设置并读回选项；缓存连接的 connect 必须返回0，TCP_INFO
必须仍为 SYN_SENT。客户端报告本地端口后等待协调器通过 stdin 放行首次写入。
协调器在这一屏障处排空独立抓包，要求该连接尚无 SYN；放行后必须观察同一
端口携已协商 cookie 和完整请求的 SYN。既有 cookie 请求/返回/复用、普通空 SYN、
精确流、peer、半关闭、EOF、native opens 与零遗留 mbuf 检查同时保留。
此测试不依赖睡眠，验证明确的写入前屏障，不宣称任意时长的空闲行为。
不修改运行时或上游协议实现，来源案例计数不变；非阻塞延迟 connect、写前取消、
缓存过期、丢包重传、IPv6 和性能仍未验证。

`native-fstack-tcp-fastopen-cancel` 补齐首次写入前关闭延迟连接的边界。
宿主参考、native 客户端和 native 服务端均先协商 cookie，再创建缓存 cookie
连接，要求 connect 返回0且 TCP_INFO 仍为 SYN_SENT；不写入即 close，随后
fcntl 必须返回 EBADF。客户端在关闭后等待 stdin 屏障，协调器检查独立抓包中
该连接没有任何 TCP 报文，再放行下一条不同本地端口的缓存 cookie 连接。
下一连接继续使用写前屏障，随后要求携原 cookie 和完整数据的 SYN、精确回显、
peer、半关闭和 EOF，并保留普通 connect 对照。抓包直到双方退出都不得出现
已取消连接的 TCP 报文（包括 SYN、FIN、RST）；native 角色要求至少三条成功
流的 opens、DPDK TX/RX 和零遗留 mbuf，不把取消尝试算作成功流。
这是原始 Linux 对 F-Stack host bridge 场景的扩展，来源案例计数不变，未修改
运行时或上游源码。仅验证明确屏障及测试流生命周期，不宣称任意时长无报文或
SYN 已发送后的取消行为；非阻塞延迟建连、缓存过期、丢包重传、IPv6 与性能仍待覆盖。

`native-fstack-tcp-fastopen-connect-nonblocking` 补齐选项式延迟建连的非阻塞发起。
宿主参考和 native 双向互通均设置并读回 TCP_FASTOPEN_CONNECT，再设置 O_NONBLOCK。
未缓存 cookie 时 connect 必须返回 EINPROGRESS，随后经 POLLOUT 与 SO_ERROR=0
完成连接；已缓存时 connect 必须返回0，零超时 poll 立即报告 POLLOUT 且无
错误/挂断，同时 TCP_INFO 仍为 SYN_SENT、O_NONBLOCK 仍有效。
已有 stdin 屏障和独立抓包验证写入前无 SYN，放行后该端口所有 SYN 必须携
cookie 与完整请求；还要求 cookie 请求/响应/复用、普通空 SYN 对照、精确流、
peer、半关闭、EOF、native opens、DPDK TX/RX 与零遗留 mbuf。
连接发起完成后恢复阻塞模式完成流检查，因此不宣称通用非阻塞读写。
协议仍由原始 Linux 处理，来源案例计数不变，无运行时或上游修改；
缓存过期、丢包重传、IPv6 和性能仍待覆盖。

宿主 mutex 初始化与失败清理：`native-fstack-thread-runtime` 现在还覆盖普通/递归
mutex 的 malloc、属性初始化/类型设置、mutex 初始化、属性销毁故障。Ker 在
`host-thread.c` 内提供私有 mutex 表示，失败返回 NULL 并保留 pthread 错误码，
完整销毁已初始化资源；成功路径始终使用真实 pthread 锁，保留上游源码不变。
测试通过仅测试线程有效的链接器 wrapper 注入错误，检查分配、属性和 mutex
全部归零，再验证下一把真实锁可用及递归锁可重复持有。四线程共享计数与原始
Linux 启动/关闭同时执行，并要求内核实际分配适配后的 host mutex。
无返回值的 lock/unlock/free 回调发生 pthread 错误时明确 abort；子进程验证
销毁仍持有的锁不会静默释放。

DPDK worker 的单核收发不代表 LKL 宿主运行时单线程：原始 LKL `cpu.lock`
保护虚拟 CPU owner/count，内核线程和 SIGEV_THREAD 定时器都参与宿主调度。
此处保留同步，不进行锁消除，也不宣称单 lcore 独占协议栈调度或性能结论。
这是 F-Stack thread 场景的 Ker 适配扩展，FreeBSD 线程上下文 ABI 缺口仍保留，
来源案例计数不变，无 TCP/UDP 协议实现修改。

宿主线程创建失败清理：`native-fstack-thread-runtime` 进一步覆盖 pthread_create
本身失败后的启动参数所有权。Ker 在 host-thread 适配层持有启动 wrapper，
pthread_create 返回错误时释放它，返回 LKL 的0句柄并把 pthread 错误号写入 errno；
成功时由真实子线程在执行用户回调之前释放 wrapper，再传递原始参数。
仅测试线程启用的链接器故障注入分别返回 EAGAIN/EPERM，要求未调用失败回调、
分配余额归零，且 errno 从不同的哨兵值变为预期错误。每次失败后都运行真实
create/join，检查参数、结果及回调入口之前恰好一次 wrapper 释放。
默认、DEBUG、NDEBUG 三个变体及原始 Linux 启动/关闭都验证实际适配器。
未修改上游源码、协议或调度实现，不进行应用 pthread 拦截；这不等同于真实
宿主线程资源耗尽或调度策略测试，FreeBSD 上下文 ABI 缺口和来源案例计数不变。

`native-fstack-thread-runtime` 进一步覆盖正常返回和显式 host thread_exit 后的
TLS 生命周期。真实子线程分别清空 TLS、让析构函数重设三次，或持续重设超过
宿主 `_SC_THREAD_DESTRUCTOR_ITERATIONS` 公布的最小次数；join 后检查0次、3次，
以及对超出最小值的请求至少执行公布次数且不超过请求次数。每次析构入口必须
观察到该 TLS slot 已被清空，thread_exit
不得返回到后续语句，join 必须等待析构完成。
同时验证父线程 TLS 不被子线程继承或修改，删除仍持有父线程值的 key 不调用
析构函数。默认、DEBUG、NDEBUG 均直接执行现有 Ker/LKL callbacks 和真实 pthread，
不新增运行时代码、协议或调度实现，也不提高来源案例计数。公布的最小次数和
允许的额外迭代属于宿主 pthread 合同；取消线程、detached 线程生命周期和
FreeBSD 上下文 ABI 仍未覆盖。

宿主信号量边界：Ker 的 host-thread 适配层现在持有私有 POSIX semaphore，
始终使用真实 sem_init/wait/post/destroy。负计数返回 EINVAL；分配或初始化
失败返回 NULL，保留 errno 并释放已分配存储。sem_wait 仅重试 EINTR；
无法由 void callback 返回的其他 wait/post/destroy 错误明确 abort，防止
同步失败后仍继续执行内核。DPDK 收发不改变这些宿主同步语义。

`native-fstack-host-semaphore-debug/release` 验证分配与初始化失败清理、
随后正常信号量恢复、真实 SEM_VALUE_MAX post 溢出及注入的 wait/destroy
错误。后三项在尚无宿主线程时 fork 子进程，必须观察 SIGABRT。
中断场景通过真实 pthread_kill(SIGUSR1) 和不带 SA_RESTART 的 handler，
直到转发给真实 sem_wait 的 wrapper 实际观察到 EINTR；等待线程必须重试，
且直到真正 post 才能返回。join 后检查参数/结果，并恢复信号 mask/handler。
原始 Linux 还必须实际分配适配后的信号量、启动并关闭；TCP/UDP 互通继续
通过真实 DPDK 验证。上游、协议及调度实现保持不变，来源案例计数不变。
这是 F-Stack thread 场景的 Ker 同步扩展，不宣称公平性、跨进程共享信号量、
线程取消、仍有 waiter 时销毁或性能结论。

INI 重复键现已采用最后一项生效，并以重复加载隔离及真实 DPDK/native TCP
证明最终地址、EAL 与日志目录生效。`test_ff_load_config_repeat_keys_no_leak`
从 blocked 转为 scenario-adapted；Python 管理配置存储，不宣称 F-Stack
全局结构 ABI 或 C strdup/free 泄漏检测。该配置批次后未完成为 224 blocked + 20 partial。

描述符命名空间共存场景 `test_ff_kernel_fd_encode_roundtrip` 现通过真实
Ker/LKL export/lookup 与宿主 fd 预留验证，转为 scenario-adapted。
Ker 使用映射表，不使用 F-Stack 固定偏移编码；不声明其 helper ABI 或数值范围等价。
该描述符批次后未完成为 223 blocked + 20 partial，共 243 项。

INI 长键名来源场景已通过实际 Ker reader、CLI 覆盖和原生启动失败路径适配。
60 字符键完整保留，128 字符边界可用，129 字符在启动前拒绝；真实 Linux
未知键路径必须完整显示并正确回收。它不宣称虚构 sysctl 在内核中有效。
INI 批次后未完成为 222 blocked + 20 partial，共 242 项。


MTU 手工清单现有可执行的静态 ICMP 对应项 `native-fstack-icmp-mtu`：
原始 Linux 内核与独立宿主内核经真实 DPDK TAP/veth 双向应答，分别验证
1500 large、9000 large 和 9000 scatter。每组 IPv4/IPv6 均验证 0、1 和
最大不分片 echo 载荷；9000 对应 IPv4 8972 字节、IPv6 8952 字节。
完整 TX/RX PCAP 必须含每个请求及应答，核对载荷、IPv4 header checksum、
ICMPv4 和带伪首部的 ICMPv6 checksum，以及 1514/9014 字节的完整以太帧。
9000 scatter 必须实际使用双向 mbuf chain；large 不得使用 chain，退出时
outstanding 为 0。测试程序只构造和校验探针，echo 应答由两侧原始内核生成。

该源清单现已完成场景适配：`native-fstack-live-mtu` 在同一应用及 worker 中
执行 1500→9000→1500，large/scatter 两种模式均要求每一步 Linux ioctl 与
PMD readback 一致，并由独立宿主直接核对真实 TAP MTU。每一步都执行上述
双向 IPv4/IPv6 echo、逐阶段完整抓包，以及多一字节 DF 发送的 EMSGSIZE。
1500 部署上限必须拒绝 1501 且保留原状态。

worker 独占 ethdev，通过停设备、设置 MTU、重建 RX queue 容量并重启完成变更；
TAP scatter 的接收分段数在 queue setup 时固定，仅设置 MTU 并不足以支持增长。
应用的原始 Linux ioctl 与 worker 控制请求串行；PMD 设置失败会恢复原设备及队列，
随后回滚 Linux。真实 PMD mutation 前后两种注入失败均须恢复到 1500 并再次完成
全部切换及互通。回滚自身失败时终止后端，避免不一致状态伪装为成功，mbuf 仍须全部回收。
切换允许临时丢包，不承诺并发报文无损或瞬间原子生效；只验证真实 TAP PMD，
不替代物理网卡验收。上游 Linux/DPDK 源码保持不变。

MTU 批次后共有 129 项 scenario-adapted、20 partial、221 blocked，未完成 241 项；
另有 8 项架构专用和 55 项上游工具链专用。该批次的后续清单保留剩余 304 项的 16 个 issue 分组，
整个迁移目标仍未完成。


类型化 vdev 配置现支持 `[dpdk] nb_vdev` 与连续的 `[vdev0]..[vdevN]`，
将 iface/path/queues/queue_size/mac/cq 交给原版 DPDK `net_virtio_userN`。
缺少 nb_vdev 的精确源 fixture 已验证在库加载前失败，对应源用例转为 scenario-adapted。
完整 vdev 及 bond/vdev 重复键源用例只转为 partial：实际 PMD 不接受源 fixture 中
`iface` 与 Unix socket path 的组合，`iface` 仅适用于 vhost-kernel，不能为了通过而丢弃它。

独立 vhost/TAP 后端与 native virtio-user 前端已验证受支持的 socket 子集：
实际 MAC、2 对队列容量、512 个 RX virtqueue descriptors，以及逐方向 IPv4/IPv6
ICMP 有效载荷、完整帧和 checksum。worker 仍启用一对 RX/TX queue；容量为 2
不等于同时使用两对 queue，也不构成 RSS 迁移通过。重复键和重复 section 的最终
配置必须驱动相同真实流量；两个 DPDK 进程退出时均无遗留 mbuf，后端 socket 被删除。
源组合则必须明确报告原始 PMD 错误并清理。kernel iface 后端、bond 重复键/运行及
C 分配失败/valgrind 合同继续由 [#224](https://github.com/rutlang-ai/Ker/issues/224) 跟踪。

vdev 批次后为 130 scenario-adapted、22 partial、218 blocked，共 240 个未完成案例；
另有 8 项架构专用、55 项工具链专用。该批次后清单覆盖其余 303 项，建单不等于迁移完成。


类型化 `[bond0]` 已适配完整单 bond 来源配置：mode4、两个成员、primary、socket_id、
MAC、l34，以及 poll/up/down 延迟。固定 DPDK 的延迟键未列入初始 kvargs 白名单，
部分公开 API 也没有从共享库导出；`KER_WITH_NATIVE_BOND=ON` 构建额外的原版静态
PMD worker，通过原始 setter/getter 应用策略，不修改上游代码或镜像内部结构。
默认共享 worker 不被替换，缺少 API 时明确报错。

真实 TAP/veth 成员连接独立宿主 Linux 802.3ad bond，两个成员的 actor/partner 均须
进入 collecting/distributing、使用同一个 aggregator。原始 DPDK 启动参数和实时
getter 必须一致；随后执行双向 IPv4/IPv6 ICMP、完整帧及 checksum 校验。
断开宿主的一条路径后不重启应用，剩余路径继续互通，DPDK getter 须显示一个
LACP distributing 成员。TAP carrier 仍 UP 时 active 数可大于 distributing 数，
不能将两者混为一谈。worker 空闲时仍调用原始 PMD 的 RX/零报文 TX burst，
由 DPDK 自己服务 LACP，退出先关闭成员 queue 再释放 pool，outstanding 为 0。

完整 bond 配置、缺失 count、错误 section 三项来源用例转为 scenario-adapted。
合并的 bond/vdev 重复键源用例仍 partial：vdev 的 iface+socket 组合和 F-Stack
C 分配/valgrind 合同仍由 [#224](https://github.com/rutlang-ai/Ker/issues/224) 跟踪。
bond 批次后为 133 scenario-adapted、22 partial、215 blocked，仍有 237 个未完成案例。


完整 DPDK 配置来源案例现由 blocked 推进为 partial：同一个原始 Linux 实例接入
两个真实 DPDK 设备，分别由独立 EAL worker 负责，具有各自 IPv4/IPv6 主地址和
3/2 个 VIP。每个地址实际建立 native TCP 连接，独立宿主验证全部 14 个来源、载荷与 EOF。
绑定主接口地址的同一 UDP socket 必须从附加接口发出、经主接口收回，IPv4/IPv6
完整抓包验证这条非对称路径；两个独立 Linux 协议栈无法满足该 socket/路由合同。

附加接口 MTU 由主接口创建的 native fd 查询和修改，必须命中自己的 worker，
主接口保持 1500；自己的 2000 ceiling 拒绝 9000，恢复后两个 pool 均无遗留缓冲区。
附加 worker 启动失败、附加接口原始 Linux DAD 冲突、运行中附加 worker 退出，
均须使整个启动/后端失败并回收全部 worker，不让用户应用误以为多接口已就绪。

它不是 F-Stack 全配置通过：一接口一 EAL worker 与源全局 4-lcore/每端口 2-lcore
拓扑不同，多队列 RSS、thash 调整、80/443 RSS 表及完整配置 ABI 仍未验证，继续由
[#224](https://github.com/rutlang-ai/Ker/issues/224) 和 [#220](https://github.com/rutlang-ai/Ker/issues/220)
跟踪。当前仍为 133 scenario-adapted、23 partial、214 blocked，共 237 个未完成案例。

2026-10-23 多队列与 RSS 控制面批次

为完整 DPDK 配置的 partial 项增加真实多队列能力：主接口和附加接口可配置
1..16 对 RX/TX 队列，单线程公平轮询全部 RX，保留通道背压后缀，应用 TX 仍使用
队列 0。独立原版 vhost/TAP 后端把实际主机报文送入队列 1；双向原版 Linux
IPv4/IPv6 ICMP 和完整 PCAP 通过，真实队列计数验证队列 0 为零、队列 1 有报文。
双队列 TAP 还验证 MTU1500/9000/1500、scatter、失败回滚及零缓冲区泄漏。

RSS 适配器只调用原版 ethdev API，检查四类 TCP/UDP IPv4/IPv6 哈希能力、可读密钥、
有限 RETA，编程并逐项读回轮换映射；不支持或读回不一致会在应用启动前失败。
原版 null PMD 的控制面测试保留密钥并修复独立污染的128项 RETA，故障注入确认
成功 API 返回但内容错误也会被拒绝。这不构成真实哈希流落点测试。当前 TAP 构建
缺少 libbpf RSS、宿主禁用非特权 BPF，且全局 API 本身没有所需 RETA/密钥读回；
当前 vhost 后端也没有 RSS 支持。未更改上游源码或宿主权限来绕过这些边界。

源 `test_ff_load_config_dpdk_full` 继续为 partial；31 项 RSS/table/thash 案例没有因此
转为完成。全局多 lcore、对称 RSS、实际流落点、原版 Linux 源端口与队列配合、
80/443 表等由 issues224/220 继续跟踪。计数仍为133 scenario-adapted、23 partial、
214 blocked，237 项未完成，另外8项架构专属和55项 harness-only 保留其原因。

2026-10-23 原生回调 run/stop 批次

增加 `ker_posix_run` / `ker_posix_stop_run`，由调用方提供业务回调，Ker 仅负责运行/停止
和原版 Linux/DPDK 生命周期。保留回调参数、当前线程执行和忽略返回值的合同，支持
重复停止、外部线程停止及 NULL 回调等待；嵌套/并发 run 明确失败。停止先关闭原生
socket、等待发送队列、移除设备并停掉内核，再由 launcher 停止、回收全部 EAL worker，
确认零 mbuf 所有权后才应答。回调程序在 API 返回后继续运行六秒，验证完整清理不依赖
应用退出；独立宿主端观察四条原生 TCP 的 EOF，另有四条 UDP 交互，覆盖双接口 IPv4/IPv6。
真实 worker 退出后的失败码会反馈为 API 的 EIO 和 launcher 的125，不会伪报清理成功。

`test_ff_run_and_stop_forward` 完成原生 API 场景适配。`test_main_loop_one_iteration_then_stop`
仍为 partial：一次应用回调不等于原始 F-Stack EAL dispatch/RX/message/TX/accounting
只运行一次；独立 worker 与原版 Linux 调度器仍自主运行，未实现原始耦合循环/lcore ABI。
该差异继续在 issue223 中保留。当前为134 scenario-adapted、22 partial、214 blocked，
仍有236项未完成，另有8项架构专属及55项 harness-only。

2026-10-23 接口上下文与空上下文批次

核对固定版本原始实现，`ff_dpdk_register_if/deregister_if` 是上下文分配、保存字段及
释放函数，不是运行期设备热插拔。对应的生产 packet-device 上下文现在自行验证
连接的 Unix datagram/seqpacket 通道；非法 fd、文件、stream、Internet datagram
和未连接通道在分配前明确失败。失败保留调用方 fd/标志；成功接管单个端点、标记
CLOEXEC 并拥有独立 eventfd，释放不会关闭对端 fd。真实断连通道启动报告 ENOTCONN，
不再把所有创建错误都误报为 ENOMEM。实际分配失败、eventfd 耗尽和64次循环均检查
fd/内存所有权，原版 LKL 双接口注册/收发/移除及原版 DPDK 回收提供运行证据。

TX/RX 对 NULL 上下文安全返回 EINVAL；借用向量的指针、长度、内容和所有权均保留，
随后可用有效上下文正常传送。完成 `test_ff_dpdk_if_send_null_ctx_safe` 的双 NULL
合同；`test_ff_dpdk_if_send_null_ctx_with_mbuf` 要求释放拥有的 FreeBSD mbuf，不能
用借用 iovec 的错误返回冒充该合同，继续由 issue223 保留。也不宣称 FreeBSD 指针
布局、软件 LRO 或运行期热插拔兼容。上下文 roundtrip 与双 NULL 共完成2项适配，
当前136 scenario-adapted、21 partial、213 blocked，仍有234项未完成，另有8项
架构专属和55项 harness-only。

2026-10-23 原生 TX 卸载适配批次

实现 opt-in 的原版 Linux virtio CHECKSUM_PARTIAL/GSO 到原版 DPDK mbuf 转换，
从真实 PMD 能力和配置读回协商 Linux 特征、描述符/缓冲区上限，并扩大有界 GSO
通道。实际 TCP/UDP、分段、序号和重传仍由原版 Linux 与原版 DPDK 执行，未复制
Ker 协议状态实现。原版 TAP 的软件 checksum/IPv4 TSO 经过独立宿主线包验证：
两条各512KiB TCP 字节完整覆盖、四种长度的 IPv4/IPv6 UDP、全部 checksum、
每段 MTU 和抓包零丢包。先做1600/1500 MTU 停启再传输；large/scatter 均通过。
不支持的原版 null PMD 在应用执行前明确失败；畸形元数据在修改 buffer 前拒绝。

固定版本 TAP 的 RX-first 队列顺序会跳过 TX GSO 初始化，已通过原版 API 调整
设置顺序，无需修改依赖。其软件 GSO 不支持 IPv6，因此只声明 HOST_TSO4，
IPv6 软件分段仍归原版 Linux。TAP 拒绝卸载发送时还有无法用公开 API 恢复的
私有 header/标志所有权缺陷；实际 EAGAIN 注入后发现1个 outstanding mbuf，
已建 [#244](https://github.com/rutlang-ai/Ker/issues/244)。当前失败关闭、报告125并
回收进程，禁止重试变更过的 buffer，正常收发均为零 outstanding。

四个 `test_ff_dpdk_if_send_{ip_csum,tcp_csum,tso,udp_csum}` 的新证据全部来自原版
Linux/PMD 路径；旧 Ker 自有协议单测不再作为这些硬件案例的运行证据。
TAP 通过的是原版 PMD 的软件实现，不是物理 NIC 硬件，IPv6 TSO 也未验证，
因此四项仍为 partial，未增加完成计数。当前仍为136 scenario-adapted、21 partial、
213 blocked，共234项未完成，另有8项架构专属及55项 harness-only。
