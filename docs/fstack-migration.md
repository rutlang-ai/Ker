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
| scenario-adapted | 308 | 有现存 Ker CTest 和来源映射；是场景适配，不是 API/实现等价认证 |
| partial | 4 | 有相关场景，但未满足完整源用例合同；remaining 字段记录缺口 |
| blocked | 51 | 没有完整可执行的 Ker 对应项；明确保留缺口，不计为通过 |
| architecture-specific | 15 | FreeBSD callout、kqueue filter、mbuf 头、page-array 构建限制及线程上下文/返回值 ABI 断言，不计 Linux 测试通过 |
| harness-only | 55 | 53 个 F-Stack reload 工具链自测及 2 个 CMocka smoke；不计 Ker 网络覆盖 |

**全部原始测试已纳入；全部行为迁移尚未完成。** 当前为308 scenario-adapted、4 partial、51 blocked，共55项行为未完成；架构专用与 harness-only 不计通过。
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

下方按批次记录的计数是对应记录时点的历史快照，不是当前汇总；当前状态以本页顶部表格和最后的集成更新为准。

持续迁移以固定版本的 433 项源案例为准。未完整适配及排除边界共125项记录在
[后续清单](../tests/fstack-followups.json) 中关联一个具体 issue：55项行为未完成
（4 partial + 51 blocked），另有15项架构专用和55项上游工具链自测。
**建单不是迁移通过，也不会解除 `--require-complete` 的失败。**

后续清单将案例分为需要适配器实现、合同差异待决策、架构专用和上游工具链专用。
需要适配器的继续移植；合同差异必须逐项核对，不能为了减少计数加入无实际调用方的
API，或改写原版 Linux 协议实现。不适合直接移植的案例保留精确源 ID、理由、issue
和可接受的替代/排除边界；不把原始 helper 的成功、软件 checksum、普通 FIFO 或
额外 socket 功能测试冒充硬件 offload、跨代 reload 或原始 ABI 合同通过。

| 工作组 | 源案例数 | 处置类别 | issue |
|---|---:|---|---|
| Design generation-aware reload, IPC and drain ownership | 13 | 需要适配器实现 | [#218](https://github.com/rutlang-ai/Ker/issues/218) |
| Define a supported host exception bridge and KNI policy adaptation | 6 | 需要适配器实现 | [#219](https://github.com/rutlang-ai/Ker/issues/219) |
| Qualify RSS steering and queue-aware source-port contracts | 26 | 需要适配器实现 | [#220](https://github.com/rutlang-ai/Ker/issues/220) |
| Add positive hardware checksum and TSO acceptance coverage | 4 | 需要适配器实现 | [#221](https://github.com/rutlang-ai/Ker/issues/221) |
| Define packet-dispatch and PCB callback adaptation boundaries | 7 | 合同差异待决策 | [#222](https://github.com/rutlang-ai/Ker/issues/222) |
| Resolve device/run lifecycle and upstream fault-injection contracts | 2 | 合同差异待决策 | [#223](https://github.com/rutlang-ai/Ker/issues/223) |
| Adapt typed vdev, bond and multi-port configuration | 0 | 需要适配器实现 | [#224](https://github.com/rutlang-ai/Ker/issues/224) |
| Define a Linux-native zero-copy send and ownership contract | 7 | 合同差异待决策 | [#225](https://github.com/rutlang-ai/Ker/issues/225) |
| Resolve remaining typed configuration and intentional schema differences | 1 | 合同差异待决策 | [#226](https://github.com/rutlang-ai/Ker/issues/226) |
| Decide F-Stack primary/secondary and thread-mode compatibility | 1 | 合同差异待决策 | [#227](https://github.com/rutlang-ai/Ker/issues/227) |
| Document and qualify host/native stack coexistence configuration | 4 | 合同差异待决策 | [#228](https://github.com/rutlang-ai/Ker/issues/228) |
| Resolve unmapped host memory, time, environment and kqueue helpers | 3 | 合同差异待决策 | [#229](https://github.com/rutlang-ai/Ker/issues/229) |
| Resolve INI callback, userdata and section semantics | 6 | 合同差异待决策 | [#230](https://github.com/rutlang-ai/Ker/issues/230) |
| Record FreeBSD thread context and join-result assertions | 3 | 架构专用 | [#231](https://github.com/rutlang-ai/Ker/issues/231) |
| Record nonportable callout, kqueue, mbuf and page-array build assertions | 12 | 架构专用 | [#232](https://github.com/rutlang-ai/Ker/issues/232) |
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
| [integration/test_ff_kni_integration.c](../tests/upstream/fstack/tests/integration/test_ff_kni_integration.c) | 8 | 8 | 0 | 0 | 0 | 0 |
| [integration/test_ff_reload_integration.c](../tests/upstream/fstack/tests/integration/test_ff_reload_integration.c) | 7 | 0 | 0 | 7 | 0 | 0 |
| [integration/test_graceful_reload.sh](../tests/upstream/fstack/tests/integration/test_graceful_reload.sh) | 1 | 0 | 0 | 1 | 0 | 0 |
| [integration/test_mtu.sh](../tests/upstream/fstack/tests/integration/test_mtu.sh) | 1 | 1 | 0 | 0 | 0 | 0 |
| [unit/test_ff_callout.c](../tests/upstream/fstack/tests/unit/test_ff_callout.c) | 6 | 0 | 0 | 0 | 6 | 0 |
| [unit/test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c) | 96 | 32 | 9 | 55 | 0 | 0 |
| [unit/test_ff_config_pa.c](../tests/upstream/fstack/tests/unit/test_ff_config_pa.c) | 2 | 0 | 0 | 0 | 2 | 0 |
| [unit/test_ff_dpdk_if.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c) | 67 | 6 | 2 | 59 | 0 | 0 |
| [unit/test_ff_dpdk_kni.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c) | 25 | 15 | 0 | 10 | 0 | 0 |
| [unit/test_ff_dpdk_pcap.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_pcap.c) | 9 | 9 | 0 | 0 | 0 | 0 |
| [unit/test_ff_epoll.c](../tests/upstream/fstack/tests/unit/test_ff_epoll.c) | 21 | 19 | 0 | 0 | 2 | 0 |
| [unit/test_ff_host_interface.c](../tests/upstream/fstack/tests/unit/test_ff_host_interface.c) | 34 | 26 | 0 | 8 | 0 | 0 |
| [unit/test_ff_ini_parser.c](../tests/upstream/fstack/tests/unit/test_ff_ini_parser.c) | 25 | 19 | 1 | 5 | 0 | 0 |
| [unit/test_ff_init.c](../tests/upstream/fstack/tests/unit/test_ff_init.c) | 6 | 5 | 1 | 0 | 0 | 0 |
| [unit/test_ff_ipc.c](../tests/upstream/fstack/tests/unit/test_ff_ipc.c) | 12 | 0 | 0 | 12 | 0 | 0 |
| [unit/test_ff_log.c](../tests/upstream/fstack/tests/unit/test_ff_log.c) | 13 | 13 | 0 | 0 | 0 | 0 |
| [unit/test_ff_thread.c](../tests/upstream/fstack/tests/unit/test_ff_thread.c) | 5 | 2 | 0 | 0 | 3 | 0 |
| [unit/test_ff_zc_send.c](../tests/upstream/fstack/tests/unit/test_ff_zc_send.c) | 13 | 4 | 0 | 7 | 2 | 0 |
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

`test_ff_pthread_create_basic` 和 `test_ff_pthread_join_retval` 的原始断言已在
[线程合同审计](fstack-thread-contracts.md) 中明确为架构专用排除，不能计为 Linux 通过：
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
显式 mtu_enable 禁用分支已由后续 MTU policy 批次适配；内部配置 ABI 不声明等价。

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
`test_ff_init_fail_dpdk_if_up` 现为场景适配：真实 `lkl_if_up` 设备激活 EIO 紧随成功 loopback，
在 native READY/main 前失败，并验证实际 worker/EAL 清理与零 outstanding。非本子网网关
另行验证原始 Linux 路由拒绝；不声称 `ff_dpdk_if_up` ABI、exit(1) 或多端口回滚等价。
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


`test_ff_load_config_dpdk_extra_keys` 仍为 partial。较早的记录曾将 vdev `cq` 和
bond `down_delay` 称为缺失；后续 typed adapters 已补上配置路径：vdev 的 `cq`
被校验并传给原始 DPDK `--vdev` 参数，真实 typed-vdev 运行 profile 使用 `cq=1`
通过原始 PMD 收发流量；bond 的 poll/up/down timing 经原始 PMD setter/getter 应用和
回读，已测运行 profile 的 `down_delay=200`。源 fixture 的 `down_delay=300` 没有单独
用该精确值复测，因此这里不声称该数值的 runtime readback。

该完整 source fixture 仍不适合作为 Ker runtime profile：[dpdk] `allow` 和数字
`port_list` 不在 Ker typed schema 中；其 `iface=net_pcap0` 与 Unix socket `path=/tmp/x`
组合也被固定版本 DPDK 的 virtio-user PMD 拒绝。Ker 的命名设备选择和 strict schema
不是 F-Stack numeric port list / global config structure 的复刻。Ker 仍原样使用
`file_prefix`，不添加 F-Stack 的 `container-` 装饰；`base_virtaddr` 是原始 EAL hint，
不保证固定映射、冲突 fallback、shared hugepage 映射或该 source profile 的 secondary
使用。以上差异维持 partial，清单计数不变。


extra-keys 的 `base_virtaddr` 子集已有 typed 配置、真实 EAL 内存段地址回读和五组
宿主 TCP/UDP 证据，补充已有 `file_prefix` 子集。地址提示及 16 MiB 对齐由原始 DPDK
处理；该运行证据不消除完整 source fixture 的上述边界。


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
现为场景适配，仅对应 callback stop、run 返回和清理 smoke：Ker 的 one-shot 回调在原版 Linux
真实流量后停止，等待 worker ACK/reap 并检查零 outstanding。原测试源码注释描述的单次
EAL-lcore 耦合 dispatch/RX/message/TX/accounting 轮次不是其显式断言，也不是 Ker 实现；
该架构边界继续由 issue223 跟踪。上文数量是2026-10-23该批次的历史计数。

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

2026-10-23 TAP 卸载拒绝重试批次

增加可选隔离补丁修复 issue244：校验和使用私有全包副本，失败时保留调用者链、
字节和标志；GSO/写入拒绝恢复原 TSO 标志。公开 ethdev 无法找回已遗失的私有头部，
故记录最小上游例外，并从固定提交导出独立构建目录，不修改依赖 checkout。
worker 只对逐端口确认使用修复的驱动开放重试；未修改 PMD 保留失败关闭。
测试覆盖注入 ENOMEM/EAGAIN、GSO 部分写出、真实池耗尽、完整 mbuf 描述符/数据
保持与零泄漏，再以完整原生 TCP/UDP 和独立线包校验验证重试后的实际交付。
额外复制不作性能等价声明，部分 GSO 前缀可能重复，去重归原版 Linux TCP。
补丁说明见 [compat/dpdk/README.md](../compat/dpdk/README.md)。
四项硬件案例仍为 partial，未增加完成计数；当前仍有234项未完成迁移。

2026-10-23 virtio/vhost-kernel IPv6 TSO 批次

支持明确命名的 kernel TAP 接收模式适配：原版 virtio-user 缺少 CTRL_RX 时，
验证真实后端和 iface，设置并读回宿主 IFF_ALLMULTI，退出/错误回滚原值。
不对其他不支持的 PMD 返回假成功，也不修改 Linux/DPDK 源码。
实际 path=/dev/vhost-net、iface、MAC、queue_size512、1/2 active queue pairs
已经通过原版 PMD/宿主内核运行，五组完整 IPv4/IPv6 TCP/UDP 线包验收覆盖
checksum、TSO4、TSO6、MTU 队列停启、持久接口标志恢复、缺少 iface 拒绝和
真实设置后读回错误回滚。原版 TC 转发承载 Ethernet；全部协议与分段归原版 Linux。
物理 NIC 卸载验收仍缺失，TAP 自身的 GSO 仍只支持IPv4；四项硬件案例继续 partial。
源配置的 iface+Unix socket 字面组合仍不被固定版本 DPDK 支持，不能以受支持的
kernel tuple 冒充原例全部通过，C 分配器/combined topology 也仍由 issue224 保留。
当前仍为136 scenario-adapted、21 partial、213 blocked，共234项未完成。


2026-10-23 原版 Linux 登记缓冲区批次

新增实际 Linux mmap/munmap 支撑的缓冲区，供原生 MSG_ZEROCOPY 固定页与完成
通知使用。核实原版 F-Stack ff_veth.c/ff_syscall_wrapper.c 后保留 FreeBSD
mbuf交接ABI边界，不复制其算法镜像。未登记内存在页查找前明确 EFAULT，SO未开启
和无标志的复制发送保持原义；socket别名按原版SO_COOKIE同步选项，sendmmsg保留
已成功前缀。测试在真实网络上消费完成编号并区分COPIED，验证跨线程VMA生命周期、
完整TCP/UDP线包和显式run后的映射/控制锁/EAL回收。停止时RX后缀回收单独计数。
13项源案例仍缺少等价的owned-chain/write-cursor合同，issue225保留逐项审查。
F-Stack默认ff_dpdk_if_send同样复制；FF_USE_PAGE_ARRAY是独立可选路径。
Unix packet通道零拷贝是更强的后续里程碑，不额外作为全部13项socket快路径测试
的完成前提，也不能由完成码0冒充；其所有权/背压/故障停机要求另行保留。
当前仍为136 scenario-adapted、21 partial、213 blocked，共234项未完成。

## 零拷贝参数合同逐项验收

[13 项合同核对](fstack-zc-contracts.md) 新增 4 项真实 Linux 参数边界验收，
2 项 FreeBSD mbuf 头字段明确为结构特定，7 项继续 blocked。当前 partial + blocked
共 228 项；所有 293 项非 adapted 记录仍有 issue 跟踪，未声称全量完成。

## 原生映射缓冲区动态调整

新增 `ker_posix_buffer_realloc`，解决原始 Linux VMA 不能交给宿主 libc realloc
的内存域边界。实际 Linux 匿名映射实现扩容/缩容，保留前缀并清零新增范围；
失败保留旧映射，回滚释放失败的临时映射仍登记到关闭回收。零大小是 F-Stack
源辅助函数的指针 identity/no-op，包括外部 sentinel；不会授予注册权限。

`native-fstack-buffer-resize` 启动原始 Linux，验证 64 字节清零、8->32 保留、
零大小、跨页扩缩、失效基址，以及注入 mmap ENOMEM / munmap EIO 后的恢复和
最终完整回收。真实 virtio/vhost-kernel TCP 在原始完成通知后扩缩缓冲区，继续
验证完整 IPv4/IPv6 512KiB 线上内容。三个源内存场景进入 adapted；累计
143 adapted、21 partial、204 blocked、10 架构特定、55 harness-only，仍有225项
未完成。零拷贝写游标/空链的缺口没有因此减少，issue225 保持原处置。

## 真实宿主 Linux 异常 TAP

[宿主异常接口](host-exception.md) 将显式 outer EtherType 的入站帧送到独立 Linux
TAP，其余有效帧仍进入原始 Linux native 实例。宿主 TAP 出站通过原始 DPDK PMD
返回线路。接口独占、非持久、MAC 与实际主端口一致，退出删除；已有接口拒绝且不改写。
有界队列、真实内核 writev/AF_PACKET、原始 net_ring PMD 验证完整/部分接收、
整批限流及其 overshoot、满队列释放与关闭后回收。

生产 worker 另验证独立 veth/原始 wire PMD 下的广播/单播数据、原始 Linux
PACKET_HOST 分类、原 native UDP 共存和 RX/TX 抓包。8 项 integration 用例进入
adapted；这不是 F-Stack 私有 globals/virtio_user 热插拔 ABI 或协议/端口位图等价。
其余 30 项 KNI 源合同继续在 #219 跟踪。当前151 adapted、21partial、196blocked、
10架构特定、55harness-only，共217项 blocked/partial，完整迁移门禁仍失败。

## 原始 DPDK 协议分类与宿主/native 端口分流

新增 `exception_mode=ports`、TCP/UDP 端口列表及 accept/reject 策略，复用
原始 DPDK 解析器提供跨 mbuf 的头部几何。ARP/NDP 控制帧只复制一次到宿主，
原帧继续给原始 native Linux；真实通道背压也不能重复复制。独立 peer 网络命名
空间与两个原始 Linux 栈实际完成 IPv4/IPv6 TCP/UDP 收发，返回身份和完整非周期
数据验证实际归属，两种策略均通过。

15 项协议/端口初始化源场景和2项策略配置场景进入 adapted。源用例的短内层
IPIP 拒绝之外，还检查完整内层匹配/不匹配，避免靠一律拒绝隧道通过负例。NDP
五种类型与非 NDP/截断帧独立核对。端口模式对分片明确丢弃计数，不增加 Ker
重组或流状态替代实现；深层封装、自动临时端口归属仍未完成并保留在 #219。

当前175 adapted、21 partial、172 blocked、10架构特定、55 harness-only，
共193项 blocked/partial；KNI 源案例仍有6项，完整迁移门禁继续失败。


## 异常队列控制/普通流量入队预算

新增 `exception_console_rate` / `exception_general_rate`，按实际 ARP、L2 组播、
OSPF/NDP 分类分别扣减预算；普通单播使用 general。零关闭对应计数，启用时每次
尝试先计数，前 N 次可入队，之后消耗并释放 mbuf；满队列尝试也只扣一次。
保留独立的出队后 kernel batch gate，不用批量门禁冒充严格入队预算。
`native-fstack-exception-tap` 的四个源用例标记验证真实 TAP 字节、超限、窗口重置、
独立类别、满环和关闭释放；服务互通测试对两个策略启用预算，要求真实
host/native IPv4/IPv6 TCP/UDP 完成，并用三次 ARP channel EAGAIN 和独立抓包检查
没有重复克隆或扣减。协议处理仍由原始 Linux 完成，未修改上游 Linux/DPDK。
本批新增四项适配，issue219 保留九项源合同和已记录的功能缺口。


## 无效 EAL 进程类型拒绝合同

源用例 `test_ipfw_pr_cfg_handler_isolated` 名称具有误导性：其实际函数体向
`ff_load_config` 传入 `-t bogus_proc_type` 并断言失败，并未测试 IPFW 防火墙。
`native-fstack-eal-file-prefix` 现经真实 INI/launcher/worker 向原始 DPDK 传递
两种 `--proc-type` 参数形式，要求来自原版 EAL 的精确错误、应用 sentinel 未创建、
worker 已退出、无就绪统计/异常 TAP/运行目录。之后同一 file prefix 的合法 primary
实例仍完成真实原生 TCP/UDP；现有共享锁互斥及并行独立实例也继续验证。
这适配拒绝场景，Ker 的退出125与源函数返回-1明确区分，不声称 F-Stack parser ABI。
新增一项适配，总计173；仍有195项 blocked/partial。另两个主核用例要求具体
端口的 `lcore_list` 包含 primary，现有单 worker 不是该合同的完成证据，继续保留
在 #219，连同六项跨代 owner/分配合同，共八项源缺口。


## 实际端口 RX 核归属与主核成员校验

新增 [端口 RX lcore 配置](rx-lcores.md) `[dpdk] rx_lcores` / `--rx-lcores`，以及
独立的 `[interface.NAME] rx_lcores`。选中的原始 EAL 核实际独占 RX 队列；远端核
通过原始 DPDK SP/SC 环将完整 mbuf 交给主核，满环保留 FIFO 后缀，关闭先 join
再回收。主核继续独占 native channel、异常 TAP、PCAP、TX 和设备控制，协议仍由
原版 Linux 处理。两个源配置用例要求异常接口的实际 EAL 主核属于该端口的列表，
现在有真正使用该列表的执行证据，而不是只验证一个闲置的核心名单。

`native-fstack-rx-lcores` 以原版 virtio/vhost/TAP 独立注入两队列，验证主核0、
主核1、无异常接口时全远端 RX 三种配置的真实 lcore/CPU/队列计数，以及
IPv4/IPv6 TCP/UDP、精确异常字节、PCAP、不可变 MTU、零遗留缓冲区。
主核缺席与禁用核请求必须在应用入口前拒绝。这里没有宣称硬件 RSS。
配套 ownership CTest 使用真正的双核 net_ring，验证多段 mbuf、满环重试的字节
及 FIFO、关闭后缀 PCAP、命名冲突和真实 `/dev/full` 错误下的完整释放。
本批新增两项源适配，总计175项；193项 blocked/partial 仍未完成。#219 保留六项
跨代 owner/注入环/命名分配源合同，以及现有功能缺口，不把同代多核误记为跨代所有权。


## 远端 RX 的 MTU 事务与审计修复同步

远端 RX 现在先暂停并 join，记录/捕获/释放未交接帧，再执行原始 PMD 队列重建。
成功或成功回滚后按原核归属恢复，累计计数不重置；回滚或恢复失败则关闭会话，
不继续使用半配置设备。原始 DPDK 报告的 RX 头空间也用于 large 缓冲区上限，
修正 virtio 已建队列后设置 jumbo MTU 时设备头空间不足的问题。异常 TAP 的双设备
MTU 事务仍是独立缺口，没有用单侧修改冒充完成。

同步 #235 的分组处置约束及 #236 的 DF 抓包断言；动态 MTU 检查按九个序号验证，
静态检查按三个序号验证。严格审计发现两条已有 architecture-specific 的 FreeBSD
mbuf 头字段断言仍在 #225 contract-review 分组，现移至 #232 架构专用分组。
#225 保留七条 blocked 写入/空链/零发送合同；#232 共十条架构排除。
用例状态、433 项固定分母和175项已适配计数均不改变，也没有将建单或分组修正计为通过。


## 异常 TAP 与 wire PMD 的双设备 MTU 事务

原先显式拒绝的异常 TAP live MTU 现在由主核协调两个实际设备：先检查当前
MTU 一致性和待发队列，再暂停远端 RX，重建原始 PMD 队列，设置并读回所拥有
TAP 的 MTU。两侧成功后才恢复 RX 并确认 native 变更；任一侧设置失败都恢复
两侧旧值，回滚或恢复失败则终止会话并回收缓冲区。协议仍由原版 Linux 实现，
没有修改 Linux 或 DPDK 源码。

`native-fstack-rx-lcores` 覆盖主核0、主核1、仅主核 RX、全远端 RX，以及
PMD 和 TAP 设置前/设置后故障、TAP 回滚失败和远端恢复失败。独立宿主读取
异常 TAP 的实际 MTU，并逐字节验证异常帧及原始 Linux IPv4/IPv6 TCP/UDP。
`native-fstack-exception-tap` 还独立核对 native、实际 wire PMD TAP 和异常
TAP 的1500→1400→1500读回。仅主核 RX 没有远端 poller 重启，保留单次
启动计数；远端 RX 成功或回滚后使用原核心分配恢复。

这是已有适配场景的运行时缺口补全，不增加源用例适配计数。固定分母433项、
175项 scenario-adapted 和193项 blocked/partial 均保持不变；#219 的六项
跨代 owner、注入环及命名分配合同仍待完成，没有用同代双设备事务替代它们。


## 线程源合同的架构处置

逐项审计发现 `test_ff_pthread_create_failfast` 只调用测试文件自建的 FreeBSD
PCPU 空上下文访问器，并不创建线程或注入 malloc 失败。另两条源断言分别要求
继承 `pcurthread` 指针，以及把非空 start 返回值变为 join 的 NULL 输出；原版
Linux/LKL 的 task/TLS 和 void-start、handle-only join ABI 不表达这些合同。
详见[源断言、回调签名及实际边界证据](fstack-thread-contracts.md)及 #231。
三项改列架构专用，删除歧义 pass 映射；不添加无消费者的 FreeBSD 模拟层。
175项已适配数不变，清单为19 partial、171 blocked、13架构专用、55 harness-only，
固定分母433；190项 blocked/partial 尚未完成，完整迁移门禁必须继续失败。


## 配置存储分配失败的真实加载边界

三个原始配置 OOM 场景现在适配到实际 Python loader 的接口、vdev、bond
配置对象分配。测试子进程只替换目标 builder 的一次真实 dict 分配并抛出
MemoryError，其他解析及分配继续执行原实现；旧 launcher 三个故障点均产生
未捕获 traceback。修复后 CLI 明确返回2，在 worker limit 查询、库路径解析、
进程创建和应用入口之前结束；不产生统计或应用 marker。撤销故障后，同一
输入必须经真实 loader 成功构造一个对应 typed 对象，验证全局状态未被污染。
bond 恢复阶段使用仅实现 `--dpdk-limits` JSON 合同的测试子进程，以隔离 schema
恢复；`native-fstack-launcher-config-interop` 使用实际 worker 和原版 Linux TCP。

这适配源测试的“配置分配失败使加载失败”，不声称 C calloc 次序、NULL 指针、
全局结构布局或 ff_load_config 返回-1等价，也不承诺宿主全局 OOM 时仍能分配
诊断内存。生产代码没有测试故障开关。实际配置启动/原始 Linux TCP 回归仍需通过。
三个已适配源 ID 为 test_alloc_port_cfgs_calloc_oom_returns_error、
test_vdev_cfgs_calloc_oom_returns_error、test_bond_cfgs_calloc_oom_returns_error。
清单为178适配、19partial、168blocked、13架构专用、55harness-only，共433项；
187项 blocked/partial 仍未完成。#224 继续跟踪其余三个 typed fixture/RSS 合同。


## VLAN 记录数组与合并后 RX 核列表的分配失败

`native-fstack-launcher-config` 的测试子进程在生产 read_configuration 创建
VLAN 配置记录列表的 BUILD_LIST 指令前注入 MemoryError，明确覆盖真正的
VLAN 记录存储，而不是复用 vdev/bond 字典分配结论。退出2发生在任何 worker
查询、进程创建、库解析和应用入口之前；撤销故障后，同一输入必须还原两个
VLAN 的 tag 和全部 IPv4/IPv6 地址。这完成源 VLAN 配置分配失败拒绝场景，
不声称 C calloc 次序、结构布局或返回-1一致。

另验证 CLI VLAN 地址列表和 INI/CLI 合并后的 RX owner 核列表分配失败。
后者位于原有配置文件异常处理范围之后；main 现在也拦截参数构造 MemoryError，
返回2且不产生 traceback。三个旧版本负对照重现该缺陷，四条新路径均要求
无 marker/stats 且真实重解析恢复。故障仅由测试子进程的 opcode trace 注入，
生产没有故障开关，也没有模拟成功的配置或设备操作。

源 test_parse_lcore_mask_calloc_oom_returns_error 分配全局 proc_lcore 表；
Ker 目前把全局 mask 转交原始 EAL，RX owner 列表不是那张跨进程表。因此该项
继续 blocked，不把本批 RX 验证计成它的完整或部分迁移。清单为179适配、
19partial、167blocked、13架构专用、55harness-only，共433项，仍有186项未完成。


## 宿主与 native 同元组 socket 共存的实际边界

新增[共存合同](stack-coexistence.md)：同一进程的宿主/native UDP socket
无 reuse 标志同时绑定相同 loopback IP/port，精确字节和 peer 元组互不串流；
同一混合 epoll 保留完整64位标签，两个关闭顺序均保留幸存端流量。原始 native
UDP 计数精确为3，排除宿主流量；宿主对照必须因同内核绑定冲突而得到 EADDRINUSE。
现有同号内部 fd 映射和独立 DPDK TCP 回归继续保留。UDP 本身走各自 loopback，
不声称经过 wire PMD。

四条原始 [stack] kernel_coexist 配置断言仍 blocked：Ker 不保存该全局字段，
拒绝显式1/0/garbage，缺少该节时仍按 fd 所有权共存。实际 socket 证据不能冒充
布尔解析等价；#228 已记录精确差异。不添加成功 no-op 配置或无消费者开关。
清单179适配、19partial、167blocked、13架构专用、55harness-only保持不变，
186项 blocked/partial 仍未完成。


## Primary-only EAL 入口与源进程模式差异

新增[进程模式合同](process-modes.md)：主/附加接口的显式 secondary 参数
在任何 worker 执行前失败2；真实同前缀 primary 必须持续运行并完成后续
原始 Linux TCP/UDP。支持两种参数形式、有效 auto 实际选择 primary、CLI
primary 覆盖旧 INI secondary，并保留未知 mode 的原始 EAL 拒绝及 suffix 边界。

#227 六项继续 blocked：源 argv 用例实际要求接受 secondary/proc_id0；两条
proc_id 用例要求同一全局进程核表的正负索引；三个 thread_mode 用例要求有效
多栈/进程表、默认多进程及特定冲突。Ker 多核 RX 不是那些语义，不增加同名
no-op 配置或虚假适配映射。清单179/19/167/13/55保持不变，186项仍未完成。

## Generation/reload 所有权设计前置条件

[#218](https://github.com/rutlang-ai/Ker/issues/218) 的
[设计合同](fstack-reload-ownership.md) 明确驻留 primary、真实 secondary、
跨 master 的 epoch/双 generation、队列独占、逐 poller 停驻证明、孤儿存活、
带 census 锁的回收与延迟 IPC 的处理。源测试中的 nginx FSM 属于调用方编排；
Ker 只提供运行时与设备适配。半开连接路由仍须先证明原版 Linux 的查询及生命周期
接口，不能用 SYN 观察器或自写 TCP 状态机替代。

该设计合同先于实现，用于明确驻留会话、真实 secondary、队列所有权及回收边界，并不代表实现完整 reload。此前该文档将 NR-19 记为 partial；现在其固定 ring/ownership 断言由 generation-aware adapter 及真实 EAL 测试适配。#218 当前保留71个 blocked/partial 案例；生产 packet dispatch、flow-map、排空及 reload 场景仍未完成，完整门禁仍须拒绝175项行为案例。

## Page-array 精确排除与真实 secondary 环境核验

[精确源合同](fstack-page-array-contracts.md)确认两项 page-array 用例检查的是 F-Stack 构建模式中 BSD mbuf 引用不能跨进程释放所引起的 reload 开关限制，不是待实现的通用 Linux page-array 分配器。两项从 #218 转到 #232 架构专属组，保留源 ID，不添加无消费者的构建开关或通过映射。当前 #218 的剩余案例不包括现已适配的 NR-19 ring helper；page-array 排除也不改变其余 reload 缺口。

[实际 EAL 探针](fstack-reload-environment.md) 证明本机 no-huge primary 可启动，
但同命名空间 secondary 在共享内存初始化前失败；hugepage primary 则没有可用
hugepage。该环境证据不构成 secondary/PMD/网络通过；该历史记录时 #218 有74项未完成。

## 实际应用环境变量往返

`native-fstack-application-environment` 将源环境变量往返场景接到现有 `ker-app`
的 getenv/setenv/exec 消费路径。实际应用读取精确 preload 值、确认内部键删除并
保留 hello-world 应用环境；随后在原版 Linux 中完成 TCP 收发，要求精确连接计数
和零 outstanding mbuf。错误预期值须在 TCP 前失败。
[适配边界](application-environment.md) 不宣称 ff_* ABI 或 libc-only 成功。

当前180项场景适配、19partial、164blocked、15架构专属、55harness-only；
183项 blocked/partial 仍未完成。#229剩余9项，其他合同继续保留。

## RSS 源断言与数据面证据分层

[#220](https://github.com/rutlang-ai/Ker/issues/220) 的
[31项精确合同](fstack-rss-contracts.md) 区分配置/表/guard、独立 DPDK 软件计算和
实际 PMD 队列落点。源测试中 RETA为0会使部分具名分支未被执行，microbench还会
直接skip；现有null PMD控制读回及人为交替后端队列不能替代RSS数据面。原生产调用
来自FreeBSD PCB端口分配路径，须先确定原版Linux的真实扩展点，不能另写Ker TCP
端口选择状态机。清单及通过数不变：180/19/164/15/55，183项仍未完成。

同轮随后使用无NIC、512MiB的隔离QEMU虚拟机，在guest内部配置hugepage，
原版EAL primary/secondary完成真实共享对象查找与清理，未改宿主全局设置。
[环境记录](fstack-reload-environment.md) 明确这只解除共享内存前置条件，
不代表双master、PMD数据面、generation或reload通过。下一步可回到#218，
在该环境中实现真实监督会话；该历史记录时 #218 有74项未完成（73 blocked、1 partial）。


## Journaled control leases and source A4 namespace recycling

The resident EAL session now journals one original control mbuf per registered
coordinate before acknowledging admission. Actual borrower death before first
enqueue and after reply dequeue both recover the object, while a stopped live
borrower prevents cleanup. The isolated original-DPDK guest runs the production
session binary and commands, restores all511pool objects, and leaves no test
hugepage files after exact process-death proof.

该历史批次记录时，pinned `test_it_a14_usr2_chain_slot_recycle` scenario was adapted: three
plain masters occupy all reusable slots and die without retirement, their real
EAL secondaries keep the slots protected until cleanup, then a fourth master
and secondary get a strictly newer nonzero epoch and nonzero slot with valid
shared lookup and actual control roundtrips. Three related directory/isolation
cases are partial, with network dispatch/hardware-owner assertions explicitly
remaining. This does not qualify hardware handover, actual application USR2,
generation network packet transport or full reload.

Historical inventory at that batch:181scenario-adapted,22partial,160blocked,15architecture-specific,
55harness-only (433total). At that time the completion gate failed for182unfinished
cases. Issue#218 then tracked78incomplete cases (74blocked/4partial).


2026-10-24 多 worker 停止 ACK 回归

将 #242 的并发回收修复带入后续迁移分支，保留现有 worker 生命周期检查和配置边界。
全部 worker 的十秒退出等待同时开始，收集所有结果后才发送 ACK，避免串行等待
四个 worker 时超过原生 API 的三十秒截止时间。单个回收异常不会跳过其他 worker。

`native-fstack-run-stop` 新增四 worker 超时模式：两个原始 TAP PMD 继续覆盖独立宿主
IPv4/IPv6 TCP/UDP，另有两个原始 null PMD。每个实际 EAL 子进程完成清理后，
测试包装进程故意延迟六十秒退出。断言四个包装进程均触发十秒超时、被 SIGKILL
并回收，四份原始池统计均为零未归还 mbuf，API 返回 EIO，十个私有通道全部关闭，
应用仍继续运行六秒。该故障注入针对 supervisor 回收端点，不声明强制杀死 EAL
进程可以安全回收其 mbuf。构建及两个 run-stop CTest 均通过。

这是已有 run/stop 适配的缺陷修复与回归增强，不提升原始耦合 EAL 循环用例的状态。
当前清单保持 181 scenario-adapted、22 partial、160 blocked，仍有182项未完成；
15项架构专属及55项 harness-only 保留原有边界，issue223继续跟踪耦合循环差异。


2026-10-24 原始 secondary ring PMD 与独占消费者

增加显式 `ker-session --ring-pmd`：resident 配置固定原始 net_ring 设备，
真实 secondary 通过原始 TX/RX burst 往返174字节诊断帧，并核对原始设备计数。
控制与 PMD mbuf 分别由 resident 记录后授权，第二消费者拒绝 EBUSY；master
死亡不能撤销存活 borrower 的所有权。精确 borrower pidfd 死亡后回收，允许
新 epoch 接管；首次 TX 前及 RX dequeue 后死亡均恢复511个原始对象。
隔离原始 DPDK guest 的既有共享控制回归及新 PMD 验证均通过；宿主运行时
因没有共享 hugepages 跳过，不能计为宿主通过。详见[实现、用法及边界](fstack-session-pmd.md)。

本批完成 #218 的 `test_it_a14_secondary_looks_up_own_slot` 场景适配：源测试
使用原始 null PMD，不要求物理 NIC 或 Linux 包交付；它要求真实 secondary
找到自己的目录/ring、取得设备消费权且 primary 不消费，新路径覆盖这些断言。
原始固定网络 dispatch、物理设备/nohw/KNI owner 协调、向原始 Linux 交付
数据包及完整 reload 仍待实现。清单现为182 scenario-adapted、21 partial、
160 blocked、15 architecture-specific、55 harness-only，181项未完成。


2026-10-24 存活 standby 与 epoch-liveness 批次

`ker-session lease --ring-pmd --standby` 现在保留未获消费者授权的真实 EAL
secondary 和控制通道。两条不同 master/secondary 链保持同时存活，通过
共同屏障取样一个实际 PMD owner；只有持有 resident 私有 journal 授权对象的
worker 进行真实 TX/RX。owner 快照由 resident 串行返回，避免将旧授权坐标
和复用后的 epoch 分开读取。master 死亡和 borrower 冻结均不触发抢占；
精确 borrower 死亡并回收后，原 standby 在相同 PID/EAL/epoch 中实际接管。

新增 production `epoch-status`，按真实 pidfd census 证明旧 epoch 在 borrower
存活时保持 live、完全退出后 non-live，resident epoch0 继续 live；slot 被
更高 epoch 复用也不能复活旧 epoch。原始 TC-4 的这一 liveness 判定完成适配，
不声明实现其 heartbeat/stamp ABI。TC-3 的固定网络 dispatch 和异常包路由
owner 协调仍为 partial。既有控制/PMD 套件和新 standby 接管套件在隔离
DPDK hugepage guest 执行；宿主缺少 hugepages 的运行时 CTest 仍跳过。

该历史批次快照为183 scenario-adapted、21 partial、159 blocked，180项未完成；15项架构
专属及55项 harness-only 保留边界。#218 仍有76项未完成（73 blocked、3 partial）。
原始 Linux 数据包交付、排队中的 driver 崩溃注入和完整 reload 继续待实现。


2026-10-24 resident secondary 的原始 Linux 数据面

新增 `ker-session serve/run --paired-pmd`，由原始 `rte_eth_from_rings` 创建1个
network port和两个分离的固定RX/TX queues。获授权的真实EAL secondary连接
既有原始Linux virtio channel和调用方的raw Ethernet endpoint，resident不代理
存活数据面；Ker只复制/管理完整帧，不实现TCP/UDP/ARP协议。control/TX/RX
三个不同原始对象在grant ACK之前进入resident私有journal，只有exact borrower
死亡后检查队列和lease并归还，startup失败或worker丢失不伪报成功。

隔离guest内的独立原始Linux TAP peer实际完成双栈TCP4097/UDP512互通、字节/
EOF/对端核对、双向Ethernet捕获、原始PMD和imported-Linux计数。还验证真实
competing secondary不能启动应用、已READY worker在spawn前死亡被拦截，以及
应用运行时的worker丢失返回125；每次最终恢复511个原始对象。固定MTU1500
读取真实PMD值，unsupported SET由Linux事务回滚。应用stdin/stdout不被
runtime JSON污染，诊断在stderr及显式stats文件。

resident在开放admission前验证全部128个原始坐标ring及其capacity/SP/SC，
保持epoch/slot0并配置实际network port；secondary再核对全部128对象和固定
网络queues，补齐源TC-1 `test_it_a14_primary_precreates_all_slots` 的断言。
该批次完成时清单为184 scenario-adapted、20 partial、159 blocked，179项未完成；15项架构
专属及55项harness-only保留边界；该批次当时 #218 有75项未完成（73 blocked、2 partial）。
详见[数据路径、寿命和明确边界](fstack-session-packets.md)。cross-generation
flow drain、exception/KNI-owner协调、物理PMD/driver DMA及完整reload仍待实现。


2026-10-24 真实 native packet 路径的 standby 接管批次

`ker-session run --paired-pmd --standby` 保留被拒绝的真实 EAL secondary；
业务程序在授权前不启动，等待期间仅占自己的 control 对象。原消费者 exact
pidfd 死亡并归还原始设备对象后，同一 PID/EAL/epoch 获得授权，再启动新的
original Linux 实例。两代分别经过原始 TAP peer 验证 IPv4/IPv6 TCP4097 和
UDP512、实际 PMD/native 计数、MTU 回滚和最终511对象归还。另一个真正待机
排队进程分别以 SIGINT 和 SIGTERM 取消，要求状态130/143、无业务启动、worker 精确死亡及 control 对象回收；SIGTERM 时仅持有 control lease 的 worker 不产生 packet completion，原消费者与 census 保持不变。

本批扩展 TC-3 的 partial 证据，不增加已完成案例数。源 TC-3 还要求实际
exception/KNI owner 与设备消费者一致；cross-generation dispatch/drain 和旧
TCP 连接保留同样仍未完成。该批次完成时为184 scenario-adapted、20 partial、159 blocked，
179项未完成；15架构专属和55 harness-only 边界不变。详见
[fstack-session-packets.md](fstack-session-packets.md)。

2026-10-24 NR-19 generation-aware ring ownership adapter

为固定源用例 `tests/unit/test_ff_dpdk_if.c::test_ut_nr_19_drain_ring_sp_sc`
增加 resident 创建的原始 DPDK generation ring adapter。稳定 ring 名称按
`{port, queue, generation}` 区分，RX 使用 MP/SC、TX 使用 SP/SC；resident
从已认证的 ATTACHED 记录绑定身份及私有 pidfd，跨代 owner 可使用独立 slot 和
epoch。适配器校验 mbuf 所属 pool 及完整 segment chain，拒绝操作时保留调用者
所有权；unregister/re-admit 保留同一 ring 与排队对象，只有精确进程死亡后
resident 才能回收已证明归属的对象，含糊状态保持 fail-closed。

隔离的原始 DPDK EAL guest 中，组件测试由一个 primary 和两个真实 secondary
检查两个 queues/两个 generations 的真实 ring：RX 精确对象传递和错误 owner 拒绝、
multisegment mbuf、peer TX、满 ring 的单次计数及调用者所有权、FIFO 排空、同一
ring 的 unregister/re-admit、精确死亡恢复和最终 pool baseline。另一项 guest 测试
让两个 resident-authenticated ATTACHED secondary（不同 slot/epoch）执行六个实际
adapter probe，覆盖 RX payload/queue 隔离、空与成功 peer TX、满 ring 拒绝和计数、
FIFO 释放及 pool delta；第三个同时存活的 generation-0 owner 被拒绝，最终清理通过。
完整 bindings、guest 日志及各失败尝试分类见外部 evidence manifest
`nr19-generation-rings-build.json`。这只适配 generation-ring ownership helper 场景；
adapter 尚未接入 worker 的生产 packet dispatch/flow-map，不声称外部 TX burst、TCP/UDP
流量或完整 reload。

TC-3 observer 场景 `tests/integration/test_ff_gendir_mp_integration.c::test_it_a14_two_masters_single_consumer`
以两条真实 master 链、相同 generation/process、同步状态采样和各自 typed control-ring token
场景适配。它只验证所记录 observer 合同，不代表更广的 cross-generation packet dispatch、
exception-owner/flow agreement 或完整 reload。

TC-5 `test_it_a14_probe_roundtrip_tools_contract` 的窄 coordinate-query/ring-name 选择场景
由 `native-fstack-session-coordinate` 适配：实际 EAL worker 在 authenticated ATTACHED 后发送
unseeded typed query，resident 校验 live pidfd peer 和 exact journaled control object，再由 worker
仅用返回坐标调用 production `ring_name` helper 并查找 proc1 RX ring。unbound query 返回 EPERM
及全零身份/坐标；guest 验证精确 pidfd 清理、511 个 pool 对象和 resident DRAINED。Ker internal
command 13 不兼容 FF_RELOAD_CMD_QUERY/ff_ipc ABI，不声称 cookies、多候选发现、fallback、packet
transport、TCP/flow migration 或 full reload。host CTest 因 hugepage preflight 跳过；运行证据来自
隔离的 original-DPDK guest。

截至 TC-5 coordinate adapter 批次的历史 inventory 为190 scenario-adapted、18 partial、155 blocked、15 architecture-specific、
55 harness-only（433 total）；当时173 项仍未完成。该快照早于 TC-7、P1 detach 与 directory admission 更新；其余 reload、flow-map、external-TX、TCP-continuity、
ff_ipc cookie/multi-candidate/no-fallback、crash-matrix 和 physical-handover 合同仍未完成。

2026-10-24 TC-7 USR2 drain-peer semantics

`test_it_a14_usr2_drain_peer_semantics` 现标为 scenario-adapted。Ker resident 对 exact ATTACHED worker 作 drain-mode 授权，并只接受该 worker 发出的心跳；旧 master 已被回收、worker 仍存活且 stamp 新鲜时，另一真实 EAL secondary 观察到 peer1=1。worker 精确死亡且两秒 freshness 窗口届满后，查询回退到 caller-epoch/opposite-generation，peer1=0。guest5 的 SHA 绑定证据同时检查 reload-active fallback、镜像一致性、普通 worker 的 parent-death 退出和511对象清理。这个映射只覆盖该 TC-7 源用例；F-M5-1 是辅助 mirror oracle，不单独增加映射。TC-7 的 guest5 证据是早期 ABI v7 的独立历史运行；其余 nonowner/foreign TX、flow-map、外部 TX、TCP 连续性及完整 reload 仍未完成。

2026-10-24 P1 configured-ring detach and empty-queue cleanup

`test_p1_drain_queue_ownership`, `test_p1_drain_peer_tx` and `test_p1_drain_nonowner_tx` are
scenario-adapted through `native-fstack-session-generation-detach`. The real original-DPDK EAL
fixture journals one known-pool object in each of eight RX/TX, queue and generation rings. With
no foreign peer and an owner in the source generation, it drains configured RX q0/g0 and TX
q1/g0 (+2); with the resident-authorized foreign selector, it drains only RX q0/g0 (+1) and
retains TX plus the other six objects. The non-owner case uses an authenticated same-master
slot/epoch where generation 1 holds the real PMD/RX lease and generation 0 detaches; only RX
q0/g0 is reclaimed (+1), with TX and all other objects retained. Tests cover exact owner
snapshot rejection and replay denial, repeated detach, same-identity re-admission, persistent
ring identity, and positive cleanup to 511 available objects with no remaining users or PMD
owner. A separate held-dequeue case verifies bounded fail-closed status 125 with no detach ACK.
The earlier mode-1 evidence is bound to commit `67bfc5b652f76d36fdf827657fa48dde223a76ec` and aggregate
manifest SHA-256 `71e23ac944f6958db88f956742a4bbe2e654a68963525f43b2147ee508cd12ce`. Those historical runs were split: guest5 passed ten parent suites but failed at P1; guest9 passed the P1 fixture. The later integrated run below supplies the full single-image result.

`test_p1_drain_empty_qconf` is scenario-adapted through
`native-fstack-session-generation-empty-config`. With primary-owned RX/TX cleanup masks zero,
a real EAL guest proves that orderly detach and same-ring re-admission retain all eight
populated objects and exact ring pointers, restoring 511 available objects with zero in use
and no PMD owner. Its invalid-selected-entry fatal path is separate safety evidence. Historically, the empty
profile and invalid-only profile passed in separate immutable runs using identical production
binaries; those split runs did not provide an all-profile image. Full historical bindings are in
`/home/hurricane/.local/state/ker-compat-work/fstack-followups/session-drain-empty-config-invalid-only1/aggregate-evidence.json`.

The integrated candidate `0ea4bcb1bfa9fe28f07444aba7b0ad6d417d0c13` passed all 14 suites in one fresh guest image. The actual-result manifest `/home/hurricane/.local/state/ker-compat-work/fstack-followups/session-tx-full-visibility-guest2/actual-result-txfull-normal2.json` (SHA-256 `c25a5ead4dad477852db7800f4c0a69c772d08448e5d21989f28a51ccb723721`) binds package `e3fc692ba4172a5c810dd056ae5d908245db5fd5a7478ba40190995f83d2da02`, image `fb5a1029bce203cf934a7c2e9c7dadcefbdbad1fa9bb6c8058f60fae9b611a38`, and serial `cb00c7379594ea6813fdd41921373ead1528c107066c082ea1a6658d24384b13`. The full-ring test reported `tx_full=1`, `tx_drop=0`, `tx_peak=64` at capacity 64, and `rx_peak=0`; all inherited session suites also passed, the pool was fully reclaimed, and QEMU exited 0 after normal power-down. A separate private negative-control guest disabled event-time peak updates and failed specifically with `tx_full=1`, `tx_peak=0`, `capacity=64`, `tx_drop=0`, `rx_peak=0` after drain and cleanup. Its result `/home/hurricane/.local/state/ker-compat-work/fstack-followups/session-tx-full-visibility-mutation1/actual-result-txfull-peakmutation1.json` (SHA-256 `984609cd9b30c6da02f4b4473ded3a55421c4e9ca287247fcf0eb6b4fb83dab4`) records the mutation build lineage from `476d20bae93691c5c1e1f0dd880b1c996e26a5b0`; production code and the registration fixture were byte-identical to the normal candidate. The initial normal attempt failure remains preserved separately. This evidence does not claim physical-NIC behavior or broader TX semantics.

A later portability validation at candidate `16f27ed0f13b3a5e424d9082cad6f3b0a59fa0fe` passed the complete 15-suite guest matrix, including the configured/custom-prefix DPDK plugin-path discovery fixture. The result manifest `/home/hurricane/.local/state/ker-compat-work/fstack-followups/session-driver-paths-integrated-guest1/actual-result-driverpaths-full15-1.json` (SHA-256 `c48fbaf75164d971ac92e802a206a401495770fc2a2d0c528cd534d65002e224`) binds package manifest `4a6490542312d7854b1d837b9a809f6a07e6fcaf3bde6b209d9532e229a978a3`, image `a602222a63ca719321c7cec6b87596c1f3e8c04a9304df63bc93ffed5b0d0699`, and serial `5cda0488a8c5ca455bc465c73c29d1abcddc113bc818bad7f881c65be00ee11c`. Every suite exited zero, the combined matrix marker was present, and QEMU exited zero after normal power-down. The run adds a fixture portability regression check and does not change migration counts or source-case classifications. It is separate from the host-only 4/4 offload result below; no physical-NIC behavior is claimed.

The F-M4-1 mapping covers only real ring-full visibility and caller ownership. These mappings do
not qualify foreign-epoch TX, TX burst/payload, flow-map, external TX, TCP continuity or full
reload. Current totals are 204 scenario-adapted, 12 partial and 147 blocked (159 behavior cases
unfinished); #218 has 61 remaining cases (all blocked).
Directory full/missing/invalid/primary-slot-busy/success are adapted; live-slot remains
blocked.

TX checksum/TSO software-path evidence is separate: the approved host-only result
`/home/hurricane/.local/state/ker-compat-work/native-offload-source-qualification-result-v2.json`
(SHA-256 `67509c905134f20c858845f9dcb2d8ca02bf5653e66e4de7e3b318516351581e`) records 4/4 host
CTest profiles on TAP and virtio/vhost-kernel. The tested offload source blobs are byte-identical
to qualified parent `87a705d96a368dfa30606df830b81a756b9c08f5`; the 13-suite session guest adds no
offload run. No physical-NIC result is claimed; issue #221 remains open.


## MTU 禁用策略迁移

`test_mtu_disabled_port_over_1500_fails` 通过 `[dpdk] mtu_enable=0` 或
`--no-mtu-enable` 适配。主接口与所有附加接口的有效 `max_mtu` 均取配置上限与
1500 的较小值，因此启动请求和运行中的 MTU 修改都受同一上限约束。
Ker 保持已有的默认启用行为，区别于 F-Stack 默认关闭；这里只适配显式禁用场景。

`native-fstack-mtu-enable-config` 的五项检查覆盖 1280/1500 边界、1501/2000/9000
拒绝、worker/application 尚未执行、CLI 覆盖、重复键、更低上限、配置恢复和
附加接口无法扩大上限。非法配置上限在求有效上限前仍拒绝。
`native-fstack-mtu-enable-live` 比较显式 1500 ceiling、CLI 禁用与 INI 禁用：原版 Linux
在三个阶段保持 MTU1500，拒绝9000后双向 IPv4/IPv6 ICMP仍成功，真实 TAP MTU、
DPDK counters、抓包 checksum 和零 outstanding 都须通过。
当前共205项 scenario-adapted、12项 partial、146项 blocked；158项行为仍未完成。

本批验证：相关8项CTest通过；扩充INI运行profile后专用live CTest再次通过。
配置相关80项Python检查、专用5项检查及21项清单审计测试通过，
106个固定源文件/433项清单完整性审计通过；全量完成门禁仍因158项未完成而失败。


## 缺失启动配置的源合同

`test_ff_load_config_empty_ini` 名称含 empty_ini，但固定源代码实际仅用
`argc=1` 调用 loader，检查未提供任何配置的失败；它没有创建或读取空INI。
`native-fstack-config-lifecycle` 新增三项相关检查，验证真实CLI无参数、逐项缺失
address/port/eal、缺失应用命令均在库/worker/application初始化前返回2，
并验证随后有效配置恢复。完整CLI参数不必提供配置文件；空文件配合完整CLI也可
启动解析，但空文件本身不能补齐所需字段。这保留Ker既有CLI行为，不强制必传-c，
也不将F-Stack内部-1返回值解释成相同公共ABI。

本批只将上述一项源案例转为scenario-adapted。当前206项scenario-adapted、
12项partial、145项blocked，共157项行为仍待完成。


## 畸形 VLAN 节名拒绝

`test_vlan_cfg_handler_bad_section_returns_zero` 的源断言是畸形 `[vlanXX]`
使配置加载失败。Ker以自己的 `[vlan.ID]` 语法适配此场景：`[vlan.XX]`、
空/带符号/非ASCII/超范围ID在真实reader和CLI中拒绝，返回2且worker/application
没有执行。不是直接执行整个F-Stack配置fixture，也不声明C callback返回值或
全局VLAN数组ABI等价。

`native-fstack-config-lifecycle` 新增三项相关检查，覆盖畸形节在合法节之前或
之后、修正后双VLAN的地址列表、随后无VLAN的干净加载、合法ID1/4094及01/1
数值别名冲突。源用例中孤立VLAN/filter和越界数组项的成功跳过行为继续保留缺口。
当前207项scenario-adapted、12项partial、144项blocked，156项行为仍待完成。

本批16项配置生命周期检查、对应CTest及21项清单审计测试均通过；
完整清单仍因144项blocked和12项partial保持未完成。


## 原始 Linux 实时时钟连续刷新

`test_ff_get_current_time_advances` 通过 `native-fstack-realtime-refresh`
适配其两次刷新后时间前进的可观察场景。测试实际启动私有原版 Linux，使用生产
`ker_native_sync_realtime` 同步，再通过原始 `clock_gettime` 读取；每次刷新
必须读取宿主realtime一次，结果的秒/纳秒规范且处于独立宿主采样窗口内。
两次刷新之间实际等待2ms，原生realtime严格前进，原生monotonic的增量保持在
宿主monotonic采样窗口中。只修改私有内核时钟，不修改宿主时钟。

同批两个独立CTest `native-fstack-realtime-refresh-host-error` 与
`native-fstack-realtime-refresh-invalid-nsec` 是Ker扩展：宿主EIO或原版Linux
拒绝非法纳秒值时必须分别返回-EIO/-EINVAL，时钟保持原来的连续进度；去除故障后
刷新恢复成功。它们不另计两项上游迁移，也不将错误返回冒充F-Stack fatal断言。
F-Stack缓存getter、NULL分离输出参数ABI及fatal刷新错误场景继续保留缺口。

本批原有realtime与三个新增CTest全部通过；编译启用-Wall -Wextra -Werror。
当前208项scenario-adapted、12项partial、143项blocked，155项行为尚未完成。

本批Debug/Release各4项realtime CTest通过，21项清单审计测试与
106文件/433项完整性审计通过；完整迁移门禁仍因155项未完成返回2。


## RX-15 resident 孤儿 ring 回收安全

`test_rx15_primary_purges_orphaned_rings` 从blocked推进为partial，继续留在
issue #218；完整适配仍为208项，13项partial、142项blocked，共155项行为未完成。
三个独立CTest `native-fstack-session-orphan-live`、`-identity`、`-reap` 使用
生产generation-ring adapter、真实原版DPDK EAL/ring/mempool及真实子进程pidfd。
所有adapter调用由primary执行，子进程仅提供实际存活/死亡证据，不是secondary
EAL或packet-worker集成，也不发送原生Linux网络流量。

每例将16个独立payload对象分布到两代、两队列的八条RX/TX ring。活身份和六种
错误身份均不能回收或改变队列、对象字节及引用；进程死亡后错误身份仍被拒绝。
确认gen1死亡后恰好释放8个归属已死消费者的对象，保留gen0 RX与gen1 TX中的
8个活消费者对象。live/identity例验证原指针、完整字节和FIFO，reap例让最后
一个消费者也死亡并回收剩余对象。重复reap拒绝，最终127对象池全部恢复；
销毁前的quiescent telemetry验证TX drop分别为4或8且无full/packet-drop事件。

源用例中的无directory、尚未附加消费者、外部purge锁及reset timeout、dead
marker退役后保留新未注册消费者数据、完整slot reset分支继续保留缺口。Ker生产
enqueue要求目标已admit，不能靠直接向未归属ring写对象来冒充这些合同已实现。

本批Debug/Release各3项独立CTest通过，21项清单审计测试和106文件/433项
完整性审计通过。完整迁移门禁仍因142项blocked及13项partial返回2。


## RX-15 活消费者持有对象时的拒绝与恢复

三个新增CTest `native-fstack-session-orphan-inflight-rx`、`-tx`、`-both`
验证生产adapter中活消费者持有RX对象、TX peer对象或两者时的回收行为。
确认gen1死亡后，readiness返回-EBUSY；实际reap达到有界超时后同样返回-EBUSY，
八条ring的剩余对象、已取出的对象字节/引用和pool计数都保持不变。
相同活身份重新admit成功，证明超时路径恢复了两代operation gate。

both例只归还一个对象时再次验证拒绝与超时回滚；全部归还后readiness成功且不
回收对象，随后reap重试成功。保留对象仍以原指针及完整字节按FIFO交付，最终127
对象池完全恢复，quiescent TX drop仍精确为4。所有adapter调用仍由primary执行，
子进程仅提供实际pidfd lifetime。

这里验证的是active-operation lease，不是源用例的外部purge-owner锁/reset ABI。
RX-15继续partial，原有remaining不变；当前208项完整适配、13项partial、142项
blocked，共155项行为未完成。本批Debug/Release各6项orphan CTest全部通过，
包含原有三例和三个新增profile。

本批21项清单审计测试及106文件/433项完整性审计通过；完整迁移门禁继续返回2。


## UT-NR-14 resident 控制消息边界

`test_ut_nr_14_reload_msg_serdes` 从blocked推进为partial，继续留在issue #218。
`native-fstack-session-control-roundtrip/malformed/replay` 三个独立CTest启动
真实production resident和原版DPDK EAL，以真实AF_UNIX SOCK_SEQPACKET连接
执行生产Python client及原始帧请求；由resident验证真实peer credentials/pidfd。
使用私有runtime目录、no-huge/no-PCI模式，明确没有secondary EAL、PMD收发或
原生Linux协议栈流量。宿主控制socket结果只证明这个运行适配器的控制消息行为。

roundtrip验证STATUS/EPOCH_LIVE及高位64-bit epoch/sequence。malformed覆盖
0/1/127/129/256字节记录、非法magic/version/status/字段及未知command，验证
带符号errno、坏长度断开及同一连接或新连接上的有效后继查询。replay验证相同
MASTER/RELEASE请求返回逐字节相同回复，冲突和较旧序列号被拒绝且不能释放epoch，
真正release之后epoch消失。每例验证511可用对象、无user/lease、resident正常退出
以及自己的控制socket被删除。

F-Stack的FF_RELOAD fill/parse ABI、各reload subcommand及gen/status/heartbeat
语义、NULL输入和可空输出指针合同仍待实现，不将Ker命令编号映射成这些命令。
CI将三个新CTest列入严格session必跑清单，并从实际CMake注册验证跳过/漏测/未知
session测试仍失败。当前208项完整适配、14项partial、141项blocked；155项行为
尚未完成，完整迁移门禁继续保持失败。

本批Debug/Release各3项控制消息CTest、21项selector测试、21项迁移审计测试
均通过；真实CMake图29项session测试与CI必跑清单完全一致。

## UT-NR-14 控制槽位边界扩展

在同一真实resident控制通道组中新增三个CTest：
`native-fstack-session-control-isolation/capacity/recycle`。isolation验证同一PID
的独立连接具有不同slot/epoch及独立重放缓存，其他连接即使持有有效ticket也不能
release，不正确token同样不能释放。capacity申请全部三个非resident槽位，验证
第四个申请及其重放返回ENOSPC；释放一个槽位之后，旧序列号继续返回缓存错误，
更高序列号成功申请。recycle验证显式release后复用槽位时epoch严格递增，旧ticket、
混合epoch和已release连接都不能释放新持有者，旧epoch保持失效。

每例通过实际STATUS/EPOCH_LIVE查询验证拒绝请求没有改变持有者、user数或511个
可用对象，最后验证精确释放、resident正常退出和socket清理。没有模拟resident，
没有secondary EAL或网络报文，也不将同一PID的多连接证据扩展为跨进程死亡回收。
UT-NR-14保持partial，原始FF_RELOAD ABI、reload子命令及C指针合同仍由issue #218
跟踪；迁移计数保持208项完整适配、14项partial、141项blocked，155项行为未完成。

本批Debug/Release各6项控制CTest通过，21项迁移审计测试及22项CI选择器测试
通过；两个真实CMake图各32项session注册均与严格CI清单一致。

## TC-4 master 控制进程生命周期扩展

`native-fstack-session-control-master-eof/master-death/master-frozen` 使用独立
Python master子进程及真实credential/pidfd校验。eof在子进程确认关闭socket后
检查epoch仍live，正常退出后才回收；death在保持控制连接时SIGKILL；frozen关闭
socket后以精确pidfd发送SIGSTOP，确认进程已停止，全部三个槽位保持占用且第四个
申请返回ENOSPC，再SIGKILL并等待实际死亡回收。每例保留其他活master作隔离对照，
验证resident epoch0存活、旧epoch失效、槽位复用时epoch递增及旧ticket被拒绝。
STATUS验证511可用对象及零user/lease，最后验证resident和socket完整清理。

这些是TC-4既有scenario-adapted映射的master控制适配器补充证据；本批只启动
primary EAL，没有secondary EAL/borrower或网络流量。原有standby测试继续负责
真实secondary/borrower存活证据，不将本批扩展为F-Stack heartbeat老化、硬件
RX-owner接管、STOPPED用户确认或完整reload。208项完整适配、14项partial、
141项blocked及155项行为未完成的计数不变。

本批Debug/Release各9项控制CTest通过，21项迁移审计测试及22项CI选择器测试
通过；两个真实CMake图各35项session注册均与严格CI清单一致。

## P2 release-epoch proof 的控制 lease 子集

`test_p2_release_epoch_needs_proof` 从blocked推进为partial，仍由issue #218
跟踪。新增`native-fstack-session-control-reservation-eof/reservation-death/reservation-coordinates`
三个CTest，由真实master的独立direct-child通过生产控制socket申请实际mbuf lease。
只要借用进程存活，MASTER RELEASE就返回EBUSY；关闭socket也不构成退出证明。
正常退出或SIGKILL后，以精确pidfd证明死亡，resident才回收对应lease。
双坐标案例占用generation0/process0和generation1/process3，第一名子进程退出
只归还一个对象，第二名仍阻止release；最后一名退出后master方可释放epoch。

每阶段验证实际STATUS中的user数、占用及可用对象数和epoch存活，resident
退出时验证511个对象全部归还、无slot/user以及socket清理。没有secondary EAL、
硬件访问或网络报文；STOPPED确认、硬件reclaim超时和refusal计数、证明后切换
RX-owner generation及F-Stack release API仍未实现，不计为完整源案例通过。
当前208项scenario-adapted、15项partial、140项blocked，155项行为仍未完成。

本批Debug/Release各12项控制CTest通过，21项迁移审计测试及22项CI选择器测试
通过；两个真实CMake图各38项session注册均与严格CI清单一致。

## P2 user-registration proof 的控制登记子集

新增`native-fstack-session-control-reservation-replay/reservation-collision/reservation-bounds`
三个真实resident测试，将`test_p2_hw_user_proof`从blocked推进为partial，继续留在
issue #218。独立direct-child在generation1/process3登记实际控制mbuf lease：
相同序列号的RESERVE重放回复逐字节相同且只占一个对象；另一个连接申请同一坐标
返回EBUSY且原登记不变。generation/process越界（含UINT64_MAX）和错误slot、
session、epoch、token均被拒绝，每次检查无user或对象分配；同一连接之后的
有效登记成功。已登记连接用新序列号再次RESERVE返回EINVAL。

每例检查live borrower阻止release、EOF后仍保留、精确pidfd死亡后回收，最后
验证511可用对象、零slot/user、resident及socket清理。这是控制登记与只读census
证据，没有secondary EAL或硬件。序列号缓存幂等不等于源user_add的操作幂等；
源ACTIVE/STOPPED表、显式stop/release确认、users_clear/epoch_users_clear及
独立硬件坐标证明仍未实现。当前208项scenario-adapted、16项partial、139项blocked，
155项行为仍未完成。

本批Debug/Release各15项控制CTest通过，21项迁移审计测试及22项CI选择器测试
通过；两个真实CMake图各41项session注册均与严格CI清单一致。

## P2 orphan epoch lifetime 的控制 lease 子集

`native-fstack-session-orphan-reservation-eof/frozen/staged` 在真实resident上
由独立master创建direct-child控制借用者，再SIGKILL master。eof借用者已关闭
socket，frozen借用者已确认SIGSTOP；两者即使失去master仍保留epoch及实际mbuf
lease。staged使用两个generation/process坐标，精确pidfd死亡后只回收对应对象，
剩余活借用者继续保留epoch；最后一个退出后才释放slot，复用时要求更高epoch且
拒绝旧ticket。另一个活master及resident epoch0全程保持live。

测试进程临时作为subreaper，持有子进程pidfd并负责收养/回收孤儿，最后恢复原状态；
独立私有进程组覆盖未完成启动时的清理。每阶段验证实际user/object计数，退出时
要求511对象归还、无slot/user及socket清理。这里没有secondary EAL或硬件，
精确pidfd登记不等于F-Stack fresh/stale heartbeat及RX reclaim合同。
`test_p2_orphan_workers_keep_epoch_live`仅从blocked推进为partial，仍由issue #218
跟踪；208项scenario-adapted、17项partial、138项blocked，155项行为仍未完成。

本批Debug/Release各18项控制/孤儿reservation CTest通过，21项迁移审计测试及
22项CI选择器测试通过；两个真实CMake图各44项session注册均与严格CI清单一致。

## M5 cross-master ring 命名空间子集

`native-fstack-session-namespace-names/isolation/recreate` 使用resident共用的
`ker_session_ring_name`和原版DPDK EAL/rte_ring，创建全部4slot×2generation×
4process×4channel共128个真实ring。名字与对象均唯一；同名创建返回EEXIST且
不替换原对象。名字刚好放得下时成功，截断不越过canary，越界坐标明确拒绝。
每个ring分别装满64个caller-owned token，检查满队列拒绝、FIFO指针/字节身份及
跨坐标隔离；只释放重建slot1/2，slot0/3中的对象与数据仍保持。所有ring排空、
释放、lookup消失后才允许EAL cleanup成功。

生产格式保持`ker_sN_gN_pN_CHANNEL`不变，命名实现从io-session.c提取为共用helper，
同时给未支持坐标增加显式EINVAL边界。测试没有复制一套命名算法，也没有修改
Linux/DPDK上游。它们是primary-only组件测试，没有secondary EAL、mbuf lease、
resident登记、网络流量或epoch复用授权证明。
`test_ut_nr_m5_cross_master_name_isolation`从blocked推进为partial，继续留在
issue #218：源proc7/127、FF_SYSCTL..FF_MSG_NUM、legacy/no-epoch及字面name ABI
仍未实现。208项scenario-adapted、18项partial、137项blocked，155项行为仍未完成。

本批Debug/Release各21项namespace/控制/孤儿reservation CTest通过，21项迁移
审计测试及22项CI选择器测试通过；两个真实CMake图各47项session注册与CI清单一致。

## dpdk_extra_keys 的精确 bond 时序值

`native-fstack-typed-bond-source-timings`直接读取固定源fixture的bond
poll/up/down=100/200/300，生产typed loader的字段测试和真实原版PMD运行
分别验证配置保留及initial/final getter读回。两个TAP/veth成员连接独立宿主Linux
802.3ad bond，双方达到collecting/distributing后完成原生Linux与host的IPv4/IPv6
ICMP及完整wire校验；移除一个成员链路后仍收发成功，退出outstanding=0。
原有100/100/200运行对照同样通过，8项bond配置测试通过。

删除`test_ff_load_config_dpdk_extra_keys` remaining中“source down_delay=300
尚无runtime读回”的具体缺口；该案例仍partial，allow/port_list、原始vdev tuple、
完整配置ABI及base-address精确映射/secondary等边界继续留在原issue。这里没有
精确毫秒级failover性能或物理NIC时序证明。当前208项scenario-adapted、18项partial、
137项blocked，155项行为仍未完成，完成计数不变。

## 重复 bond 字段的实际最终值

`native-fstack-typed-bond-source-repeat`直接读取固定源fixture的重复bond
字段序列，保留两次slave/primary/MAC/xmit_policy。仅将源eth0/eth1明确映射
为独立测试的两个真实TAP ethdev ID0/1；原版mode4 PMD必须读回最终members=2、
primary=1、MAC=cc:dd:ee:ff:00:11、l34。运行验证独立host Linux LACP、双向
IPv4/IPv6 ICMP与完整wire校验，移除一条成员链路后继续收发，outstanding=0。
该配置显式沿用100/100/200测试时序以隔离重复字段，不计源省略时序的默认值合同。

9项bond配置测试及三组实际bond运行（既有、source timings、source repeat）通过；
`test_ff_load_config_bond_vdev_repeat_keys_no_leak`继续partial，combined bond/vdev、
源iface+socket tuple和C分配器ABI仍未实现。208项scenario-adapted、18项partial、
137项blocked及155项行为未完成的计数不变。

## 原生 VMA 有界写入错误合同

`ker_posix_buffer_write`以精确登记base及显式offset检查实际请求长度，使用生产
native-buffer登记和原版Linux VMA；不模拟mbuf/header或隐式cursor。三个CTest
`native-fstack-buffer-write-overflow/null/copy`验证4字节范围拒绝8字节写、NULL数据
拒绝、拒绝后字节/登记不变、有效后继写、size_t溢出、错基址、跨页/重叠/零长度、
inactive/stale拒绝及最终VMA全部回收。原有resize测试继续通过。

源`test_ff_zc_mbuf_write_overflow_returns_error`和
`test_ff_zc_mbuf_write_null_data_returns_error`的错误返回场景推进为scenario-adapted，
从issue225的未完成列表移除。U5/U8/multi-segment的pkthdr/cursor/chain合同、
最小零长度分配及零字节send拒绝仍待实现；standalone测试不计网络或PMD证据。
当前210项scenario-adapted、18项partial、135项blocked，153项行为未完成。

本批Debug/Release各4项write/resize CTest通过，两种共享库均导出新符号；21项迁移
审计及22项CI选择器测试通过。三项write测试纳入无需EAL/PMD的必跑清单。

## 有界写入的共享库/socket 集成

将有界写入接入实际preloaded共享库调用者：在原版Linux loopback UDP与
MSG_ERRQUEUE前验证写溢出、NULL错误不投递数据、不消耗completion ID，原字节
不变且后继有效发送/8192字节scatter-gather正常。runner严格要求六个唯一source
marker；退出后再次write返回ENETDOWN，映射/guard/mbuf全部归还。

Debug/Release的`native-fstack-zc-validation`均通过，Debug完整
`native-fstack-native-buffers`软件virtio数据通路回归通过。按与CI相同方式设置
配置DPDK安装目录的LD_LIBRARY_PATH以加载原版PMD依赖；loopback结果不计外部wire。
这是既有两项写错误映射的集成补强，210项scenario-adapted、18项partial、
135项blocked及153项行为未完成的计数不变。

## 有界写入的跨线程所有权扩展

新增`native-fstack-buffer-write-parallel/handoff`：四个实际pthread各自持有
独立原版Linux VMA，重复多页写、溢出/NULL拒绝和精确字节验证，并检查各线程
errno与主线程sentinel互不污染。另一个场景明确join生产者后交给消费者，验证
扩容保留数据、旧base/非法写拒绝、跨页写和释放。全部alloc/release及唯一残留
映射的shutdown回收必须精确匹配。这里不允许未同步write/free/send竞争。

Debug/Release各两项新CTest通过；两例加入无需EAL/PMD的CI必跑清单。这是
既有两个写入错误案例的Ker扩展，210项scenario-adapted、18项partial、
135项blocked和153项行为未完成的计数不变。

## 原生 VMA owned append cursor

新增opaque native writer，owner与VMA登记共用生命周期；成功append才增加逻辑
已写长度，失败保持长度/字节不变，view返回借用数据，raw free/write/realloc
不能绕过owner。零容量持有最小backing，逻辑容量仍为0；raw buffer_alloc(0)继续
EINVAL，普通Linux零字节UDP继续保持原语义。

`native-fstack-buffer-writer-empty/append/zero`分别适配源owned empty allocation、
两次ab/cd写入得到逻辑长度4及精确abcd、空/非空游标上的零长度写no-op。三例从
blocked推进为scenario-adapted；仅有header字段断言的初始m_pkthdr.len案例继续
architecture-specific，新增逻辑游标不声称该FreeBSD布局。m_next/per-node m_len
多段链及owned零字节send拒绝仍由issue225保留，不用单VMA或普通UDP替代证明。
当前213项scenario-adapted、18项partial、132项blocked，150项行为未完成。

本批Debug/Release各9项buffer CTest通过，四个writer符号在两种共享库中均导出；
21项迁移审计及22项CI选择器测试通过，三个新CTest加入hosted-safe必跑清单。

## Owned writer 的共享库/socket 集成

实际preloaded ABI在IPv4/IPv6原版Linux loopback上验证空owner、累计append、
拒绝回滚与零append无队列副作用。普通零字节UDP仍有datagram及completion ID0，
随后精确4字节发送和完成后的8字节scatter-gather保留编号与字节，完成后才destroy。
退出回收raw残留和空owner，shutdown release数必须为2；迟到的view/append/destroy
返回ENETDOWN且view输出不变。runner要求九个唯一source marker。

Debug/Release的zc-validation通过，Debug完整virtio/native-buffer回归通过。
这是三项既有writer源行为映射的集成补强，不覆盖source零字节send拒绝或mbuf
布局/多节点链；213项scenario-adapted、18项partial、132项blocked，150项行为未完成。

## Owned writer 的失败与同步交接

新增`native-fstack-buffer-writer-constructor/retry`，使用thread-local定点故障
验证构造malloc/mmap失败回滚、临时登记释放、munmap失败后的owner保留和真实
重试。producer/consumer明确join后交接，失败owner仍可append且不影响另一owner；
重复destroy不再触发unmap，最终3次成功分配/释放与唯一shutdown owner精确匹配。
Debug/Release两项新CTest均通过，并列入hosted-safe必跑清单。

这是已有三项owned writer映射的Ker适配器扩展，不新增FreeBSD malloc/chain ABI、
无同步访问或网络证明；213项scenario-adapted、18项partial、132项blocked，
150项行为未完成，计数不变。

## Owned-send 的非空 payload 合同

新增`ker_posix_buffer_writer_send`，非空且位于已写范围内才进入与普通sendto
共用的原版Linux发送适配路径。NULL/零长度/INT_MAX及范围溢出返回EINVAL，
host fd和native非socket被明确拒绝，无host fallback。IPv4/IPv6 loopback验证
拒绝无datagram/completion、完整prefix与offset子范围精确送达、成功/失败均保留
owner/cursor、完成后才再次append/destroy；普通Linux零字节UDP仍有datagram/ID0。
runner要求十个唯一source marker。

`test_ff_zc_send_zero_nbytes_returns_einval`从blocked推进为scenario-adapted，
补强既有NULL/overflow/valid send映射。此合同不等于FreeBSD mbuf-consuming ABI，
多节点m_len/m_next仍由issue225保留。当前214项scenario-adapted、18项partial、
131项blocked，149项行为未完成。

本批Debug/Release zc-validation均通过，Debug完整virtio/native-buffer回归通过；
两种共享库导出writer_send，21项迁移审计及22项CI选择器测试通过。

分段 owned writer 补齐 `test_ff_zc_mbuf_write_multi_segment`：真实原版 Linux
VMA 节点分别保存128/50字节，暴露每段已写长度与总长度178。生产适配支持跨段
追加、别名输入快照与失败原子性；构造回滚、部分销毁重试和shutdown回收均有测试。
此项计为场景适配，不宣称FreeBSD mbuf字段/ABI、网络传输或全链路零拷贝等价。
issue225的最后一个行为项已有映射，因此从未完成分组移除；issue232的两个头字段
断言继续保留architecture-specific状态。

可选current-time输出补齐源`test_ff_get_current_time_null_sec/null_nsec`两项，
通过实际原版Linux CLOCK_REALTIME读取，不新建Ker时间缓存。旧私有epoch与
直接kernel读数夹验排除host fallback；错误与inactive输出保留另有测试。
源cached timestamp布局和clock-error致命断言不作为本批适配内容。

## Named-interface malformed-section rejection

`native-fstack-interface-section-validation` adapts only the pinned
`test_port_cfg_handler_bad_section_returns_zero` rejection scenario through
Ker’s actual `[interface.NAME]` grammar. Empty, punctuated, whitespace,
non-ASCII and overlong names fail the reader and CLI before worker/application
execution, on either side of a valid record. Correcting the section restores
both typed interface records without leaking partial state into later loads.
Valid names of1/32 characters and `XX` remain supported: F-Stack’s numeric
`[portXX]` spelling is deliberately not that grammar and remains unknown.
This is configuration evidence, not a callback/global-array ABI or traffic pass.
The permissive over-max skip case remains blocked. Counts are218 adapted,
18 partial,127 blocked,15 architecture-specific and55 harness-only.


### 本轮未完成案例迁移：IPC 地址与消息所有权（12 项）

可选导出组件 `ker::ipc` 以未修改的固定 F-Stack 消息传输实现适配调用方拥有的
原版 EAL、共享池与队列。12 个 `test_ff_ipc.c` 源案例从 blocked 完成场景适配；
[运行合同及逐项验证](fstack-ipc.md)记录源名字、真实 secondary 所有权、
死亡回收、probe 和安装后的调用方验证。隔离 guest 运行原版 EAL primary 和
20 个独立 secondary，12 个源标记全部通过，64/64 对象回收，示例退出 0，
guest 正常关机。宿主机没有共享 hugepages 时的 skip 不构成该证据。

以 `7f46febca` 为基线，本轮累计 **21/50** 个不同的原未完成案例；当前总数
239 scenario-adapted、17 partial、107 blocked。余下 29 个仍需实际实现及验证。
此组件不实现 FreeBSD 控制命令、驻留服务完整 reload 或网络协议状态机。


### M5 队列命名与旧布局运行适配（2 项）

`ker_ipc_format_ring` 为实际 provider 创建队列，保留原版 epoch-slot 映射、
slot0/legacy 命名、长度错误与关闭 generation 时的逐字节不变量。
`fstack-ipc-epoch-names`、`fstack-ipc-legacy-names` 覆盖两个完整源断言，
guest2 再以真实原版 EAL secondary 验证 AUTO 发现旧名称队列及实际收发、
64/64 对象回收。参见 [IPC 资格证据](fstack-ipc.md)。两个源案例从 blocked
完成场景适配，本轮累计 **23/50**，总数 241 adapted、105 blocked、17 partial；
还需完成 27 个基线中的未完成案例。


### UT-NR-14 原始消息序列化完成

此前 resident 控制协议的 partial 证据保留其有限范围。现在独立的
`ker::reload` 以未修改的固定 `ff_reload.c` 完成原始 FF_RELOAD 填充/解析合同，
包括全部七种子命令、无效消息/命令、NULL 消息与可选输出。真实原版 EAL
primary 使用同一 helper 回答 QUERY，secondary 保留 PID/cookie/负载往返
所有子命令；其他控制操作仍明确返回不支持。
[运行合同与资格证据](fstack-reload-messages.md)记录 guest3 的 15 项源断言、
22 个 secondary、64/64 回收以及安装调用方。

该源案例从 partial 完成场景适配，本轮累计 **24/50**；当前 242 adapted、
16 partial、105 blocked，剩余目标为 26 个基线未完成源案例。此计数不代表
驻留控制协议获得 F-Stack ABI，也不代表完整 reload 或硬件切换完成。


### 同一 master 的 RX 标记与 park barrier（2 项）

`ker_reload_poll` 使用未修改的原版 gate 决定是否调用应用的同步收发函数；
拒绝轮次在先前回调返回后写入原版 epoch-tagged 确认。两个完整源断言由
`fstack-reload-markers`、`fstack-reload-barrier` 覆盖，并在真实原版 EAL
secondary/net_ring 中验证：未完成回调阻止切换、单纯回调返回仍不足、旧 epoch
不能满足新轮次、所有旧 worker 确认后接管、切回及同 slot 后继进程重用。
仓库程序和安装后的独立消费者各得到原版 PMD RX/TX 4/4、63/63 对象回收，
guest 正常关闭。完整合同与散列见 [polling 资格证据](fstack-reload-polling.md)。

两个原 blocked 案例完成场景适配，本轮累计 **26/50**，当前 244 adapted、
16 partial、103 blocked。尚需完成 24 个基线未完成案例。跨 master 目录、
硬件用户证明、崩溃回收、Linux 网络报文及完整 reload 不在本批完成范围内。


### 原版目标 heartbeat、READY 与轮次控制（1 项）

`test_ut_nr_22_heartbeat_and_rx_return` 的全部源断言已通过；实际 poll 在目标
generation 的每一轮（含拒绝 RX 的轮次）调用原版 heartbeat helper。真实
secondary 被 SIGSTOP 后，由父进程 WUNTRACED 确认，原版 DPDK timer sampler
只报告 stall/rebase，不转移 RX；SIGCONT 后推进恢复，READY 与实际 PID/epoch
关联，完成与中止保留原始观察值。仓库和安装消费者均通过 PMD4/4、63/63
回收及正常退出，见 [heartbeat 资格证据](fstack-reload-heartbeat.md)。

本轮累计 **27/50**，总数 245 adapted、16 partial、102 blocked；剩余目标
为 23 个基线未完成案例。未将纯 helper、宿主 skip 或重复安装验证另计为完成。


### 调用方的原版 reload 策略（4 项）

UT-NR-10 四项纯 FSM 源合同现由未修改的固定 nginx 策略头及调用方 controller
适配。应用策略只在示例/测试中，未加入 Ker 库。状态实际约束 READY、park、
交接、mbuf drain、旧 worker 退场及 pidfd 确认；仓库示例和独立安装消费者
均完成两次原版 EAL/net_ring 切换、一次安全停用后的 abort/reset、PMD4/4
收发及63/63回收。四项断言覆盖全部12个合法转换、7×11矩阵、无效状态、
五个错误入口与恢复，参见 [调用方策略合同](fstack-reload-controller.md)。

仅这四个原 blocked 源案例新增完成，本轮累计 **31/50**，总数249 adapted、
16 partial、98 blocked，剩余目标19项。实际 rollback 证明 READY-timeout
公共路径，并非所有运行期崩溃排列；完整 nginx reload、跨 master、Linux
流量和 TCP 连续性仍未完成。


### 独立 master 的目录与使用者证明（5 项）

`test_p2_hw_user_proof`、`test_p2_reclaim_needs_user_proof`、
`test_p2_release_epoch_needs_proof`、`test_p2_orphan_workers_keep_epoch_live`、
`test_rx15_ring_user_census_and_purge_lock` 现已完整适配。
未修改的原始 P2/RX-15 断言、实际两 master/四 secondary EAL、原版 net_ring
收发、孤儿/停用/死亡证明和 ring 保留/回收/重新准入，在仓库和安装程序中通过。
来源、边界及 guest10 散列见[目录合同](fstack-reload-directory.md)。
本目标当前累计 **36/50**，254 adapted、96 blocked、13 partial；尚需完成14项。
物理 NIC、TCP 连续性和完整应用 reload 不在这五项证明范围内。


### M5 目录定位、完整命名矩阵与同代交接（4 项）

`test_ut_nr_m5_gendir_arbitration`、`test_ut_nr_m5_probe_epoch_fallback`、
`test_ut_nr_m5_cross_master_name_isolation`、`test_ut_nr_m5_cross_master_handover_sequence`
现已完整适配。原始完整函数断言、QUERY 驱动的原版 IPC 队列选择、160 个坐标组合
及独立 master 的同代交接/故障回退在仓库和安装消费者中通过；
见 [M5 合同与散列](fstack-reload-coordinates.md)。
目标累计 **40/50**，258 adapted、93 blocked、12 partial，尚需10个基线未完成案例。


### 原版 generation pool 与三类 cache 策略（2 项）

`test_ut_nr_18_gen_pool_config`、`test_ut_nr_21_shared_pool_cache_size` 现已完整适配。
`ker::pools` 编译未修改的原始内存策略/选择函数，并提供真实 DPDK 创建、借用和分配。
仓库与安装消费者验证 legacy cache256/16/256 的实际使用/flush、新 EAL 在旧 mbuf
未归还时加入、同 lcore0 的跨代归还、真实 PMD4/4 和五个共享池63/63回收；
[pool合同](fstack-pools.md)记录来源与guest13散列。目标累计 **42/50**，剩余8项。
当前260 adapted、91 blocked、12 partial；不将 reference 缓存策略冒充 FreeBSD page-array ABI。


## Transient slot admission completion after PR #386

This batch completes exactly two baseline blocked cases from merge
`9206b9d48d3c33c6742d7e384d0e39797527e03a`:
`test_p2_slot_transient_window` and `test_p2_slot_transient_exhausted`.
The machine catalog changes from 268/12/83 to 270/12/81
(scenario-adapted/partial/blocked); 93 behavioral cases remain incomplete.
The previous top-of-page 260/12/91 summary was stale relative to the merged
268/12/83 catalog; correcting that drift does not add eight new completions.
The 50-case ledger from PR #386 remains unchanged.

Complete source assertions, real EAL master/orphan admission, original timing
and failure counters, separately installed production consumption and exact PMD
reclamation are documented in [transient slot qualification](fstack-reload-slot-window.md).
The 50 ms budget is an original private test knob; production APIs and their
default budget are unchanged. No other generation/reload case is promoted.

## Standalone RSS thash equivalence cases

Exactly `test_ff_rss_thash_equivalence_hitrate` and
`test_ff_rss_thash6_equivalence_hitrate` now run their unchanged original
assertions against real DPDK, including fixed seeds, RETA128/512 and all
200 tuples per size. Both full loops must reach200/200; EAL failure and
skips are fatal. Repeatability, solver-rejection controls and context/EAL
cleanup are checked. See [qualification](fstack-rss-thash.md).
This changes270/12/81 to272/12/79 (adapted/partial/blocked), leaving91
behavioral cases incomplete. It qualifies dependency arithmetic only; PMD
queue landing, source-port tables/steering and Linux allocator integration
remain separate unfinished contracts.

## Caller-owned flow-map metadata contracts

Exactly UT-NR-23, A1 single-phase/admission/revoke and P3 bounded-growth
now execute their complete unchanged source assertions against the pinned
original process-local table. The table is linked only into a caller example;
its enabled/attached dependency gates use caller configuration and actual
`ker::reload` state observations. Real EAL/net_ring IPv4/IPv6 UDP fixtures
exercise30 complete metadata-directed deliveries and exact ownership cleanup.
See [qualification](fstack-flow-map.md).

This batch changes272/12/79 to277/12/74 (adapted/partial/blocked), leaving86
behavioral cases incomplete. The pure metadata tests do not qualify Linux
SYN/PCB integration, half-open packet dispatch, cross-generation transport,
TCP continuity or full graceful reload. Original Linux retains protocol state;
application routing policy remains outside Ker libraries.

## PEER callback ownership boundary

`test_ut_nr_27_dispatch_peer_boundary` is now scenario-adapted through the
optional `ker::peer_dispatcher` ownership bridge. The callback still borrows
data; successful peer enqueue transfers the original mbuf, while full and
closed-window paths release it exactly once. Real EAL/net_ring FIFO checks,
segment-based counters, unique-pool reclamation and an independently installed
consumer qualify this memory/transport boundary. See
[qualification](fstack-peer-dispatch.md).

Only this case changes status:277/12/74 becomes278/12/73
(adapted/partial/blocked), leaving85 behavioral cases incomplete. Peer discovery,
USR2 mirror selection, native PCB integration, cross-master transport and full
reload remain outside this qualification. P1 foreign-epoch TX remains blocked
by the current bank's one-identity-per-generation admission boundary.

## Parked TX ownership and burst guards

Four source integration scenarios now have public Ker counterparts:
`test_it_a09_tx_divert_no_hw`, `test_it_a09_drain_ring_tx_watermark`,
`test_it_a09_send_burst_guard` and `test_it_a09_main_loop_parked_pass`.
The optional `ker::reload_tx` byte/mbuf adapter retains caller-selected
queue/ring policy and routes every hardware burst through the synchronous
reload poll gate. Real EAL/net_ring and independent TX callbacks preserve
the original12-packet,4x64/255+1,32-packet guard and five-packet residue
assertions, with FIFO verification and complete512-object reclamation.
See [qualification](fstack-parked-tx.md).

This batch changes278/12/73 to282/12/69 (adapted/partial/blocked), leaving81
behavioral cases incomplete. It carries the already merged PEER ownership
change from the former feature branch into the integration branch as well.
Boot/veth/config ABI, native PCB hooks, concurrent/cross-master takeover,
physical NIC and full application reload remain unqualified.

## A10 synthetic dispatch and window mechanisms

Exactly `test_it_a10_halfopen_dispatch` and
`test_it_a10_halfopen_window_mechanism` now have source-shaped real-EAL
qualification. The original source harness simulates metadata admission and
links no protocol stack. Its unchanged classifier and packet/key builders run
in a caller-only policy fixture, composed with existing public peer/reload
components and the original flow table. Actual PMD input, exact application
input bytes/ownership, parked software consumption without recirculation,
closed-window drop and complete512-object reclamation are verified. See
[qualification](fstack-a10-dispatch.md).

Only these two source cases change status:282/12/69 becomes284/12/67
(adapted/partial/blocked), leaving79 behavioral cases incomplete. This does not
qualify actual half-open TCP connections, Linux SYN/PCB hooks, ESTABLISHED,
no-RST, real syncache drain, two-process handover or full RV12/reload.
Ker libraries, native protocol implementations and upstream code remain unchanged.

## Separate configuration-unload migration

One additional source case is qualified through the unchanged caller-side parser,
not through Ker runtime configuration. See [scope and validation](fstack-config-inspector.md).
The current catalog becomes285/12/66; all remaining runtime contracts stay open.

### Original parser case: `test_ff_load_config_valid_minimal_ini`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_valid_minimal_ini`. The catalog becomes286/11/66. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_unknown_section`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_unknown_section`. The catalog becomes287/10/66. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_all_sections`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_all_sections`. The catalog becomes288/9/66. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_dpdk_full`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_dpdk_full`. The catalog becomes289/8/66. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_portlist_nonint`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_portlist_nonint`. The catalog becomes290/8/65. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_rss_check_cfg_handler_no_port_no_vlan`

The unchanged source assertion and fixture run through `fstack-config-source-test_rss_check_cfg_handler_no_port_no_vlan`. A target-only postcheck first verifies that the production inspector rejects the unsafe plan with its configuration still reset, then invokes the retained upstream loader and records the real `rss_check.enable` INI callback returning 0. This makes the NULL assertion evidence of the original handler's missing-port guard rather than reset state. The catalog becomes291/8/64; no legacy settings are applied to Ker.

### Original parser case: `test_rss_tbl_cfg_handler_bad_tuple`

Complete original assertions and fixtures: `fstack-config-source-test_rss_tbl_cfg_handler_bad_tuple`. The catalog becomes292/8/63. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_rss_check_thash_adjust_off_parses`

Complete original assertions and fixtures: `fstack-config-source-test_rss_check_thash_adjust_off_parses`. The catalog becomes293/8/62. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_vlan_cfg_handler_id_not_in_filter_returns_one`

Complete original assertions and fixtures: `fstack-config-source-test_vlan_cfg_handler_id_not_in_filter_returns_one`. The catalog becomes294/8/61. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_vdev_full`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_vdev_full`. The catalog becomes295/7/61. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_port_cfg_handler_id_over_max_returns_one`

Complete original assertions and fixtures: `fstack-config-source-test_port_cfg_handler_id_over_max_returns_one`. The catalog becomes296/7/60. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_freebsd_boot_multi_entries`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_freebsd_boot_multi_entries`. The catalog becomes297/6/60. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_inet6_fixture_ignored`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_inet6_fixture_ignored`. The catalog becomes298/6/59. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_argv_t_override`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_argv_t_override`. The catalog becomes299/6/58. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_vlan_cfg_handler_portid_over_max_skips`

Complete original assertions and fixtures: `fstack-config-source-test_vlan_cfg_handler_portid_over_max_skips`. The catalog becomes300/6/57. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_parse_lcore_mask_proc_id_in_range`

Complete original assertions and fixtures: `fstack-config-source-test_parse_lcore_mask_proc_id_in_range`. The catalog becomes301/6/56. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_parse_lcore_mask_proc_id_over_count_fails`

Complete original assertions and fixtures: `fstack-config-source-test_parse_lcore_mask_proc_id_over_count_fails`. The catalog becomes302/6/55. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_dpdk_extra_keys`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_dpdk_extra_keys`. The catalog becomes303/5/55. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_bond_vdev_repeat_keys_no_leak`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_bond_vdev_repeat_keys_no_leak`. The catalog becomes304/4/55. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_parse_lcore_mask_calloc_oom_returns_error`

Complete original assertions and fixtures: `fstack-config-source-test_parse_lcore_mask_calloc_oom_returns_error`. The catalog becomes305/4/54. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_thread_mode_enabled`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_thread_mode_enabled`. The catalog becomes306/4/53. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_thread_mode_default_off`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_thread_mode_default_off`. The catalog becomes307/4/52. This caller-side document inspection does not apply legacy settings to Ker.

### Original parser case: `test_ff_load_config_thread_mode_secondary_conflict`

Complete original assertions and fixtures: `fstack-config-source-test_ff_load_config_thread_mode_secondary_conflict`. The catalog becomes308/4/51. This caller-side document inspection does not apply legacy settings to Ker.
