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
| scenario-adapted | 91 | 有现存 Ker CTest 和来源映射；是场景适配，不是 API/实现等价认证 |
| partial | 13 | 有相关场景，但未满足完整源用例合同；remaining 字段记录缺口 |
| blocked | 266 | 没有完整可执行的 Ker 对应项；明确保留缺口，不计为通过 |
| architecture-specific | 8 | FreeBSD callout/内部 kqueue filter 断言，不适用于 Linux 内部结构 |
| harness-only | 55 | 53 个 F-Stack reload 工具链自测及 2 个 CMocka smoke；不计 Ker 网络覆盖 |

**全部原始测试已纳入；全部行为迁移尚未完成。**
完整逐项 ID、处置理由和 CTest 链接在 [机器清单](../tests/fstack-migration.json)。
一个 Ker CTest 可以适配多项上游场景；Ker 来源条目中还包含大量
Ker 自有扩展，不能把这些扩展数量当作已迁移上游用例数。

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
12 个 mutation/门禁用例验证快照与目录完整性、适配状态、存在且匹配来源的 CTest、源文件和源用例对应关系、provenance 到 Ker CTest 的显式绑定（包括拒绝无关现存 CTest、缺失绑定和无效绑定类型），以及未完成门禁；CI 将清单校验标为 provenance。

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
| [integration/test_ff_dpdk_if_integration.c](../tests/upstream/fstack/tests/integration/test_ff_dpdk_if_integration.c) | 20 | 12 | 8 | 0 | 0 | 0 |
| [integration/test_ff_gendir_mp_integration.c](../tests/upstream/fstack/tests/integration/test_ff_gendir_mp_integration.c) | 7 | 0 | 0 | 7 | 0 | 0 |
| [integration/test_ff_kni_integration.c](../tests/upstream/fstack/tests/integration/test_ff_kni_integration.c) | 8 | 0 | 0 | 8 | 0 | 0 |
| [integration/test_ff_reload_integration.c](../tests/upstream/fstack/tests/integration/test_ff_reload_integration.c) | 7 | 0 | 0 | 7 | 0 | 0 |
| [integration/test_graceful_reload.sh](../tests/upstream/fstack/tests/integration/test_graceful_reload.sh) | 1 | 0 | 0 | 1 | 0 | 0 |
| [integration/test_mtu.sh](../tests/upstream/fstack/tests/integration/test_mtu.sh) | 1 | 0 | 0 | 1 | 0 | 0 |
| [unit/test_ff_callout.c](../tests/upstream/fstack/tests/unit/test_ff_callout.c) | 6 | 0 | 0 | 0 | 6 | 0 |
| [unit/test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c) | 96 | 0 | 0 | 96 | 0 | 0 |
| [unit/test_ff_config_pa.c](../tests/upstream/fstack/tests/unit/test_ff_config_pa.c) | 2 | 0 | 0 | 2 | 0 | 0 |
| [unit/test_ff_dpdk_if.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c) | 67 | 0 | 1 | 66 | 0 | 0 |
| [unit/test_ff_dpdk_kni.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c) | 25 | 0 | 0 | 25 | 0 | 0 |
| [unit/test_ff_dpdk_pcap.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_pcap.c) | 9 | 9 | 0 | 0 | 0 | 0 |
| [unit/test_ff_epoll.c](../tests/upstream/fstack/tests/unit/test_ff_epoll.c) | 21 | 18 | 0 | 1 | 2 | 0 |
| [unit/test_ff_host_interface.c](../tests/upstream/fstack/tests/unit/test_ff_host_interface.c) | 34 | 16 | 0 | 18 | 0 | 0 |
| [unit/test_ff_ini_parser.c](../tests/upstream/fstack/tests/unit/test_ff_ini_parser.c) | 25 | 18 | 1 | 6 | 0 | 0 |
| [unit/test_ff_init.c](../tests/upstream/fstack/tests/unit/test_ff_init.c) | 6 | 3 | 1 | 2 | 0 | 0 |
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
内核启动失败和接口激活失败的定点注入仍未完成，继续保留 blocked。
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
