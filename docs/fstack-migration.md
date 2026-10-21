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
| scenario-adapted | 125 | 有现存 Ker CTest 和来源映射；是场景适配，不是 API/实现等价认证 |
| partial | 19 | 有相关场景，但未满足完整源用例合同；remaining 字段记录缺口 |
| blocked | 226 | 没有完整可执行的 Ker 对应项；明确保留缺口，不计为通过 |
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
| [unit/test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c) | 96 | 14 | 2 | 80 | 0 | 0 |
| [unit/test_ff_config_pa.c](../tests/upstream/fstack/tests/unit/test_ff_config_pa.c) | 2 | 0 | 0 | 2 | 0 | 0 |
| [unit/test_ff_dpdk_if.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c) | 67 | 5 | 1 | 61 | 0 | 0 |
| [unit/test_ff_dpdk_kni.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c) | 25 | 0 | 0 | 25 | 0 | 0 |
| [unit/test_ff_dpdk_pcap.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_pcap.c) | 9 | 9 | 0 | 0 | 0 | 0 |
| [unit/test_ff_epoll.c](../tests/upstream/fstack/tests/unit/test_ff_epoll.c) | 21 | 19 | 0 | 0 | 2 | 0 |
| [unit/test_ff_host_interface.c](../tests/upstream/fstack/tests/unit/test_ff_host_interface.c) | 34 | 20 | 0 | 14 | 0 | 0 |
| [unit/test_ff_ini_parser.c](../tests/upstream/fstack/tests/unit/test_ff_ini_parser.c) | 25 | 18 | 1 | 6 | 0 | 0 |
| [unit/test_ff_init.c](../tests/upstream/fstack/tests/unit/test_ff_init.c) | 6 | 4 | 2 | 0 | 0 | 0 |
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
IPv6 jumbo 外部互通尚未验证；1280 下限保证默认双栈接口的配置范围。
`[network] max_mtu` / `--max-mtu` 提供独立部署上限（默认 9000，范围 1280–9000），请求 MTU 不得超过它。
9000 请求对 2000 上限在启动前拒绝；CLI 覆盖上限到 9000 后执行同一真实 jumbo 互通测试。
`test_mtu_port_over_max_fails` 已从部分覆盖转为场景适配；此上限不是硬件能力探测或 mbuf pool 大小设置。
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
