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
| scenario-adapted | 162 | 有现存 Ker CTest 和来源映射；是场景适配，不是 API/实现等价认证 |
| partial | 13 | 有相关场景，但未满足完整源用例合同；remaining 字段记录缺口 |
| blocked | 195 | 没有完整可执行的 Ker 对应项；明确保留缺口，不计为通过 |
| architecture-specific | 8 | FreeBSD callout/内部 kqueue filter 断言，不适用于 Linux 内部结构 |
| harness-only | 55 | 53 个 F-Stack reload 工具链自测及 2 个 CMocka smoke；不计 Ker 网络覆盖 |

**全部原始测试已纳入；全部行为迁移尚未完成。**
当前待完成 **208 项**（195 blocked + 13 partial）。
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
| [unit/test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c) | 96 | 39 | 0 | 57 | 0 | 0 |
| [unit/test_ff_config_pa.c](../tests/upstream/fstack/tests/unit/test_ff_config_pa.c) | 2 | 0 | 0 | 2 | 0 | 0 |
| [unit/test_ff_dpdk_if.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c) | 67 | 6 | 1 | 60 | 0 | 0 |
| [unit/test_ff_dpdk_kni.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c) | 25 | 0 | 0 | 25 | 0 | 0 |
| [unit/test_ff_dpdk_pcap.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_pcap.c) | 9 | 9 | 0 | 0 | 0 | 0 |
| [unit/test_ff_epoll.c](../tests/upstream/fstack/tests/unit/test_ff_epoll.c) | 21 | 19 | 0 | 0 | 2 | 0 |
| [unit/test_ff_host_interface.c](../tests/upstream/fstack/tests/unit/test_ff_host_interface.c) | 34 | 31 | 1 | 2 | 0 | 0 |
| [unit/test_ff_ini_parser.c](../tests/upstream/fstack/tests/unit/test_ff_ini_parser.c) | 25 | 25 | 0 | 0 | 0 | 0 |
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
IPv6 VIP/VLAN 与 RA/SLAAC 部署尚未验收；默认网关和跨网段验证见下文。

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
IPv6 VIP/VLAN 等未迁移。清单计数仍为 117 adapted、16 partial、237 blocked。
尚未验收路由更新/故障切换、RA/SLAAC、IPv6 VIP/VLAN 和真实物理网卡。

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
最多 16 个 VLAN，ID 1–4094；每个最多 8 个 IPv4 地址，首地址为主地址，其余为 VIP。
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

## 非法 port/VLAN 配置与显式 jumbo 禁用边界

本批将以下三项从 blocked 调整为 scenario-adapted，均执行生产
`ker-run` loader，不调用上游 parser 或复制其内部结构：

| 固定源用例 | Ker CTest |
|---|---|
| `test_port_cfg_handler_bad_section_returns_zero` | `native-fstack-config-port-section` |
| `test_vlan_cfg_handler_bad_section_returns_zero` | `native-fstack-config-vlan-section` |
| `test_mtu_disabled_port_over_1500_fails` | `native-fstack-config-jumbo-gate` |

三个 CTest 共七个 unittest 方法。非法 port/VLAN 节在有效设置前后都必须拒绝；
CLI 覆盖不能掩盖文件中的非法节。VLAN 另覆盖原始 `[vlanXX]` 拼写和 Ker
`[vlan.ID]` 的空、非数字及越界 ID，失败后再加载有效设置必须恢复正确值。
Ker 的单个 port 由 `[dpdk] port` 选择，不实现上游 `[portN]` 数组或其 handler ABI。
这些是非法配置的拒绝场景，不把所有未知节都等同为上游已迁移。

jumbo 禁用场景显式使用 Ker `max_mtu=1500`，分别在 large/scatter 模式验证
1500 可解析、1501 和 9000 拒绝、配置与 CLI 的双向覆盖，以及失败后上限不串状态。
Ker 没有 `mtu_enable` 开关，默认 `max_mtu=9000`；此处适配的是显式部署门限，
不声明与上游“默认禁用 jumbo”相同。正向检查只验证生产 loader 的类型和值；
不能据此声明设备已设置 MTU 或报文已送达。

所有负向场景均执行实际 launcher 子进程，以退出码 2 和对应诊断验证拒绝发生在
库解析/worker 准备之前；不存在的库与 worker 路径不会进入报错结果。
不修改配置实现、Linux/DPDK 或只读快照；既有实际 jumbo/VLAN 测试保持独立。

当前清单：128 adapted、18 partial、224 blocked、8 architecture-specific、
55 harness-only，共 433 项。待完成由 245 降至 **242**（224 blocked + 18 partial）；
`--require-complete` 仍必须失败。

2026-11-16 基于集成提交 `c21dd045e` 的验证：三个新增 CTest、既有
launcher-config/config-lifecycle 和两项 migration audit 共 **7/7 通过**。
新增七个 unittest 方法既运行实际子进程拒绝路径，也在同一解释器中执行失败解析，
再检查有效加载及全局默认值，防止仅用新进程掩盖配置串状态。
清单完整性审计通过；完整迁移门禁按预期返回 2（224 blocked + 18 partial）。
本批只运行相关配置和审计测试，未重跑完整内核构建、网络互通或全量 CTest。

## 主机线程创建失败的参数所有权

在集成提交 `3fc8bf1a1` 上复现固定 LKL POSIX host callback 的泄漏：分配
thread-start wrapper 后，`pthread_create` 返回错误直接退出，没有释放 wrapper。
新增 EAGAIN 注入在修复前使 `native-fstack-thread-runtime` 的 allocation-balance
断言失败；不是仅依据源码推断，也没有通过真实系统线程耗尽制造故障。

本批复用另一开发线提交 `4f99cadba` 的 Ker `thread_create` 适配：分配失败返回
零；pthread 创建失败释放 start 参数、把返回的错误号写入 errno 并返回零；成功线程先
复制参数并释放 wrapper，再进入原始例程。所有成功路径调用真实 pthread_create，
不修改固定 Linux/LKL，也不改变 Linux 调度、网络协议或 thread-join/TLS 合同。

测试分别注入 EAGAIN/EPERM，要求未运行回调、分配余额归零和准确 errno。
每次失败后以真实 pthread 创建/join 恢复，检查参数传递、wrapper 在例程入口前
只释放一次。既有四线程 semaphore/mutex/TLS/destructor 检查继续执行，最后由
原始 Linux 启动、实际调用受监测的 host thread callback 并 halt。

此为已迁移线程场景的 Ker 失败回滚扩展，迁移数量不变。另一个仍 blocked 的
`test_ff_pthread_create_failfast` 实际检查 NULL FreeBSD pcpup 的 curcpu panic，
不能用 pthread 创建失败冒充其通过；本批纠正了该项的处置理由。

2026-11-16 验证：修复前的线程测试按预期失败，修复后 Debug 全量 **194/194**
通过，无 skip；Release 线程测试 **1/1** 通过。固定 Linux/LKL 未修改，复用
其已验证构建产物。此批不新增迁移计数，仍为 128 adapted、18 partial、
224 blocked，待完成 242 项。

## host mutex 初始化回滚与 void 回调错误

本批在 `fdd15b2f3` 的线程创建修复上继续推进，复用另一开发线
`3d0f68d03` 的 Ker mutex 适配。固定 LKL POSIX mutex allocator 在初始化报错后
仍返回对象，且没有销毁 attributes；新增 mutex-init EAGAIN 测试在修复前失败，
随后在 Ker 适配层完成所有权和错误处理，不修改固定 Linux/LKL。

normal/recursive 两种 mutex 分别覆盖 malloc、attribute init/type、mutex init、
attribute destroy 返回错误。每个返回 NULL/准确 errno，检查 heap、attribute、
已初始化 mutex 余额；后续创建、真实 lock/unlock、recursive 双重 lock/unlock
及销毁必须恢复。attribute-destroy 注入在真实 attributes 已释放后返回 EIO，
以安全观察已初始化 mutex 的回滚，不声称证明未被真实 pthread 释放的资源。

opaque mutex 的四个 callback 由 Ker 成组替换，保持 pthread 成功语义。lock、
unlock、destroy 的 void callback 无法返回错误，检测到失败时明确 abort。
测试在启动 host 线程前 fork 子进程，对有效 mutex 的 destroy 注入 EBUSY 并要求
SIGABRT；不实际销毁已加锁 mutex，避免借用未定义行为。

增加 DEBUG 与 NDEBUG 两种 CTest profile，检查不使用 assert。DEBUG 的普通锁
使用原 callback 同样的 ERRORCHECK 选项，非 DEBUG 保持默认类型；两个分支和
recursive 类型均检测 attribute-type 设置失败。原始 Linux 仍实际调用计数的
mutex callback，并完成启动/关闭；先前线程创建故障和四线程 TLS/计数检查保留。

此项属于已适配线程场景的生产运行时修复，不增加上游源案例完成数量；当前
128 adapted、18 partial、224 blocked，待完成 242 项保持不变。

2026-11-16 验证：修复前新增 EAGAIN 检查失败；修复后普通/DEBUG/NDEBUG profile
均通过，Debug 全量 **196/196** 无 skip，优化 Release 三 profile **3/3** 通过。
复用固定内核产物，重新构建当前适配库与测试，未重跑 sanitizer 或硬件验收。

## host semaphore 不可恢复错误与真实 EINTR

本批继续在 `1048a247e` 上整合运行时修复，复用另一开发线 `89466bf0c` 的
Ker semaphore 适配。固定 LKL POSIX callback 会在 wait/post/destroy 失败时
记录警告后继续，void callback 无法将该失败返回给原始 Linux。新增测试先
以真实 SEM_VALUE_MAX post 溢出复现：修复前子进程继续运行，SIGABRT 检查失败。

Ker 成组持有 opaque sem_alloc/free/up/down callbacks，成功路径使用真实
sem_init/wait/post/destroy，负初值 EINVAL，malloc/init 失败回收存储并保留
errno。EINTR 重试行为保持；其他无法报告的 wait/post/destroy 失败明确 abort，
防止未获得同步却继续执行内核。上游 Linux/LKL 与调度/协议实现不修改。

`native-fstack-host-semaphore-debug/release` 检查分配及 init ENOSPC/ENOMEM 的
余额和恢复；无 host 线程时 fork 的子进程要求真实 post 溢出及注入的
wait/destroy EINVAL 均 SIGABRT。中断场景使用真实 pthread_kill(SIGUSR1)、
无 SA_RESTART 的 handler 和转发真实 sem_wait 的 wrapper，必须实际观察到
EINTR、重试并保持等待，直到真正 post。join 后检查参数/结果并恢复 signal
mask/handler。之后原始 Linux 必须分配被计数的真实适配信号量、启动并 halt。

这是 F-Stack thread argument 场景的 Ker 同步扩展，没有上游注册的 semaphore
用例；不增加源案例完成数，也不声明公平性、跨进程共享、线程取消、活跃
waiter 销毁或性能。128 adapted、18 partial、224 blocked，待完成 242 项不变。

2026-11-16 验证：修复前实际 post 溢出检查失败；修复后 Debug 全量
**198/198** 无 skip，优化 Release 两个 semaphore profile **2/2** 通过。
先前线程创建、mutex 初始化和网络互通测试继续运行。固定内核产物复用，
未改动上游代码或提升源案例完成数量。

## TLS key 删除失败与槽值恢复

基于已合并 #594 的集成提交 `57d5bc535`，复用另一开发线 `7c622c5f8` 的 TLS
回归和 Ker 删除错误处理。`key_free` 原先忽略 pthread_key_delete 错误并释放
wrapper，丢失仍注册 key 的管理对象；新增注入测试在修复前观察到子进程继续
执行，要求 SIGABRT 的断言失败。修复仅在 Ker 的 void callback 中将该错误
记录到 errno 并明确 abort，不修改 Linux/LKL、成功 pthread 语义或 TLS 布局。

同一测试还覆盖 pthread_key_create 的 EAGAIN/ENOMEM：NULL、准确 errno、
wrapper 余额为零，之后真实创建/删除恢复。pthread_setspecific ENOMEM 分别
作用于空槽和已有值槽，失败必须返回 -1/errno，原槽值不变；随后真实 set、
get、clear、delete 成功且余额归零。所有成功操作直接使用真实 pthread。

删除错误在尚无 host 线程时 fork 的子进程中注入；底层 key 保持有效且未注销，
不借用无效 pthread key 行为。默认、DEBUG、NDEBUG 使用 CHECK，原始 Linux
仍以相同 host callback 表正常启动/关闭。属于已适配线程场景的 Ker 生命周期
修复，128 adapted、18 partial、224 blocked，剩余 242 项不变。

2026-11-16 验证：删除错误场景修复前失败，修复后 Debug 全量 **198/198**
无 skip，优化 Release 三线程 profile **3/3** 通过。固定内核复用，当前 Ker
适配库与测试重新构建；不提升上游源案例状态。

## pthread join/detach 到 LKL 的内部薄适配

基于 `b496a8307`（已合并 #595）复用 `014d5067a` 的完成阶段测试与错误转换，
不新增 Ker 线程库。LKL callback 的 one-handle join 与无参数 detach 签名不同于
pthread；适配直接调用 pthread_join(handle, NULL) 和 pthread_detach(pthread_self())，
保持原 pthread 身份。应用继续直接使用标准 pthread，公共导出表没有线程 API。

分别复现两个错误：detach 注入 EINVAL 后原 callback 警告并返回，终止检查
失败；修复 detach 后，join 注入 EDEADLK 返回 -1 但未设置 errno，错误码检查
失败。最终 join 只在内部 LKL 边界转换为 0 或 -1/errno，void detach 在失败时
明确 abort。Linux/LKL 与 pthread 成功路径不改，不创建额外线程管理或调度层。

测试 fork 的成功控制对当前真实 pthread self-detach，并以 pthread_getattr_np
核对实际 DETACHED 状态；失败控制用有效 pthread 注入 EINVAL，要求 SIGABRT。
随后在有效 joinable pthread 上注入 EDEADLK/EINVAL/ESRCH，检查错误号，
并对同一个线程执行真实 join，确保回收和 callback completion。所有子进程
控制均在父进程创建 worker pthread 前完成，注入不把无效句柄传给 pthread。

属于既有线程场景的 Ker/LKL 适配修复，不完成 FreeBSD join 返回值槽或
curcpu/TLS 合同，不提升源案例数量；128 adapted、18 partial、224 blocked，
剩余 242 项不变。

2026-11-16 验证：两项错误分别复现后修复；Debug 全量 **198/198** 无 skip，
优化 Release 线程矩阵 **3/3** 通过。动态导出表没有应用 pthread/Ker 线程接口，
正常操作全部通过真实 pthread；固定内核复用且保持不变。未增加源案例迁移数。


## 原始 Linux 实时时钟更新后的前进

基于已合并 #596 的集成提交 `6491156cd`，移植独立开发线 `a6f36344a` 的
`test_ff_get_current_time_advances` 场景。测试启动固定版本原始 Linux，使用
生产 constructor 调用的 `ker_native_sync_realtime()`，先将私有内核设置为
2000 年旧 epoch，再验证首次同步、宿主 realtime EIO、原始 Linux 拒绝非法
纳秒 EINVAL、恢复同步后的时间读数。秒/纳秒必须归一化并按字典序前进。

每阶段在原始 Linux 的 `poll(NULL, 0, 25)` 前后读取原生 REALTIME/MONOTONIC，
两者 elapsed 必须至少为 25ms，并落在宿主 monotonic 采样区间内（1ms 容差）。
采样期间宿主 realtime 读取次数不得增加；时间前进必须由私有 Linux 时钟
给出。同步失败保留旧 epoch，并验证该 epoch 仍前进，随后能够恢复同步。
全部 settime 仅作用于私有 Linux，不修改宿主时间。

新增 `native-fstack-realtime-updates`，保留原 `native-fstack-realtime` 的
错误传播、宿主 epoch 区间、重复同步检查。这是读钟合同的场景适配，不
提供 FreeBSD static current_ts 缓存或 NULL 输出分量 API，不声明正在等待
timer 的 clock-step、TCP 重传或 NIC 流量覆盖。上游及 Ker 生产代码均不修改。

本批一个源场景由 blocked 改为 scenario-adapted，清单与来源映射同步更新：
**129 adapted、18 partial、223 blocked，待完成 241 项**。

2026-11-16 验证：Debug 中原 realtime、新增 updates、清单完整性与 mutation
门禁 **4/4** 通过，优化 Release 两个时钟 CTest **2/2** 通过，无 skip。
重新构建直接链接生产适配器的 realtime 测试，固定 Linux 产物经 CMake
fingerprint 验证后复用；未重建内核或重跑全量网络、sanitizer、物理 NIC。
完整迁移门禁仍按预期返回 2（223 blocked + 18 partial）。日志保存在工作树外
`~/.local/state/ker-native-linux/realtime-updates-integration-validation/`。


## 原生 fd 往返与宿主命名空间区分

`native-fstack-fd-roundtrip` 迁移固定 F-Stack 的
`test_ff_kernel_fd_encode_roundtrip`，直接链接生产 fd-table.c 并启动原始 Linux。
Ker 通过真实宿主占位 fd 和映射表管理原生 Linux fd；源测试的固定偏移编码
与按数值阈值分类不适用于这个表示。迁移保留命名空间区分、导出与逆向查询
合同，不引入 FF_KERNEL_FD_BASE 或另一套 fd codec。

源样本 0、3、1024、65535 作为真实宿主 fd 的分配下界。四个同时存活的
UDP/TCP socket 导出后应用 fd 互不冲突，重复查询必须得到同一个真实 native
fd，SO_TYPE 由原始 Linux 确认，宿主占位 fd 具有实际 CLOEXEC。宿主 /dev/null
描述符在整个过程中可读且不在原生映射表中。关闭后 native fd 必须返回
Linux EBADF，宿主保留槽也必须释放。

特别检查最后一个有效槽 65535：先作为普通宿主 fd，后作为原生 TCP 的
应用 fd，再回收为普通宿主 fd，最后导出新的原生 UDP socket。每次分类和
SO_TYPE 都必须正确，不能留下旧映射。-1 和 65536 不可查询为有效映射。
测试只在自身进程内将 RLIMIT_NOFILE soft limit 提高到 65536，并在关闭所有
测试 fd 后恢复；hard limit 需至少为 65536。没有宿主协议 socket fallback，
没有改动生产、Linux/LKL 或 DPDK 代码。不声明固定偏移 ABI 等价、真实 fd
耗尽、并发 fd 回收、网络流量或 NIC 覆盖。

本批基于时钟迁移提交 `1576fbbb3`（PR #597），新增一个已迁移源场景：
**130 adapted、18 partial、222 blocked，待完成 240 项**。


2026-11-16 验证：Debug 两个 fd CTest **2/2**、清单完整性和 mutation guards
**2/2**、优化 Release 两个 fd CTest **2/2** 通过，无 skip。固定 Linux
产物复用，fd 测试和直接链接的生产 fd/memory/clock 适配器重新构建；未重建
完整内核、重跑全量网络、sanitizer 或物理 NIC。完整迁移门禁按预期返回 2，
报告 222 blocked + 18 partial。日志保存在工作树外
`~/.local/state/ker-native-linux/fd-roundtrip-integration-validation/`。


## 真实启动链中的环境变量往返

`native-fstack-environment` 迁移 `test_ff_setenv_getenv_roundtrip`。应用继续
直接使用 POSIX setenv/getenv，Ker 不新增环境变量 API；测试经过生产
ker-run、ker-app 和 preload constructor，避免只执行脱离 Ker 的 libc 断言。

三次独立启动分别输入已有 FF_UNIT_TEST_VAR、无该变量、再次已有变量；应用
必须观察到正确初值，将其设为 hello-world 并准确读回，overwrite=0 不覆盖，
最后 unset 自己的值。每次都验证固定原始 Linux release、原始宿主 TCP syscall
被 app guard 拒绝，以及通过 POSIX wrapper 在私有 198.18.0.2 地址成功创建、
bind 原生 TCP socket。真实 net_tap worker 必须完成初始化和 teardown，
原生 shutdown diagnostics 存在，mbuf outstanding 为零，实际 EAL cleanup
返回零。测试 CHECK 不依赖 assert，Debug/Release 都保留断言。

此项属于宿主环境合同的场景适配，不提供 F-Stack helper ABI、私有 Linux
环境 syscall、跨进程共享环境或另一套环境变量管理实现，也不声明 TCP 握手
或 NIC 流量覆盖。全部生产、Linux/LKL/DPDK 代码不修改。namespace/net_tap
运行要求与现有 native 启动测试一致。

本批接续 fd 往返提交 `edf64ec0c`，新增一个源场景：
**131 adapted、18 partial、221 blocked，待完成 239 项**。


2026-11-16 验证：Debug 环境场景、清单完整性和 mutation guards **3/3**
通过，优化 Release 环境场景 **1/1** 通过，无 skip；每个环境 CTest 内执行
三次真实 launcher/native/worker 生命周期。固定 Linux 产物经 CMake 校验后
复用，两个构建的 Ker preload、worker/app guard 和测试重新构建。未重建
内核或重跑全量网络、sanitizer、物理 NIC。完整迁移门禁按预期返回 2，
报告 221 blocked + 18 partial。日志归档于工作树外
`~/.local/state/ker-native-linux/environment-integration-validation/`。


## 接口激活失败的直接返回路径

接续 `289e3faeb` 的迁移分支，复用另一开发线 `58b75c806`（来源 `62c8a0968`）
的接口激活失败测试。此前 `test_ff_init_fail_dpdk_if_up` 只有 off-subnet route
失败等相关覆盖，缺少直接 lkl_if_up 负返回。本批补齐 loopback/device 两个
activation 错误处理入口，源项仍保留 partial。

新增 non-installed `ker-posix-if-up-failure`，使用与生产 ker-posix 完全相同的
适配层源文件和固定原始 liblkl，仅添加测试链接器 wrapper。成功控制调用真实
lkl_if_up；loopback EIO 后不得调用设备 activation；设备 EIO 必须在真实
loopback 成功之后出现。精确 trace 校验调用顺序和返回值。两种错误都必须
在 native READY/application main 之前返回 launcher 状态 125，应用 marker
不存在，不能生成 native 成功诊断。真实 worker/EAL 完成清理且 outstanding
mbuf 为零。

独立 production control 设置同样 hook 环境变量，仍须正常启动且无 trace，
证明测试注入不进入生产路径。成功 app 的接口/UP/MTU 检查改用 CHECK；移除
该 target 的 -UNDEBUG，让 Release 真正在 NDEBUG 下验证相同检查。未修改
任何生产、Linux/LKL/DPDK 实现，也不注入成功 stub。

F-Stack 的 ff_dpdk_if_up ABI、精确 FreeBSD 初始化顺序仍不是 Ker 接口；注入
错误不等于自然发生的 kernel/NIC 故障，故不升级为 scenario-adapted。
**131 adapted、18 partial、221 blocked，待完成 239 项**保持不变，但该
partial 源项的直接接口失败覆盖缺口已补齐，remaining 与 provenance 同步更新。


2026-11-16 验证：Debug 扩展启动失败 CTest **1/1**、原生命周期与两项清单
门禁 **3/3** 通过。优化 Release 启动失败 **1/1** 通过；生命周期控制首次
因缺少 TCP echo 测试可执行文件未完成，补构建依赖后重跑 **1/1** 通过。
八个启动失败/控制场景均检查真实 EAL cleanup；普通生命周期继续测试独立
宿主 TCP 对端。nm 确认 production 无 wrapper 符号，而测试变体具有该符号；
Release probe 编译 flags 为 -O3 -DNDEBUG，未含 -UNDEBUG。固定原始 Linux
产物复用，生产与变体适配库及相关测试重新构建，无上游改动；未运行全量
CTest、sanitizer 或物理 NIC。完整迁移门禁按预期返回 2。
日志与二进制隔离/编译 flags 证据保存于工作树外
`~/.local/state/ker-native-linux/if-up-integration-validation/`。


## 关键启动映射失败必须终止

接续 `147587def`，为 `test_ff_mmap_failure_exits` 增加原始 Linux 启动内存
分配失败证据，源项从 blocked 推进为 **partial**。不把不同 mmap flags/API
合同直接算作已迁移。

`native-fstack-boot-memory-debug/release` 安装实际 Ker memory/thread/clock
callbacks，page_alloc 计数后转发到固定版本 POSIX host。Linux bootmem_init
请求真实 64 MiB 页面时，测试专用 mmap64 wrapper 返回 MAP_FAILED/ENOMEM；
pipe 记录尺寸、错误和 page_alloc 次数，只有实际 boot mapping 才能触发。
子进程在父进程启动任何内核/host 线程之前 fork，关闭 core dump；必须因
原始 Linux 的 BUG_ON(!memory_start) 进入真实 panic callback 并以 SIGABRT
终止，不能从 lkl_start_kernel 返回成功或以普通错误退出冒充 fatal panic。

随后父进程禁用故障，真实启动相同固定 Linux，执行 timed poll 和 UDP socket
创建/关闭，再 halt/cleanup。必须只分配和释放一次真实 boot mapping，
mincore 验证起始及末尾页面均已解除。错误状态不污染父进程。正常 mmap64
调用始终转发真实宿主函数，Ker 线程仍由 pthread 提供；没有改动任何生产、
Linux/LKL/DPDK 源码。

源用例的 conflicting MAP_SHARED|MAP_PRIVATE flags、ff_mmap 翻译与 exit ABI
仍无对应 Ker wrapper；现有 exact-address mmap 本身返回 NULL，此批没有
改变该合同。覆盖的是不可恢复的内核启动分配失败，不是任意应用映射失败、
自然内存耗尽或 NIC 流量。两种 DEBUG/NDEBUG 只作用于 Ker 适配器/测试，
固定原始 Linux 产物复用。

当前 **131 adapted、19 partial、220 blocked，待完成 239 项**；未增加完成数。


2026-11-17 验证：Debug 构建的两种 adapter profile **2/2**、优化 Release
构建的两种 profile **2/2**、清单完整性与 mutation guards **2/2** 均通过，
无 skip。测试与直接链接的 Ker memory/thread/clock 适配器重新构建；未重建
固定内核，未执行全量网络、sanitizer、自然 OOM 压力或物理 NIC。完整迁移
门禁仍按预期返回 2，报告 220 blocked + 19 partial。日志保存于工作树外
`~/.local/state/ker-native-linux/boot-memory-integration-validation/`。


## 应用共享匿名与私有文件映射

接续 `c32bd070b`，新增 `native-fstack-mmap-shared` 和
`native-fstack-mmap-file-private`，分别迁移 `test_ff_mmap_map_shared_anon`、
`test_ff_mmap_file_backed_no_anon`。应用进程内存继续使用宿主 POSIX mmap，
不增加 Ker 内存 API；这些场景与 LKL 的 exact-address boot-memory callback
不同，也不意味着非 MMU 原始内核新增文件 mmap/shared-physical-memory 功能。

测试经过真实 launcher/app guard/preload 启动。应用确认固定原始 Linux
身份和原始宿主 TCP syscall 拒绝，再连接独立宿主 TCP 对端。共享匿名场景
映射两页 MAP_SHARED|MAP_ANONYMOUS，检查零初始化与 host /proc/self/maps
中的 rw-s 权限。文件场景创建/立即 unlink 真实临时文件、写入确定字节，
以无 MAP_ANONYMOUS 的 MAP_PRIVATE 映射，检查 rw-p；另建只读共享 witness。
关闭宿主文件 fd 后，映射和原生 TCP 都必须继续可用。

映射本身作为完整 send/recv buffer，经原始 Linux TCP/DPDK 与宿主对端交换
两页含 NUL 的 payload，逐字节验证 XOR 后的响应。文件 witness 必须保留
原内容，证明 recv 到私有映射触发写时复制，没有写坏文件。最后 munmap，
mincore 确认解除映射；worker 必须记录真实 TX/RX、原始 Linux active opens、
零 outstanding mbuf 和成功 EAL cleanup。协议行为仍来自原始 Linux。

未增加初始化后 fork 支持，不把 rw-s 元数据检查当作跨进程共享可见性资格；
不声明零拷贝、文件持久性、LKL MMU 或 F-Stack helper ABI 等价。全部生产、
Linux/LKL/DPDK 代码不修改。

本批两个源场景从 blocked 改为 scenario-adapted：
**133 adapted、19 partial、218 blocked，待完成 237 项**。


2026-11-17 验证：Debug 映射互通 **2/2**、优化 Release **2/2**、清单完整性
与 mutation guards **2/2** 均通过，无 skip。每个映射场景均真实启动
DPDK net_tap、原始 Linux 和独立宿主 TCP 对端。初次 runner 使用了错误
统计字段名，修正为现有 tx/rx 后重跑通过；没有生产实现修复。
固定内核产物复用，当前 Ker preload、worker/app guard 和新测试重新构建；
未重建内核或运行全量 CTest、sanitizer、物理 NIC。完整迁移门禁按预期返回
2（218 blocked + 19 partial）。日志保存于工作树外
`~/.local/state/ker-native-linux/application-mappings-integration-validation/`。


## calloc 清零与 realloc 前缀保留

接续 `cf424d256`，增加 `native-fstack-calloc`、
`native-fstack-realloc-grow`，分别迁移 `test_ff_calloc_zeros_memory` 和
`test_ff_realloc_grow`。复用真实 TCP/DPDK 内存互通驱动，并将 fixture 更名为
`fstack-memory-interop.c` / `memory-interop.py`，已有共享/文件映射 CTest 名称
及其合同保留。应用内存继续由 POSIX malloc/calloc/realloc/free 提供，不创建
Ker heap API 或替换内核分配器。

calloc 模式先逐字节检查源用例的 calloc(16,4)，再检查两页应用缓冲区全部
清零；填入确定 payload 后，直接作为原始 Linux TCP send/recv buffer，经
DPDK 与独立宿主 peer 交换并核对完整响应，最后 free。

realloc 模式先验证源 8 字节 0x10..0x17 扩到 32 字节后前缀保留，再将已写入
32 字节扩到两页并核对。完成相同原生 TCP 交换后，再扩到四页，整个网络
响应前缀必须保持；新尾部只有写入后才检查，不能假设 realloc 会将其清零。
最后 free。测试 target 禁用 calloc/realloc builtins，优化 Release 仍执行
实际分配调用与 CHECK；不要求 realloc 一定移动地址。

每例要求固定原始 Linux 身份、raw host TCP syscall 拒绝、原生 active opens、
真实 DPDK TX/RX、零 outstanding mbuf 和实际 EAL cleanup。未修改生产或
Linux/LKL/DPDK 代码。不声明失败 realloc/OOM、分配器性能、内核 heap API
或零拷贝。F-Stack realloc(size=0) 保留原指针的独立合同与 POSIX 不同，
对应源项继续 blocked，未被本批覆盖。

本批两个源场景由 blocked 改为 scenario-adapted：
**135 adapted、19 partial、216 blocked，待完成 235 项**。


2026-11-17 验证：Debug 的原映射与新增分配场景 **4/4**、优化 Release
**4/4**、清单完整性与 mutation guards **2/2** 均通过，无 skip。每例都完成
真实原始 Linux TCP/DPDK 与独立宿主 peer 的完整字节互通。固定 Linux 产物
复用，当前 preload、worker/app guard 和 memory fixture 重新构建；未重建
完整内核、运行全量 CTest、sanitizer 或自然内存耗尽压力。完整迁移门禁按
预期返回 2（216 blocked + 19 partial）。日志与 Release allocator symbol/
编译 flags 记录于工作树外
`~/.local/state/ker-native-linux/application-allocation-integration-validation/`。


## 无部署配置调用的拒绝与恢复

接续 `08934605d`，新增 `native-fstack-config-missing` 迁移
`test_ff_load_config_empty_ini`。该源名容易误解：固定源码只传 argv[0]、
无 -c filename，并不实际读取空文件。测试保留缺少部署信息必须失败的场景，
不把可选 INI 改成 Ker 必填项。

精确的 parse_arguments([]) 必须报告缺少 address、port、eal。实际 CLI
subprocess 还使用不存在的 library/worker 路径和可生成 marker 的应用命令，
要求状态 2、准确缺失字段诊断、无 traceback/库或 worker 解析错误、无应用
执行。无 INI 和真实空 INI 都测试完全缺省，以及各缺一项设置的情况。
每次在同一解释器拒绝后，完整 CLI-only 设置仍必须成功并准确保留地址、
port 和 EAL token；INI 缺省本身不构成错误。

这是配置拒绝合同的场景适配，不声明 F-Stack mandatory filename、NULL fopen
ABI、global schema/layout 等价，也不触发 DPDK/原生内核/NIC 初始化。
全部生产和上游代码保持不变。该源项由 blocked 改为 scenario-adapted：
**136 adapted、19 partial、215 blocked，待完成 234 项**。


2026-11-17 验证：新增 MissingDeploymentTests 的两个 unittest 方法通过；
新增 CTest、原 launcher/config lifecycle/port/VLAN/MTU 回归与两项清单门禁
共 **8/8** CTest 通过，无 skip。生产 Python 配置 loader 直接被执行；没有
修改或重建 native 二进制，也未运行内核/DPDK 网络测试。CMake 注册测试时
仍校验复用的固定内核 fingerprint。完整迁移门禁按预期返回 2，报告
215 blocked + 19 partial。日志保存于工作树外
`~/.local/state/ker-native-linux/missing-config-integration-validation/`。


## lcore mask 配置分配失败

接续 `0e4acfb2e`，迁移 `test_parse_lcore_mask_calloc_oom_returns_error` 的
lcore 配置分配失败拒绝场景。Ker 不创建 F-Stack proc_lcore 数组；实际依赖
是 Python 十六进制转换、规范化字符串及 EAL 参数构造。原实现对这些阶段的
MemoryError 没有处理，会冒出 traceback，而不是正常报告配置失败。

新增 `native-fstack-config-lcore-allocation`：在生产 main 的实际解析路径，
仅对 mask 的 int(...,16) 或 format(...,'x') 注入 MemoryError，其他 provider
调用仍使用真实 Python 行为。CLI 和 INI 各两处失败，修复前四种情况均逃逸。
Ker 现在只在 lcore-mask 处理范围捕获 MemoryError，返回 argparse 状态 2
与明确诊断；不继续解析不存在的 library/worker，不调用 subprocess.Popen。
同一数字只解析一次，正常 mask 归一化和 EAL CPU 选择冲突规则保持。

每次失败后检查 CONFIG_DEFAULTS 完整保留，再解除注入重新解析同一输入，
必须恢复 canonical mask、准确 EAL -c token、地址和 port。没有成功 stub，
不修改原始 Linux/DPDK，也不新增测试 hook 到生产。此为错误处理场景适配，
不声明 F-Stack calloc 次序/数组布局、任意配置阶段 OOM 或自然进程级内存
耗尽时仍可恢复；Python parser 报错本身仍需要宿主资源。

本批一个源场景由 blocked 改为 scenario-adapted：
**137 adapted、19 partial、214 blocked，待完成 233 项**。


2026-11-17 验证：两个新 unittest 方法的四个 subcase 在修复前均因
MemoryError 逃逸失败；修复后配置与清单 CTest **9/9** 通过，真实
`native-fstack-lcore-mask` **1/1** 通过，验证原始 Linux TCP/DPDK 双角色
互通、INI mask/CLI 优先级与真实 EAL lcore/main CPU。故障注入仅在配置
main 的单元驱动中，实际网络控制不注入故障。生产 Python launcher 直接
执行当前源码；复用既有 native 二进制与校验过的固定 Linux 产物，没有
上游改动、全量 CTest、sanitizer 或自然 OOM 压力资格。完整迁移门禁按预期
返回 2（214 blocked + 19 partial）。日志保存于工作树外
`~/.local/state/ker-native-linux/lcore-allocation-integration-validation/`。


## VLAN 配置分配失败与半成品隔离

接续 `264b09d98`，增加 `native-fstack-config-vlan-allocation`，迁移
`test_vlan_cfgs_calloc_oom_returns_error` 的 VLAN 配置分配失败合同。Ker 使用
typed VLAN 地址列表，不模拟 F-Stack 第三次 calloc 或数组布局。

测试只在真实 VLAN 地址列表 provider 的第一个或第二个调用注入 MemoryError，
较早的成功调用仍调用真实实现。CLI/INI 共四种故障，另对 INI 的
read_configuration 边界注入一次 MemoryError。修复前五种情况均逃逸为
traceback；现在 VLAN converter 将分配失败交给 argparse 正常报告，INI
加载边界处理 MemoryError 和转换器的 ArgumentTypeError，统一返回状态 2。
普通 VLAN 值/范围/重复校验规则保持不变，不继续解析不存在的 library/worker
或创建子进程。

第二个 VLAN 失败前，第一个 VLAN 确实已构造成功；失败后 CONFIG_DEFAULTS
必须完全不变，解除注入后重新解析必须精确恢复两个 VLAN 及其全部地址，
不能夹带旧的半成品结果。地址、port、EAL token 同时保持。没有成功 stub，
不修改原始 Linux/LKL/DPDK，不声明任意位置的进程级自然 OOM 可恢复、源
calloc 次序或 NIC 故障等价；错误诊断本身仍需要宿主资源。

本批一个源场景由 blocked 改为 scenario-adapted：
**138 adapted、19 partial、213 blocked，待完成 232 项**。


2026-11-17 验证：三个新 unittest 方法的五个 subcase 在修复前均因
MemoryError 逃逸失败；修复后配置与清单 CTest **10/10** 通过，实际
`native-fstack-vlan` **1/1** 通过，验证原始 Linux 的双 VLAN/VIP TCP+UDP、
完整 tag/checksum、设备隔离与清理。错误注入仅在配置单元驱动，实际网络
控制不注入故障。生产 Python launcher 执行当前源码，复用已有 native
二进制与经校验的固定原始 Linux；未改上游、运行全量 CTest/sanitizer 或
自然 OOM 压力。完整迁移门禁按预期返回 2（213 blocked + 19 partial）。
日志保存于工作树外
`~/.local/state/ker-native-linux/vlan-allocation-integration-validation/`。

## DPDK 端口队列表分配失败

`native-fstack-port-queue-allocation` 适配
`test_alloc_port_cfgs_calloc_oom_returns_error`。F-Stack 在 INI 加载期间分配
端口配置数组，Ker 在所选 ethdev 的 DPDK 队列配置阶段分配队列表。测试在真实
`net_tap` worker 里分别让原始 DPDK 的 RX 或 TX 队列表分配返回 ENOMEM。
RX 分配失败必须中止 TX 分配。TX 分配失败前 RX 队列表确实已分配，测试跟踪
同一个指针，并确认它在 EAL 清理前已经释放。

两种失败均要求 launcher 返回 125，worker 和原生 Linux 均未报告就绪，
应用未启动，且实际 EAL 清理成功、mbuf 计数归零、TAP 被移除。随后在同一网络
namespace 使用相同 DPDK 端口名与 TAP 名无故障启动，通过原始 Linux socket
ioctl 验证 loopback、IPv4 和 MTU。故障注入仅用于测试，适配证据限于启动
与清理路径。

2026-11-19 验证使用固定 gitlink 新构建的 DPDK 和通过构建指纹校验的原始
Linux 产物。Debug 全量 CTest 通过 211/211，Release 的启动错误、端口队列
分配和清单检查通过 4/4。两个构建均无跳过。完整迁移门禁返回 2，仍有
212 项 blocked 和 19 项 partial。

## 空设备上下文

`native-fstack-null-packet-context` 迁移 `test_ff_dpdk_if_send_null_ctx_safe`。
通过真实 Ker/LKL 设备操作调用 TX 和 RX，要求空上下文与空向量返回
`-1/EINVAL`。修复前用例触发 SIGSEGV。加入统一的空上下文检查后，
有效设备仍通过原 datagram channel 双向逐字节传输，分配和描述符计数均回收。
此用例针对双 NULL 入参，另一个用例的 FreeBSD mbuf 所有权合同仍在清单中。

## 原生启动期间实时时钟读取失败

`native-fstack-realtime-startup-failure` 迁移
`test_ff_update_current_ts_assert_fail_on_clock_error`。真实 DPDK worker
就绪后，测试仅在原生应用初始化读取宿主 `CLOCK_REALTIME` 时注入 `EIO`。
检查读时钟和失败诊断，要求进程返回 125、无原生 READY、应用未执行，
且 DPDK EAL 清理成功、无遗留 mbuf。随后在同一网络 namespace
重新启动，转发真实时钟读取并验证原始 Linux 接口及清理。
F-Stack 的缓存时钟更新以断言失败，Ker 的适配发生在原生启动边界。

## 配置释放后独立加载

`native-fstack-config-release` 适配 `test_ff_unload_config_zeroes_state`。
上游清理全局配置指针，Ker 的生产解析器返回每次独立拥有的配置对象。
测试重复加载并丢弃包含 lcore、VLAN、sysctl 的配置 32 次，通过弱引用验证
配置 namespace 和类型化地址对象可回收，同时检查进程描述符集合恢复。
每轮再从空文件加载并验证 CLI 设置及默认值，确保前一轮的配置状态已隔离。

## 保留 INI 长键的完整名称

`test_ini_parse_stream_long_key_name` 适配到生产 `[sysctl]` 解析和原生启动。
两个 60 字符的键共享前 59 个字符，解析后仍可区分，CLI 仅覆盖完整名称匹配的键。
128 字符边界可解析，超长键报错。真实 DPDK 和原始 Linux 启动时，未注册的
60 字符键从其完整 procfs 路径返回 ENOENT，随后正常回收 worker 资源。

## 重复注册监听描述符

`native-fstack-epoll` 适配 `test_ff_host_kqueue_ctl_add_idempotent`。
调用方显式处理重复 ADD 返回的 EEXIST，再用 MOD 更新 TCP listener 的应用
标识。新连接到达时，可容纳两条事件的 epoll 等待恰好返回一条新标识事件。
一次 DEL 移除就绪观察，排队的连接仍能接受。测试在独立宿主和 Ker 原生
Linux 各运行一次，并检查原生 TCP 计数。

## 省略实时时钟秒输出

`native-fstack-current-time-null-seconds` 适配 `test_ff_get_current_time_null_sec`。
通过 `ker_posix_get_current_time(NULL, &ns)` 读取原始 Linux 的
`CLOCK_REALTIME`，与前后两次原始内核采样比较。非活动实例返回 ENETDOWN。
单次内核读取注入 EIO 后，调用方的纳秒输出保持原值，下一次读取可以恢复。

## 省略实时时钟纳秒输出

`native-fstack-current-time-null-nanoseconds` 适配 `test_ff_get_current_time_null_nsec`。
先读取原始 Linux 的独立旧 epoch，再同步到当前 Unix epoch，验证传入 NULL
可以只取得秒。注入 EIO 时保留秒输出，两个输出均为 NULL 时仍读取内核。
另在真实 DPDK 和原生启动恢复用例中，从实际应用进程调用已导出的 API，
验证启动同步后的时间。

## INI 续行回调

`fstack-ini-multiline` 补齐 `test_ini_parse_stream_multiline_value_continuation`。
调用方用 `find_package(ker CONFIG REQUIRED)` 和 `ker::ini` 链接低层解析器，
由固定版本的原始 F-Stack/inih 处理输入。测试使用真实文件流，验证起始行
与两条续行按顺序产生三次独立回调，并保留调用方的文件所有权。
类型化 `ker-run` 配置继续将 EAL 续行合并为一个值。

`fstack-ini-no-section` 适配 `test_ini_parse_stream_no_section`。
低层解析器将首个节声明之前的键值交给回调，节名为空字符串。

`fstack-ini-handler-rejection` 适配 `test_ini_parse_stream_handler_returns_zero`。
回调拒绝第二行时，解析返回行号 2，并将后续键值留给调用方。

`fstack-ini-null-file` 适配 `test_ini_parse_file_null`。
NULL FILE 返回 -1 且不触发回调，随后可以从有效文件正常解析。

`fstack-ini-long-section` 适配 `test_ini_parse_stream_long_section_name`。
固定版低层解析器将 60 字符节名截为 49 个字符，后续键值仍完整。

`fstack-ini-user-data` 适配 `test_ini_parse_stream_user_data_passed`。
验证回调收到调用方传入的原始上下文指针，且保留该上下文中的标记。

## Legacy 配置文档最小场景

`fstack-config-source-test_ff_load_config_valid_minimal_ini` 使用只随测试构建
的文档检查适配器，运行固定版本的原断言和输入。它检查 lcore mask、channel、
promiscuous、NUMA、idle sleep 和 TX delay 等解析结果。
每例执行五次加载和释放，并检查 EAL 参数计划清空。配置解析器、所需头文件
和断言片段均有来源校验。测试证据限于 legacy 文档解析和计划构建。

`fstack-config-source-test_ff_load_config_unknown_section` 适配 `test_ff_load_config_unknown_section`。检查有未知节时 legacy lcore 与 KNI 字段仍按原断言解析。

`fstack-config-source-test_ff_load_config_all_sections` 适配 `test_ff_load_config_all_sections`。执行全节配置的完整原断言，检查各 legacy 配置字段。

`fstack-config-source-test_ff_load_config_dpdk_full` 适配 `test_ff_load_config_dpdk_full`。执行完整 DPDK 配置的原字段断言。

`fstack-config-source-test_ff_load_config_freebsd_boot_multi_entries` 适配 `test_ff_load_config_freebsd_boot_multi_entries`。检查固定原始配置中的 boot 与 sysctl 链表，保留原记录数断言。

`fstack-config-source-test_ff_load_config_tcp_ecn_default_off` 适配 `test_ff_load_config_tcp_ecn_default_off`。检查 legacy TCP ECN 默认值，原始 Linux 仍拥有原生运行时策略。

`fstack-config-source-test_ff_load_config_inet6_fixture_ignored` 适配 `test_ff_load_config_inet6_fixture_ignored`。以不带 INET6 的 legacy 解析构建加载原 IPv6 fixture，验证原 IPv4 字段断言。

`fstack-config-source-test_ff_load_config_repeat_keys_no_leak` 适配 `test_ff_load_config_repeat_keys_no_leak`。验证 legacy 重复 IPv4 键以最后值生效，并在泄漏检测下反复释放。

`fstack-config-source-test_ff_load_config_dpdk_extra_keys` 适配 `test_ff_load_config_dpdk_extra_keys`。检查 base virtual address、file prefix、vdev 队列与 bond delay 的解析。

`fstack-config-source-test_ff_load_config_vdev_full` 适配 `test_ff_load_config_vdev_full`。保留原 vdev 配置字段断言。
