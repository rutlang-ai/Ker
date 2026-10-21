# UDP 功能验收矩阵

范围是 Ker 公开 POSIX socket 适配层承载的原始 Linux 6.12.113 IPv4/IPv6 UDP，
包含真实 DPDK net_tap、独立宿主对端及路由器。协议、校验和、分片、重组、
ICMP 和路由行为均由原始 Linux 执行。报文注入器仅生成独立测试向量。

机器清单为 [tests/udp-validation.json](../tests/udp-validation.json)。
当前共 37 个验收条目：33 个功能条目、1 个已知不兼容边界、3 个部署/扩展验收缺口。
多个条目可以由同一个包含完整断言的 CTest 验证，条目数量不能作为独立测试数量。
25 个带 `native-udp` 标签的 CTest 必须全部登记并实际执行；增加测试却遗漏清单会使门禁失败。

## 一次执行与报告

先按 [原生后端说明](native-tcp.md) 构建 native 配置，并设置构建所用 DPDK 动态库/PMD 路径。
测试需要 Python 3、`ctest`、`ip`、`unshare`，并允许非特权 user/network namespace。
所有网络拓扑和 sysctl 修改都位于隔离 namespace 或私有原生内核中。

```sh
python3 tools/validate-udp.py --build-dir /path/to/native-build \
  --report /path/to/udp-validation-report.json
```

报告保存每个 CTest 的实际结果、功能条目状态、JUnit 和日志路径，以及选中 CTest 命令引用的本地脚本、二进制和库文件 SHA-256。
只接受此命令在指定 build 目录中实际执行成功的测试；缺失、跳过、失败和基础设施错误均不能计为通过。
单独的 JUnit 文件和退出码不能证明结果来自当前 build 的二进制，因此不接受导入 JUnit；
保留的 `--from-junit` / `--ctest-returncode` 参数会明确报错。这样报告中的二进制哈希对应本次执行所用的 build。

```sh
python3 tools/validate-udp.py --build-dir /path/to/native-build \
  --report /path/to/udp-validation-report.json --require-complete
```

默认返回 0 表示自动检查通过。`--require-complete` 在存在已知不兼容或部署缺口时返回 2；
报告中的 `all_features_supported_and_validated` 此时必须为 false。
`udp-validation-report-guards` 的 7 个门禁测试验证缺失/跳过/重复结果、遗漏 CTest、
基础设施错误和已知不兼容不会被错误标绿。

## 自动功能验收

| 范围 | 主要断言与证据 |
|---|---|
| IPv4/IPv6 socket 合同 | 创建标志、fd alias、绑定冲突、未连接错误；宿主与 native 运行相同程序 |
| 数据与消息接口 | 零长度报文、sendto/recvfrom、vectored sendmsg/recvmsg、sendmmsg/recvmmsg、逐条长度、边界及未写区 |
| 接收与事件 | poll/epoll、完整事件 tag、FIONREAD、PEEK、消费式 TRUNC、队列读空、后续恢复 |
| 阻塞与批量 | SO_RCVTIMEO、MSG_WAITFORONE、非空队列 recvmmsg timeout 指针；不承诺修复原始 Linux 的空队列 timeout 限制 |
| connect 与端口复用 | 来源过滤、AF_UNSPEC 断开、重连、reuseport 稳定流单成员投递、关闭成员后恢复、IPv4-mapped UDP/V6ONLY |
| UDP 组包 | 两族 UDP_CORK、MSG_MORE、flush、未 flush 就 close；IPv6 外部链路 UDP_SEGMENT |
| UDP_SEGMENT / UDP_GRO | 两族 loopback 分段内容/边界及 GRO 控制消息；GRO 允许合并，不保证每次收到聚合报文 |
| 队列压力 | 小接收缓冲区真实丢包、SO_RXQ_OVFL、读空后继续接收；不假定 UDP 提供可靠传输或流控 |
| ancillary data | 两族 pktinfo、TTL/hop limit、TOS/tclass、软件接收时间戳、CTRUNC 后恢复；IPv6 外部发送显式选择源地址 |
| 错误反馈 | 两族外部 ICMP port-unreachable，connected/unconnected error queue、SO_ERROR、引用 payload/offender、错误队列截断与恢复 |
| IPv4 分片 | 1472/1473/4096/65507 字节、MTU 拒绝、jumbo MTU；独立宿主对端与原生计数 |
| IPv6 分片 | 1452/1453/4096/65527 字节双向互通，完整抓包重组后验证 UDP 长度与非零正确校验和，超长拒绝后恢复 |
| 错包与故障向量 | 两族坏校验和拒绝；IPv4 零校验和接收、IPv6 零校验和拒绝；倒序分片重组、未完整重组超时与真实 ICMP 响应 |
| UDP 重排/重复 | 交付实际到达顺序及重复报文；不增加重排或去重协议；故障向量后继续正常收包 |
| 动态 PMTU | 独立路由器出口 MTU1280，真实 IPv4 ICMP frag-needed / IPv6 Packet Too Big、ee_info、缓存 MTU、后续本地 EMSGSIZE、小报文恢复 |
| IPv4 多播 | ASM、SSM、第三来源拒绝、两 socket fanout、join/leave/rejoin、接口/TTL/packet info |
| IPv6 多播 | ASM/SSM、第三来源拒绝、fanout 与退组重入；native 主动和监听两种角色 |
| IPv4 广播 | 子网广播及 255.255.255.255，SO_BROADCAST 权限、三种发送接口、元数据与单播恢复 |
| IPv6 部署 | 地址/NDP/DAD、global/link-local 默认网关、独立路由器跨网段双向 TCP/UDP；hop limit 64→63 与路由器转发计数 |

`host-udp-contract-matrix` 与 `native-udp-contract-matrix` 各执行 21 组公开 API 断言。
`native-udp-network6` 执行 ancillary、错误队列、分片、软件分段、ASM、SSM 六类，
每类分别运行 native client 和 native server；宿主对端也必须完成逐字节校验。
IPv4 SSM、limited broadcast、两族 PMTU 和原始报文故障向量另有独立 CTest。
所有 native 场景要求 worker outstanding=0；IPv4 与 IPv6 UDP/分片/重组计数分别来自
私有 Linux `/proc/net/snmp` 和 `/proc/net/snmp6`。丢包用例会明确要求相应错误计数增加。

## 已确认不兼容与尚未验收

| 状态 | 内容 |
|---|---|
| **不支持，已有对照证据** | 宿主 SIGUSR1 不能中断 native 阻塞 UDP recvfrom。测试观察主线程实际阻塞后发信号；宿主返回 EINTR，native 仍等 SO_RCVTIMEO 后返回 EAGAIN。`native-udp-signal-boundary` 通过只表示这个限制被准确检测 |
| **未验收** | 物理 NIC 的 checksum/segmentation offload、多队列与 RSS；当前是关闭硬件卸载的单队列 net_tap |
| **未验收** | 长时间并发、内存压力、故障恢复、吞吐和时延指标；本批是有界功能测试 |
| **扩展接口/应用兼容缺口** | sendfile/splice/io_uring、真正零拷贝、libc 内部 DNS resolver 等路径；没有以 socket 测试代替这些接口的验收 |

本矩阵不宣称 F-Stack 全量迁移完成。固定 F-Stack 原始用例仍有 16 项 partial、237 项 blocked；
新验收主要是原始 Linux UDP 功能扩展证据，不把它们虚增为已适配的上游用例。
