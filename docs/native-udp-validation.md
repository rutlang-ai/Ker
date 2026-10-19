# 原生 Linux UDP socket 验证

本文记录现有 POSIX 适配层中的 IPv4 UDP 验证，基础测试从 unicast 开始。socket、datagram 边界、
checksum、地址查询和事件就绪由完整导入的 Linux 6.12.113 实现；Ker 负责 API
转换、fd、packet I/O 和诊断。源码 pin 与构建方式沿用 [原生后端](native-tcp.md)。
不使用基础库的 UDP 报文构造器或 packet view 代替原生 socket。

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-interop$' --output-on-failure
```

测试用真实 DPDK net_tap/veth 连接独立宿主 Linux UDP 对端，三种 API 各运行
原生客户端和服务端两种角色，共六种组合。两个端点都必须报告逐字节校验成功。

| 验证 | 断言 |
| --- | --- |
| sendto/recvfrom | 每方向 0、1、33、257 字节的四个 datagram，保持边界与顺序，校验源地址/端口 |
| 零长度 datagram | epoll 通知就绪，接收返回 0 后同一 socket 继续收发非空报文，不当作 TCP EOF |
| sendmsg/recvmsg | scatter/gather、客户端 connected UDP 与 getpeername；FIONREAD 返回首报文长度 |
| MSG_PEEK/MSG_TRUNC | 短缓冲区 peek 返回完整报文长度并正确设置 MSG_TRUNC；报文仍在队列，随后完整读取不截断 |
| sendmmsg/recvmmsg | 按返回的消息数推进，逐项检查 msg_len、来源与报文内容；空报文仍占一个消息条目 |
| 队列清空 | 非阻塞 recv 返回 EAGAIN |
| 原生路径与回收 | 每实例 UDP InDatagrams/OutDatagrams 至少为 4，InErrors/NoPorts 为 0，DPDK TX/RX 非零且 outstanding=0 |

`--stats` 的 `native` 对象新增 `udp_in_datagrams`、`udp_out_datagrams`、
`udp_in_errors`、`udp_no_ports`，均读取原生 Linux `/proc/net/snmp` 的 `Udp:`
计数；既有 TCP 字段保持含义。UDP-only 实例不要求 TCP open 计数增长。

F-Stack 来源及文件 SHA-256 见 [provenance](../tests/fstack-provenance.json)。
上游 TX checksum 用例不验证 socket；其 UDP/epoll 示例是 API 使用参考且忽略
零长度 payload，本批明确覆盖这一差异，没有复制 ff_* 实现或测试 harness。

基础 datagram 测试范围为小报文 IPv4 unicast；分片由下文的独立测试验证。
DNS resolver 透明兼容、IPv6、fragmented UDP 尚未由基础测试验收；IPv4 多播见下文
的单独测试。公开能力位仍按 TCP 首版定义；本批
增加的是原生 UDP 路径验证和可追溯计数。


## 消费式接收截断与批量返回长度

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-receive-truncation$' --output-on-failure
```

本项补充基础测试中「先短 peek、再完整读取」以外的消费式截断。宿主参考、原生
客户端和原生服务端均使用独立 Linux 对端，经 DPDK net_tap/veth 运行相同断言。
服务端按请求发送 0、1、33、257 字节报文，客户端接收容量仅 7 字节。

- recvfrom 不带 MSG_TRUNC 时返回 min(报文长度, 7)，只保留相应前缀。
- recvmsg 使用 3+4 字节两段 iovec，也只返回复制长度；输出 MSG_TRUNC 当且仅当
  报文超过容量，MSG_CTRUNC 不得出现。
- recvmmsg 使用相同短 iovec、输入 MSG_TRUNC|MSG_DONTWAIT：每条 msg_len 必须是
  完整报文长度，缓冲区仍只复制前 7 字节，输出截断标志按各条报文分别校验。
  每次请求触发两条不同记录的回复，批量返回 1 或 2 都允许，按实际消息数推进。
- 所有接收均核对前缀及未写区域的 0xa5 哨兵、来源 tuple、EPOLLIN 与完整 64 位
  tag；FIONREAD 在接收前必须返回队首完整报文长度。零长度报文仍占一个批量条目，
  不视为 EOF，后续报文仍必须成功收取。
- 服务端等待下一条请求才发送下一轮，因此每轮结束时 EAGAIN、FIONREAD=0 和无
  epoll 就绪可验证截断尾部已丢弃，而不是留作下一条报文。最终确认交互完成后退出，
  不使用固定 sleep。

原生客户端 UDP OutDatagrams/InDatagrams 至少为 13/17，原生服务端至少为 17/13；
两端 InErrors/NoPorts 为零，DPDK TX/RX 非零且 outstanding=0。这是 F-Stack UDP/
epoll 示例的 Ker/Linux 扩展，不是上游截断测试或等价性声明。仅增加测试，不修改
Linux 或 Ker 适配代码；未覆盖 recvmmsg timeout/MSG_WAITFORONE、错误指针或网络丢包。


## Linux 异步错误与恢复

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-errors$' --output-on-failure
```

在隔离网络 namespace 中，connected 和 unconnected UDP 各先跑宿主 Linux
基线，再通过原生 Linux/DPDK 访问独立宿主对端。向未监听端口发送小报文，由
宿主内核产生真实 ICMP port-unreachable；测试不构造或注入 ICMP。

- 只订阅 EPOLLIN 仍收到 EPOLLERR；SO_ERROR 返回 ECONNREFUSED。
- 读取 SO_ERROR 后 error queue 仍保持错误就绪；MSG_ERRQUEUE 返回原始 payload、
  目标地址/端口、IP_RECVERR 控制消息及正确的 errno、ICMP origin/type/code 和 offender 地址。
- 读空 error queue 返回 EAGAIN，SO_ERROR 清零且 epoll 不再报告错误。
- 使用同一 socket 访问正常 UDP 对端并校验 echo；connected 模式重新 connect 到正常端口。
- 原生实例 UDP OutDatagrams 至少 2、InDatagrams 至少 1，DPDK TX/RX 非零、
  outstanding=0；独立对端也必须确认 payload。

这是 Ker 针对 Linux 的兼容性扩展，并非 F-Stack 上游已经覆盖 IP_RECVERR 的声明。
协议与错误队列均由导入 Linux 执行，适配层无需修改。此项只验证 IPv4 ICMP
port-unreachable；不代表 PMTU/EMSGSIZE、所有 ICMP 错误、error queue 截断、
所有 ancillary data 已验收；IP_PKTINFO 和软件接收时间戳的单独验收见下文。


## Packet info 与软件接收时间戳

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-ancillary$' --output-on-failure
```

同一 POSIX 测试程序先运行宿主 Linux 基线，再让原生 Linux 分别作为客户端和
wildcard-bind 服务端，与独立宿主对端通信，每方向三个带不同内容的 datagram。
两个端点均检查 payload、源地址/端口和控制消息。

- 开启 IP_PKTINFO 和 SO_TIMESTAMPNS，并查询选项确认生效。
- 接收 IP_PKTINFO 的目标地址、local address 与实际本地地址一致；interface index
  为正且在同一 socket 上保持一致，不要求宿主与原生内核使用相同编号。
- sendmsg 携带 IP_PKTINFO 选择本地源地址；获得接收 interface 后也指定该 interface，
  对端验证实际源地址。wildcard 服务端不会把 INADDR_ANY 当作报文目标地址。
- SCM_TIMESTAMPNS 包含有效 timespec，秒数处于宿主 CLOCK_REALTIME 收包区间内，
  边界容差一秒；不以时间戳精度或性能作为断言。
- 中间 datagram 的 control buffer 只有一字节，必须返回 MSG_CTRUNC，payload 仍完整。
  下一报文恢复完整 buffer 后重新获得两个完整控制消息，且无 MSG_CTRUNC/MSG_TRUNC。
- 每个原生实例 UDP InDatagrams/OutDatagrams 至少 3，DPDK TX/RX 非零，outstanding=0。

该测试发现 LKL POSIX host 的 monotonic 时钟同时用于初始化 persistent clock，
原生软件接收时间戳因此缺少墙钟 epoch。Ker 现在在内核启动后、网络启用前，
读取宿主 CLOCK_REALTIME 并调用原生 clock_settime 初始化私有内核的 realtime。
不会设置宿主时钟，也不改动上游 clocksource 或协议定时器。

这里验证 x86_64/glibc 的 SO_TIMESTAMPNS 软件时间戳 ABI 和初始 realtime 对齐；
没有实现启动后的宿主 NTP/手动时钟跳变同步，不包含硬件时间戳、所有 time64
选项、multicast 或所有控制消息。来源与扩展范围记录在 provenance 中。


## MTU、分片与大报文恢复

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-mtu$' --output-on-failure
```

先运行宿主参考，再让原生 Linux 分别作为客户端和服务端，经 DPDK net_tap/veth
连接独立宿主 Linux 对端。wire MTU 为 1500；仅此测试将隔离 namespace 的
loopback MTU 也设为 1500，使宿主参考使用相同边界。两个端点均执行以下断言：

- connected UDP 的 IP_MTU 返回 1500，IP_MTU_DISCOVER 查询值与设置值一致。
- IP_PMTUDISC_DO 下，1473 字节 payload 发送返回 EMSGSIZE；epoll 即使只订阅 IN
  也报告 ERR。MSG_ERRQUEUE 返回零字节 payload，并提供 SO_EE_ORIGIN_LOCAL、
  EMSGSIZE、ee_info=1500、原目标地址/端口和 AF_UNSPEC offender。
- 清空错误队列后错误就绪消失；1472 字节 payload 在 DO 模式下成功通信。
  这是无 IPv4 option 时的 1500 - 20 - 8 边界。
- 切换 IP_PMTUDISC_DONT 后，1473、4096、65507 字节 payload 逐字节往返成功，
  保持 datagram 边界和对端 tuple。65507 是本测试无 option 的 IPv4 UDP 最大 payload。
- 65508 字节 payload 返回 EMSGSIZE；清空其本地错误队列后，同一 socket 再次
  成功收发 1472 字节 datagram。检查清除 ERR 时允许已到达的正常 IN 就绪。

`--stats` 的 `native` 对象增加 `ip_frag_ok`、`ip_frag_creates`、`ip_reasm_ok`、
`ip_reasm_fails`，分别读取原生 `/proc/net/snmp` 中 `Ip:` 的 FragOKs、FragCreates、
ReasmOKs、ReasmFails。每个原生实例要求至少三次分片成功、生成至少 50 个分片、
至少三次重组成功且无重组失败；UDP InDatagrams/OutDatagrams 各至少 5，DPDK
TX/RX 非零、outstanding=0。诊断输出缓冲区扩为 1024 字节以容纳新增 uint64 字段。

分片、重组及 MTU 错误全部来自导入 Linux；没有构造替代协议路径或修改上游源码。
该验收覆盖固定 MTU、无丢包的 IPv4 unicast。它不代表路由器 ICMP frag-needed 驱动的
动态 PMTU 更新、分片丢失/重排/超时、IPv6、多播、硬件 offload 或物理 NIC 已通过。

## IPv4 多播与成员关系

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-multicast$' --output-on-failure
# 多播接收应用需要在原有 ker-run 参数中加上：
ker-run --all-multicast ... -- application ...
```

测试先运行宿主参考，再将原生 Linux 分别作为发送端和接收端，使用
239.255.42.17 和独立宿主 Linux 对端经 DPDK net_tap/veth 通信。

- 发送端通过 IP_MULTICAST_IF 选择本地接口，查询确认设置；设置并查询
  IP_MULTICAST_TTL=7、IP_MULTICAST_LOOP=1。loop=1 也使宿主参考能接收同内核的多播副本。
- 两个接收 socket 使用 SO_REUSEADDR 绑定同一端口，各设置 IP_MULTICAST_ALL=0
  并在本地接口入组；重复入组返回 EADDRINUSE。
- 首个 datagram 必须送达两个 socket，逐字节校验 payload、源 tuple，
  IP_PKTINFO 中的目标 group、本地地址和正 interface index，以及收到的 TTL=7。
  poll 等待指定 socket，epoll 检查就绪集合，避免依赖两个接收者的唤醒顺序。
- 一个 socket 退组并关闭；另一个退组、检查重复退组返回 EADDRNOTAVAIL，再重新入组。
  完成重新入组后才发出 unicast ACK，随后接收第二个多播 datagram 并回 ACK。
- 原生发送端 UDP InDatagrams/OutDatagrams 各至少 2；原生接收端 InDatagrams
  至少 3、OutDatagrams 至少 2。两实例均要求 DPDK TX/RX 非零、UDP 错误为零和 outstanding=0。

测试发现 net_tap 默认接收规则不会将这些多播帧交给原生接收端。新的显式
`--all-multicast` 启动选项请求并检查 DPDK ethdev 的 all-multicast 模式；不支持或
未成功启用时启动失败，不宣称接收成功。普通启动保留原来的接收模式。
当前 packet channel 不传播动态 MAC group 订阅，all-multicast 将多播帧交给原始
Linux，由 Linux 执行成员过滤和协议处理，不在 Ker 内实现多播/IGMP 协议。

该验收是同一链路上的小报文 IPv4 ASM，不验证退组空窗期的非投递、多播路由器
IGMP 互通、跨网段转发、source-specific multicast、IPv6 或物理 NIC 的过滤能力。


## IPv4 子网广播与发送权限

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-broadcast$' --output-on-failure
```

测试先运行宿主参考，再运行原生客户端和原生服务端，与独立 Linux 对端经 DPDK
net_tap/veth 互通。使用同链路的 198.18.0.255/24 子网广播地址；服务端绑定 wildcard，
接收广播不需要设置 SO_BROADCAST，客户端显式绑定本地地址并核对 getsockname。

- SO_BROADCAST 默认必须为零。sendto、sendmsg 和单条 sendmmsg 分别在关闭该选项时
  返回 EACCES；开启并查询确认后，各发送一个 37 字节广播 datagram，并等待单播回复。
- 每次回复后都关闭并查询确认 SO_BROADCAST；第三个广播之后再验证一次 EACCES，
  随后同一 socket 在选项关闭时发送普通单播，必须正常收到回复。
- 每个 datagram 核对完整 payload、源地址/端口、EPOLLIN 和 64 位事件 tag。
  IP_PKTINFO 必须报告实际广播或单播目的地址、正确本地地址及正 interface index。
  同类流量的 interface index 保持一致，但宿主参考的单播可走 loopback，因此不要求
  广播与单播使用同一个 index。接收队列最后必须返回 EAGAIN。
- 两个原生实例都要求 UDP InDatagrams/OutDatagrams 至少各 4、InErrors/NoPorts 为零、
  DPDK TX/RX 非零和 outstanding=0。没有修改 Linux 协议、Ker 适配或 ethdev 模式。

这是 F-Stack UDP/epoll 示例的 Ker/Linux 扩展，不是上游广播测试或 API 等价性声明。
本项只验证同链路小报文子网广播，不覆盖 limited broadcast 255.255.255.255、多接口
路由、广播转发、物理 NIC 过滤、广播分片或实际发现协议。socket 权限和目的地址
分类均由原始 Linux 执行。


## UDP connect、来源过滤与断开

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-connect-lifecycle$' --output-on-failure
```

测试先跑宿主参考，再将原生 Linux 分别作为客户端和双端口服务端，与独立 Linux
对端经 DPDK net_tap/veth 互通。客户端显式绑定本地地址和非零端口，再创建 dup alias；
同一个 socket/epoll 注册在整个生命周期内保持，不依赖固定 sleep。

- 通过 alias connect 到服务端 A，原 fd 的 getpeername 必须匹配 A；默认目的地址
  发送的请求由 A 收到。B 随后发出错误来源报文，必须从 IP_RECVERR 队列收到真实
  ICMP Port Unreachable，核对引用 payload、目的 tuple、错误 origin/type/code 和
  offender。确认拒绝后 A 才发正常回复，客户端只收到正常回复，队列随后为 EAGAIN。
- 原 fd 重连 B 后，alias 查询必须匹配 B，本地 tuple 不变，默认发送改由 B 接收。
  客户端在仍连接 B 时显式 sendto A：A 必须收到该报文，但 A 的回复仍被来源过滤，
  同样以 ICMP 错误确认；B 发出有效确认。原 fd 的对端仍是 B，后续默认发送也仍去 B。
- alias 用 AF_UNSPEC 断开后，原 fd 的 getpeername 必须 ENOTCONN，两个 fd 的显式
  绑定均保留，无目的地址的 send 必须 EDESTADDRREQ 且 SO_ERROR 仍为零。随后通过
  sendto A 恢复普通收发，来自 A、B 的两条回复都必须收到，允许它们以任意顺序到达。
- 所有 datagram 检查 token、来源地址/端口、EPOLLIN/EPOLLERR 与完整 64 位 tag。
  错误队列完全排空后服务端 SO_ERROR 为零，所有普通接收队列末尾必须 EAGAIN。

原生客户端 UDP OutDatagrams/InDatagrams 至少为 5/6，NoPorts 至少为 2，对应两次
有意的错误来源拒绝；原生服务端至少为 8/5，NoPorts 为零。两端 InErrors 为零，
DPDK TX/RX 非零且 outstanding=0。本项中的 NoPorts 增长是来源过滤的预期证据，
区别于其他正常 UDP 场景的零错误要求。

这是 F-Stack UDP/epoll 示例的 Ker/Linux 扩展；不声明上游 F-Stack 等价性，AF_UNSPEC
按明确测试的 Linux 语义解释。非零端口 bind 是保留本地 tuple 的前提，本项不覆盖
自动绑定或 port=0 时断开后的端口选择，也不覆盖多接口路由、并发重连、IPv6 或 DNS。
仅增加测试，UDP 对端选择、过滤、ICMP 与断开行为全部由原始 Linux 执行。
