# Linux networking selftests 迁移清单

固定 Linux 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`。以下分母由各目录原版 `make emit_tests COLLECTION=<目录>` 得到，代表默认注册入口，不是 C helper 数量、运行参数组合数或内部断言数。此清单仅覆盖 `tools/testing/selftests/net` 下列十个上游 collection，不包含 `drivers/net` 或独立 BPF collection。

| collection | 默认注册入口 | 当前接入范围 |
| --- | ---: | --- |
| `net` | 106 | `sk_connect_zero_addr`、四个完整 binding 程序、`reuseport_dualstack`、`sk_so_peek_off`、`tun`、`reuseport_addr_any.sh`、`run_netsocktests`、`tap`、`netlink-dumps`、`netns-name.sh`；共 13 个入口本地通过 |
| `net/af_unix` | 5 | 全部接入 host-backed IPC 兼容性测试，与 imported Linux 分开统计 |
| `net/mptcp` | 10 | [全部完整 shell 入口](linux-mptcp-join.md)本地通过，共 508 项 TAP 场景；最终 CI/review 单独核对 |
| `net/tcp_ao` | 24 | [全部双栈入口](linux-tcp-ao-tests.md)，已知上游 XFAIL 单列 |
| `net/packetdrill` | 24 | [完整原版 24 个脚本](linux-packetdrill-selftests.md)，48 个 imported Linux 双栈配置本地通过；CI/review 单独核对 |
| `net/forwarding` | 107 | `router_vid_1.sh`、`min_max_mtu.sh`、`router_bridge.sh`、`router_nh.sh`、`router_bridge_vlan.sh`、`router_bridge_1d.sh`、`router_bridge_vlan_upper.sh`、`router_bridge_pvid_vlan_upper.sh`、`router_bridge_vlan_upper_pvid.sh`、`router_broadcast.sh`、`bridge_mdb_host.sh`、`bridge_sticky_fdb.sh`、`bridge_fdb_learning_limit.sh`、`bridge_mdb_port_down.sh`、`bridge_port_isolation.sh`、`bridge_vlan_unaware.sh`、`bridge_vlan_aware.sh`、`bridge_locked_port.sh`、`bridge_vlan_mcast.sh`、`ip6_forward_instats_vrf.sh`、`bridge_igmp.sh`、`bridge_mld.sh`、`bridge_mdb.sh`、`bridge_mdb_max.sh`、`pedit_ip.sh`、`pedit_l4port.sh`、`pedit_dsfield.sh`、`tc_flower_port_range.sh`、`tc_flower_l2_miss.sh`、`tc_flower_cfm.sh`、`tc_chains.sh` 完整入口本地通过；其余 76 个尚未逐个接入 |
| `net/hsr` | 2 | 尚未接入 |
| `net/netfilter` | 29 | `conntrack_dump_flush`、`conntrack_icmp_related.sh`、`conntrack_ipip_mtu.sh`、`rpath.sh`、`xt_string.sh` 完整入口本地通过；其余 24 个尚未逐个接入 |
| `net/openvswitch` | 1 | 尚未接入 |
| `net/rds` | 2 | 尚未接入 |
| 合计 | 310 | 逐个保留原版入口合同，不用 Ker 自编回归抵扣 |

原版 `tcp_inq`、MPTCP C helper 和 KUnit 已有的运行配置另行记录，不增加这个默认注册入口分母。Ker 集成测试中的 netfilter、veth、VRF 等功能覆盖，也不代表对应完整上游 shell 已迁移。

按本地完整入口合同统计，当前接入 112/310，剩余 198；其中 107 个通过 imported Linux，另 5 个是 host-backed AF_UNIX。严格只统计 imported Linux 时尚有 203 个。`net/` 本目录剩余 93/106。提交后的 hosted CI/review 资格仍须单独核对。

## 完整 socket 程序

| 原版程序 / CTest 后缀 | 完整运行结果 | 验证范围 |
| --- | --- | --- |
| `reuseaddr_conflict` | 原版程序退出成功 | IPv4 listener 与 IPv6 wildcard 创建/关闭期间的复用冲突 |
| `sk_bind_sendto_listen` | 原版程序退出成功 | 两个 IPv6 socket 的 bind、零长 Fast Open sendto 及后续 listen |
| `bind_timewait` | 2/2 TAP | localhost 与 wildcard 两组真实 TCP 连接关闭后的 EADDRINUSE |
| `bind_wildcard` | 132/132 TAP | 44 组 IPv4、IPv6、v4-mapped 地址组合，各执行 plain、REUSEADDR、REUSEPORT |
| `reuseport_dualstack` | 原版全部六组及 SUCCESS | UDP 小/大 reuseport group 和 TCP，交换双栈创建顺序，断言 IPv4 数据优先进入 IPv4 socket |
| `sk_so_peek_off` | 原版四个明确成功输出 | TCP/UDP 的 IPv4/IPv6，保留 MSG_PEEK、MSG_TRUNC 与 SO_PEEK_OFF 的全部偏移断言 |
| `run_netsocktests` | 原版 shell 的完整输出和成功退出 | 原版 `socket.c` 的全部五次创建：IPv4 TCP/UDP 各成功一次，无效地址族一次 EAFNOSUPPORT、类型/协议不匹配两次 EPROTONOSUPPORT |

源文件、`kselftest.h`、`kselftest_harness.h` 和 Makefile 在执行前后与 pinned Git blob 逐字节核对，编译保留原版断言。原版 harness 的 fork 与宿主 IPC 保留；IP socket 操作经已验证的私有 fixture 进入同一个常驻 Linux，内核 owner 不 fork。binding 判定、端口表、TIME_WAIT 和原版 errno 均来自 Linux，本批没有增加协议实现或修改生产 API。

显式 `close()` 等到实际 native close 完成并返回原版结果后才释放通信通道，保持原版按顺序关闭 accepted、client、listener socket 的语义。进程退出时遗留的通道仍由 EOF 清理；不以等待、重试 bind 或修改 TIME_WAIT 协议逻辑掩盖适配器的关闭顺序问题。

四个 CTest 均使用默认 native 内核配置，本地完整通过。fixture 分别记录 5、2、6、1056 次实际 native socket() 创建；TIME_WAIT 的两次 accept 单独计数，并要求 Linux ActiveOpens/PassiveOpens 均为 2。每次成功创建都验证 native descriptor 类型，缺失 backend 的对照必须拒绝。所有 native socket、packet outstanding 均归零，worker 正常关闭。两个非 TAP 程序按完整程序退出状态记录，不伪造断言计数。

新增的两个完整程序使用同一个私有 native fixture。UDP 通过真实 POSIX facade 创建并验证 descriptor kind；epoll_create/ctl/wait 直接使用导入 Linux 的 epoll，保留原版 `timeout=-1` 阻塞等待与 event.data，不在宿主生成 readiness。`reuseport_dualstack` 要求 110 次 socket 创建（其中 88 个 UDP）、2 次 accept、6 次 epoll 创建、104 次注册及 6 次等待；`sk_so_peek_off` 要求 12 次 socket 创建（其中 6 个 UDP）和 2 次 accept。后者上游可能在全部不支持时仍退出 0，因此 runner 额外要求 TCP/UDP × IPv4/IPv6 的四行原版成功输出；不把退出 0 或跳过当成完成。两者的 TCP ActiveOpens/PassiveOpens 均须为 2，正常关闭后无 live socket 或 outstanding packet。本地结果和最终 hosted CI/review 分别记录。

`linux-original-net-*.json` 包括原版输出、TAP、源码与二进制 hash、内核 fingerprint、native socket/accept 计数和清理结果。CI 的完整 default CTest graph 必须包含这七项及其 JUnit 结果，不能跳过。

`run_netsocktests` 与原版 `socket.c` 分别和 pinned Git blob 逐字节核对。四次 IPv4 调用通过真实 POSIX facade 进入导入 Linux；AF_MAX 经私有测试 runtime 直接调用 `lkl_sys_socket`，避免公共 facade 对非网络地址族的宿主 IPC 路径。fixture 将 Linux 的实际 errno 原样传回，不在代理端生成预期错误。runner 还要求原生计数为五次调用、一次 EAFNOSUPPORT、两次 EPROTONOSUPPORT、TCP/UDP 各一次真实成功，并验证 descriptor kind 和 SO_PROTOCOL。这样上游允许 IPv4 未配置时退出成功的路径不能计为完成。缺失 backend 的原版 helper 必须失败，清理后无 live socket/outstanding packet，worker 正常退出。该入口本地通过，hosted CI/review 单独确认。

```bash
ctest --test-dir build-native-on --no-tests=error \
  -R '^linux-original-net-' --output-on-failure
```

## Packetdrill

[完整原版 packetdrill 迁移](linux-packetdrill-selftests.md)使用 unchanged Google 工具 revision `8051382e6ac928c4c13a88b34832649d9b07abc2` 和单独 fingerprint 的 native TUN/FQ 内核。24 个原版脚本经原版 runner 执行 IPv4/IPv6 共 48 个配置，保留全部包内容、syscall、时间及内嵌 TCP_INFO 断言。本地完整 CTest 已通过，最终提交的 hosted CI/review 仍须单独通过。此前宿主基线单列，不计 native 覆盖。

## TUN 与地址优先级

`config/native-linux-net-selftests.config` 为单独 fingerprint 的 native 配置，启用原版 TUN 与 DCCP；不修改 Linux 源码。CTest 的 `linux-original-net-tun` 编译原版 `tun.c`，完整执行 5 项 TAP，涵盖两次 attach、四次 detach、错误队列操作的 EINVAL 和设备生命周期。fixture 必须记录 10 次真实 TUN open、10 次 TUNSETIFF、7 次 TUNSETQUEUE 和 5 次 native Netlink socket 创建。

`linux-original-net-reuseport_addr_any` 完整运行未修改的 `reuseport_addr_any.sh`、`in_netns.sh` 和 C helper。UDP/TCP/DCCP 分别执行 IPv4、IPv6、IPv4 mapped to IPv6，共九组原版成功输出；即使上游缺失 DCCP 时退出 0，也不能计为通过。实际 native 证据要求 91 次 socket 创建（30 UDP、31 DCCP、30 TCP）、6 次 accept、9 次 epoll 创建、81 次注册、9 次等待，以及一次真实 namespace 创建/删除。删除 namespace 前读取其原版 `/proc/thread-self/net/snmp`，要求 TCP ActiveOpens/PassiveOpens 均为 3；根 namespace 两者为 0。协议和地址选择均来自导入 Linux。

两项完整入口本地通过，总耗时约 3 秒，native fingerprint 为 `d40b9a892a5b01196cf3f91cc07eb54b810bd7451089e5e91d1b10f28fcb130c`。缺失 backend 的原版程序对照必须失败。runner 保留源文件执行前后的 pinned Git blob 检查、完整断言、20 秒清理上限、零 live socket、零 outstanding packet 和正常 worker 退出要求。

共享 fixture 先排空所有 RPC，确认每个 worker 完成原生 descriptor close 和 namespace release，再通过已有 runtime 接口完成 native halt，最后 join 全部宿主线程。这样 LKL 在 halt 中统一回收原生 task 并删除 TLS key，避免退出某个 pthread 时的 LKL TLS destructor 将 CPU 调度给等待宿主条件变量的另一个 worker。持有空闲管理通道的 shutdown 对照验证此先后顺序；不延长 deadline 或绕过内核清理。

CI 在专用 native 配置中强制执行两个入口，核对实际 TUN/DCCP 配置、两项唯一注册、无 skip 的 JUnit 和匹配 fingerprint 的 JSON 证据：

```bash
python3 tools/ci/native_tests.py net-profile build-native-net-selftests native-net-selftests-ctest.xml
```

## Macvtap 报文测试

原版 `tap.c` 在单独 fingerprint 的 `config/native-linux-macvtap.config` 中完整执行 3/3 TAP：合法 UDP GSO、合法 UDP 校验和报文，以及错误以太网协议报文的真实 EINVAL。Linux 的 dummy、macvlan、macvtap、tap 和 sysfs 均须实际编译启用；源文件、断言和报文构造保持原样。

fixture 转发原版创建/删除链路的 Netlink 请求，并从导入 Linux 的 `/sys/class/macvtap/tap<ifindex>/dev` 读取动态 major/minor，再在私有 native 文件系统中建立 `/dev/tap<ifindex>`。设备名称中的 ifindex 不等于其分配的 minor，不能用宿主设备或推算的设备号代替。TUNSETIFF 与三个报文写入全部进入 Linux macvtap 驱动，不在 Ker 中模拟成功或错误。

本地完整通过，native fingerprint 为 `ee89323c0726f946f02cecf45efbfcc7b21f5a0a52b1740d38a6ebbf4547cb9f`。证据要求 12 次真实 Netlink socket、3 次 native macvtap open、3 次成功 TUNSETIFF、2 次共 2149 字节的成功 device write 和 1 次实际 EINVAL。缺失 backend 的原版 harness 必须失败；结束时无 live descriptor/outstanding packet，owner/worker 正常关闭。此项计为一个默认入口，hosted CI/review 单独确认。

CI 强制检查专用配置、唯一注册、三个明确 TAP 名称、无 skip 的 JUnit 和匹配 fingerprint 的 JSON：

```bash
python3 tools/ci/native_tests.py macvtap-profile build-native-macvtap native-macvtap-ctest.xml
```


## Netlink dump 生命周期

原版 `netlink-dumps.c` 在独立的 `config/native-linux-netlink-dumps.config` 中完整执行三个 TAP 用例：`global.test_sanity`、`global.close_in_progress`、`global.close_with_ref`。前者验证 generic Netlink policy dump 跨两次接收，后两者在 dump 进行中分别直接关闭、带 POSIX 消息队列通知引用关闭。原版源文件、harness 和断言保持不变。

专用配置实际启用 `CONFIG_POSIX_MQUEUE=y`。只有该原版程序的 raw `syscall()` 经私有编译适配转发 `mq_open`、`mq_notify`；宿主传输自身的 syscall 不受影响。runtime 将 facade descriptor 翻译为真实 native descriptor，并构造 Linux `SIGEV_THREAD` 通知，让原版 mqueue 实现获取并保留 Netlink socket 引用。cookie 内容原样传入内核，不在 Ker 中合成通知、dump 或成功返回。内核和依赖源码均无本地修改。

上游未断言 `mq_notify` 的返回值，runner 因此额外要求一次真实成功的通知注册、一条随后实际关闭的被引用 Netlink descriptor，以及消息队列 descriptor 的正常回收。完整证据还要求三次 generic Netlink 创建、三次共 84 字节的原始 dump 请求、两次原始接收，三个准确 TAP 名称和无 skip。缺失 backend 对照必须失败；native live descriptor、outstanding packet 均归零，worker 正常关闭。消息队列名称与上游一致，在独立内核实例结束时回收；不提前 unlink 或改变原版生命周期。

本地完整通过，native fingerprint 为 `130c31bb9c04219ac28071b85d338adb509d2c5227238b3069cd34a023b9c4df`。该程序计一个默认入口，hosted CI/review 另行核对。CI 强制验证专用内核配置、唯一注册、准确 TAP 矩阵、native 引用计数和无 skip 的 JUnit：

```bash
python3 tools/ci/native_tests.py netlink-dumps-profile build-native-netlink-dumps native-netlink-dumps-ctest.xml
```


## Namespace 与设备名称

完整未修改的 `netns-name.sh` 和 `lib.sh` 在单独的 `config/native-linux-netns-name.config` 中执行，真实启用 dummy 驱动。原版 shell 检查普通移动、名称冲突拒绝、移动时重命名、备用名称冲突拒绝，以及备用名称跨 namespace 的可见性；保留原版所有返回值检查和清理。该入口不输出 TAP，不将五组场景或 30 次工具调用计作额外注册入口。

普通链路操作与查询使用固定 iproute2 6.12.0 的原版 `ip`，只把 socket 调用转发到常驻内核。移动操作将源设备 index 和目标 namespace 的真实 native fd 编码为 rtnetlink 请求，逐次要求真实内核 ACK；不把宿主 `/run/netns` 或宿主 PID 当作 native namespace。名称检查、重命名、备用名称冲突和查询结果均来自导入 Linux，没有自编名称表或成功 stub。

runner 要求原版 `[ OK ]` 输出、25 次原版 `ip` 操作及五次真实移动结果 `[0, EEXIST, 0, EEXIST, 0]`，核对原版备用名称查询的目标成功/源失败，两次 namespace 创建/删除，无协议 socket 替代和零 live descriptor/outstanding packet。缺失 backend 的整个原版脚本必须失败；该负对照仅将 `WAIT_TIMEOUT` 设为一秒，正向原版等待设置保持默认。源码在执行前后逐字节核对，固定工具 provenance 和 binary hash 单列。native fingerprint 为 `d3ebd0dbf314cab88786a9e45994aec7fd752c7a91086e1bd90e24aaa06220c1`；本地完整通过，hosted CI/review 单独确认。

```bash
python3 tools/ci/native_tests.py netns-name-profile build-native-netns-name native-netns-name-ctest.xml
```

## 网关 forwarding

Ker 的目标应用包括网关和 WAF，因此优先迁移转发、路由、VLAN/VRF、netfilter、conntrack 和 NAT 的完整上游入口。HTTP/TLS 解析和 WAF 规则属于调用方。

`forwarding/router_vid_1.sh` 在独立的 `config/native-linux-forwarding.config` 中完整运行。该配置启用 `CONFIG_IP_ROUTE_MULTIPATH=y`，保留原版 `nexthop` 路由命令；默认配置缺失该能力时不注册此测试。原版 shell、两个公共 lib 和 forwarding Makefile 在执行前后均与 pinned Git blob 逐字节核对。四个 veth 接口、四个 VLAN 1 子接口、两个 VRF、地址和路由由原版 iproute2 6.12.0 经 Netlink 配置到导入 Linux。

原版 `ip vrf exec` 的宿主 cgroup BPF 无法引用常驻 Linux 的设备，私有测试适配器在创建每个 IP socket 时调用原生 `SO_BINDTODEVICE`，设置同一 `sk_bound_dev_if` 字段；路由查找、VRF 隔离、VLAN 和转发行为均来自 Linux。未知 VRF 必须让原版 ping 失败；同一后端的 loopback ping 对照必须成功。`sysctl` 读写导入 Linux 的真实 proc，不修改宿主 sysctl。

本地完整原版两项测试通过，IPv4/IPv6 均保留默认 10 次 ping、0.1 秒间隔、5 秒 deadline；实际各收到 10 个回包，原生 `ForwDatagrams` 和 `Ip6OutForwDatagrams` 各增加 20。缺失 backend 的完整原版脚本必须失败；不以跳过、退出 0 或自编转发测试抵扣入口。清理必须无 live socket/outstanding packet、worker 正常退出。CI 单独构建该内核配置，强制运行完整入口和同样的证据门禁，上传 JSON/JUnit/manifest。hosted CI/review 资格单独核对。

`forwarding/min_max_mtu.sh` 使用同一原生 forwarding 配置，完整执行六项原版测试：普通 IPv4/IPv6 ping、最大/最小 MTU 配置、最大/最小边界流量。实际 veth 的 min/max 为 68/65535，超出边界的四次配置必须返回内核错误。最大 MTU 下的 IPv4/IPv6 原版 ping 分别发送 65507/65487 字节 payload，均收到全部十个回包；降低接口 MTU 后，两个相同包长的原版 ping 必须失败；最小 MTU 下 40 字节 IPv4 payload 必须成功。原版脚本明确不在最小 MTU 下测试 IPv6，保留这一合同，不创造额外通过项。

共 128 条原版拓扑/配置/流量/清理命令，经真实 Netlink 和 ICMP 执行。六项均须明确输出 OK，不能用 XFAIL 或缺失子项抵扣；native socket/packet 必须归零，保留完整脚本缺失后端和无效 VRF 对照。CI 的 forwarding profile 强制运行 VLAN 1、MTU、广播三个完整入口及广播 realtime ABI 控制，核对各自的独立 JSON/JUnit。

`forwarding/router_broadcast.sh` 保留原版 `ping_ipv4` 完整入口及全部 16 个结果。六个 veth、三个主机 VRF、三组 /24 地址和全部静态路由由 unchanged iproute2 配置到 Linux。原版分别关闭和开启 all、rp1、rp2 的 `bc_forwarding`，保留每次探测的 `-I`、10 次请求、0.1 秒间隔、5 秒 deadline、`-b` 和原版 literal grep；不改为“所有回复”或 ping 退出码的判定。两个同网段丢弃案例要求指定路由器来源缺失，允许原版合同之外的其他来源回复。

每次探测前后记录真实 link/address/FIB、sysctl 和 `/proc/net/snmp`；本地四个定向广播转发案例各增加 20 个 `ForwDatagrams`，其余十二个为零。原版 ping 的 `2>&1` 字节顺序在 transport 内保留，GNU grep 以原始参数执行并记录实际输入、退出码和输出。保留 iputils 自身的广播/源地址提示，同时拒绝 backward-clock 诊断；私有 broadcast preload 通过已有 RPC 读取 native realtime，每次实际读取十次，另有必须通过的 host/null-timeval/fail-closed ABI 控制。未修改 Linux、iproute2 或上游 selftest。

清理核对三个 VRF 删除、原版保留的六个 veth 均 down/unmastered 且无 global 地址/路由，forwarding、broadcast 和 echo sysctl 恢复观察到的初始值，native live socket/outstanding packet 归零且 worker 正常退出。保留缺失后端整个原版入口失败、未知 VRF 拒绝和同后端 loopback 成功的对照。本地 forwarding gate 4/4 通过，沿用 native fingerprint `b60a3229d073cfe2709134257f5e6279b75ecca52e78444919e713f78110ea2a`；hosted CI/review 资格另行核对。此批只增加一个默认入口。

`forwarding/bridge_mdb_host.sh` 完整运行 `mdb_add_del_test`，保留三个原版 TEST 和每组的 add、文本 grep、delete、缺失检查。MAC `01:00:01:c0:ff:ee` 使用显式 permanent；IPv4 `225.1.2.3` 和 IPv6 `ff02::42` 省略状态参数，由 Linux 创建 temp entry。目标端口均为桥本机 `br0`，不是下属 veth 端口。所有操作经 unchanged iproute2 6.12.0 的真实 Netlink 接口执行，没有修改上游脚本、库或 Linux。

每条原版 bridge 命令前后都读取实际 MDB、link/address/FIB/VLAN 状态，核对 `mcast_snooping=1`、桥与端口 UP/forwarding、host VRF 和双栈地址/路由。六次 mutation 分别证明目标的存在、准确 port/group/state 和删除效果，允许无关动态组播成员保留。清理要求 br0/VRF 消失、原版保留的两个 veth down/unmastered 且无 global 地址/路由、目标 MDB 不残留，native live socket/outstanding packet 归零且 worker 正常退出。保留缺失 backend 的完整入口失败与 VRF 绑定对照。本入口不发送测试流量，不用 forwarding MIB 代替 MDB 证明。

沿用实际已启用 `CONFIG_BRIDGE_IGMP_SNOOPING=y` 的 bridge profile 和 native fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`。CI bridge gate 强制八个完整原版入口与 realtime ABI 控制，上传各自 JSON/JUnit；hosted CI/review 资格另行核对。此批仅增加一个默认入口。

`forwarding/bridge_sticky_fdb.sh` 完整执行原版 `sticky` 入口。原版在 veth1 添加 static/sticky MAC `de:ad:be:ef:13:37`，实际 Linux 产生 VID 1 和省略 VID 的 VID 0 两项；原版 VLAN 1 delete 成功移除前者，VID 0 保留。随后 unchanged Mausezahn 从另一主机 veth2 发出一帧原版指定源以太网 MAC 的 ARP request；原版 bridge JSON/jq 最终仍在 veth1 找到该 MAC。保留原版命令、参数、默认等待、未检查的 delete/sender 状态和最终 jq 判定，在额外证据合同中要求实际发送与状态效果。

私有 packet preload 复用已有真实 AF_PACKET 通道，并转发 libnet 所需的原生 ifreq 查询。服务端仅在 Linux send 成功后记录原始帧、返回长度和发送接口，不构造或改写帧。本地实际帧长 42 字节，native veth2 TX、veth3 RX、veth1 TX、veth0 RX 均增加一帧和 42 字节；合同核对指定以太网源 MAC、广播目的、ARP request 及完整长度，保留工具原有的 ARP payload。原版 add/delete/流量/show 前后分别读取实际 FDB 和链路计数，要求端口 UP/forwarding/learning、VID 1 删除、VID 0 static/sticky 不迁移。清理要求 br0/FDB 消失、四个 veth down/unmastered、无地址/路由残留及 live socket/outstanding packet 为零。独立控制验证普通 MPTCP adapter 仍拒绝缺失 backend 和 AF_PACKET。

本地实际 Mausezahn、ping、iproute2 binary hash 单列；沿用 bridge kernel/config 和 fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`。CI 强制八个完整 bridge 入口和 realtime ABI 控制，上传独立 JSON/JUnit；hosted 工具与产物资格单独核对。此批仅增加一个默认入口。

`forwarding/router_bridge.sh` 在专用 `config/native-linux-bridge-selftests.config` 中完整运行，启用真实 Linux bridge、VLAN filtering、VRF 和 multipath routing。原版 14 个阶段包含十次双栈 ping：初始连通、桥端口重新挂接后连通、移除 bridge self PVID 后隔离、恢复 PVID 后连通，以及先挂接端口再添加默认 PVID 后连通。保留原版全部 10 次请求、0.1 秒间隔、5 秒 deadline 和阶段间 sleep，预期失败的两个 ping 必须真实失败；不修改 Linux、iproute2 或原版 selftest。

iproute2 6.12.0 的 unchanged `bridge` 工具和 `ip` 使用同一原生 Netlink 通道。每次 ping 前读取真实 bridge 类型、VLAN filtering、端口 master/forwarding 状态和 VLAN 1 flags，要求仅隔离阶段缺失 PVID/untagged。完整 110 条原版命令还须保留 remaster、default PVID 0→1 的顺序及成功清理。实际 IPv4/IPv6 forwarding MIB 各至少增加 80；结束后 br1/VRF 设备消失、forwarding sysctl 恢复、live socket/outstanding packet 为零，worker 正常退出。保留完整入口缺失 backend、未知 VRF 与同后端 loopback 对照。

本地完整原版及 `bridge-profile` CI gate 通过，native fingerprint 为 `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`，并使用 hosted CI 对应的 Ubuntu iputils 20240117 ping 验证。gate 要求实际配置、唯一原版入口、无 skip 的 JUnit 和匹配 fingerprint 的完整 JSON；最终提交的 hosted CI/review 资格仍须单独核对。该程序计一个默认入口。

`forwarding/router_nh.sh` 完整运行两个原版双栈 ping，保留所有拓扑、`nexthop`、路由替换、clsact 创建/删除及 cleanup 命令。专用 `config/native-linux-nexthop-selftests.config` 启用 multipath、NET_CLS_ACT 和 NET_SCH_INGRESS；原版 iproute2 6.12.0 `ip`/`tc` 经已有 Netlink 通道操作导入 Linux，不修改 Linux、工具或原版脚本及三个公共库。

原版创建两个 AF_INET6 nexthop（101→veth1，102→veth2），IPv4 和 IPv6 各有两条路由引用它们。每次 ping 前读取实际 AF_INET6 nexthop dump、双栈 FIB、clsact 和 `route get fibmatch`。IPv4 实际选中 nhid 102；原版 IPv6 配置同时保留 metric 256 的直连路由和 metric 1024 的 nhid 路由，实际选中直连路由。本项保留并记录这个上游合同，不将 IPv6 ping 宣称为经 nhid 转发的流量证明。

本地使用 hosted Ubuntu iputils 20240117 完整通过，两次 ping 均保持 10 个回包、0.1 秒间隔和 5 秒 deadline，实际 IPv4/IPv6 forwarding MIB 各增加 20。要求 clsact/VRF 清理、forwarding sysctl 恢复、live socket/outstanding packet 为零和 worker 正常退出；上游未显式删除的 nexthop/路由随常驻内核关闭释放，不额外改写原版 cleanup。完整脚本缺失 backend 必须失败，未知 VRF 必须拒绝，同后端 loopback 对照成功。`nexthop-profile` gate 强制配置、唯一完整入口、无 skip JUnit、匹配 fingerprint 和完整证据。本地 native fingerprint 为 `6414aae9fd58c1f5012289ba99c8f3bab5a883982a6b2da969d4964f06a1cc3d`；hosted CI/review 资格另行核对。该程序计一个默认入口。

`forwarding/router_bridge_vlan.sh` 使用已有 bridge profile，完整执行 11 个阶段、9 行原版 TEST 结果及 8 次原版 ping。主机保留 VLAN 555/777 子接口和双栈路由，bridge 端口同时允许两个 tagged VLAN；bridge self PVID 从 555 切换至 777，再恢复 555。切换期间 VLAN 555 的两个 ping 必须真实失败，VLAN 777 的双栈流量和恢复后的 VLAN 555 流量必须成功。所有包数、间隔、deadline、sleep 及上游断言保持原样，不修改 Linux、iproute2 或 selftest 源码。

134 条原版命令逐项记录。每次 ping 前读取实际 bridge VLAN filtering/default PVID、forwarding 端口、self PVID、tagged 端口 VLAN 和主机子接口；每次 bridge 命令后读取完整原生 VLAN 表，核对 VLAN 333 的真实增删及 PVID 555→777→555 顺序。IPv4/IPv6 forwarding MIB 各增加 60，结束后 bridge、两个 VRF 和两个 VLAN 子接口消失，forwarding sysctl 恢复，live socket/outstanding packet 为零，worker 正常退出。完整脚本缺失后端及未知 VRF 对照必须失败，同后端 loopback 对照成功。

本地完整入口及 hosted Ubuntu ping 复验通过，沿用未变的实际 bridge 内核配置和 fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`。`bridge-profile` gate 强制同时运行 `router_bridge.sh`、`router_bridge_vlan.sh`、`router_bridge_1d.sh`、`router_bridge_vlan_upper.sh`、`router_bridge_pvid_vlan_upper.sh`、`router_bridge_vlan_upper_pvid.sh`、`bridge_mdb_host.sh` 和 `bridge_sticky_fdb.sh`，各自验证唯一注册、原版 program 标识、完整 JSON 和无 skip JUnit；八个入口均从默认 profile 排除，不能在缺少真实 bridge/VLAN 支持时抵扣通过。hosted CI/review 资格另行核对。此批仅新增一个默认入口。

`forwarding/router_bridge_1d.sh` 使用同一实际 native bridge 配置，完整执行五个原版阶段和八次双栈 ping。两个独立 802.1D bridge（br1/br2，vlan_filtering=0）分别承接 veth1.100/veth1.200，主机保留对应 VLAN 100/200 子接口。原版先验证两组双栈连通性，再解除两个 bridge VLAN 端口、等待原版两秒、按原版顺序重新挂接，最后重复两组双栈连通性检查；包数、间隔、deadline、sleep、上游断言及协议代码保持原样。

每次原版 ping 前读取实际 native link 状态，核对两个 bridge 的模式、MAC、VLAN 端口/master/forwarding 状态及主机 VLAN/VRF；每次原版 master/nomaster 操作后读取实际端口状态，确认解除和重新挂接真正发生。校验按原始记录的位置区分重复的挂接命令，保留完整生命周期顺序。IPv4/IPv6 forwarding MIB 各增加 80；原版 cleanup 后两个 bridge、四个 VLAN 子接口和两个 VRF 均消失，forwarding sysctl 恢复，live socket/outstanding packet 为零且 worker 正常退出。缺失 backend、未知 VRF 和同后端 loopback 对照分别验证失败与成功。

`bridge-profile` gate 同时强制八个完整入口、时钟 ABI 控制及其独立 JSON/JUnit。本地使用 hosted Ubuntu iputils 20240117 验证，native fingerprint 仍为 `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`，复用实际 immutable kernel/library，并核对当前输入/config/library hash。Linux、iproute2、原版 shell 和公共库不改动。hosted CI/review 资格另行核对，此批仅新增一个默认入口。

## Bridge VLAN upper 双栈路由

完整未修改的 `forwarding/router_bridge_vlan_upper.sh` 使用现有 bridge 配置运行五个原版阶段，输出四行原版 TEST 成功结果。`br1.555` 和 `br1.777` 是实际 VLAN-filtering bridge 上的路由接口，分别承接 VLAN 555/777 的 IPv4/IPv6 地址和 connected FIB 路由；两端主机的 `veth0.555`、`veth3.777` 则属于各自 VRF。原版先执行双栈 ping，再按原版顺序解除两个端口、等待原版两秒、重新挂接并恢复 tagged VLAN 成员，最后重复双栈 ping。包数、间隔、deadline、sleep、断言和 Linux/iproute2/selftest 源码均保持不变。

每次原版 ping 前读取完整 native link、address、双栈 FIB 和 bridge VLAN 表，验证两个 bridge upper 的 parent/VID/地址/路由、两个主机 upper 的 VRF、两个 forwarding 端口及各自 tagged VLAN。每次 master/nomaster 操作后读取端口真实状态，每次 bridge VLAN 命令后读取真实 VLAN 表，并按记录位置验证解除、重新挂接、VLAN re-add、流量和 cleanup 顺序，不能把重复命令当成同一次操作。

本地使用 hosted Ubuntu iputils 20240117 完整通过，四次 ping 各收齐十个回包、stderr 为空且均记录实际 native realtime 读取。IPv4/IPv6 forwarding MIB 各增加 40；原版 cleanup 后 bridge、bridge/host VLAN upper 和 VRF 均消失，forwarding sysctl 恢复，live socket/outstanding packet 为零，worker 正常退出。缺失 backend 必须失败，未知 VRF 必须拒绝，同后端 loopback 对照成功。沿用实际 native fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`。CI 的 bridge profile 强制六个完整原版入口加时钟 ABI 控制共 7 项，无 skip；hosted CI/review 另行核对。本批仅新增一个默认入口。

## Self PVID 与临时 VLAN upper

完整原版 `forwarding/router_bridge_pvid_vlan_upper.sh` 在已有 native bridge profile 中运行五个默认阶段、四个双栈 ping 成功结果。bridge 的 `vlan_default_pvid=0`，self VLAN 10 为 PVID/untagged，端口 veth1 的 VLAN 10 保持 tagged；基础路由地址位于 `br1`。原版在两组双栈 ping 之间临时创建 `br1.10`、启用接口、添加任意 IPv4 地址 192.0.2.33/28，保留原版一秒等待后删除 upper，验证 PVID 路由仍正常。Linux、iproute2、脚本、公共库、包数、时序和断言均未修改。

每次 ping 前和每次 upper 创建、启用、地址添加、删除后读取实际 native link/address、双栈 FIB 和 VLAN 表。合同验证临时 upper 的 parent/VID/UP、192.0.2.32/28 connected route 的真实出现与消失，同时要求原 bridge 的 self PVID、地址和双栈路由一直保留。四次 ping 各收到十个回包、stderr 为空且有真实 native realtime 读取；IPv4/IPv6 forwarding MIB 各增加 40。原版 cleanup 后 bridge、临时和主机 VLAN、VRF 消失，forwarding sysctl 恢复，live socket/outstanding packet 为零且 worker 正常关闭。缺失 backend、未知 VRF 与 loopback 对照分别验证拒绝和实际成功。

沿用 native fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`，使用 hosted Ubuntu iputils 20240117 本地完整通过。CI 强制六个完整原版 bridge 入口与时钟 ABI 控制共 7 项及其 JSON/JUnit，不允许 skip；hosted CI/review 另行核对。本批仅新增一个默认入口。

## VLAN upper 与 self PVID 设置、取消和迁移

完整原版 `forwarding/router_bridge_vlan_upper_pvid.sh` 使用现有 native bridge 配置运行八个默认阶段，产生六行原版双栈 ping 成功结果。持久 `br1.10` 承接原版路由地址，base bridge 的 `vlan_default_pvid=0`。原版先在 self VID 10 设置并取消 PVID，随后再次设置 VID 10 的 PVID 并将其移至 VID 20；两次原版一秒等待、全部流量、命令和断言保持不变。

每次 ping 前及每次 bridge VLAN 命令后读取实际 native link/address、双栈 FIB 和完整 VLAN 表。合同按命令位置核对两次相同的 `vid 10 pvid self`，并要求 self VLAN 状态依次为 VID 10 无 PVID、VID 10 PVID、取消 PVID、再次设置、VID 20 PVID 且 VID 10 保留。端口 VID 10 始终 tagged，`br1.10` 的 parent/VID/UP、双栈地址和 connected routes 在四次 PVID 变更后均保持有效；原版地址不能移到 base bridge。

本地使用 hosted Ubuntu iputils 20240117 完整通过，六次原版 ping 各收到十个回包、stderr 为空并有真实 native realtime 读取，IPv4/IPv6 forwarding MIB 各增加 60。原版 cleanup 后 bridge、VLAN upper、主机 VLAN、VRF 消失，forwarding sysctl 恢复，socket/outstanding packet 为零，worker 正常退出。VID 20 随原版 bridge 删除回收，不额外改写 cleanup。缺失 backend 必须失败，未知 VRF 必须拒绝，同后端 loopback 对照成功。

沿用实际 native fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`，不修改 Linux、iproute2、原版脚本或公共库。CI 强制六个完整 bridge 入口与时钟 ABI 控制共 7 项及完整 JSON/JUnit，无 skip；hosted CI/review 另行核对。本批仅新增一个默认入口。

## Conntrack zone dump/flush

`netfilter/conntrack_dump_flush.c` 在独立 `config/native-linux-conntrack.config` 中完整执行三个原版 TAP case：按 zone dump、清空指定 zone、清空默认 zone，并验证其他 zone 的 IPv4/IPv6 tuple 保留。每项原版 fixture 在四个 zone 中插入八条 tuple；总计 24 次 CT_NEW、15 次 CT_GET、2 次 CT_DELETE，来自三个真实 NETLINK_NETFILTER socket 的 41 次请求、5180 字节。所有 conntrack table、zone filtering、错误及 dump 数据均来自导入 Linux。

原版程序通过原版 libmnl 的真实 socket/Netlink 调用进入已有私有 preload；不修改 C 测试、libmnl 或 Linux 源码。编译保留全部断言和原版 harness fork；执行前后核对 C 源码、Makefile、kselftest 两个头文件与 pinned Git blob。原版缺失 backend 时会全部 SKIP 并退出 0，runner 必须拒绝此路径，要求三个精确 TAP 名称全部通过、无 skip/fail/XFAIL，并要求 socket/packet 归零和 worker 正常退出。这里验证 conntrack 表管理，不将 tuple 插入计成 TCP 连接流量测试。hosted CI/review 单独核对。

## ICMP RELATED 与 NAT

`netfilter/conntrack_icmp_related.sh` 在独立 `config/native-linux-nat-selftests.config` 中完整运行，保留四个真实 native namespace、双栈路由、1280 字节瓶颈、nftables/conntrack/masquerade 规则，以及原版全部包长和 timeout。原版 iproute2 配置普通拓扑，只有跨 namespace 的 veth fd 与 native proc/sysctl 需要既有适配器转换；原版 nft、ping、ping6 的 socket 调用进入同一常驻 Linux，不修改上游脚本、断言或协议实现。

完整脚本两行 PASS，六次原版 ping 覆盖 IPv4/IPv6 连通性、1300 字节 PMTU 失败和 ICMP redirect。15 次真实 nft counter 读取逐项核对，包括 RELATED 的 1 packet/576 bytes、2 packets/1856 bytes，两个 redirect 的 1 packet/112 bytes 与 1 packet/192 bytes。删除 router namespace 前额外读取实际 NAT JSON，IPv4/IPv6 masquerade 各记录两次探测，分别为 2356/2396 bytes；不以仅加载规则或退出 0 作为 NAT 生效证据。

专用 preload/server 复用已有 classic BPF 程序指针序列化，原样传递 ping 的 filter 指令到 native SO_ATTACH_FILTER，要求原版 stderr 无过滤器安装警告。新开关只作用于该私有测试 fixture；生产 API 和协议不变。缺失 backend 的整个原版脚本必须失败。四个 native namespace 均创建/删除，live socket、packet outstanding 为零，worker 正常退出；hosted CI/review 单独核对。


## IPIP PMTU 与 conntrack

完整原版 `netfilter/conntrack_ipip_mtu.sh` 在独立 `config/native-linux-ipip-selftests.config` 中运行：五个 native namespace、四对 veth、两个 IPIP tunnel、1400 字节 WAN MTU，分别在无 conntrack 与加载 conntrack FORWARD match 时发送三次 1400 字节 UDP 数据。两组必须收到原版断言要求的恰好 1400 字节并输出完整两行 OK；脚本、lib.sh、Makefile、包长和原版超时逐字节保持不变。

原版 iproute2、ss、socat 和 iptables-legacy 的网络调用进入同一个 imported Linux。libc AI_ADDRCONFIG 只为解析查询宿主 namespace，因此隔离的宿主传输接口配置真实 IPv4 地址；IP 数据 socket 仍强制进入 native backend。跨 namespace veth fd、proc/sysctl 和工具执行采用既有适配器；混合宿主 pipe/native socket 的 poll/select 分别读取真实宿主和 Linux readiness，不将 RPC 通道当成网络就绪事件。

独立控制程序验证真实 UDP 与宿主 pipe 的超时、单方/双方就绪、select 写就绪、HUP、POLLNVAL/EBADF，以及缺失 backend 时拒绝。原版 shell 有意忽略 PMTU 探测期间 socat 的退出状态；保留其 stderr，只接受有实际 native syscall 计数佐证的 EMSGSIZE/ECONNREFUSED，并继续要求两组完整数据断言。没有修改 Linux 分片、PMTU 或 conntrack 行为。

本地完整入口和控制通过，native fingerprint `43382ec08169bba6733c7d50bf548985c20ed5df2b81b1bc4c004d305a6f7906`。五个 namespace 均删除，live socket/outstanding packet 归零，worker 正常退出。CI 的 `ipip-profile` gate 检查实际内核配置、唯一注册、无 skip 的 JUnit、匹配 fingerprint 的 JSON 与同一完整证据合同；hosted CI/review 资格另行确认。


## 反向路径过滤与 VRF

完整原版 `netfilter/rpath.sh` 在独立 `config/native-linux-rpath-selftests.config` 中运行，强制原版 iptables-legacy、ip6tables-legacy 和 nft 三套工具全部参与。保留普通接口与 VRF 两轮、IPv4/IPv6 的正常/反向路径异常流量、原版 ping 超时、全部正向/反向匹配和 FIB 计数断言，不修改上游脚本或 Linux 实现。

该配置启用 dummy、双栈 legacy raw/rpfilter、nft inet/FIB 和 `CONFIG_IP_ROUTE_MULTIPATH`。固定 Linux 的 `fib_info_nh_uses_dev()` 只有在 MULTIPATH 分支使用 `nhc_l3mdev_matches_dev()`，因此这是完整 IPv4 VRF 验证需要的实际内核配置。配置缺失时，CI 的 CMake/manifest gate 必须拒绝；不修改原版 rpfilter 判断或跳过 VRF。

普通拓扑、地址、邻居、VRF 与规则均由原版工具经 native socket 执行；仅跨 namespace 的 veth fd 和 proc/sysctl 使用既有 runtime 适配器。原版 iputils 产生的特定 source-device warning 由 runner 原样记录，并检查实际 native 源地址、全部原版结果及真实规则计数；其他错误仍拒绝。

本地完整入口通过，native fingerprint `367d168f2003a7a7194c5251918d3653d4f856dcf0b498e4b7c26214856ecca6`。额外证据合同核对 8 次探测、16 次 legacy raw 规则计数读取、8 次 nft 双栈 FIB 计数读取，以及四次清零、原版 VRF 转换顺序。两个 namespace 均删除，native live socket/outstanding packet 为零，worker 正常退出。缺失 backend 的原版脚本必须失败或跳过，不能计为成功。CI 的 `rpath-profile` gate 要求完整唯一入口、无 skip 的 JUnit、实际配置和相同 fingerprint 的 JSON；最终 hosted CI/review 资格单独确认。


## 字符串偏移与 skb 边界

完整原版 `netfilter/xt_string.sh` 和两个原版 lib.sh 在独立 `config/native-linux-xt-string-selftests.config` 中运行。实际启用 Linux 的 xt_string、TEXTSEARCH、BM、KMP、dummy 与 legacy IPv4 filter；不修改上游脚本、算法或协议实现。

原版 socat 通过 native UDP 向 dummy 接口发送十份字节不变的 payload，保留 `-t 1`、全部偏移、`foo bar baz` 字符串，以及四条 BM/KMP × 两组 from/to 规则。八轮真实 OUTPUT 规则快照分别验证范围前、低位、包尾、跨 skb 数据块边界、第二块起点、最大 to 边界和范围外。1495 偏移时只有范围正确的 KMP 规则计数一次、1506 bytes；不将这个测试描述成 Ker 自编内容检测或 WAF 业务逻辑。

普通 iproute2、iptables-legacy、socat 原版工具经现有 namespace/socket 适配进入同一常驻 Linux；stdin 传输保留原版文件字节，混合宿主 pipe/native UDP readiness 复用已有适配。宿主传输 namespace 的实际 IPv4 地址只满足 libc AI_ADDRCONFIG 查询，数据 socket 必须进入 native backend。

本地完整入口及 CI gate 通过，fingerprint `81cee4f404d84696958a4698995d247b828417cd423294c1fb15eacdd05b1758`。要求十次真实 native UDP 创建、八次 reset/计数读取顺序、四条规则的精确参数及 packet/byte 计数。一个 native namespace 创建/删除，live socket/outstanding packet 为零，worker 正常退出；缺失 backend 的完整原版脚本必须失败。`xt-string-profile` gate 验证实际配置、唯一完整入口、无 skip 的 JUnit 和匹配 fingerprint 的 JSON；hosted CI/review 资格另行核对。

## FDB 学习计数与上限

完整原版 `forwarding/bridge_fdb_learning_limit.sh` 在现有 bridge profile 中运行两个默认测试函数，保留 12 行原版成功结果。第一组验证 16 个动态学习地址的计数，以及 learned、static、user、extern_learn、local 五类条目的插入、删除和替换计数；第二组将实际 bridge 的 `fdb_max_learned` 设置为 8，验证七轮原版填充中的六轮受限学习，以及达到上限后的五类条目准入。上游内部 `PING_COUNT=1`、118 次 ping、间隔、deadline、sleep 和全部 jq/算术断言均保持不变。

每次原版 ping 前后读取实际 native link/FDB，核对源 MAC、两个独立 VRF、桥接端口及回包端口的 `learning off`。允许原版 MAC 变更引起的真实内核控制报文在 ping 前已经学习该地址；ping 后的计数和 VID 0 条目仍必须精确匹配。达到上限后，第 9–16 个源地址不再加入 FDB，原版 ping 仍全部成功；不把发送尝试计成成功学习。逐项保留 18 次原版 `fdb_n_learned` 查询和五次无 VLAN 字段的目标 MAC 查询，并记录全部 FDB 增删、替换以及 local 端口 MAC/挂接/解除前后的真实状态。

原版工具能力探测必须实际支持 `fdb_max_learned`，内核计数不能为 null；零退出的 SKIP 也不能计为通过。结束时 br0、两个 VRF 消失，六个 veth 按原版 cleanup 关闭并解除 master，目标 FDB、全局地址和路由清空，native socket/outstanding packet 为零且 worker 正常退出。Linux、iproute2、原版脚本、内核配置和生产 API 均无修改。沿用 native fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`；CI 强制九个完整 bridge 入口加时钟 ABI 控制共 10 项及其独立 JSON/JUnit，无 skip。此项新增一个完整入口，本地结果与最终 hosted CI/review 资格单独记录。

## 关闭端口上的永久 MDB 条目

完整未修改的 `forwarding/bridge_mdb_port_down.sh` 执行唯一默认测试 `add_del_to_port_down`，保留原版 10 秒 bridge grace period、两次端口等待、两次发送后的 1 秒等待、全部 TC/jq/grep 断言。先在关闭的 veth2 端口上添加 br0 的永久组播条目 239.10.10.10，再开启端口并发送原版组播 UDP；随后再次关闭端口，验证条目仍然存在并删除它，重新开启后重复同一发送。两次原版 `mcast_packet_test` 分别返回 1、0，由原版 `check_fail`、`check_err` 判断通过。

原版 iproute2 `tc` 经该入口专用进程传输进入同一 imported Linux，实际 ingress flower 匹配 IPv4/UDP 与目标组播 MAC，gact drop 动作统计依次为 1 packet/92 bytes/1 drop、0/0/0。独立的内核 AF_PACKET 记录确认原版 Mausezahn 发送两个具有相同原版参数和长度的 106 字节 Ethernet/IPv4/UDP 报文，UDP 源/目的端口 2048/4096，64 字节原版负载（不限制工具的填充字节或跨调用的校验和/ID）；首包真实经过 veth0→veth1→veth2→veth3。删除条目后仍要求真实发送、目标端口处于 UP/forwarding 且 mcast_flood off，最后的原版 TC counter 必须为零。允许原版等待前的即时观察尚未收到首包，不额外缩短原版投递期限。

每次 MDB 增删与持久性查询均观察真实端口 DOWN、桥接配置及目标条目的出现/消失，绑定实际 br0 ifindex 与 veth2；运行期间不排斥无关的动态 IPv6 MDB。完整 TC qdisc/filter 增删、查询必须全部成功，原版 tc 二进制 hash 与 pinned 工具来源匹配。清理后 br0、两个 VRF 消失，四个 veth DOWN/解除 master、MDB/地址/路由清空，native socket/outstanding packet 为零且 worker 正常关闭。

Ker 的桥接测试配置启用真实 `CONFIG_NET_CLS_ACT`、`CONFIG_NET_SCH_INGRESS`、`CONFIG_NET_CLS_FLOWER` 和 `CONFIG_NET_ACT_GACT`，实际 fingerprint 更新为 `6bfdfffd796cdfb3d21525ca18c2cd5c86d79ccdfce80dbaf54f0238e903329e`。Linux 源码、协议、原版 selftest 和 iproute2 均未修改。CI 强制检查实际内核四个选项，运行十个完整 bridge 原版入口加时钟控制共 11 项，并上传本入口的独立 JSON/JUnit。旧的 6ee bridge profile 缺少 TC 支持，不能用于本入口资格。此项新增一个完整入口；最终 hosted CI/review 仍独立核对。

## 桥接端口隔离与未知单播

完整原版 `forwarding/bridge_port_isolation.sh` 保留三个默认函数和三行原版 TEST 结果。三个主机分别位于独立 VRF，原生 bridge 的 veth1/veth2 开启 isolated，veth4 关闭 isolated。IPv4/IPv6 各自验证 h1→h2 失败、h3→h2 成功，全部原版 `-c 10 -i 0.1 -w 5`、断言和等待保持不变；不固定邻居解析失败路径的发送计数，也不让脚本内部 RET 重置掩盖负向结果。

两次原版未知单播探测分别从 h1、h3 向 `de:ad:be:ef:13:37` / `192.0.2.100` 发送一个 98 字节 Ethernet/IPv4 报文、64 字节负载。TC flower 的目标端口 veth3 ingress counter 必须依次为 0、1，后一窗口为 84 IP bytes/1 drop。每次发送前读取真实 FDB，要求目标 MAC 未知；读取真实 isolated 标志、三个 VRF/地址、promisc 增删和实际 AF_PACKET frame/ifindex。投递与桥接计数使用原版 sleep1 后已有的 TC 查询状态，不要求即时观察提前收到报文，亦不限制工具的负载填充字节。

普通与报文专用私有 preload 都复用已有的 native gettimeofday 适配，给 iputils 的原版 SO_TIMESTAMP 使用同一 Linux 时钟；新增独立报文 preload ABI 控制，覆盖宿主透传、NULL timeval/旧 timezone ABI 及缺少 native descriptor 时的 ENOTCONN。四次原版 ping 必须记录真实 native realtime 读取。生产 API、Linux 协议、原版脚本、工具和内核配置均无改动，沿用 TC profile fingerprint `6bfdfffd796cdfb3d21525ca18c2cd5c86d79ccdfce80dbaf54f0238e903329e`。

清理后 bridge、三个 VRF 消失，六个 veth 关闭并解除 master，promisc/全局地址/路由及 bridge FDB 回收，native socket/outstanding packet 为零且 worker 正常关闭。原版 tc JSON 能力探测、两个完整 qdisc/filter 增删窗口和缺失 backend/未知 VRF 对照均强制核验。CI 要求 11 个完整原版入口及两种时钟 ABI 控制共 13 项，独立 JSON/JUnit 无 skip；最终 hosted CI/review 单独确认。本项新增一个完整默认入口。

## VLAN-unaware 桥的学习、老化与泛洪

完整未修改的 `forwarding/bridge_vlan_unaware.sh` 执行四个默认函数，保留 ping、ping6、FDB learning、Unknown unicast flood 和 Unregistered multicast flood 五行原版结果。实际 br0 的 vlan_filtering=0、mcast_snooping=0、ageing_time=1000 centiseconds，两个主机位于独立 VRF。两个原版 ping 均发送并接收十包，使用真实 native realtime 适配。

学习测试先关闭源端口未知单播泛洪，确认目标 MAC 尚未学习且目的 ingress TC counter 为零；原版 Mausezahn 以目标源 MAC 发送后，实际动态 VID 0 FDB 条目出现在 veth1/br0，后续已知单播到达目标。原版 ageing_time 加十秒的等待保持完整，20 秒后条目消失；关闭 learning 后再次发送仍不能学习。随后分别关闭、开启未知单播 flood 和 mcast_flood，四次原版探测对应实际 flower counter 0、1、0、1。全部八次 AF_PACKET 发送均为 98 字节，六次原版 TC 查询核对 0/1 packet、0/84 IP bytes 和相同 drop 数；源端口与桥接计数以原版 sleep 后的查询为准，不增加更早投递期限。

合同核对完整 qdisc/filter 与 promisc 生命周期、原版参数、FDB 查询顺序和真实单调时间跨度。保留 Mausezahn 未指定的负载填充与报文字段自由度。结束时 br0、两个 VRF、目标 FDB、promisc、全局地址和路由清空，veth 关闭解除 master，native socket/outstanding packet 为零且 worker 正常关闭。缺失 backend 与未知 VRF 对照必须失败。沿用原生 TC profile `6bfdfffd796cdfb3d21525ca18c2cd5c86d79ccdfce80dbaf54f0238e903329e`；上游源码、脚本、工具、生产 API 和内核配置均未修改。CI 强制十二个完整入口和两个时钟 ABI 控制共十四项，独立 JSON/JUnit 无 skip。本项新增一个完整默认入口；hosted CI/review 资格仍单独确认。

## VLAN-aware 桥的 VLAN 删除、外部学习与其他 TPID

完整未修改的 `forwarding/bridge_vlan_aware.sh` 执行七个默认函数、十一行原版结果，包含双栈 ping、学习/老化、两类泛洪、VLAN10 添加删除后双栈连通性、extern_learn 老化与漫游，以及其他 TPID 的三项判断。br0 实际启用 802.1Q VLAN filtering、PVID1、ageing_time=1000 centiseconds 和 mcast_snooping=0。保留学习阶段及外部学习阶段各自完整的 ageing_time 加十秒等待，保留所有原版参数、断言和投递等待。

证据覆盖实际动态 VLAN1 FDB 学习/老化/learning off，VLAN10 出现后删除且 PVID1 不变，以及 VLAN1 extern_learn 条目在 veth1 上不老化、发送后漫游到 veth2 并删除。原版漫游发送后没有 sleep，合同只使用它已有的 FDB 查询，不增加等待或要求更早的即时状态。原版 ethtool `-K` 经现有真实 native Netlink 运行，记录工具 hash/version 和实际 feature readback；两个 veth VLAN receive filter 均为 fixed off，不宣称支持或启用了硬件 offload。

最后两个真实 31 字节 AF_PACKET 报文完整保留原版指定的 802.1ad TPID/VID3、802.1Q TPID/VID5 和九字节负载。原生桥将其按 PVID1 处理，来源 MAC 的真实 FDB VLAN 必须为 1；第一次 TC ingress 累计为 1 packet/13 bytes/1 drop，删除源端口 PVID1 后第二次发送仍保持该计数。恢复 PVID1 和完整 clsact/promisc 清理均强制检查。全入口共十一帧、944 字节，IPv4 的八个学习/泛洪探测和一次漫游帧均保留原版格式。

所有源/桥接端口遍历证据都在原版已有的后续 FDB/TC 查询时判断，允许提前观察尚未投递。清理要求 bridge/VRF/FDB、promisc、全局地址和路由消失，四个 veth 关闭解除 master，native socket/outstanding packet 为零、worker 正常退出。CI 强制十三个完整入口与两个时钟 ABI 控制共十五项、独立 JSON/JUnit 无 skip。沿用 native TC fingerprint `6bfdfffd796cdfb3d21525ca18c2cd5c86d79ccdfce80dbaf54f0238e903329e`；无需 C、Linux/iproute2、原版脚本、生产 API 或内核配置修改。本项新增一个完整默认入口，本地与最终 hosted CI/review 资格分别核对。

## 锁定端口、MAC 认证与真实 MIRRED 重定向

完整未修改的 `forwarding/bridge_locked_port.sh` 执行八个默认函数和八行原版结果，保留十八次双栈/VLAN100 ping 的全部参数与成功/失败判断。前十二次分别在 IPv4、IPv6、VLAN100 中检查未锁定、锁定未认证、静态 FDB 认证、解锁删除认证四阶段；之后验证 MAB 自动建立 locked FDB、静态替换解除认证限制、以及重定向移除前后的连通性。所有 ping 均读取真实 native realtime，完整 native bridge/VRF/VLAN 路径、实际锁定/learning/MAB 标志和 FDB VID/端口/状态必须对应各阶段。

五次原版 Mausezahn 调用均保留 `-c 5 -d 100msec -t udp -a ... -b rand`，独立内核 AF_PACKET 记录全部二十五帧。本地实际为 25×42 字节、1050 字节；合同按实际 frame/result 求和核验总字节，允许原版工具未指定的默认负载和随机目的 MAC 变化，同时校验真实源 MAC、接口及一致的 IPv4/UDP 长度。原版后续 FDB 查询确认 locked 条目创建、漫游到未锁定端口并清除 locked 标志、禁止漫游回锁定端口。关闭第一端口 MAB 只清除该端口 locked 条目，保留两项静态认证及第二端口 locked 条目。两种非法 MAB 配置必须由真实内核拒绝，原有标志不变。

最后一次成功 ping 的 ingress flower 必须包含真实 Linux MIRRED egress redirect 到 veth2，内核动作计数在该次原版 ping 期间至少增加十个包和 840 字节；允许此前已有无关控制报文。此阶段不学习源 MAC 的 locked FDB。删除 filter 后原版 ping 必须失败，真实 locked 条目随后出现。没有新增投递 sleep，也不把 Mausezahn 返回时的即时状态当作原版 FDB 查询期限。原版 feature probe 返回 SKIP 或漏掉任一结果均不得计为通过。

Ker 的隔离桥接测试配置启用真实 `CONFIG_NET_ACT_MIRRED=y`，native fingerprint 更新为 `89ba0eab4a997830cfa3d8c0520a33696d0ab3868a53ec24a6fbc0d5c49e15fe`；源码与配置来源均绑定，Linux、原版脚本、iproute2、C 代码和生产 API 未修改。清理要求 bridge、两个 VRF、两个 VLAN100 设备、目标 FDB/MDB、全局地址和路由回收，veth 关闭解除 master，socket/outstanding packet 为零且 worker 正常退出。CI 强制十四个完整原版入口与两个时钟 ABI 控制共十六项，核对 MIRRED 实际配置、唯一完整 inventory、独立 JSON/JUnit 无 skip。本项新增一个完整默认入口，hosted CI/review 资格仍单独确认。


## 完整 bridge VLAN multicast 入口

完整未修改的 `forwarding/bridge_vlan_mcast.sh` 执行全部 11 个默认函数、36 行原版结果与 216 个实际工具命令。Ker 不改 Linux、iproute2 或原版 shell；通过已有原生 NETLINK_ROUTE、AF_PACKET 与时间适配运行。逐项核对 VLAN10 的默认值、snooping/querier 开关、IGMPv2/v3、MLDv1/v2、last-member/startup/membership/querier/query/response 参数和恢复值。八个原版查询时间窗同时要求实际 TC flower/GACT 包字节计数和 Linux bridge-slave multicast xstats 差分符合原版值，保留全部等待时间。

固定上游 `vlmc_v2join_test` 的 join 判断误读了 `if [ $expect -eq 0 ]` 的退出状态，单独的原版 OK 行不能证明目标 MDB 行为。因此额外使用只读原生 MDB 通知和入口包观察器，绑定实际 bridge/端口 ifindex、VID10、组地址 `239.10.10.10`、主机 MAC 与真实时间戳，要求目标成员在原版五秒窗口内按两秒 membership timer 实际过期。若 Linux 随后的有效 unsolicited IGMPv2 report 重新建立条目，则必须同时观察真实过期、后续报告、MDB NEW 和一致的剩余 timer；若原版查询时条目已消失，则必须证明最后事件为删除。不会把仍存在但没有真实过期证据的条目算作通过。原版 snooping 开/关、三个 join/leave 周期、无条目状态和最终 leave 都另行验证。

外部 querier 的 br1 拓扑和原版两秒等待保持不变；不要求原版未执行的 VRF 重新绑定。router-port 阶段发送实际十个 VID10 IPv4/UDP 原版帧（每个174字节，包含128字节负载），在原版后续 TC 查询处要求路由端口计数10、另一个端口计数0，并验证实际路径计数。关闭 VLAN filtering 必须同时关闭 native multicast VLAN snooping；原版清理后 bridge、VRF、VLAN child、地址、路由、MDB/FDB、packet sockets 与 fixture 资源均不能残留。只读观察器不发包、不设置网络状态，不增加或缩短原版等待。

该批次的完整 bridge profile 包含15个原版完整入口和两个真实 realtime ABI 控制。实际原生报告投影保留全部216条命令及所消费的原始通知、报文和快照，以原报告 SHA-256 绑定；单元测试另行拒绝通知丢失/截断/overrun、伪过期、缺失刷新、错误 timer、TC/xstats 不一致、缩短等待、错误 VLAN/端口和资源泄漏。迁移计数仍与发布后 hosted CI 和 review 资格分开核对。


## 完整 IPv6 VRF 入站统计入口

完整未修改的 `forwarding/ip6_forward_instats_vrf.sh` 执行全部五个默认函数与102个原版命令。两端主机和路由器使用三个真实 native VRF、四个 veth 和原版 IPv6 地址/路由，出站设备及接收端 MTU 为1280。保留原版 `router` VRF master 未置 UP 的状态，通过其真实 slave 设备完成转发；不为消除 traceroute 的缺失跳回复修改上游拓扑。

保留十次 ping6、1300字节超大 ping、默认 traceroute6、临时关闭 forwarding 和真实 forward XFRM block policy 五种流量。要求原版 traceroute6 正常退出并到达第二跳目标，不能只因发出部分报文后错误退出、原版仍输出 OK 就计为完成。直接读取原生调用任务命名空间的 `/proc/net/dev_snmp6/veth1`，把原版前后计数与实际流量前后快照、native ifindex 逐项绑定：`Ip6InTooBigErrors`、`Ip6InHdrErrors`、`Ip6InAddrErrors`、`Ip6InDiscards` 必须分别增长，不能由其他错误类别替代。错误阶段 ping 的实际发送次数与 native 计数对应，不改变原版 `-c 1 -w 5` 参数或假设工具只会尝试发送一次。

Ker 测试适配层为原版 iproute2 接通现有原生 NETLINK_XFRM 通路，并让显式 UDP protocol17 使用已有 native UDP socket 路径；协议、路由、ICMPv6、MTU 和 XFRM 行为均来自未修改的 Linux。每接口 proc 读取仅接受一个 IFNAMSIZ 范围内的接口名，原生缺失接口和路径越界分别返回真实 ENOENT 与显式 EOPNOTSUPP。新增实际 `CONFIG_XFRM_USER`，不伪造策略或计数。固定 iproute2 的 XFRM dump 为文本，观察器保留其真实原始输出，验证策略从无到 block 再删除。

plain bridge preload 复用已有的 host/native mixed poll/select 实现，支持原版 traceroute6 的多个 UDP socket；同一 native fixture 中的 IPv6 UDP17 控制实测超时、独立/同时就绪、EBADF 与 EINTR，并在缺失后端时拒绝 host socket 回退。原版结束后必须恢复 MTU、双栈 forwarding，清理 VRF、地址、路由和 XFRM policy，所有 native socket/缓冲及 worker 正常退出。完整 profile 包含16个 bridge/VRF 原版入口与两个 realtime ABI 控制，迁移计数继续与发布后 CI/review 资格分开核对。


## 完整 IGMP 源过滤入口

完整未修改的 `forwarding/bridge_igmp.sh` 执行全部14个默认函数，保留15行原版结果、775条原版命令、322次 JSON MDB 查询、3次文本 MDB 查询和14次显式组删除。IGMPv2 的实际 autojoin/leave 由 Linux 产生；IGMPv3 的32个原版 Mausezahn 控制报文及51个 UDP 数据探测逐帧绑定真实 native AF_PACKET 发送记录。报文源接口/MAC、IPv4/IGMP checksum、原版报告字节、组地址和 UDP 端口/64字节负载必须符合原版命令，不用原版 OK 标签替代流量证据。

独立合同逐个验证每次报告后原版实际查询处的 wildcard INCLUDE/EXCLUDE 模式、完整 source list、正值/零 timer、每个 S,G 的 blocked 标志，以及最终自动添加条目的 `added_by_star_ex`。中间准备状态同样必须成立，不能仅验证最终状态。保留原版一秒交付等待、三秒 BLOCK 到期、五秒 EXCLUDE 转换与 IGMPv2 加入/离开等待；不对正值剩余 timer 规定固定数值。最后一个场景要求两个真实 native bridge 端口具有各自的组/源状态，按原版顺序分别清理。

原版 `v3inc_is_exclude_test` 的调用者没有局部 X/Y 数组，准备函数中的局部数组不会传出，因此该场景实际只发送 source100 的 UDP 转发探测。保留原版代码，明确不声称其执行了 X/Y 源流量；独立原生 MDB 合同仍检查其 active{1,2}/blocked{20,21} 状态。其余全部实际 UDP 探测要求原版接收端 flower/gact 计数精确为1或0，正向计数的字节数为92，且实际源端、桥端口和接收端路径计数相符。异步交付在原版后续 TC 查询处判断，不要求发送调用刚返回时已交付。

Ker 仅增加私有只读 SG 状态观察与完整入口接线，协议行为来自未修改的 pinned Linux；不增加协议替代实现或伪造状态。完整19项 bridge profile 包含17个原版入口与两个 realtime ABI 控制。实际原生报告投影以原报告 SHA-256 绑定，保留全部775条原版命令及合同消费的真实状态；单元测试拒绝任意一次 MDB 查询缺失 wildcard、错误源集合/标志/timer、假转发、缩短等待、缺失报文与清理/资源泄漏。发布后 hosted CI/review 资格仍须单独核对。


## 完整 MLDv2 源过滤入口

完整未修改的 `forwarding/bridge_mld.sh` 执行全部13个默认函数，保留13行原版结果、754条原版命令、322次 JSON MDB 查询和14次组删除。32个控制探测使用原版完整 Ethernet/IPv6/MLDv2 字面报文，保留其固定的源 MAC/link-local 地址、Hop-by-Hop Router Alert、hop limit1和有效 ICMPv6 checksum；不替换成 Ker 生成的报告或当前主机 MAC。49个实际 IPv6 UDP 数据帧逐一绑定原版 Mausezahn `-6 -p 64` 参数和实际 native AF_PACKET 注入记录。

独立合同逐个要求每个原版查询时的 wildcard INCLUDE/EXCLUDE、完整 IPv6 source list、正值/零 timer、S,G blocked 标志和最终 `added_by_star_ex` 双端口状态；所有准备阶段与一秒、三秒、五秒原版等待均保持。完整 IPv6 主机/VRF/veth/bridge 路径、单项及多项 querier/成员间隔设置和实际清理状态分别检查。每个原版接收端 flower/gact 分类器必须从零开始，在原版交付等待后的查询处产生精确的1或0包计数、112字节网络层长度和对应的 native 路径计数。

原版 `mldv2inc_is_exclude_test` 同样没有调用者局部 X/Y 数组，因此只实际探测 source100 转发；不声称补齐了原版未执行的源流量。捕获的原版 Mausezahn IPv6 UDP 帧另有零 UDP checksum：原版入口的判断点是 UDP 校验前的 ingress flower，所证明的是 Linux bridge 的二层源过滤/转发，不是 UDP socket 成功收包。保留实际原版字节与该范围边界，控制报文的有效 ICMPv6 checksum 则另行验证；合同允许工具生成有效 UDP checksum 的等价二层流量。

该批次只增加私有原生观察及完整入口接线，没有修改 pinned Linux、DPDK、iproute2 或协议实现。完整20项 bridge profile 包含18个原版入口与两个 realtime ABI 控制。实际原生报告投影保留全部754条命令、原始查询输出与所有消费的快照，以合格原报告 SHA-256 绑定；单元验证覆盖全部322个查询与状态、报文、计数、等待、标量和资源清理的反例。迁移计数继续与发布后的 hosted CI 和 review 资格分开核对。


## 完整 MDB API、大规模表项与转发入口

完整未修改的 `forwarding/bridge_mdb.sh` 执行全部27项原版结果，保留1171个原版命令阶段以及 `tc_common.sh` 的默认1000ms busywait。三轮原版批处理分别创建 IPv4、IPv6 和二层组：每轮为两个桥、每桥32个真实 dummy 端口、每端口256个组，共16,384条记录。独立合同核对实际执行前的完整 batch 文本及 SHA，并分别读取两个桥的原版 dump，要求每桥8192条永久记录的端口、组、VID、唯一性和完整笛卡尔积一致。启用原版 `CONFIG_DUMMY=y` 驱动；不把不支持的设备创建或部分 batch 成功计入覆盖。

321次实际 native MDB add/replace/del/flush 均有操作前后状态。逐项核对主机/端口组、VID10/20、INCLUDE/EXCLUDE、源集合、S,G 子项、blocked 与自动派生标志、协议归属和永久/临时 timer；失败操作不得修改状态，成功操作不得破坏其他受检组。选择性 flush 必须只移除匹配端口、VID、协议与永久状态的记录。保留原版所有预期拒绝与清理命令，不以统一成功返回绕过不支持的边界。

51个原版 native AF_PACKET 帧包含47个数据探测与4个 IGMPv3/MLDv2 控制报告。数据探测覆盖主机 MDB、端口 EXCLUDE/INCLUDE 和二层组；实际 VLAN10/20、双 VRF、veth/bridge 路径、发送字节与接收端 flower/gact 的两个独立句柄计数逐项校验。原版读计数重试可以等待异步交付，最终查询必须精确符合每个原版累计计数。控制报告保持原版字面字节和校验和，并在后续原版查询点验证永久源列表不变、临时源列表接纳新源。

该入口的原版 IPv6 UDP 探测仍可包含零 UDP checksum，判断点是 UDP 校验前的二层 ingress flower，不声称 socket 收包。其 MLD 报告字面的 Hop-by-Hop 头也按实际原版保留，不改写为其他入口的 Router Alert 模板。原版 querier 十秒等待、负向后端/未知 VRF 对照、全部 bridge/dummy/VLAN/VRF 清理和零 live socket/outstanding、worker 正常退出均单独验证。完整21项 bridge profile 包含19个原版入口和两个 realtime ABI 控制；本地完成与后续 hosted CI/review 资格继续分别记录。

新增配置的回归验证还保留 FDB learning 入口的首次设置观察边界：flush 后只允许零 learned 项，或唯一的默认源 MAC 项；紧接着的原版 static/use 命令后 learned 计数必须归零，其余15次 flush 仍须为零。两个独立只读快照不能证明默认项是否曾被删除再学习，因此不把该瞬间当作原子清空证据，也不放宽受检 MAC、限额与后续清理约束。


## 完整 MDB 端口与 VLAN 组数上限入口

完整未修改的 `forwarding/bridge_mdb_max.sh` 覆盖 802.1D、802.1Q 和 VLAN snooping 三种配置，执行64行原版结果、718条工具命令与88个实际 IGMPv3/IGMPv2 leave、MLDv2/MLDv1 done 控制帧。组数、零表示无限额、100的显式读写、低于当前数量的限额、超限拒绝、端口及每 VLAN 的独立限额和 snooping 开关后的恢复均由原版 Linux 处理。84次配置 API 调用保留真实前后 MDB 状态；506次原版 bridge 调用保留实际组表和限额观察。

独立合同将原版 JSON 组数与完整 native MDB 表项逐个对照，并验证每个限额设置只改变指定端口或 VLAN。派生的 n+1、n+2、n2-1、n1+n2+2 参数由对应原版查询计算；跨 VLAN 场景根据实际基线选择较低/较高数量的一侧。自动加入的背景组可使两次运行选择不同 VLAN 和限额数值，合同保留原版分支及公式，不把一次运行的背景成员数固定为协议规则。

配置 API 的超限创建必须返回实际 `mcast_max_groups` extack 并完整回滚。控制报告则保留原版允许的部分接纳：wildcard、source list 与 S,G 转发表项分别检查，实际 S,G 数量受端口和 VLAN 剩余容量共同约束。Linux 在无法创建对应 S,G 条目时仍可能保留报告源列表；二者分开核对，不把逻辑源信息当作已创建的转发表项。其余端口、VID 和组的状态保持，原版 fastleave 必须删除目标组。

每个原版报告的接口、MAC、IPv4/IPv6、IGMP/MLD 字面内容、校验和、实际 native AF_PACKET 记录和真实源端/桥端口计数均绑定，保留全部一秒等待。关闭再启用 VLAN snooping 必须移除临时条目、保留永久条目，并恢复原版100的 per-VLAN 限额。缺失后端/未知 VRF 必须拒绝，全部拓扑和转发表清理后无 live socket 或 outstanding packet，worker 正常退出。完整22项 bridge profile 包含20个原版入口与两个 realtime ABI 控制，发布后的 hosted CI/review 资格继续单独核对。


## 完整 IPv4/IPv6 PEDIT 地址修改入口

完整未修改的 `forwarding/pedit_ip.sh` 执行两项基线 ping 和八项地址修改检查：IPv4/IPv6、源/目的地址、桥入口/出口三个维度的全部组合。Ker 配置启用原版 `CONFIG_NET_ACT_PEDIT`；规则安装、报头修改、软件 flower 匹配与真实计数均来自导入 Linux，未修改上游驱动或测试脚本。

每项保留原版10个报文、20ms间隔、100字节载荷与1000ms计数等待。80个实际 native AF_PACKET 注入帧绑定真实源接口、源/目的 MAC、原始 IPv4/IPv6 地址、头长度和载荷长度；原版 IPv4 输入校验和独立核对。Mausezahn 未由原版 argv 指定的载荷填充值、IPv4 ID/TTL 和 IPv6 flow label/hop limit 保留实际记录，不固定为某次运行的默认值。独立合同要求实际双 VRF、PVID1桥和完整 veth 路径，并核对原版 PEDIT 的 header type、offset、set值、mask、动作绑定与接收端 `skip_hw` flower 的修改后地址。各阶段规则只存在于指定位置，删除后不得遗留。安装前规则缺失、安装后规则存在证明新规则代际；IPv6源地址编辑可使背景控制帧提前匹配，因而不要求发送前计数为零，而要求正式探测后实际新增至少10个匹配包。

原版断言要求 PEDIT 和接收端计数至少10包；未收窄成固定计数，因为未限定协议的 PEDIT 还可能处理真实后台报文。输入 trace 是修改前的发送记录，接收证明来自 Linux ingress flower 对修改后地址的实际匹配，不声称拥有修改后的线缆抓包或应用 socket 收包证据。PEDIT 地址修改没有额外 checksum repair 动作，因此不把二层分类成功当作三层校验和或 socket 交付成功。

原版 IPv4/IPv6 基线 ping、未知 VRF/缺失后端拒绝、全部 bridge/VRF/规则/地址/路由清理以及零 live socket/outstanding 和正常 worker 退出分别验证。完整23项 bridge profile 包含21个原版入口与两个 realtime ABI 控制；本地完成与发布后的 hosted CI/review 继续分别核对。


## 完整 UDP/TCP PEDIT 端口修改入口

完整未修改的 `forwarding/pedit_l4port.sh` 执行一项基线 ping，以及 UDP/TCP、源/目的端口、桥入口/出口、1/11111/65535三种端口值的24种组合；25行原版结果均保留。每项发送10个实际报文，保留20ms间隔、100字节载荷和原版计数等待。240个 native AF_PACKET 输入帧共35520字节，发送接口、MAC、IPv4地址、UDP/TCP协议和原始54321/12345端口由实际字节独立验证。

原版 Linux PEDIT 以真实 UDP/TCP header type、offset0、16位掩码和值修改对应半字；接收端 `skip_hw` flower 必须匹配修改后的端口和协议。所有原版规则安装、计数查询及删除均保留实际前后状态，覆盖各个指定 ingress/egress位置；双 VRF、桥PVID和四个 veth跳点分别验证。原版 `act_pedit.c` 在无法解析背景报文时会递增 `overlimits` 后返回原动作；计数与原版测试分开核对，受检发送仍必须增加至少10次可编辑处理并在接收端匹配，不能用背景计数替代。

该测试的判断点为校验 UDP/TCP checksum 之前的二层分类，不宣称 socket 收包、TCP状态机或 checksum repair；输入报文记录也不当作修改后的线缆抓包。未由原版参数指定的载荷内容及 IP/TCP默认字段保留真实记录而不固定为单次工具默认值。未知 VRF/缺失后端必须拒绝，规则、桥、VRF、地址、路由和正常退出后的所有资源逐项清理。完整24项 bridge profile 包含22个原版入口与两个 realtime ABI控制；hosted CI/review资格另行核对。


## 完整 DS field、DSCP 与 ECN PEDIT 入口

完整未修改的 `forwarding/pedit_dsfield.sh` 执行两项基线 ping 与86个原版场景：IPv4/IPv6 DS field 全字节设置、保留 ECN 的 DSCP 设置、保留 DSCP 的 ECN 设置，以及两个原版组合场景；各自覆盖桥入口和出口。88行原版结果、675条实际命令、860个实际 native AF_PACKET 输入帧和140840发送字节保留完整合同。每项维持10包、20ms间隔、100字节载荷和原版计数等待。

独立合同按原版值集合计算每个目标 TOS/traffic class，核对 native PEDIT key 在 IPv4首字偏移16位、IPv6首字偏移20位的 retain mask/value；非目标位必须保留，接收端软件 flower 必须匹配实际保留/更新后的8位值。输入明确指定 TOS125、TCP54321/12345端口和原版地址，实际 MAC/接口、IP版本/头长度、IPv4 checksum、载荷长度与真实桥/VRF路径分别验证。未指定的填充内容、IP ID/TTL、IPv6 flow label/hop limit和TCP默认字段不固定为单次工具默认值。

两个原版“set DSCP + set ECN”场景有明确覆盖边界：两个 PEDIT 动作均配置 `pass`，因此第一个动作结束执行，第二个动作计数实际为零；原始 TOS已经是目标125。合同保留该配置和零执行证据，不改写上游动作链，也不声称接收匹配证明第二个动作执行或组合修改有效。其他场景的真实 PEDIT/接收计数必须从实际发送前基线新增至少10次，背景流量不得替代受检探测。

完整规则代际、每个 ingress/egress位置、规则删除、桥/VRF/地址/路由清理、负后端与未知 VRF对照及正常退出后的零资源均单独校验。原版判断点仍为二层 ingress flower；不宣称修改后的线缆抓包、IPv4 checksum repair或TCP/socket交付。完整25项 bridge profile包含23个原版入口与两个 realtime ABI控制，后续hosted CI/review资格另行审计。


## 完整 TC flower 端口范围入口

完整未修改的 `forwarding/tc_flower_port_range.sh` 覆盖 IPv4/IPv6 UDP/TCP四项原版场景。每项分别发送最小100/300、中间150/350、最大200/400三个范围内端口组合，再发送源端口99或201、目的端口299或401以及双端口越界的五种范围外组合。32个实际 native AF_PACKET 帧共5056字节，原版154条工具命令与所有真实观察保留。

原版 Linux flower 的源端口100—200、目的端口300—400及双地址/协议匹配在实际软件 ingress/egress位置验证。入口 `gact pass` 与出口 `gact drop` 的原版计数查询分别精确累计1、2、3，再在全部越界探测后保持3；入口/出口字节计数和出口 drop计数独立核对。原版未开启 VLAN filtering的桥、双VRF和真实veth路径保留，全部越界探测后的聚合窗口要求出口与对端二层接收计数至少增加5包；该证据不是逐帧接收抓包。

合同绑定每个源接口、源/目的MAC、IPv4/IPv6头、UDP/TCP协议和边界端口字节，保留100字节载荷长度。未指定的工具填充或默认字段不固定；原版IPv6 TCP输入仍可包含零TCP checksum，二层TC/bridge证据不当作TCP/socket交付。规则必须新建并逐位置删除，所有拓扑、地址、路由和资源正常清理。共享拓扑/清理校验仅增加保留既有默认值的显式参数；没有修改Linux分类器、bridge、TCP/UDP实现或内核配置。完整26项bridge profile包含24个原版入口及两个realtime ABI控制，发布后的hosted CI/review仍单独核对。


`tc_flower_l2_miss.sh` 的完整原版入口保留 unicast、IPv4/IPv6 multicast、IPv4/IPv6 link-local multicast 和 broadcast 六组结果、12 个原始发包及全部 FDB/MDB 设置、查询和清理。Ker bridge profile 新增上游 `CONFIG_NET_TC_SKB_EXT=y`（自动选择 `SKB_EXTENSIONS`），让 Linux 桥产生并传递实际 skb miss 元数据；不修改上游网络代码，不在 Ker 内生成分类结果。缺少该选项的首轮真实失败与随后六组原版成功但独立合同尚待接入的报告均单独保留，不计为合格证据。

独立合同将 unicast 的未知/静态 FDB/删除后未知，以及 IPv4/IPv6 multicast 的未注册/永久 MDB/删除后未注册分别绑定至真实 egress flower `l2_miss=1/0` 规则及累计 `(1,0) → (1,1) → (2,1)` 包和字节计数。Link-local multicast 命中原版 `l2_miss=1`，broadcast 命中 `l2_miss=0`；保留真实 querier、router-port、双 VRF、untagged bridge 与 veth 路径。每个原始输入帧的 native ifindex、MAC、IP 地址与长度均核验，并要求实际源 TX、桥入口 RX、桥出口 TX、peer RX 观测窗口前进。读数可异步完成，最终原版 counter query 窗口必须精确命中；不伪造同步成功。

原始 Mausezahn 未指定的填充、IP ID、TTL/TOS、IPv6 flow/hop/next-header 与 broadcast EtherType 不作为固定内容断言；IPv4 输入校验和仍独立验证。12 个输入帧共 1654 bytes，全部资源正常释放。AF_PACKET 是发出前的输入记录，egress 分类计数和 peer RX 是桥接路径证据；不声称逐帧出口抓包或 socket 接收。独立测试拒绝丢失发包、miss 分类、计数、FDB/MDB 状态、规则代次、路径、清理和 backend 对照，CI 必须上传该入口原始报告并与同一 native fingerprint 绑定。


`tc_flower_cfm.sh` 保留原版三个完整子测试：CFM opcode、maintenance domain level，以及二者联合匹配。11 个原始 Mausezahn 输入帧全部为 64 bytes，共 704 bytes；原版 EtherType、level、opcode、flags 和 TLV offset 六字节输入头与实际 native MAC/ifindex 绑定。Linux 原生 ingress flower 在真实 `veth0 ↔ veth1` 双 VRF 路径执行完整 drop 规则，独立核验每个原版查询窗口的精确 packet/drop 与 去除 14-byte Ethernet 头后的 50-byte 计数、零命中反例及逐代安装/删除；不把单独 level 或 opcode 命中当成联合匹配成功。

该原版入口先加载 `tc_common.sh` 再加载 `lib.sh`，因此保留真实 pinned `tc -j` 能力探测及它原本的 usage 输出/零退出码。Ker observer 对这次能力探测不查询尚未创建的网口；随后只观察实际两个 veth 端点，不伪造 JSON 支持或成功分类。首轮探测被 observer 阻断、四口观察不适用于两口拓扑的失败，以及三个原版 OK 但合同待接入的报告分别保留，均不计合格结果。所有规则与输入头来自 unchanged pinned Linux shell，分类和 drop 由原始 Linux flower/GACT 实现，本批不改 Linux/iproute2 源码、内核配置或 C runtime。

独立负向测试覆盖 CFM 键、联合匹配、硬件/软件归属、action、counter、输入帧、能力探测、规则代次、双 VRF 路径、backend 拒绝及清理。原版连续发包可先于异步统计完成，以原版最终查询窗口为命中判定；未指定的填充保持自由。源端 AF_PACKET 记录与实际 native 链路统计证明输入路径，不声称 socket 接收、CFM 业务状态机或出口抓包。hosted CI/review 仍须与最终提交单独绑定。


`tc_chains.sh` 保留四个原始软件子测试：不可达 chain 不应命中、GACT goto chain 1 必须命中目标并绕过 chain 0 的后续 drop、显式 chain 创建/查询/删除，以及 flower template 的符合/拒绝行为。两个原始 IPv4 输入帧各 98 bytes，共 196 bytes，独立绑定 native MAC/ifindex、IP 地址/头长/输入校验和；实际双 VRF/veth 路径计数前进。不可达规则与错误优先级规则在原版查询窗口必须保持零，goto 与目标 drop 各命中一次，native action byte 计数各为去除 Ethernet 头后的 84 bytes。两个不符合模板的添加必须由原生内核以 `Mask does not fit the template` 拒绝，后续删除不存在 handle 的错误也保留；不把任意失败或不支持当成模板拒绝成功。

Ker 只增加实际 `tc -j -s chain show` 前后观测，核验原生 chain ID、template key、显式引用与规则代次，保留原版真实 `tc -j` / `tc help` 能力探测和 1000ms busywait。原始脚本的硬件分支在 native veth 上不可用：必须记录真实 native `ethtool -k veth0`、前后 JSON feature 与原版 `INFO: Could not test offloaded functionality`；不声称硬件 offload 已迁移或伪造 feature。所有执行的规则和动作均来自 Linux flower/GACT，无 Ker 协议替代，本批不修改上游源码、内核配置或 C runtime。共享两口清理合同参数保留 CFM 原有默认值。

独立负向测试拒绝错误 goto、错误命中/字节/drop、模板键/errno、丢失 chain/规则/输入帧、虚构硬件能力、native 路径与资源清理；未指定的 IP ID/TOS/TTL/protocol 和填充仍可变化。native ingress 分类与链路窗口不等同 socket 接收或出口抓包。最初完整原版四项 OK 但合同待接入的两份 capture 均保留为 FAIL；只有新合同实际运行的 PASS 报告作为 fixture 来源。hosted CI/review 与最终提交单独核验。
