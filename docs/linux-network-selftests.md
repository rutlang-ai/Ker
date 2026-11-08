# Linux networking selftests 迁移清单

固定 Linux 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`。以下分母由各目录原版 `make emit_tests COLLECTION=<目录>` 得到，代表默认注册入口，不是 C helper 数量、运行参数组合数或内部断言数。此清单仅覆盖 `tools/testing/selftests/net` 下列十个上游 collection，不包含 `drivers/net` 或独立 BPF collection。

| collection | 默认注册入口 | 当前接入范围 |
| --- | ---: | --- |
| `net` | 106 | `sk_connect_zero_addr`、四个完整 binding 程序、`reuseport_dualstack`、`sk_so_peek_off`、`tun`、`reuseport_addr_any.sh`、`run_netsocktests`、`tap`、`netlink-dumps`、`netns-name.sh`；共 13 个入口本地通过 |
| `net/af_unix` | 5 | 全部接入 host-backed IPC 兼容性测试，与 imported Linux 分开统计 |
| `net/mptcp` | 10 | [全部完整 shell 入口](linux-mptcp-join.md)本地通过，共 508 项 TAP 场景；最终 CI/review 单独核对 |
| `net/tcp_ao` | 24 | [全部双栈入口](linux-tcp-ao-tests.md)，已知上游 XFAIL 单列 |
| `net/packetdrill` | 24 | [完整原版 24 个脚本](linux-packetdrill-selftests.md)，48 个 imported Linux 双栈配置本地通过；CI/review 单独核对 |
| `net/forwarding` | 107 | `router_vid_1.sh`、`min_max_mtu.sh`、`router_bridge.sh`、`router_nh.sh`、`router_bridge_vlan.sh`、`router_bridge_1d.sh`、`router_bridge_vlan_upper.sh`、`router_bridge_pvid_vlan_upper.sh` 完整入口本地通过；其余 99 个尚未逐个接入 |
| `net/hsr` | 2 | 尚未接入 |
| `net/netfilter` | 29 | `conntrack_dump_flush`、`conntrack_icmp_related.sh`、`conntrack_ipip_mtu.sh`、`rpath.sh`、`xt_string.sh` 完整入口本地通过；其余 24 个尚未逐个接入 |
| `net/openvswitch` | 1 | 尚未接入 |
| `net/rds` | 2 | 尚未接入 |
| 合计 | 310 | 逐个保留原版入口合同，不用 Ker 自编回归抵扣 |

原版 `tcp_inq`、MPTCP C helper 和 KUnit 已有的运行配置另行记录，不增加这个默认注册入口分母。Ker 集成测试中的 netfilter、veth、VRF 等功能覆盖，也不代表对应完整上游 shell 已迁移。

按本地完整入口合同统计，当前接入 89/310，剩余 221；其中 84 个通过 imported Linux，另 5 个是 host-backed AF_UNIX。严格只统计 imported Linux 时尚有 226 个。`net/` 本目录剩余 93/106。提交后的 hosted CI/review 资格仍须单独核对。

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

共 128 条原版拓扑/配置/流量/清理命令，经真实 Netlink 和 ICMP 执行。六项均须明确输出 OK，不能用 XFAIL 或缺失子项抵扣；native socket/packet 必须归零，保留完整脚本缺失后端和无效 VRF 对照。CI 的 forwarding profile 同时强制运行两个完整入口并核对各自的独立 JSON/JUnit。

`forwarding/router_bridge.sh` 在专用 `config/native-linux-bridge-selftests.config` 中完整运行，启用真实 Linux bridge、VLAN filtering、VRF 和 multipath routing。原版 14 个阶段包含十次双栈 ping：初始连通、桥端口重新挂接后连通、移除 bridge self PVID 后隔离、恢复 PVID 后连通，以及先挂接端口再添加默认 PVID 后连通。保留原版全部 10 次请求、0.1 秒间隔、5 秒 deadline 和阶段间 sleep，预期失败的两个 ping 必须真实失败；不修改 Linux、iproute2 或原版 selftest。

iproute2 6.12.0 的 unchanged `bridge` 工具和 `ip` 使用同一原生 Netlink 通道。每次 ping 前读取真实 bridge 类型、VLAN filtering、端口 master/forwarding 状态和 VLAN 1 flags，要求仅隔离阶段缺失 PVID/untagged。完整 110 条原版命令还须保留 remaster、default PVID 0→1 的顺序及成功清理。实际 IPv4/IPv6 forwarding MIB 各至少增加 80；结束后 br1/VRF 设备消失、forwarding sysctl 恢复、live socket/outstanding packet 为零，worker 正常退出。保留完整入口缺失 backend、未知 VRF 与同后端 loopback 对照。

本地完整原版及 `bridge-profile` CI gate 通过，native fingerprint 为 `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`，并使用 hosted CI 对应的 Ubuntu iputils 20240117 ping 验证。gate 要求实际配置、唯一原版入口、无 skip 的 JUnit 和匹配 fingerprint 的完整 JSON；最终提交的 hosted CI/review 资格仍须单独核对。该程序计一个默认入口。

`forwarding/router_nh.sh` 完整运行两个原版双栈 ping，保留所有拓扑、`nexthop`、路由替换、clsact 创建/删除及 cleanup 命令。专用 `config/native-linux-nexthop-selftests.config` 启用 multipath、NET_CLS_ACT 和 NET_SCH_INGRESS；原版 iproute2 6.12.0 `ip`/`tc` 经已有 Netlink 通道操作导入 Linux，不修改 Linux、工具或原版脚本及三个公共库。

原版创建两个 AF_INET6 nexthop（101→veth1，102→veth2），IPv4 和 IPv6 各有两条路由引用它们。每次 ping 前读取实际 AF_INET6 nexthop dump、双栈 FIB、clsact 和 `route get fibmatch`。IPv4 实际选中 nhid 102；原版 IPv6 配置同时保留 metric 256 的直连路由和 metric 1024 的 nhid 路由，实际选中直连路由。本项保留并记录这个上游合同，不将 IPv6 ping 宣称为经 nhid 转发的流量证明。

本地使用 hosted Ubuntu iputils 20240117 完整通过，两次 ping 均保持 10 个回包、0.1 秒间隔和 5 秒 deadline，实际 IPv4/IPv6 forwarding MIB 各增加 20。要求 clsact/VRF 清理、forwarding sysctl 恢复、live socket/outstanding packet 为零和 worker 正常退出；上游未显式删除的 nexthop/路由随常驻内核关闭释放，不额外改写原版 cleanup。完整脚本缺失 backend 必须失败，未知 VRF 必须拒绝，同后端 loopback 对照成功。`nexthop-profile` gate 强制配置、唯一完整入口、无 skip JUnit、匹配 fingerprint 和完整证据。本地 native fingerprint 为 `6414aae9fd58c1f5012289ba99c8f3bab5a883982a6b2da969d4964f06a1cc3d`；hosted CI/review 资格另行核对。该程序计一个默认入口。

`forwarding/router_bridge_vlan.sh` 使用已有 bridge profile，完整执行 11 个阶段、9 行原版 TEST 结果及 8 次原版 ping。主机保留 VLAN 555/777 子接口和双栈路由，bridge 端口同时允许两个 tagged VLAN；bridge self PVID 从 555 切换至 777，再恢复 555。切换期间 VLAN 555 的两个 ping 必须真实失败，VLAN 777 的双栈流量和恢复后的 VLAN 555 流量必须成功。所有包数、间隔、deadline、sleep 及上游断言保持原样，不修改 Linux、iproute2 或 selftest 源码。

134 条原版命令逐项记录。每次 ping 前读取实际 bridge VLAN filtering/default PVID、forwarding 端口、self PVID、tagged 端口 VLAN 和主机子接口；每次 bridge 命令后读取完整原生 VLAN 表，核对 VLAN 333 的真实增删及 PVID 555→777→555 顺序。IPv4/IPv6 forwarding MIB 各增加 60，结束后 bridge、两个 VRF 和两个 VLAN 子接口消失，forwarding sysctl 恢复，live socket/outstanding packet 为零，worker 正常退出。完整脚本缺失后端及未知 VRF 对照必须失败，同后端 loopback 对照成功。

本地完整入口及 hosted Ubuntu ping 复验通过，沿用未变的实际 bridge 内核配置和 fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`。`bridge-profile` gate 强制同时运行 `router_bridge.sh`、`router_bridge_vlan.sh`、`router_bridge_1d.sh`、`router_bridge_vlan_upper.sh` 和 `router_bridge_pvid_vlan_upper.sh`，各自验证唯一注册、原版 program 标识、完整 JSON 和无 skip JUnit；五个入口均从默认 profile 排除，不能在缺少真实 bridge/VLAN 支持时抵扣通过。hosted CI/review 资格另行核对。此批仅新增一个默认入口。

`forwarding/router_bridge_1d.sh` 使用同一实际 native bridge 配置，完整执行五个原版阶段和八次双栈 ping。两个独立 802.1D bridge（br1/br2，vlan_filtering=0）分别承接 veth1.100/veth1.200，主机保留对应 VLAN 100/200 子接口。原版先验证两组双栈连通性，再解除两个 bridge VLAN 端口、等待原版两秒、按原版顺序重新挂接，最后重复两组双栈连通性检查；包数、间隔、deadline、sleep、上游断言及协议代码保持原样。

每次原版 ping 前读取实际 native link 状态，核对两个 bridge 的模式、MAC、VLAN 端口/master/forwarding 状态及主机 VLAN/VRF；每次原版 master/nomaster 操作后读取实际端口状态，确认解除和重新挂接真正发生。校验按原始记录的位置区分重复的挂接命令，保留完整生命周期顺序。IPv4/IPv6 forwarding MIB 各增加 80；原版 cleanup 后两个 bridge、四个 VLAN 子接口和两个 VRF 均消失，forwarding sysctl 恢复，live socket/outstanding packet 为零且 worker 正常退出。缺失 backend、未知 VRF 和同后端 loopback 对照分别验证失败与成功。

`bridge-profile` gate 同时强制五个完整入口、时钟 ABI 控制及其独立 JSON/JUnit。本地使用 hosted Ubuntu iputils 20240117 验证，native fingerprint 仍为 `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`，复用实际 immutable kernel/library，并核对当前输入/config/library hash。Linux、iproute2、原版 shell 和公共库不改动。hosted CI/review 资格另行核对，此批仅新增一个默认入口。

## Bridge VLAN upper 双栈路由

完整未修改的 `forwarding/router_bridge_vlan_upper.sh` 使用现有 bridge 配置运行五个原版阶段，输出四行原版 TEST 成功结果。`br1.555` 和 `br1.777` 是实际 VLAN-filtering bridge 上的路由接口，分别承接 VLAN 555/777 的 IPv4/IPv6 地址和 connected FIB 路由；两端主机的 `veth0.555`、`veth3.777` 则属于各自 VRF。原版先执行双栈 ping，再按原版顺序解除两个端口、等待原版两秒、重新挂接并恢复 tagged VLAN 成员，最后重复双栈 ping。包数、间隔、deadline、sleep、断言和 Linux/iproute2/selftest 源码均保持不变。

每次原版 ping 前读取完整 native link、address、双栈 FIB 和 bridge VLAN 表，验证两个 bridge upper 的 parent/VID/地址/路由、两个主机 upper 的 VRF、两个 forwarding 端口及各自 tagged VLAN。每次 master/nomaster 操作后读取端口真实状态，每次 bridge VLAN 命令后读取真实 VLAN 表，并按记录位置验证解除、重新挂接、VLAN re-add、流量和 cleanup 顺序，不能把重复命令当成同一次操作。

本地使用 hosted Ubuntu iputils 20240117 完整通过，四次 ping 各收齐十个回包、stderr 为空且均记录实际 native realtime 读取。IPv4/IPv6 forwarding MIB 各增加 40；原版 cleanup 后 bridge、bridge/host VLAN upper 和 VRF 均消失，forwarding sysctl 恢复，live socket/outstanding packet 为零，worker 正常退出。缺失 backend 必须失败，未知 VRF 必须拒绝，同后端 loopback 对照成功。沿用实际 native fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`。CI 的 bridge profile 强制五个完整原版入口加时钟 ABI 控制共 6 项，无 skip；hosted CI/review 另行核对。本批仅新增一个默认入口。

## Self PVID 与临时 VLAN upper

完整原版 `forwarding/router_bridge_pvid_vlan_upper.sh` 在已有 native bridge profile 中运行五个默认阶段、四个双栈 ping 成功结果。bridge 的 `vlan_default_pvid=0`，self VLAN 10 为 PVID/untagged，端口 veth1 的 VLAN 10 保持 tagged；基础路由地址位于 `br1`。原版在两组双栈 ping 之间临时创建 `br1.10`、启用接口、添加任意 IPv4 地址 192.0.2.33/28，保留原版一秒等待后删除 upper，验证 PVID 路由仍正常。Linux、iproute2、脚本、公共库、包数、时序和断言均未修改。

每次 ping 前和每次 upper 创建、启用、地址添加、删除后读取实际 native link/address、双栈 FIB 和 VLAN 表。合同验证临时 upper 的 parent/VID/UP、192.0.2.32/28 connected route 的真实出现与消失，同时要求原 bridge 的 self PVID、地址和双栈路由一直保留。四次 ping 各收到十个回包、stderr 为空且有真实 native realtime 读取；IPv4/IPv6 forwarding MIB 各增加 40。原版 cleanup 后 bridge、临时和主机 VLAN、VRF 消失，forwarding sysctl 恢复，live socket/outstanding packet 为零且 worker 正常关闭。缺失 backend、未知 VRF 与 loopback 对照分别验证拒绝和实际成功。

沿用 native fingerprint `6ee942b2c8460007ae8131a5f0764b4ff646c6efd9d0340d2b282d025eadedf5`，使用 hosted Ubuntu iputils 20240117 本地完整通过。CI 强制五个完整原版 bridge 入口与时钟 ABI 控制共 6 项及其 JSON/JUnit，不允许 skip；hosted CI/review 另行核对。本批仅新增一个默认入口。

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
