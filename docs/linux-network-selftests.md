# Linux networking selftests 迁移清单

固定 Linux 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`。以下分母由各目录原版 `make emit_tests COLLECTION=<目录>` 得到，代表默认注册入口，不是 C helper 数量、运行参数组合数或内部断言数。此清单仅覆盖 `tools/testing/selftests/net` 下列十个上游 collection，不包含 `drivers/net` 或独立 BPF collection。

| collection | 默认注册入口 | 当前接入范围 |
| --- | ---: | --- |
| `net` | 106 | `sk_connect_zero_addr`、四个完整 binding 程序、`reuseport_dualstack`、`sk_so_peek_off`、`tun`、`reuseport_addr_any.sh`、`run_netsocktests`、`tap`；共 11 个入口本地通过 |
| `net/af_unix` | 5 | 全部接入 host-backed IPC 兼容性测试，与 imported Linux 分开统计 |
| `net/mptcp` | 10 | [全部完整 shell 入口](linux-mptcp-join.md)本地通过，共 508 项 TAP 场景；最终 CI/review 单独核对 |
| `net/tcp_ao` | 24 | [全部双栈入口](linux-tcp-ao-tests.md)，已知上游 XFAIL 单列 |
| `net/packetdrill` | 24 | [完整原版 24 个脚本](linux-packetdrill-selftests.md)，48 个 imported Linux 双栈配置本地通过；CI/review 单独核对 |
| `net/forwarding` | 107 | 尚未逐个接入完整原版入口 |
| `net/hsr` | 2 | 尚未接入 |
| `net/netfilter` | 29 | 尚未逐个接入完整原版入口 |
| `net/openvswitch` | 1 | 尚未接入 |
| `net/rds` | 2 | 尚未接入 |
| 合计 | 310 | 逐个保留原版入口合同，不用 Ker 自编回归抵扣 |

原版 `tcp_inq`、MPTCP C helper 和 KUnit 已有的运行配置另行记录，不增加这个默认注册入口分母。Ker 集成测试中的 netfilter、veth、VRF 等功能覆盖，也不代表对应完整上游 shell 已迁移。

按本地完整入口合同统计，当前接入 74/310，剩余 236；其中 69 个通过 imported Linux，另 5 个是 host-backed AF_UNIX。严格只统计 imported Linux 时尚有 241 个。`net/` 本目录剩余 95/106。提交后的 hosted CI/review 资格仍须单独核对。

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
