# Linux networking selftests 迁移清单

固定 Linux 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`。以下分母由各目录原版 `make emit_tests COLLECTION=<目录>` 得到，代表默认注册入口，不是 C helper 数量、运行参数组合数或内部断言数。此清单仅覆盖 `tools/testing/selftests/net` 下列十个上游 collection，不包含 `drivers/net` 或独立 BPF collection。

| collection | 默认注册入口 | 当前接入范围 |
| --- | ---: | --- |
| `net` | 106 | `sk_connect_zero_addr` 及本批四个完整 binding 程序 |
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

## 本批完整 binding 程序

| 原版程序 / CTest 后缀 | 完整运行结果 | 验证范围 |
| --- | --- | --- |
| `reuseaddr_conflict` | 原版程序退出成功 | IPv4 listener 与 IPv6 wildcard 创建/关闭期间的复用冲突 |
| `sk_bind_sendto_listen` | 原版程序退出成功 | 两个 IPv6 socket 的 bind、零长 Fast Open sendto 及后续 listen |
| `bind_timewait` | 2/2 TAP | localhost 与 wildcard 两组真实 TCP 连接关闭后的 EADDRINUSE |
| `bind_wildcard` | 132/132 TAP | 44 组 IPv4、IPv6、v4-mapped 地址组合，各执行 plain、REUSEADDR、REUSEPORT |

源文件、`kselftest.h`、`kselftest_harness.h` 和 Makefile 在执行前后与 pinned Git blob 逐字节核对，编译保留原版断言。原版 harness 的 fork 与宿主 IPC 保留；IP socket 操作经已验证的私有 fixture 进入同一个常驻 Linux，内核 owner 不 fork。binding 判定、端口表、TIME_WAIT 和原版 errno 均来自 Linux，本批没有增加协议实现或修改生产 API。

显式 `close()` 等到实际 native close 完成并返回原版结果后才释放通信通道，保持原版按顺序关闭 accepted、client、listener socket 的语义。进程退出时遗留的通道仍由 EOF 清理；不以等待、重试 bind 或修改 TIME_WAIT 协议逻辑掩盖适配器的关闭顺序问题。

四个 CTest 均使用默认 native 内核配置，本地完整通过。fixture 分别记录 5、2、6、1056 次实际 native socket() 创建；TIME_WAIT 的两次 accept 单独计数，并要求 Linux ActiveOpens/PassiveOpens 均为 2。每次成功创建都验证 native descriptor 类型，缺失 backend 的对照必须拒绝。所有 native socket、packet outstanding 均归零，worker 正常关闭。两个非 TAP 程序按完整程序退出状态记录，不伪造断言计数。

`linux-original-net-*.json` 包括原版输出、TAP、源码与二进制 hash、内核 fingerprint、native socket/accept 计数和清理结果。CI 的完整 default CTest graph 必须包含这四项及其 JUnit 结果，不能跳过。

```bash
ctest --test-dir build-native-on --no-tests=error \
  -R '^linux-original-net-' --output-on-failure
```

## Packetdrill

[完整原版 packetdrill 迁移](linux-packetdrill-selftests.md)使用 unchanged Google 工具 revision `8051382e6ac928c4c13a88b34832649d9b07abc2` 和单独 fingerprint 的 native TUN/FQ 内核。24 个原版脚本经原版 runner 执行 IPv4/IPv6 共 48 个配置，保留全部包内容、syscall、时间及内嵌 TCP_INFO 断言。本地完整 CTest 已通过，最终提交的 hosted CI/review 仍须单独通过。此前宿主基线单列，不计 native 覆盖。
