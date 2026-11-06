# 原版 MPTCP connect 完整 shell 测试

在 pinned Linux 6.12.113（`7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`）和原版 LKL 上，以下四个默认入口已经各自完整通过 68 项 TAP 检查：

| 上游入口 | CTest 入口 | 原版检查 |
| --- | --- | --- |
| `mptcp_connect.sh` | `linux-original-mptcp-connect-connect` | 68/68 |
| `mptcp_connect_mmap.sh` | `linux-original-mptcp-connect-mmap` | 68/68 |
| `mptcp_connect_sendfile.sh` | `linux-original-mptcp-connect-sendfile` | 68/68 |
| `mptcp_connect_checksum.sh` | `linux-original-mptcp-connect-checksum` | 68/68 |

运行保留原版 shell、三个 mode wrapper、`mptcp_lib.sh`、网络公共库、helper C 源码和 Makefile；执行前后均与 pinned Git 对象逐字节核验。未传入缩短矩阵的参数，也未固定或关闭脚本默认随机文件大小、loss、delay、reorder 和 ethtool 选择。`SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES=1` 和 `SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY=1` 要求所有功能可用且所有断言实际通过；SKIP、IGNORE、TODO 和 `not ok` 均拒绝计入完成。

每个入口执行原版 sysctl 禁用检查、48 次双栈 ping、loopback 与 multihost 传输、TCP fallback、两种 peek mode、MPTFO、IPv4/IPv6 透明代理和三次完整断开重连。66 次传输的 132 次原版双向 `cmp` 必须全部成功。透明代理另外要求 4 次真实 nft 规则安装/清理、8 次内核确认的 policy-routing 操作和成功的数据传输。

## 原版内核与工具路径

`config/native-linux-mptcp-connect.config` 是独立、带 fingerprint 的测试配置，启用真实 nftables socket/tproxy 支持。生产默认配置和 ingress-freeze/admission 的 netfilter 编译约束保留；CI 分别运行默认完整测试图、原有 sockopt 配置，以及这四个 connect 入口的专用配置。

拓扑、sysctl 和 proc 操作进入同一常驻导入 Linux。跨 namespace veth 与 policy rule/route 使用真实 rtnetlink 请求和 ACK。pinned iproute2 6.12.0 的 ss/nstat/tc、原版 ping、ethtool、nft 通过私有 socket transport 调用该内核，工具二进制 hash 写入证据。netem 的 loss、delay、reorder 和相关性从真实内核 readback 核对。helper 内部 `system("ss ...")` 也查询导入内核，保证完整断开等待的语义。`if_nametoindex` 和 `if_indextoname` 双向查询都进入原生 namespace，避免将 native endpoint 的设备索引按宿主接口名显示。

mmap 的大 write 通过有界的真实 native short write 传输。sendfile 的输入按有界块上传到 sealed memfd，再导入只读 native 文件，随后调用 Linux 自身的 sendfile；32 MiB 上限覆盖原版默认最大约 24 MiB 的重复传输输入。显式/隐式文件 offset 取自实际 syscall 结果；输入身份和修改时间在导入前后核验。该接口仅存在于未安装的 tests-ON fixture，生产的跨内核 fd 边界未扩张。

resident server 复用少量常驻 native task，结束通道时关闭 socket/输入文件并返回 root namespace。这样完整脚本超过 6000 次通道访问不会反复创建、销毁 LKL host task，也不会由空闲任务持有被删除的 namespace。SIGPIPE 在原调用者执行；共享内核 owner 返回实际 EPIPE。

## 证据与回归

runner 要求精确的 68 项 TAP、全部文件比较、真实 ICMP/nft/policy-routing 活动、native MPTCP 协商与 TCP fallback，以及超过 4096 次通道访问且少于 64 个 worker 槽位。最后必须删除全部 6 个 namespace、socket 归零、内核和 DPDK worker 正常停止、packet outstanding 归零。

每个 CTest 生成同名 JSON、原始 stdout/stderr 和 hash。JSON 包括源码/工具/二进制指纹、原版 TAP、内核操作和 qdisc readback、文件比较、namespace/socket 计数及最终 packet ownership。CI 的 `connect-profile` gate 逐个检查四个入口、JUnit、68 项原版检查和对应 kernel fingerprint，不能用其它入口的通过数抵扣。

至此 MPTCP Makefile 的 10 个完整 shell 入口已完成 9 个，剩余 `mptcp_join.sh` 完整故障矩阵继续单独推进。原版 [TCP-AO](linux-tcp-ao-tests.md) 的 24 个注册入口独立回归。
