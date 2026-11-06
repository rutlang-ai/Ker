# 完整原版 MPTCP socket option 脚本

直接执行固定 Linux stable 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 的完整默认 `tools/testing/selftests/net/mptcp/mptcp_sockopt.sh`，保留脚本、库、helper 的源码、拓扑、等待、随机数据和全部断言。11 项 TAP 检查均必须通过，不接受 skip、IGNORE、TODO 或不完整计划。

覆盖 IPv4/IPv6 双向传输与 packet mark、两个 SOL_MPTCP socket option 配置，以及五个原版 TCP_INQ 配置。本批补齐完整 shell 入口，既有 helper 配置继续独立记录；后续迁移已补齐 [10 个完整 shell 入口](linux-mptcp-join.md)。TCP-AO 的 24 个注册入口已接入，仍作为内核回归测试执行，其 6 个已知上游 XFAIL 单列、不计通过。

## 实际内核拓扑与过滤

原版脚本建立三个独立的 native network namespace、四对 veth、IPv4/IPv6 地址、路由、MPTCP endpoint 和 limits。私有 scaffold 只把 `ip` 的 setup 请求转换成真实 rtnetlink UAPI，并保留两个 namespace 的实际 fd。原版 `pm_nl_ctl` 通过实际 generic Netlink 配置路径管理，未重写其请求、输出或断言。

系统原版 `iptables-legacy` / `ip6tables-legacy` 使用测试专用 preload，将真实 netfilter socket option 操作送入同一个导入内核。只有进程间嵌套的 `ipt_replace`/`ip6t_replace` counters 指针需要搬运；规则、匹配、DROP、TCP mark 传播与计数都来自原版 Linux。xtables 锁文件放在本次私有临时目录，防止触碰宿主全局锁。工具版本与二进制 SHA-256 写入证据。

测试专用的 `config/native-linux-mptcp-sockopt.config` profile 启用原版 xtables、mark match、IPv4/IPv6 filter；生产/default native 配置不启用这些额外 hook registrant，因此不会削弱 ingress-freeze queue 的编译期和运行时 hook-inventory guard。profile fragment、Linux/LKL revisions、kernel config hash 和 library hash 均写入独立 fingerprint manifest；没有修改 Linux 源码。私有 raw socket 创建入口仅存在于 tests-ON runtime，不安装为公共 API。普通 facade 的权限边界保持原样。

原版脚本执行完后，在独立对照 namespace 里分别安装 IPv4/IPv6 mark-zero DROP 规则，发送真实未标记的非阻塞 MPTCP SYN。两者均必须使真实 DROP counter 增加，防止将零 DROP 误当作过滤根本没有生效。对照不计入原版 11 项用例。

## 证据与回收

`linux-original-mptcp-sockopt-shell.json` 保存固定源码、helper、preload、facade 与工具哈希，完整原版 stdout/stderr、11 项检查、35 条实际内核 ACK 后记录的拓扑操作、负对照 counter 和实际内核活动。销毁 namespace pin 前读取真实 `MPTcpExt`，要求 MP_JOIN SYN 与 ACK 计数非零，验证多地址场景确实执行原版子流握手。缺失能力明确失败，不回退到宿主 IP socket，也不生成替代诊断结果。

原版三个 namespace 和一个负对照 namespace 必须全部删除，socket 归零，native kernel/DPDK worker 正常退出，packet outstanding 归零。流量经导入内核内部 veth/loopback；本批不宣称外部 DPDK 多路径互通通过。[完整 JOIN 故障矩阵](linux-mptcp-join.md)另有 126 项原版检查的运行证据。

## 重现

使用专用 netfilter profile 构建新的 Linux/LKL fingerprint；不得把 profile 配置放进生产/default defconfig，也不得复用不同 fingerprint 的 manifest。安装原版 legacy iptables 工具，并使用既有 pinned iproute2 diag tools：

```bash
python3 tools/build-native-linux.py --build /tmp/native-linux-sockopt \
  --config-fragment config/native-linux-mptcp-sockopt.config
cmake -S . -B build-native-sockopt -DKER_NATIVE_LINUX_BUILD=/tmp/native-linux-sockopt \
  -DKER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON -DBUILD_TESTING=ON
ctest --test-dir build-native-sockopt -R '^linux-original-mptcp-sockopt-shell$' --output-on-failure
```

CI 在保留 default profile 全量 CTest（包括 C24/C28 ingress-freeze tests）的同时，单独配置此 profile 并强制要求原版 shell entry 出现在 CTest inventory 与 JUnit 中且通过。两个 profile 的证据分别上传；sockopt test 的 JSON fingerprint 必须匹配专用 manifest。既有 AF_UNIX、MPTCP、TCP-AO 原版测试继续在 default profile 回归。
