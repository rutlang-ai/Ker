# 原版 MPTCP JOIN 完整故障矩阵

Pinned Linux 6.12.113 的 `mptcp_join.sh` 默认入口完整通过 **126/126 项 TAP 场景**。运行保留原版 shell、公共库、Makefile、`mptcp_connect.c` 和 `pm_nl_ctl.c`，执行前后逐字节核对 pinned Git 对象；没有选择单个分组、删减场景、修改断言或忽略 flaky 检查。

## 覆盖与适配

完整矩阵包括 subflow 限制与错误路径、地址通告与超时、链路故障、地址删除/重加、IPv6/IPv4-mapped 与混合地址、backup/priority、端口与 syncookie、checksum、deny JOIN ID 0、fullmesh、fastclose、真实数据篡改、userspace PM 和 endpoint 生命周期。

`config/native-linux-mptcp-join.config` 在隔离的原版内核中启用真实 xtables BPF/length/statistic 匹配、MARK/REJECT、netem、clsact、fw classifier、pedit 与 checksum action。生产默认内核及 admission 的 netfilter 编译约束保留。CI 的 `join-profile` gate 单独要求 126 项原版场景、对应 kernel fingerprint、JUnit 和完整清理证据。

pinned iproute2 6.12.0 的 ip/ss/nstat/tc 与原版 iptables-legacy/ip6tables-legacy 通过私有 transport 访问常驻导入 Linux。拓扑和故障注入由 Linux 自身实现。脚本读取的 `/sys/class/net/<dev>/statistics/tx_bytes` 从同一原生接口的 rtnetlink `IFLA_STATS64` 传输，保留真实计数与完整 readback；不读取宿主 sysfs 接口。设备名与索引的双向查询均进入原生 namespace，因此 `pm_nl_ctl` 展示真实 native endpoint 的设备名。

常驻 worker 的生命周期、原始工具/脚本指纹、文件和信号传输与 [connect 完整入口](linux-mptcp-connect-shells.md)共用适配层。原版协议实现与上游测试源码均未修改。

## 本地完整运行证据

完整 126 场景运行耗时 968.22 秒，所有 TAP 均通过，无 SKIP/IGNORE/TODO，原版 stderr 为空。126 次拓扑创建共创建并删除 253 个 namespace（含一个隔离对照），最终 native socket 为 0，packet outstanding 为 0，内核与 worker 正常停止。

本次真实执行记录包含 29,498 次通道访问、8 个常驻 worker 槽位、9,944 个 native netlink socket、38 次 filter set、66 次 filter get，以及原生 namespace MIB 累计 177 个 MP_JOIN SYN 接收、172 个 MP_JOIN ACK 接收。故障注入场景保留其原版预期错误和计数检查；这些值不是从 TAP 通过数推导。

这些流量使用导入内核内部的 veth/loopback。外部 DPDK 多路径互通属于另一项验证范围。

## 完整入口清单

| 上游 shell 入口 | 完整 TAP 场景 |
| --- | ---: |
| `mptcp_connect.sh` | 68 |
| `mptcp_connect_mmap.sh` | 68 |
| `mptcp_connect_sendfile.sh` | 68 |
| `mptcp_connect_checksum.sh` | 68 |
| `pm_netlink.sh` | 23 |
| `mptcp_join.sh` | 126 |
| `diag.sh` | 29 |
| `simult_flows.sh` | 10 |
| `mptcp_sockopt.sh` | 11 |
| `userspace_pm.sh` | 37 |

至此 pinned Makefile 的 10 个完整 MPTCP shell 入口均已本地跑通，共 508 项 TAP 场景。独立的 KUnit、C helper 和 TCP-AO 结果分别记录；托管 CI 和 PR review 仍须在最终提交上通过，不将本地结果替代它们。
