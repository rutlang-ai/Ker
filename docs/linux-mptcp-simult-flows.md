# 完整原版 MPTCP simult_flows.sh

运行固定 Linux 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 中未修改的 `simult_flows.sh`、`mptcp_lib.sh`、`mptcp_connect.c` 与 `pm_nl_ctl.c`。保留 16 MiB/80 KiB 原始数据、原版时间上限、五个带宽/延迟组合与每组正反两个方向，共 10 项 TAP 检查。不接受失败、skip、IGNORE 或不完整计划，原版标注 flaky 的组合也严格执行。

## 真实拓扑和流控

原版脚本配置三个独立 native network namespace、三对 veth、IPv4/IPv6 地址及转发路由，使用原版 PM helper 绑定实际 native interface index 并开启第二个子流。私有 scaffold 只适配进程间 namespace/device 操作，不实现协议行为。

iproute2 固定为 6.12.0，沿用原归档 SHA-256 校验；编译未修改的 `tc`，记录源码和工具哈希。原版 `tc` 通过私有 preload 向实际 Linux rtnetlink 发送 qdisc 请求。每次 add 成功后，额外运行原版 `tc -j qdisc show`，核对实际 netem 的 rate、delay 和 limit。必须有 30 条已获内核 ACK 的拓扑操作与 20 次成功的 netem add/readback。删除尚不存在的 qdisc 是原版脚本的预期操作，单独保留真实返回码。

native 配置启用原版 NET_SCHED/NET_SCH_NETEM；Linux 源码不变。协议、拥塞控制、重排、流控和实际传输时间均由原版实现及原版断言决定。

## 测试内存供给

原有 LKL 启动固定为 64 MiB，Linux 会据实际可用页自行计算 TCP buffer 上限。该配置使首次完整执行中的部分非对称带宽测试超出原版时间限制，不能计为通过。本入口显式给测试内核 512 MiB，保持 Linux 自己的 autotuning 与协议参数；未修改原版测试或时间断言，也未手工覆盖 TCP/MPTCP sysctl。

`KER_LINUX_SELFTEST_MEMORY_MB` 仅在 tests-ON fixture 中编译，范围为 64..1024 MiB。生产 tests-OFF 库不包含这个覆盖入口，仍使用 64 MiB。报告记录真实 `/proc/meminfo`、`tcp_wmem`、`tcp_rmem` 与请求资源，检查实际容量。其它原版测试仍默认 64 MiB。

## 结果与范围

`linux-original-mptcp-simult-flows.json` 包含完整原版输出、10 项结果、工具/源码/内核 provenance、真实 qdisc 回读、内核资源和实际 native 活动。必须完成 20 个协商端点、10 次 accept、至少 10 次 MP_JOIN SYN 与 10 次 ACK 接收，且没有 TCP fallback；数据量、socket 归零、四个 namespace pin（含保留供原版清理检查的独立 namespace）回收和 packet outstanding 均检查。

本批完成一个完整 shell 入口，其后 [`userspace_pm.sh`](linux-mptcp-userspace-pm.md) 完成 37 项检查，MPTCP 剩余 5 个：`mptcp_connect.sh`、`mptcp_connect_mmap.sh`、`mptcp_connect_sendfile.sh`、`mptcp_connect_checksum.sh`、`mptcp_join.sh`。TCP-AO 的 24 个注册入口保持独立回归，6 个已知上游 XFAIL 不计通过断言。

流量在导入内核内部 veth/loopback 上运行；不推断外部 DPDK 多路径验证已完成。CI 强制检查本入口在 inventory/JUnit 中存在并通过。

```bash
ctest --test-dir build-native-on -R '^linux-original-mptcp-simult-flows$' --output-on-failure
```
