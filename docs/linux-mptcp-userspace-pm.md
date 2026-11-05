# 完整原版 MPTCP userspace_pm.sh

固定 Linux 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 的 `userspace_pm.sh`、`mptcp_lib.sh`、`mptcp_connect.c`、`pm_nl_ctl.c` 均保持原样，运行前后逐字节核对固定 Git 对象。完整执行 37 项 TAP 检查，拒绝失败、缺项、skip、IGNORE 和 TODO。保留原版等待、输入文件和断言。

原版脚本在两个实际 native network namespace 和一对 veth 上运行 IPv4/IPv6 两条持久连接，设置真实 `net.mptcp.pm_type=1`。原版 `pm_nl_ctl` 订阅真实 Generic Netlink multicast，解析内核事件并供原版 shell 核对 token、地址、端口、server_side、deny_join_id0 和事件类型。覆盖无效 token/id、ADD_ADDR/RM_ADDR、双向 IPv4/IPv6 子流增删、混合地址族、MP_PRIO TX/RX 及 listener 创建/关闭。计数由原版 nstat 读取真实内核 proc 数据。

私有测试适配将单个 native socket 的无限期 read-select 转为有限片段的真实 native poll；不把宿主 RPC 通道可读性冒充协议事件。其它未支持的 native select 组合明确返回 EOPNOTSUPP。事件读取器被原版清理终止后，通道关闭使服务端释放实际 native netlink socket。

原版客户端使用 sendfile。私有适配将不超过 `MS_MAX - 8` 字节的原始常规文件复制到封存的宿主 memfd，再通过已有 tests-ON 文件导入入口创建 native 只读文件，最后执行原版 Linux sendfile。显式 offset 和隐式文件位置按实际返回值更新。大文件和非文件输入明确拒绝；没有扩展生产跨内核文件传输边界，也没有用宿主 TCP 或自制协议发送代替原版 sendfile。

`linux-original-mptcp-userspace-pm.json` 记录完整原版输出、37 项结果、源码/二进制/内核/iproute2 哈希、真实 pm_type、内核内存资源、13 条实际成功 ACK 的拓扑操作和 native 活动计数。要求两个连接的四个协商端点、两次 accept、至少八次 MP_JOIN SYN/ACK、至少两次实际 sendfile、零 fallback。原版两个 namespace 与独立清理控制 namespace 的三个 pin、所有 native sockets 和 packet outstanding 必须归零。

本入口在 CI inventory/JUnit 中强制存在并通过。它验证导入内核内部 veth 上的用户态 PM 控制面与协议行为，不推断外部 DPDK 多路径验证完成。生产 tests-OFF 不包含私有测试 ABI。

MPTCP 剩余五个完整注册 shell 入口：`mptcp_connect.sh`、`mptcp_connect_mmap.sh`、`mptcp_connect_sendfile.sh`、`mptcp_connect_checksum.sh`、`mptcp_join.sh`。TCP-AO 的全部 24 个 IPv4/IPv6 入口独立回归，848 个通过断言和 6 个已知上游 XFAIL 分开记录。

```bash
ctest --test-dir build-native-on -R '^linux-original-mptcp-userspace-pm$' --output-on-failure
```
