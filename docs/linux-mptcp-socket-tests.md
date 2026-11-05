# 原版 MPTCP socket 信息与 INQ 测试

本批直接编译固定 Linux 6.12.113 中未修改的 `tools/testing/selftests/net/mptcp/mptcp_sockopt.c` 和 `mptcp_inq.c`。保留原版随机数据长度、进程、同步、超时和全部断言；不重写协议实现，也不修改原版程序来适应测试结果。

| CTest | 场景 |
|---|---|
| `linux-original-mptcp-sockopt-ipv4` / `ipv6` | `MPTCP_INFO`、`MPTCP_TCPINFO`、`MPTCP_SUBFLOW_ADDRS`、`MPTCP_FULL_INFO`、非法长度与前向兼容长度、`IP_TOS`、收发字节/序列与 EOF |
| `linux-original-mptcp-inq-ipv4` / `ipv6` | 每个地址族运行 MPTCP/MPTCP、TCP/MPTCP、MPTCP/TCP 和 TCP/TCP；检查 `FIONREAD`、`TIOCOUTQ`、`SIOCOUTQNSD`、`TCP_CM_INQ`、批量收发和 FIN 后 EOF |

共 2 个 sockopt 配置和 8 个 INQ 配置。INQ 的混合协议和 TCP/TCP 是回退/对照配置，不能计为 MPTCP 协商成功。默认 MPTCP/MPTCP 配置额外覆盖原版脚本没有调用的 helper 默认参数；TCP/TCP IPv6 也是额外对照。

## 进程和内核边界

两个原版程序均先执行真正的宿主 `fork()`，随后才创建网络 socket。直接在子进程里继承一个线程化 LKL 实例不能满足这个边界，因此使用不安装的测试专用常驻 socket 服务：

- 原版 `fork`、`waitpid`、pipe、AF_UNIX 同步、随机输入和 alarm 保持宿主行为；程序和断言源码不变。
- 链接期 wrapper 将测试实际使用的 IP socket 调用送到同一个常驻导入内核。每个 socket 使用独立线程，保留阻塞 accept/connect/read；真实 Linux 处理 MPTCP、TCP、队列、控制消息和关闭。
- `MPTCP_FULL_INFO` 仅转换进程间嵌套指针：在服务端分配实际输出空间，将 Linux 输出逐字节搬回原地址。兼容原版 helper 较短的 `mptcp_info` ABI，不扩展原版 optlen。
- `recvmsg` 保留真实内核返回的 payload、控制消息、长度和 flags。地址查询也指向原生 socket，不能读到宿主控制通道的 AF_UNIX 地址。
- 缺少服务时明确报错，禁止宿主 IP socket 回退；不支持的参数返回错误。这是限定于当前原版 helper 调用集的私有适配，不是通用跨进程 socket API，不支持 fork 后继承已创建的网络 fd。

服务检查每个 IP socket 的 native descriptor kind，并读取真实 `MPTCP_INFO` 标志确认协商。固定内核回退后会把 getsockopt 交给 TCP；此时记录实际 `EOPNOTSUPP`/`ENOPROTOOPT` 及成功的原生 `TCP_INFO`，不伪造 MPTCP 信息。runner 要求 native socket/accept 次数、全部收发字节、嵌套 full-info 和 INQ 调用证据、socket 归零、worker 正常退出和 packet outstanding 归零。原版程序即使 exit 0，只要输出 skipped/unsupported/XFAIL 也判失败。缺少后端和损坏消息另有负对照。

流量走导入内核的 loopback。DPDK worker 用于启动真实运行时，但本批不能算外部 DPDK 链路、多子流或 MP_JOIN 验证。

## 重现与计数

native tests-ON 构建设置 `KER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON`，然后：

```bash
ctest --test-dir build-native-on -R '^linux-original-mptcp-(sockopt|inq)-ipv' --output-on-failure
```

CI 强制检查这 4 个 CTest 的 inventory 和 JUnit，不允许跳过；`linux-original-mptcp-*.json` 保留源码与二进制哈希、Linux revision、内核指纹、每次原版执行结果及实际 native 计数。

两个 helper 在上游均属于 `TEST_GEN_FILES`。**本批不代表完整 `mptcp_sockopt.sh` 已迁移**：该脚本还包含多地址拓扑和 packet mark/iptables 路径。本批后仍有 9 个完整注册 shell 入口待迁移；已完成的完整入口仍是 `pm_netlink.sh` 默认模式。TCP-AO 的 24 个入口和已记录的 6 个上游 XFAIL 独立统计，不与 MPTCP helper 配置混算。
