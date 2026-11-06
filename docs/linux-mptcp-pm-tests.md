# 原版 MPTCP 路径管理 selftest

固定 Linux 6.12.113 的 `tools/testing/selftests/net/mptcp/pm_netlink.sh` 已按默认 `pm_nl_ctl` 模式接入导入内核，共 23 项原版 TAP 检查。脚本、`pm_nl_ctl.c`、MPTCP shell library、network library 和 Makefile 均保持固定 Git blob 的原始字节，运行前后再次核验。原版工具使用同一固定源码生成的 UAPI 头文件。

覆盖默认地址表和 limits、地址增删/dump、重复地址、硬上限、ID 递增/回绕、flush、未知标志、非法 limits，以及 backup/fullmesh 标志切换。它是上游 10 个注册 shell 入口中的 1 个；[首批 mptcp_connect 配置](linux-mptcp-tests.md)不计为其他 shell 入口已经迁移。

## 跨进程共享真实内核状态

原版脚本每次启动独立的 `pm_nl_ctl` 进程；给每个进程新建 LKL 实例会丢失前一次命令的路径管理状态。因此测试使用一个常驻的导入内核实例，外部原版工具通过仅用于测试的本地传输访问它。

`linux-mptcp-pm-proxy.c` 通过链接包装适配工具的 Netlink socket/接口名称查询。Netlink 请求、属性、标志和内核回复，包括 `NLMSG_ERROR`，原样转发；它不解析或实现 MPTCP 路径管理命令。地址表、limits、ID 分配和错误语义均来自原版 Linux `net/mptcp/pm_netlink.c`。

测试专用 `ip` 适配脚本只处理原版入口需要的 namespace、loopback-up、sysctl 和工具执行操作。namespace 名称映射到真实导入内核 namespace fd；loopback 和 sysctl 由原版内核处理。原版工具的多个进程因此共享同一命名空间的真实状态。未支持的命令失败，不返回成功桩。宿主 `ip -Version` 和脚本的宿主文件存在性预检只检查执行条件；它们不计作导入内核覆盖。执行原版脚本前，还必须实际读取导入内核的 MPTCP enabled 状态。

常驻执行器仅在私有目录中提供同 UID 的本地测试接口；它和代理程序只在 tests-ON selftest 构建中生成，不安装为生产服务。行政 Netlink socket 与 loopback-up 操作使用私有测试 fixture；生产 facade 的 Netlink 权限策略不变。

## 验证与证据

`linux-original-mptcp-pm-netlink` 要求完整 23 项 TAP 检查，拒绝 failure、skip、IGNORE/Flaky、TODO 或不完整计划。强制 `SELFTESTS_MPTCP_LIB_EXPECT_ALL_FEATURES=1` 与 `SELFTESTS_MPTCP_LIB_OVERRIDE_FLAKY=1`，防止特性缺失或 flaky 标记掩盖问题。

独立控制验证两个真实 namespace 的地址表隔离，以及后端不存在时工具必须失败，不能回退到宿主 Netlink。未知 fixture 操作必须返回 `EOPNOTSUPP`，畸形 transport frame 必须被拒绝且不能停止真实内核。常驻内核必须正常结束，namespace/Netlink socket 和 packet outstanding 都必须回收。

首次验证的实际记录为 564 个 native Netlink socket、1128 次请求与回复、3 个 namespace 创建/删除、3 次 sysctl 写入、1 次 loopback-up。地址表隔离控制不增加上游注册入口或 TAP 检查数量。控制面测试没有数据连接，不据此宣称 MP_JOIN、多子流吞吐或外部 DPDK 互通通过。

CI 将该 CTest 列为必跑项，禁止缺失或跳过。`linux-original-mptcp-pm-netlink.json` 保存源码/工具/执行器/facade 哈希、内核指纹、原版输出、控制结果、真实 native 操作与资源回收证据。

```bash
cmake -S . -B build-native-on -DKER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON
cmake --build build-native-on --target ker-linux-mptcp-pm-server ker-linux-mptcp-pm-nl-ctl
ctest --test-dir build-native-on -R '^linux-original-mptcp-pm-netlink$' --output-on-failure
```

当前入口使用原版 `pm_nl_ctl` 默认模式，不宣称已经支持 `pm_netlink.sh -i` 的 iproute2 模式或其他脚本的任意 ip/tc/iptables 命令。后续 [userspace PM](linux-mptcp-userspace-pm.md)已覆盖原版事件监听，[完整入口汇总](linux-mptcp-join.md)记录 10 个默认 shell 入口的本地通过结果。任意非默认参数和外部 DPDK 多路径互通不由此推断。
