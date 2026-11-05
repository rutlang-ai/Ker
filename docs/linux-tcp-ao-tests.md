# 原版 Linux TCP-AO selftests

固定 Linux 6.12.113 的 `tools/testing/selftests/net/tcp_ao/Makefile` 注册了 12 个程序配置，各运行 IPv4/IPv6，共 24 个入口。本批全部接入 CTest，使用原版程序和原版 aolib 的断言、拓扑、密钥/算法矩阵、计数检查、TCP repair 与 tracepoint 检查；没有修改这些上游文件。`icmps-accept.c` 是上游指向 `icmps-discard.c` 的符号链接，通过上游定义 `TEST_ICMPS_ACCEPT` 区分行为。

覆盖 `bench-lookups`、`connect`、`connect-deny`、`icmps-accept`、`icmps-discard`、`key-management`、`restore`、`rst`、`self-connect`、`seq-ext`、`setsockopt-closed` 和 `unsigned-md5`。这是导入内核自身的测试，不是用 F-Stack 回归替代内核测试。

## 执行边界与适配

两个对端和它们的 veth/VRF、网络命名空间都在同一个导入 Linux 实例内。它们使用真实 Linux TCP-AO/MD5、crypto、rtnetlink、procfs 和 tracefs；协议包经原版内核的内部 veth 传递。本批不宣称 TCP-AO 已经通过独立宿主对端或外部 DPDK 线缆互通验证。Ker launcher 的 DPDK worker 仍参与正常启动和回收，但此处不能以它的启动代替协议活动证据。

`linux-tcp-ao-adapter.c` 只适配测试基础设施：

- 将 namespace、proc/tracefs 文件操作交给实际 LKL syscall，并将 rtnetlink 中嵌入的 namespace fd 映射到同一个 Linux 文件表。
- 将原版线程应继承的网络命名空间带入新的 LKL host-thread task；没有将原版双命名空间拓扑合并。
- 用私有 tests-ON fixture 创建具有管理权限的 rtnetlink socket。普通 facade netlink 的权限拒绝策略保持不变。
- trace_pipe 用真实非阻塞内核读取与可取消的宿主等待衔接，保留原版 tracing 收集和 pthread_cancel/join 清理流程。
- 原版 aolib 会从 ELF destructor 再次调用 exit。适配层等它完成自身清理后，停止仍在服务的测试对端继续进入 facade，执行真实 Ker 内核回收，再转交原退出码。等待切片保持 select/poll 的原始期限，不产生假的连接结果。

这些 fixture 不提供协议实现。私有 `ker_linux_selftest_call` 只存在于 `BUILD_TESTING=ON` 的库中，不是安装的公共头文件/API；生产 tests-OFF 构建不包含该符号。原版 TCP-AO 断言仍决定测试结果。

内核配置启用 NET_NS、VETH、VRF、TCP_AO、TCP_MD5SIG、tracepoint 依赖及原版算法矩阵所需 crypto。selftest UAPI 由同一固定 Linux 源码生成，使用当前 native backend 支持的 x86-64 用户 ABI。源文件、aolib 和 kselftest 的 Git blob 在运行前后核验；符号链接的目标字符串与实际源文件分别核验。

## 结果与已知上游 XFAIL

24 个入口均完成，共记录 848 个通过断言、6 个上游预期失败。当前固定内核中，两个 `key-management` 配置各有 118 个通过断言和 3 个原版标注的 XFAIL。三项涉及 listen 前已设置的 current/rnext key：listen 后仍保留标记，以及无法删除这两个 busy key。这些分支在固定 `key-management.c` 中明确使用 `test_xfail`/`FAULT_FIXME`。

报告将它们单列为 `upstream_xfails`，状态为 `PASS_WITH_UPSTREAM_XFAIL`，不计入通过断言。只有这三个完整已知描述在该程序中获准；新增 XFAIL、任何失败、skip、xpass、错误、TAP 缺项或计划不符均使 CTest 失败。其余 22 个入口状态为 `PASS_IMPORTED_LINUX`。

每个 `linux-original-tcp-ao-*.json` 保留源码、程序和 facade 哈希、内核指纹、完整 stdout/stderr、TAP 通过断言与上游 XFAIL，以及真实内核 namespace/proc/netlink/mount 操作记录。socket 创建还核验 descriptor 确实属于 native facade。原版用例自行检查每 socket 和 proc TCP-AO 计数、认证拒绝、修复/回绕和预期 trace events；不会伪造这些证据。launcher 还要求正常内核退出与 packet outstanding 归零。

## 重现

依照 [native 构建](native-tcp.md) 重建当前 defconfig 对应的 Linux/LKL，安装 `rsync`（UAPI headers_install 依赖），然后：

```bash
cmake -S . -B build-native-on -DBUILD_TESTING=ON \
  -DKER_WITH_NATIVE_TCP=ON -DKER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON \
  -DKER_NATIVE_LINUX_BUILD=/path/to/native-linux-build
cmake --build build-native-on -j8
ctest --test-dir build-native-on -R '^linux-original-tcp-ao-' --output-on-failure
```

CI 强制要求全部 24 项出现在 inventory/JUnit 中，禁止跳过，上传 JSON 和完整 JUnit。此处完成的是固定版本 TCP-AO 目录的 24 个注册入口；[MPTCP 完整 shell 矩阵](linux-mptcp-tests.md)仍单独记录为未完成。
