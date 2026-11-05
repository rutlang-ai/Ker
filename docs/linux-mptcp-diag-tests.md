# 完整原版 MPTCP diag.sh

直接执行固定 Linux stable 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 的完整 `tools/testing/selftests/net/mptcp/diag.sh`。脚本、库、`mptcp_connect.c`、参数、循环次数和断言均保持原样，全部 **29 项 TAP 检查**必须通过，禁止 skip、IGNORE、TODO 和不完整计划。

覆盖监听 socket 的目标/源端口与地址过滤，MP_CAPABLE 握手、remote key、TCP fallback，最后收发/ACK 时间，MPTCP in-use 与 established 计数、清理，以及原版的 100 组并发连接和 100 个 listener。helper、KUnit 和完整脚本分开统计；本批完成一个注册 shell 入口，剩余 **7 个**。

## 实际内核与工具

所有连接运行在同一个真实导入内核的原版 loopback 和 network namespace 中。私有常驻服务的线程执行实际 socket、fcntl、poll、shutdown、Netlink 和 proc 操作；协议、诊断过滤、状态与计数都由原版 Linux 实现。未修改生产 facade 或 Linux 源码。

原版 `ss` 和 `nstat` 从固定 iproute2 **6.12.0** 编译，归档 SHA-256 为 `bbd141ef7b5d0127cc2152843ba61f274dc32814fa3e0f13e7d07a080bef53d9`，由 `tools/ci/build_iproute2_diag.sh` 下载、校验和构建。它们通过只在本测试使用的 preload 读取原生 Netlink/proc；不生成替代的 `ss` 列表、MPTCP 状态或计数器值。

`ip` scaffold 只转换命名空间生命周期、loopback、sysctl 和执行上下文。原版 cat/grep/awk/nstat 读取真实 proc 字节。常驻进程的线程位于不同 native netns，`/proc/net/*` 因而映射到 `/proc/thread-self/net/*`，避免 Linux 的 `/proc/self/net` 指向常驻进程 leader 的 namespace。此映射只存在于私有 fixture。

Netlink 消息和多 iovec 数据通过测试通道搬运，保留地址、控制消息、flags 和 `MSG_PEEK|MSG_TRUNC` 长度。poll 使用实际 native poll 的短片段维持原版总超时，让宿主 SIGUSR1 能正常终止原版 helper；被信号中断的通道响应先收完整，避免后续调用读到前一条响应。此 fixture 不安装，不承诺通用跨进程 fd 继承或全部 socket API。

## 证据与负对照

完整执行必须产生 403 个 MPTCP socket 创建、202 次 accept、402 个协商端点和 1 个 fallback 端点，并曾同时持有至少 200 个实际 native socket。另检查实际 native descriptor kind、Netlink 活动、所有 socket 关闭、namespace pin 删除、内核/worker 正常退出与 packet outstanding 归零。

同时创建第二个真实 namespace 进行隔离对照：在主测试至少有 200 个 native socket 活跃时，原版 `ss` 和 native proc 必须仍显示对照 namespace 为空。两者均须最后删除。原版 namespace 清理 helper 的 `grep -v` 因而也能看到一个真实的不匹配项；没有伪造 namespace listing。

`linux-original-mptcp-diag.json` 保留 Linux revision、内核指纹、原版文件哈希、工具归档及二进制证明、完整输出、29 项检查、并发/隔离证据和清理计数。CI 强制检查该 CTest 在 inventory 和 JUnit 中出现并通过；不支持的边界明确失败。

流量在导入内核内部，不能由这些结果推断外部 DPDK 路径、MP_JOIN、多子流恢复或其余脚本已完成。原有 MPTCP helper、KUnit 和 TCP-AO 测试继续独立运行。

## 重现

```bash
bash tools/ci/build_iproute2_diag.sh /path/to/iproute2-diag
cmake -S . -B build-native-on -DKER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON \
  -DKER_MPTCP_DIAG_TOOLS_DIR=/path/to/iproute2-diag
cmake --build build-native-on
ctest --test-dir build-native-on -R '^linux-original-mptcp-diag$' --output-on-failure
```

使用已有 native Linux/DPDK 配置和 manifest。可执行 shim 放在实际 binary 所在的可执行目录，避免 `/dev/shm` 的 noexec 挂载影响它们；socket 和测试数据可留在 `/dev/shm`。
