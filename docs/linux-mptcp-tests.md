# 原始 Linux MPTCP 执行与首批 selftest 场景

固定 Linux stable 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`。native 内核启用原版 `CONFIG_MPTCP=y`、`CONFIG_MPTCP_IPV6=y`；未修改 Linux 网络协议代码。应用通过已有 POSIX facade 创建 `IPPROTO_MPTCP` socket，握手、DSS、重传与关闭均由原始 Linux 处理。

## 本批执行范围

使用固定源码中未修改的 `tools/testing/selftests/net/mptcp/mptcp_connect.c`，Ker 与独立宿主对端均运行该原版程序。保留程序中的 ULP/socket 检查及收发实现。

| CTest | 原生角色 | 配置 |
|---|---|---|
| `linux-original-mptcp-ipv4-client` | IPv4 客户端 | poll / mmap / sendfile + TCP-only 对端回退对照 |
| `linux-original-mptcp-ipv4-server` | IPv4 服务端 | 同上 |
| `linux-original-mptcp-ipv6-client` | IPv6 客户端 | 同上 |
| `linux-original-mptcp-ipv6-server` | IPv6 服务端 | 同上 |

共 **12 个 MPTCP 协商与双向数据配置，加 4 个 TCP 回退对照**。逐方向比较超过 48 KiB 的不同内容，完整保留二进制字节与尾部；检查 DPDK TX/RX、原生 opens 和 packet outstanding 归零。

这些是原版 helper 的首批 Ker 执行场景。上游将 `mptcp_connect` 列为 `TEST_GEN_FILES`；本批不把它或 4 个 CTest 冒充为 4 个上游 shell 入口迁移完成。

## 证明实际协商与测试适配

native 诊断读取原始 Linux `MPTcpExt` MIB，并导出 MP_CAPABLE SYN/SYNACK/ACK 与 fallback 计数。正常场景必须有对应客户端/服务端握手计数，且 fallback 为零。DPDK 抓包必须同时包含 MP_CAPABLE 握手和 DSS 数据选项。TCP-only 对端即使传输完整，也必须无法通过 MPTCP 协商判定；对照结果不计 MPTCP 成功。

原版 `mptcp_connect` 源文件保持字节一致。链接的 Ker 测试辅助代码只观察实际 listen 成功，以文件标记通知 runner，不用固定延时猜测监听就绪。

`sendfile` 场景将其不可变输入准备为导入内核中的只读文件，然后调用原版程序与原版 Linux sendfile。私有准备入口只在 tests-ON 库中存在，不安装为公共 API。这样输入 fd 与 socket fd 属于同一个内核；生产 facade 对跨宿主/原生 fd 的 sendfile/splice 拒绝合同保持不变。本批不宣称支持跨内核文件零拷贝。

`linux-original-mptcp-*.json` 记录 Linux revision、内核指纹、源码/程序哈希、每个配置的日志、原生统计与抓包解析。对应 captures 目录保留原始 PCAP；CI 上传 JSON 和 PCAP，要求全部四个 CTest 出现在清单和 JUnit 中且不跳过。

## 重现与剩余范围

用 `tools/build-native-linux.py` 重新构建启用 MPTCP 后的内核，原有指纹的内核不能冒用。native testing build 启用 `KER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON`，构建 `ker-linux-mptcp-connect` 后运行：

```bash
ctest --test-dir build-native-on -R '^linux-original-mptcp-' --output-on-failure
```

本批使用一条数据路径和一个子流。上游 10 个 shell 入口的完整拓扑/参数矩阵仍未完整迁移，包括多地址 PM、MP_JOIN、多子流恢复、故障注入、动态 endpoint/limits、诊断和重复连接等；不能由本批单子流 MP_CAPABLE/DSS 通过推断这些能力完成。独立宿主对端需要支持 MPTCP；不支持时测试失败，不用普通 TCP 成功替代。
