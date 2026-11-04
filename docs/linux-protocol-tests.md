# Linux 原版协议测试

F-Stack 场景适配只计回归覆盖，不能代替 Linux 自己的协议测试，也不增加下表的原版测试数量。Ker 编写的丢包、乱序、窗口、FIN 等导入内核集成用例，同样与原版 Linux selftests 分开统计。

## 已接入范围

测试直接编译固定 Linux stable 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 的 `tools/testing/selftests/net/` 源文件，不复制、改写源码或断言。

| CTest | 原版源文件与参数 | 验证范围 |
|---|---|---|
| `linux-original-sk-connect-zero-addr` | `sk_connect_zero_addr.c` | IPv6 未指定目标地址 `::` 的原版 listen/connect 断言 |
| `linux-original-tcp-inq-ipv4` | `tcp_inq.c -4` | IPv4 TCP_INQ 辅助数据及接收队列字节数 |
| `linux-original-tcp-inq-ipv6` | `tcp_inq.c -6` | IPv6 TCP_INQ 辅助数据及接收队列字节数 |

这是 **2 个原版程序、3 种运行配置**。它们使用导入 Linux 的 loopback，不证明外部 DPDK 数据链路、NIC 或 offload 行为，也不代表完整 TCP 状态机覆盖。上游 `tcp_inq` 的编译警告按上游不使用 `-Werror` 的方式处理；Ker 源码仍使用严格警告检查。

另有 `linux-original-reject-host-only` 对照：先在宿主机运行原版程序，再启动空闲的导入内核，确认宿主成功没有产生导入内核的 TCP open 计数。结果记为 `HOST_ONLY_REJECTED`，不计入原版协议测试通过数量。

## 执行与证据

`tests/posix/linux-original-selftest.py` 通过 `ker-run`、`libker-posix` 和实际 native Linux worker 运行程序；每次使用独立用户/网络命名空间。程序退出码必须成功，且导入内核 TCP MIB 的 active/passive opens 均须增长，资源 outstanding 必须归零。没有 native 连接活动的宿主机通过不能算作内核通过；不使用 broker 的非阻塞 API 合同替代原版阻塞 socket 语义。

运行前后将源文件字节与构建 manifest 中固定 Linux revision 的 Git blob 比较。生成的 `linux-original-*.json` 记录源码/二进制 SHA-256、Linux revision、内核构建指纹、参数、退出码、输出和实际 native 计数。源码变更、程序失败、缺少 native 活动或回收失败都会使 CTest 失败，不按 skip 处理。

在已有 [native Linux 构建](native-tcp.md) 的基础上：

```bash
cmake -S . -B build-native-on -DKER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON
cmake --build build-native-on --target ker-linux-selftest-sk_connect_zero_addr ker-linux-selftest-tcp_inq
ctest --test-dir build-native-on -R '^linux-original-' --output-on-failure
```

仅运行原版协议配置可使用 `ctest --test-dir build-native-on -L protocol-selftest`；宿主对照单独标记 `linux-upstream-control`。完整 runner 还需要已有 native 构建的 `ker-posix`、`ker-io-worker` 目标以及 TAP PMD。

native CI 显式启用该构建选项，构建全部目标并运行完整 CTest 图。CI helper 同时要求这 4 个 CTest 出现在清单和 JUnit 结果中，拒绝缺失、失败和跳过，避免选项被关闭后静默减少覆盖。

## 仍未覆盖

当前固定 native 内核配置未启用 `CONFIG_KUNIT`；没有把 KUnit 结果算作通过。固定 Linux 源码中的 `tools/testing/selftests/net/packetdrill` 尚未接入 Ker 执行。Linux 完整 networking selftests 也尚未跑完。

TCP 握手、ACK/窗口、重传、拥塞控制以及 FIN/RST 状态转换的原版测试覆盖仍需继续补齐。已有 F-Stack 回归、Ker 自编互通和本页首批原版 selftests 不能消除此缺口。
