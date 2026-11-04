# Linux 原版 AF_UNIX 测试

AF_UNIX 属于必测接口范围。本批使用固定 Linux stable 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 的原版 `tools/testing/selftests/net/af_unix/` 程序及 kselftest harness，保留源码、断言和 fork 行为。

| 原版程序 | 子用例数 | 范围 |
|---|---:|---|
| `diag_uid` | 2 | UNIX socket inode/cookie、诊断 UID 与 user namespace |
| `msg_oob` | 40 | UNIX 紧急数据、peek、inline、mark、SIGURG 和 epoll，与宿主 TCP 对比 |
| `scm_pidfd` | 4 | pathname/abstract、stream/datagram、pidfd 与凭据 |
| `scm_rights` | 20 | FD 引用图、环、listener 与 OOB 变体及 UNIX socket 回收 |
| `unix_connect` | 8 | pathname/abstract、stream/datagram 与 network namespace 隔离 |

共 **5 个程序、74 个子用例**。每个程序分别执行宿主基线与 Ker socket preload 适配运行，原版 TAP 用例列表必须完全一致，且不得有失败、跳过或 expected failure。不是将两次运行合计为 148 个上游用例。

## 执行后端

当前多进程应用使用的 `libker-socket-preload` 将 AF_UNIX 和 AF_NETLINK 留在宿主，因此 `diag_uid` 的诊断查询与目标 UNIX socket 属于同一内核。测试加载实际生产适配库，验证其 socket、message I/O、FD 管理、fork、ioctl 和 epoll 路径；不初始化进程内 LKL 内核，也不把宿主 AF_UNIX 成功记为导入内核 AF_UNIX 通过。

原版 `msg_oob` 用同一内核的 TCP 作为 UNIX urgent-data 比较基准。测试专用 observer 仅在此程序中让 TCP 参考 socket 使用宿主系统调用；AF_UNIX socket 仍调用实际生产适配库。其余 FD 操作仍经过 Ker preload 的宿主分支。该 TCP 参考不计入 Ker TCP 覆盖，也不放宽生产适配库对未配置 broker 的 INET socket 拒绝行为。

observer 核对实际 `socket` 符号的库路径、Ker 专用导出符号以及 runtime-ready 状态，并记录 UNIX 操作和宿主 TCP 参考。缺少/替换适配库会使测试失败。`unix_connect` 另有 UNIX socket 失败注入对照，要求原版断言确实失败。

测试发现并修复了适配层的一个宿主 IPC 边界：未配置 broker 时，host-only epoll 应使用宿主 epoll；配置了 broker 时继续使用原有组合 epoll 路径。修复前，在相同 observer 和成功的宿主基线下，原版 `msg_oob` 于 epoll 创建断言失败；修复后 40 个子用例通过。生产协议实现不变。

## 构建与证据

使用与 [Linux 原版协议测试](linux-protocol-tests.md) 相同的 `KER_BUILD_LINUX_PROTOCOL_SELFTESTS=ON` 选项。完整 native testing build 构建实际 preload、observer 和五个原版程序后运行：

```bash
ctest --test-dir build-native-on -R '^linux-original-af-unix-' --output-on-failure
```

每次执行前后校验原版源文件、`kselftest_harness.h` 和 `kselftest.h` 与固定 Git blob 完全一致。`linux-original-af-unix-*.json` 保存源码/程序/适配库/observer 的 SHA-256、两种运行输出、具体 TAP 用例列表及 observer 记录。CTest 使用独立 user/network namespace 和工作目录，不改写上游文件。CI 必须注册并运行全部五项，拒绝缺失和跳过，证据沿用 native reports artifact。

## 覆盖边界

本批记录为 `PASS_HOST_COMPATIBILITY`，与 [导入内核协议测试](linux-protocol-tests.md) 分开统计。已有 Ker 编写的 broker/SCM_RIGHTS 等回归也不冒充原版用例。

直接使用 `libker-posix` 时，进程内 native 内核初始化后的 fork 仍明确不支持；其 AF_UNIX 宿主透传与 native AF_NETLINK 混合诊断边界不在本批多进程 preload 结果之内。带 native capability 的混合 FD 传递也需要独立合同验证，不能由这些纯宿主 UNIX socket 用例推断支持。
