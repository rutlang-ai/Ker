# 原生 TCP 首版验收记录

2026-10-18 在 x86_64 Fedora 主机运行。宿主 Linux 为 `7.2.11-200.fc44.x86_64`，GCC `16.2.1`，CMake `4.3.0`。实际导入内核 `6.12.113+` 与宿主不同。此记录覆盖软件设备和独立宿主 TCP 对端，不代表物理 NIC 或生产负载认证。

| 验收 | 结果 |
| --- | --- |
| Debug 构建全量 CTest | 101/101，通过；包含 96 个基础/F-Stack 适配用例和 5 个原生 TCP 用例 |
| RelWithDebInfo，原生 TCP 标签 | 5/5，通过 |
| 关闭 DPDK 与完整后端 | 基础构建与 3/3 测试通过 |
| UBSan，原生 TCP 标签 | 5/5，通过；适配库、worker、guard 和测试程序启用 undefined sanitizer，遇错停止 |
| ASan + UBSan，原生 TCP 标签 | 5/5，通过；适配库、worker、guard 和测试程序启用 address/undefined sanitizer |
| 安装后程序 | 安装目录中的 launcher、guard、worker、共享库完成主动/被动互通和 fd 兼容测试 |
| 外部 CMake 项目 | `find_package(ker CONFIG REQUIRED)`，链接 `ker::posix`；经安装 launcher 的默认路径运行，查询实际 release 和能力位成功 |
| 既有程序 | curl `8.18.0` HTTP；`redis-server` 命令提供的 Valkey `9.0.6` 完成 32 个连接、16 并发、1024 SET/GET 对与 SHUTDOWN |
| 固定源码构建重放 | 重用生成工作树、配置和输出成功；协议目录与原始 Linux tree 一致 |

ASan 的导入内核库未重新插桩，`detect_leaks=0`；该结果用于检验 Ker API/runtime 边界的内存访问，不声称覆盖完整内核内部访问或泄漏。包内存回收另由每次真实 DPDK 关闭后的 `outstanding=0` 断言验证。ASan 运行时通过实际 ELF 共享库预加载到应用前，不能将发行版 GCC 的 linker script 当成 LD_PRELOAD 库。

本次生成源码的 tree 为 `b93ff967656b4af400da830a7b2193a2a69e0529`，原始 Linux `net/` tree 为 `186d3489061cdfd3f30fdabba198c6979715de46`，`include/net/` tree 为 `2b87c88e520d2eb49c3f61d2dfd4b5fec1749048`。生成配置 SHA-256 为 `4916eea50ce67218228aa2af2eb667954298488927a104a0052377f132e6be5e`。具体输出库的 SHA-256 随编译器和构建环境变化，保存在各次构建记录中。

运行步骤、协议计数断言、依赖与首版兼容限制见 [部署和验收说明](native-tcp.md)。

## 2026-11-15 vectored I/O 回归

在本地旧基线 `e78413c78` 加入此测试及已有 rollback 用例后，
Debug 构建 `build-fstack-native-vectored` 全量 CTest **108/108 通过**，其中
原生 TCP 标签 **6/6 通过**。包括工作区已有的 6 个 chain/TX rollback 用例，
以及本次新增的 `native-posix-tcp-vectored`。新增用例在主动、被动两种角色下
通过实际 DPDK `net_tap` 与独立宿主 TCP 对端互通，每向验证 262147 字节，
覆盖交替 vectored/message I/O、空 iovec、短写偏移重试、peek/waitall、
半关闭后反向发送和 EOF/RDHUP；两种角色均检查原生连接计数、DPDK 收发及
`outstanding=0`。

本次 CMake 使用本地已有的固定 Linux/LKL 构建（`bridge-mdb` 输出，含额外
bridge 配置），配置 SHA-256 为
`52c1079078cb67a15c268e91b069610f5dea5b6b120115c73e677b2eb9e28b7a`。
CMake 校验固定提交及配置/库指纹通过；本次重新编译 Ker 库与测试，未重新
编译完整内核，也未重跑安装、sanitizer 或物理 NIC 验收。上述历史验收记录
仍对应各自当时的构建。
