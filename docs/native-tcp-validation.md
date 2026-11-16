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

## 2026-11-16 接收半关闭回归

基于集成分支提交 `3c9eafb16`，在独立分支 `test/native-tcp-shutdown-read` 新增
`native-fstack-tcp-shutdown-read`。宿主参考、原生客户端与原生服务端分别验证
空队列和已排队数据的本地接收半关闭、dup 共享状态、低水位下的 EOF/readiness
和关闭原 fd 后的反向发送。每个原生角色要求至少五次对应 TCP open、真实
DPDK RX/TX 和 `outstanding=0`。

本次从固定 Linux/LKL 源码重新构建完整内核、Ker 适配库和测试，使用默认
`config/native-linux.defconfig`；构建器确认原始协议路径不变，CMake 通过
输入 fingerprint、配置和库指纹校验。Linux release 为 `6.12.113+`，
配置 SHA-256 为 `3aca0137b1852368b19da5f9667df1c89a26799009548b5fe9cf9fa09d590400`，
生成源码 tree 为 `b93ff967656b4af400da830a7b2193a2a69e0529`；
原始 `net/` 和 `include/net/` tree 与上述首版记录一致。

Debug 全量 CTest **190/190 通过**（无 skip），其中 `native-tcp` 标签
**42/42**、`native-udp` 标签 **25/25**；标签可能重叠，不合并计数。
新增测试通过宿主参考、原生客户端和原生服务端；两个原生实例各记录五次
对应 TCP open，并确认 DPDK RX/TX 非零及 `outstanding=0`。运行命令：

```sh
ctest --test-dir /tmp/ker-shutdown-read-build --output-on-failure --parallel 3 --no-tests=error
```

本次未重跑 sanitizer、安装或物理 NIC 验收，不作性能声明。

## 2026-11-16 host thread 创建失败回滚

集成基线 `3fc8bf1a1` 使用的固定 LKL host callback 在 pthread_create 失败时
未释放 start wrapper。本批先加入 EAGAIN/EPERM 注入检查：修复前 Debug
`native-fstack-thread-runtime` 在 allocation-balance 断言失败；移入 Ker 适配层
修复（来源 `4f99cadba`）后，该测试通过。错误返回零句柄和对应 errno，回调
不运行，分配余额归零；每次失败后的真实 create/join 验证成功参数及 wrapper
在例程入口前仅释放一次。原始 Linux 同样调用该 host callback 并正常启停。

重新构建当前 Debug Ker 库及全套测试后，**194/194 CTest 通过，无 skip**，
包含 native-tcp 标签 **43 项**、native-udp 标签 **25 项**（标签可能重叠）。
Release 直接编译相同 host-thread 适配器的线程测试 **1/1 通过**。构建与运行：

```sh
ctest --test-dir /tmp/ker-thread-create-build --output-on-failure --parallel 3 --no-tests=error
ctest --test-dir /tmp/ker-thread-create-release -R '^native-fstack-thread-runtime$' --output-on-failure --no-tests=error
```

两种构建均复用经 CMake fingerprint 验证的固定 Linux/LKL 库，未修改或重建
上游内核；未运行 sanitizer、Release 全套、安装或物理 NIC 验收。本批是实际
资源泄漏修复，不提升上游源案例状态，也不将 pthread 错误当成 FreeBSD
curcpu/pcpup panic 合同已迁移。

## 2026-11-16 host mutex 初始化回滚

在 `fdd15b2f3` 的线程创建修复上移入 Ker mutex 适配（来源 `3d0f68d03`）。
先加入 mutex-init EAGAIN 测试，修复前原 callback 返回非空无效对象而失败；
修复后 malloc、attribute init/type、mutex init 和 post-real attribute-destroy
故障均按 NULL/errno 回滚，正常/递归 mutex 可恢复并真实加解锁和销毁。

增加两个显式 DEBUG/NDEBUG CTest profile。子进程在有效 mutex destroy 上注入
EBUSY，要求 void callback SIGABRT；避免真正销毁已加锁 mutex 的未定义行为。
每个 profile 都执行此前线程创建失败回收、四线程 TLS/析构/计数，以及真实
Linux 启停和受监测的 mutex callback。检查使用 CHECK，不依赖 assert。

当前 Debug Ker 库和全套测试重新构建后，**196/196 CTest 通过，无 skip**。
优化 Release 构建下相同三个线程 profile **3/3 通过**。完整 Debug 运行包含
native-tcp 标签 45 项、native-udp 标签 25 项，标签可能重叠。原始内核库继续
复用通过 fingerprint 验证的固定产物；未修改 Linux/LKL 或网络协议代码，
未重跑 sanitizer、安装、物理 NIC 或完整 Release 套件。本批不提升源案例状态。

## 2026-11-16 host semaphore 失败边界

在 `1048a247e` 上整合 `89466bf0c` 的 Ker semaphore 适配。新增测试先以真实
SEM_VALUE_MAX 的 post 溢出复现原 callback 继续执行：修复前子进程未 SIGABRT，
测试失败；修复后实际 EOVERFLOW、注入的 wait/destroy EINVAL 均明确终止。
分配/init ENOSPC/ENOMEM 检查回收和 errno，正常信号量操作均调用真实 POSIX API。

DEBUG/NDEBUG 两种测试通过真实 pthread_kill(SIGUSR1) 使真实 sem_wait 返回
EINTR，确认重试且直到真正 post 才放行，随后 join、检查参数/结果并恢复信号
状态。各 profile 还启动/关闭固定原始 Linux，计数其实际 semaphore allocation。

重新构建 Debug 库及全套测试后，**198/198 CTest 通过，无 skip**；优化
Release 构建下两种 semaphore profile **2/2 通过**。全量运行包含 native-tcp
标签 47 项、native-udp 标签 25 项，标签可能重叠。复用通过 fingerprint 验证的
固定内核产物，未改动上游或重建内核，未重跑 sanitizer、安装、完整 Release
套件或物理 NIC。此为运行时同步扩展，不增加已迁移上游源案例数量。
