# 原生 Linux POSIX TCP

此组件提供可运行的 IPv4 TCP 初版，优先接入现有 POSIX socket 应用。应用调用普通 `socket`、`connect`、`listen`、`accept`、`read/write`、`send/recv` 与事件接口；`ker-run` 加载 API 适配库并启动 DPDK Ethernet worker。握手、ACK、窗口、重传、拥塞控制、重组与关闭全部由原始 Linux 执行。

## 源码与架构

完整内核使用 Linux stable **6.12.113**，提交 `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`；用户态架构来自 LKL `d0f76a77e8c2ca68bd7d96190b8da09040eab072`。完整 pin 和受保护路径见 [`config/native-linux.json`](../config/native-linux.json)。它独立于现有 `third_party/linux` 的基础代码移植，避免将两个版本的内部结构混用。

构建器先确认 LKL 相对其基线没有修改 `net/`、`include/net/` 及受保护的网络接口，再将固定的 LKL 架构/runtime 变更应用到稳定版的生成工作树。Ker 只增加 `asm/ring_buffer.h` 包装头以引入原始 generic 实现，不覆盖上游文件。构建前后校验协议源码未变。构建记录包含原始网络目录 tree、生成源码 tree、配置与内核库 SHA-256；CMake 校验配置和库的指纹，启动时校验实际内核 release。

每个应用进程运行独立的原生内核，初始内存 64 MiB。原生 virtio-net 设备通过有界 UNIX datagram 通道连接 DPDK worker。worker 只转发 Ethernet，不建立 TCP 连接，不转发宿主 socket 字节流。第一版复制报文，固定 MTU 1500、单 RX/TX 队列，关闭 checksum/TSO/LRO/VLAN strip 等卸载。未支持的卸载请求报错；接收变形元数据的帧被丢弃并计数。

应用 fd 使用真实宿主占位描述符保留编号，表中持有私有 Linux fd；不会根据编号大小猜测后端。引用保护支持并发操作与关闭。宿主文件、pipe、UNIX socket 和原生网络 socket 可共同用于 poll/select/epoll；混合等待以最多 1 ms 的间隔检查原生就绪。协议定时器由原生内核运行。

## 可复现构建

验证平台为 x86_64 Linux、glibc、GCC。需要 Python 3、CMake ≥3.20、make、Git、Meson、Ninja、pkg-config、flex、bison、bc、libelf 和 OpenSSL 开发包，以及 DPDK 的构建依赖。以下路径为构建时选择，可改用工作目录以外的位置：

```sh
git submodule update --init --recursive --depth 1
KER_DPDK_DRIVERS=mempool/ring,net/ring,net/tap \
KER_DPDK_LIBS=eal,ring,mempool,mbuf,ethdev,gso \
  bash tools/build-dpdk.sh
python3 tools/build-native-linux.py --build "$PWD/build-native-linux" --jobs 16
cmake -S . -B build-native-tcp \
  -DKER_WITH_NATIVE_TCP=ON \
  -DKER_NATIVE_LINUX_BUILD="$PWD/build-native-linux" \
  -DKER_DPDK_PKGCONFIG_DIR="$PWD/third_party/dpdk/install/lib64/pkgconfig" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-native-tcp -j16
ctest --test-dir build-native-tcp --output-on-failure
cmake --install build-native-tcp --prefix "$PWD/build-native-tcp/install"
```

构建器的 Git cache 默认位于 `$XDG_CACHE_HOME/ker/native-linux.git`（未设置时为 `~/.cache/ker/native-linux.git`），可通过 `--cache` 指定。它按精确提交下载；重复运行复用已验证源码与输出，不更新依赖。源码已修改或记录不一致时停止。它还构建 LKL 自带的 hijack 库作为上游工具产物，但 Ker 不加载该库，POSIX API 转换由 `src/posix` 提供。

安装产物为 `bin/ker-run`、`bin/ker-app`、`bin/ker-io-worker`、`bin/ker-socket-echo`、`lib*/libker-posix.so`、公共头与 CMake target `ker::posix`；build/source 记录和 Linux 许可文本位于 `share/ker/native-linux`。完整生成源码保留在构建记录的 `source` 目录；分发内核库时应一并保留对应源码、配置和构建材料。此构建包含 Linux 的 GPL-2.0 代码。

## 启动现有应用

为每个实例独占一个 DPDK ethdev，并在外部配置好设备驱动、权限、hugepage、peer 与路由。选择已构建的 PMD。示例中的 PCI 地址、CPU、IP 和网关需替换为部署环境值：

```sh
PREFIX="$PWD/build-native-tcp/install"
"$PREFIX/bin/ker-run" \
  --address 192.0.2.2/24 --gateway 192.0.2.1 \
  --port 0000:03:00.0 \
  --eal '-l 2 --no-telemetry -a 0000:03:00.0' \
  --stats /tmp/ker-tcp.json \
  -- "$PREFIX/bin/ker-socket-echo" 0.0.0.0 9000
```

该命令的设备需要对应 NIC PMD；上面的最小构建仅包含用于验收的 `net_tap` 与 `net_ring`。物理 NIC 的驱动、性能和长期运行能力尚需在目标硬件上验收。echo 示例是未包含任何 Ker/LKL 头的普通 POSIX 程序，服务一个连接并在收到 EOF 后正常结束。

同样可以在 `--` 后放置现有 curl 或事件驱动服务。应用绑定 `--address` 的地址或 `0.0.0.0`。DNS 没有做完整透明适配，宿主 libc 内部 resolver 与应用自带 resolver 的路径可能不同；首版验收使用数字 IPv4 地址。应用需要自行验证所用 resolver 与部署路由。一个实例一个 IP/MAC；不要让多个实例同时使用同一网络身份。

需要查询原生能力的调用方可 `#include <ker/posix.h>` 并链接 `ker::posix`。`ker_posix_capabilities()` 返回当前实例的 DPDK/Linux/IPv4/TCP 位；`ker_posix_kernel_release()` 返回实际导入内核版本。直接运行链接此库的程序仍须由 `ker-run` 提供运行环境。基础库的 `ker_capabilities()` 保持原有语义。

## 自动验收

```sh
ctest --test-dir build-native-tcp -L native-tcp --output-on-failure
```

测试通过 `unshare -Urn` 创建独立用户/网络 namespace，使用真实 DPDK `net_tap`、veth 和独立宿主 Linux TCP 对端，不需要物理 NIC 或 hugepage。需要允许非特权 user/network namespace、可用 `/dev/net/tun`、`ip` 和 `tc`。环境不满足时测试失败并给出原因，不会假装已通过。

| 场景 | 断言 |
| --- | --- |
| 主动/被动连接 | 双向 1 MiB 校验、非阻塞 connect/accept、epoll、半关闭与 EOF |
| 丢包与乱序 | 双向 2% seeded loss、delay、reorder，数据完整；原生内核重传与乱序队列计数增长 |
| 零窗口 | 两个方向慢读和小接收缓存；原生窗口探测计数增长，恢复完整字节流 |
| 错误 | RST、ECONNRESET、EPIPE、SIGPIPE/MSG_NOSIGNAL、SO_RCVTIMEO、ECONNREFUSED、SYN 重传后 ETIMEDOUT |
| poll/select 就绪语义 | 8 个宿主/原生场景：监听、混合 pipe/TCP、重复条目与集合计数、失效 fd、OOB、SO_RCVLOWAT、EOF 和 timeout |
| F-Stack epoll 场景 | 8 个真实 TCP 场景与宿主 Linux 对照：ADD/MOD/DEL、64 位 userdata、LT/ET、oneshot、仅写就绪、半关闭与 RST；原生 active/passive open 计数必须增长 |
| 独立对端 message/vector stream | 三种 API（vector/message/batch）× 原生主动/被动角色；各方向 256 KiB + 13 字节、非阻塞短进度/重试、半关闭/EOF，逐实例检查原生 TCP 与 DPDK 计数 |
| F-Stack message/vector 场景 | 6 个宿主/原生 Linux 对照场景：sendmsg/recvmsg、readv/writev、地址查询、半关闭、非阻塞 ioctl 与 dup/dup2；原生连接计数验证，UNIX socket 明确为宿主透传 |
| fd 兼容 | 600 个宿主文件、高编号原生 fd、dup/fcntl/fstat、混合 poll/select/epoll、oneshot、多线程 churn |
| 信号等待 | ppoll/pselect/epoll_pwait/epoll_pwait2 原子解除阻塞、EINTR 与掩码恢复 |
| 隔离与回收 | 宿主已占用的端口仍可在原生 loopback 使用；直接宿主 TCP syscall 被拒绝；worker mbuf outstanding=0 |
| 现有应用（检测到程序时启用） | 原版 curl HTTP；原版 Redis/Valkey 无持久化、32 个连接、16 并发、1024 SET/GET 对及正常 SHUTDOWN |

独立的 [原生 UDP 验证](native-udp-validation.md) 另行检查 UDP socket，使用原生 UDP 计数证明路径。

这些测试运行的是完整导入内核的 TCP，区别于基础库的 F-Stack 报文 view、checksum 和生命周期适配用例。`--stats` 同时输出 Ethernet、重试/丢弃/mbuf 与原生 TCP 计数，便于追溯。

正常退出先关闭应用原生 fd，再让原始 Linux 处理待确认发送队列，默认等待最多 5 秒，可用 `--shutdown-timeout-ms 0..60000` 调整。超时或启动/设备/退出不完整返回 125；其余正常应用返回值保留。SIGKILL、`_exit` 和宿主崩溃不能进行正常排空。应用应正常关闭连接后退出。

## 首版兼容范围

支持 x86_64 Linux/glibc 的动态链接应用，IPv4 TCP、常用 socket option、普通及 vectored/message I/O、dup/fcntl/ioctl/fstat、poll/select/epoll 及上述信号掩码等待接口。宿主文件等非网络 fd 继续走宿主。其他网络协议未作为本次交付验收范围，IPv6 当前关闭。

以下边界尚未兼容，迁移应用时必须核对：

- 不支持初始化后 fork/daemonize，child 明确退出 125。服务使用前台模式；Redis/Valkey 测试关闭需要 fork 的持久化功能。每个新进程应由独立 `ker-run` 启动，不能通过 exec 或 SCM_RIGHTS 继承原生 fd。
- 静态链接、直接 syscall、io_uring、libc 内部未导出的 I/O 入口无法由 LD_PRELOAD 完整适配。`fdopen`/stdio、sendfile/splice、close_range 不支持原生 fd；这些入口可能得到占位 fd 的错误，不能将其视为已兼容。guard 拒绝直接创建宿主 TCP，启动握手保证未加载原生库时不能成功验收。
- 阻塞原生 socket 操作由 Linux 执行，宿主信号尚不能打断这类调用。适配入口也尚未实现 libc 的 pthread cancellation point 兼容（包括这些入口上的宿主 fd I/O）。需要中断控制的服务使用非阻塞 socket 加事件等待，或 socket 超时。SIGIO/O_ASYNC 明确返回 EOPNOTSUPP。
- 不支持嵌套的混合域 epoll，明确返回 EOPNOTSUPP。select 受宿主 FD_SETSIZE 限制，原生应用 fd 上限 65536（同时受宿主 RLIMIT_NOFILE 限制）。混合等待采用轮询桥接，不承诺亚毫秒唤醒。
- 原生内核与宿主的 namespace、路由、loopback、sysctl、文件系统和 PID 不相同；应用访问宿主 `/proc` 不会自动重定向到原生内核。第一版只公开启动参数与诊断计数，不提供宿主网络管理工具的透明重定向。

本次构建与验收环境见 [首版验收记录](native-tcp-validation.md)。此范围已覆盖前台运行的普通非阻塞 POSIX TCP 应用和上述现有程序。多进程透明兼容、零拷贝、多队列、IPv6 与物理网卡的交付验收属于后续扩展。
