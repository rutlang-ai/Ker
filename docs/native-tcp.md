# 原生 Linux POSIX TCP

此组件将原始 Linux TCP 接入现有 POSIX socket 应用，支持 IPv4、IPv6 loopback、配置 IPv6 地址后的同链路 TCP/UDP，以及通过 IPv4 DPDK 链路互通的 IPv4-mapped 双栈连接。应用调用普通 `socket`、`connect`、`listen`、`accept`、`read/write`、`send/recv` 与事件接口；`ker-run` 加载 API 适配库并启动 DPDK Ethernet worker。握手、ACK、窗口、重传、拥塞控制、重组与关闭全部由原始 Linux 执行。

## 源码与架构

完整内核使用 Linux stable **6.12.113**，提交 `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e`；用户态架构来自 LKL `d0f76a77e8c2ca68bd7d96190b8da09040eab072`。完整 pin 和受保护路径见 [`config/native-linux.json`](../config/native-linux.json)。它独立于现有 `third_party/linux` 的基础代码移植，避免将两个版本的内部结构混用。

构建器先确认 LKL 相对其基线没有修改 `net/`、`include/net/` 及受保护的网络接口，再将固定的 LKL 架构/runtime 变更应用到稳定版的生成工作树。Ker 只增加 `asm/ring_buffer.h` 包装头以引入原始 generic 实现，不覆盖上游文件。构建前后校验协议源码未变。构建记录包含原始网络目录 tree、生成源码 tree、配置与内核库 SHA-256；CMake 校验配置和库的指纹，启动时校验实际内核 release。

每个应用进程运行独立的原生内核，初始内存 64 MiB。原生 virtio-net 设备通过有界 UNIX datagram 通道连接 DPDK worker。worker 只转发 Ethernet，不建立 TCP 连接，不转发宿主 socket 字节流。第一版复制报文，固定 MTU 1500、单 RX/TX 队列，关闭 checksum/TSO/LRO/VLAN strip 等卸载。未支持的卸载请求报错；接收变形元数据的帧被丢弃并计数。

应用 fd 使用真实宿主占位描述符保留编号，表中持有私有 Linux fd；不会根据编号大小猜测后端。引用保护支持并发操作与关闭。宿主文件、pipe、UNIX socket 和原生网络 socket 可共同用于 poll/select/epoll；混合等待以最多 1 ms 的间隔检查原生就绪。协议定时器由原生内核运行。原生 realtime 时钟在启动时从宿主 CLOCK_REALTIME 初始化，供软件收包时间戳等使用；monotonic clocksource 保持上游行为，启动后的宿主墙钟调整尚不持续同步。

UDP 多播接收需显式给 `ker-run` 添加 `--all-multicast`，请求 DPDK ethdev 接收所有多播帧，
由原始 Linux 按 socket 成员关系过滤。设备无法启用该模式时启动失败；动态 MAC group
订阅尚未跨 packet channel 传播。已验证的 net_tap 场景见 [UDP 验证](native-udp-validation.md)。

可选 `--pcap-dir` 抓取 DPDK 收发帧；支持 snaplen、微秒/纳秒时间戳及十文件滚动，
用法与抓包边界见 [PCAP 抓包](packet-capture.md)。

## 双栈 socket 边界

应用可创建 AF_INET6 socket：IPV6_V6ONLY=1 允许 IPv6 与 IPv4 监听器使用同一端口；
设为 0 时，IPv4-mapped 地址使用原始 Linux 的双栈 TCP 实现，仍通过既有 IPv4
DPDK 链路互通。IPv6 loopback `::1` 也已验证。内核配置变化后须重新运行构建器；
旧配置的原生库会被输入指纹校验拒绝。

关闭排空同时读取 `/proc/net/tcp` 和 `/proc/net/tcp6`，包括 IPv4-mapped 连接。
IPv6 协议由上游 Linux 实现，Ker 只适配其配置、API 和排空设施。
`ker-run --address` 配置 IPv4；可选 `--address6 2001:db8:1::2/64` 或 `[network] address6`
同时安装 IPv6 地址。配置 IPv6 时，worker 自动启用 all-multicast 接收以允许 NDP；
即使指定 `--no-all-multicast` 也保留这一必需条件，原始 Linux 负责实际协议过滤。
设备无法启用接收模式会导致启动失败。LKL 在接口启用后经原始 rtnetlink 添加地址，
等待 Linux 重复地址检测完成才发布 native READY；重复地址会使启动失败。
CLI 覆盖 INI；拒绝带 scope 的地址、未指定地址、多播、loopback 与 IPv4-mapped 地址。

`native-fstack-ipv6-interop` 用真实 DPDK net_tap 与独立宿主 peer 验证 IPv6 TCP/UDP
双向收发、显式源地址绑定、NDP 得到的 MAC、同次运行中的 IPv4 TCP，以及重复地址拒绝。
IPv4 `--address` 仍必需。可选 `[network] gateway6` / `--gateway6` 配置默认网关，
要求同时配置 `address6`；支持 global 和不带 scope 的 link-local 下一跳。CLI 覆盖 INI。
Ker 只向私有原始 Linux 的 main 路由表发送带明确出接口的 rtnetlink 请求，内核验证
网关可达性；非法下一跳导致启动失败，不使用 ONLINK 标志绕过校验。宿主路由不变。
`native-fstack-ipv6-route` 在原生内核、独立 Linux 路由器、远端 Linux 网络命名空间
之间验证跨网段 TCP/UDP 双向收发。UDP 两端检查 hop limit 从 64 减为 63，路由器
转发计数必须增加；另验证省略网关不自动安装默认路由、非法 off-link 网关阻止应用启动。
RA/SLAAC 部署、路由更新/故障切换及物理网卡过滤尚未验收，
能力查询位保持既有定义。

多个 IPv6 地址可用 `[network] vip_addresses6=2001:db8:1::3/128,2001:db8:1::4/128`
或重复 `--vip-address6 2001:db8:1::3/128 --vip-address6 2001:db8:1::4/128`。
要求主地址 `address6`，最多 32 个 VIP；CLI 替换整个 INI 列表，省略时不继承环境中的内部配置。
地址必须为不重复的原生单播 IPv6 地址/前缀。VIP 与主地址共用同一个 Linux 接口，
由原始 rtnetlink 和 DAD helper 添加并确认；不创建 FreeBSD `vip_ifname` 接口。
`native-fstack-ipv6-vip` 验证主地址及两个 /128 VIP 的双向 TCP/UDP、NDP、
源地址、内核计数、完整清理，以及全部 32 个 VIP 的绑定和宿主冲突地址拒绝。

## 可复现构建

验证平台为 x86_64 Linux、glibc、GCC。需要 Python 3、CMake ≥3.20、make、Git、Meson、Ninja、pkg-config、flex、bison、bc、libelf 和 OpenSSL 开发包，以及 DPDK 的构建依赖。以下路径为构建时选择，可改用工作目录以外的位置：

```sh
git submodule update --init --recursive --depth 1
KER_DPDK_DRIVERS=mempool/ring,net/ring,net/tap,net/virtio,net/vhost,net/bonding,bus/pci,bus/vdev \
KER_DPDK_LIBS=eal,ring,mempool,mbuf,ethdev,gso,vhost,cryptodev,dmadev,sched,ip_frag \
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
| 阻塞接收超时 | 监听 accept 超时及继承；recv/recvmsg/readv 的 EAGAIN、部分 MSG_WAITALL、dup 共享选项、关闭超时后的 EOF 与恢复 |
| 阻塞发送超时 | 双向小缓冲区压力；send/writev/sendmsg 的部分进度及 EAGAIN；dup 共享 SO_SNDTIMEO，恢复后字节流完整且无重复 |
| connect 生命周期 | 拒绝连接与 dup 共享 SO_ERROR 清除、AF_UNSPEC 跨端口重连、原注册 fd 关闭后别名仍能使用 epoll 与完成收发 |
| 延迟接入 | TCP_DEFER_ACCEPT 开启时由数据触发 poll/epoll 与 accept；同一 listener 关闭选项后握手即可接入 |
| 共享监听端口 | SO_REUSEPORT 双 listener、普通 bind 冲突；关闭接入 listener 后已接受连接仍可收发，剩余 listener 继续接入 |
| listener 重启 | dup 保留监听与绑定冲突；关闭最后一个监听 alias 后 SO_REUSEADDR 重新监听同一端口，新旧连接独立存活 |
| 独立对端 urgent data | 双向 MSG_OOB/MSG_PEEK、SO_OOBINLINE、sockatmark/SIOCATMARK 边界及 poll/epoll 优先事件；普通前后缀完整且无 urgent byte 混入 |
| 独立对端接收队列 | 双向多段 MSG_PEEK/readv、FIONREAD、dup 共享队列，Linux TCP MSG_TRUNC 消费与 peek 保留，缓冲区哨兵及 EOF |
| 本地发送半关闭 | dup 共享 SHUT_WR，六种写入 API 的 EPIPE、四种 MSG_NOSIGNAL 抑制与逐调用 SIGPIPE；反向数据及 RDHUP/EOF 保持 |
| socket 契约 | 6 个宿主/原生场景：创建与 accept 标志、地址长度截断、option 错误恢复、bind 冲突及 dup/fstat 身份 |
| poll/select 就绪语义 | 8 个宿主/原生场景：监听、混合 pipe/TCP、重复条目与集合计数、失效 fd、OOB、SO_RCVLOWAT、EOF 和 timeout |
| F-Stack epoll 场景 | 8 个真实 TCP 场景与宿主 Linux 对照：ADD/MOD/DEL、64 位 userdata、LT/ET、oneshot、仅写就绪、半关闭与 RST；原生 active/passive open 计数必须增长 |
| 独立对端 message/vector stream | 三种 API（vector/message/batch）× 原生主动/被动角色；各方向 256 KiB + 13 字节、非阻塞短进度/重试、半关闭/EOF，逐实例检查原生 TCP 与 DPDK 计数 |
| F-Stack message/vector 场景 | 6 个宿主/原生 Linux 对照场景：sendmsg/recvmsg、readv/writev、地址查询、半关闭、非阻塞 ioctl 与 dup/dup2；原生连接计数验证，UNIX socket 明确为宿主透传 |
| fd 兼容 | 600 个宿主文件、高编号原生 fd、dup/fcntl/fstat、混合 poll/select/epoll、oneshot、多线程 churn |
| 动态 fd 模式 | 独立对端双向 FIONBIO/fcntl 切换，dup 共享 O_NONBLOCK、MSG_DONTWAIT 不变更状态，FIOCLEX/FIONCLEX 标志独立 |
| 信号等待 | ppoll/pselect/epoll_pwait/epoll_pwait2 原子解除阻塞、EINTR 与掩码恢复 |
| 隔离与回收 | 宿主已占用的端口仍可在原生 loopback 使用；直接宿主 TCP syscall 被拒绝；worker mbuf outstanding=0 |
| 现有应用（检测到程序时启用） | 原版 curl HTTP；原版 Redis/Valkey 无持久化、32 个连接、16 并发、1024 SET/GET 对及正常 SHUTDOWN |

`native-fstack-tcp-receive-timeouts` 先运行宿主参考，再运行原生客户端和服务端，
均连接独立 Linux 对端。监听器在报告 READY 前无客户端，accept 必须在
SO_RCVTIMEO 到期后返回 EAGAIN；accept4 取得的 socket 继承该 timeout，仍为阻塞模式。
客户端依次检查 recv、recvmsg、readv 的空队列超时，非法 tv_usec=1000000 返回
EDOM 且原选项不变。对端等待应用指令才发送数据，避免用固定 sleep 制造时序。

接收首段五字节前先用 poll 确认可读，再调用十字节 MSG_WAITALL；对端尚未收到
下一指令，不会发送余量，因此超时后必须返回已有五字节。随后空读仍返回 EAGAIN。
通过 dup alias 将 timeout 设为零，原 fd 查询也必须为零；后续 MSG_WAITALL 在
对端半关闭时返回末尾五字节，再返回 EOF，反向 ACK 仍成功。120ms 设置允许 tick
舍入，阻塞耗时仅要求 50ms..5s，不作为精度或性能指标。

原生客户端验证接收路径，原生服务端验证监听超时、继承和对端恢复；每实例要求对应的
原生 active/passive open、DPDK TX/RX 非零和 outstanding=0。本项是 F-Stack host
bridge 场景的 Ker 扩展，协议及超时由原始 Linux 执行；发送侧 SO_SNDTIMEO 见下一独立测试；本项不增加宿主信号
中断、pthread cancellation 或所有 time64 选项的验收。

`native-fstack-tcp-send-timeouts` 用独立 TCP control/data 连接协调背压，先运行宿主
参考，再运行原生客户端和服务端。两端轮流作为发送者；接收者在收到 resume marker
前不读取 data，因此小 SO_RCVBUF/SO_SNDBUF 会形成可复现压力，不依赖固定 sleep。

设置 SO_SNDTIMEO=120ms 后，首次大 send 必须返回正的部分进度；随后 send、writev、
sendmsg 各自必须出现无进度 EAGAIN。过程中所有正返回长度都累计到偏移，恢复时不会
重复发送已有前缀。非法 tv_usec=1000000 返回 EDOM 且保留原值；通过 dup alias 清零
发送 timeout 后原 fd 查询也为零。timeout 舍入和耗时边界沿用上项，不作精度承诺。

resume marker 之后，接收方增大接收缓存并逐字节验证 512 KiB + 13 字节，再通过
control ACK 确认完整性，随后交换方向。末尾半关闭并要求 EOF，确认没有额外尾部数据。
原生客户端和服务端均执行发送与接收阶段，每实例需要两次对应 TCP open、DPDK TX/RX
非零及 outstanding=0。该测试只新增验收，不修改 Linux 协议或 Ker 适配层；未覆盖
connect 超时、宿主信号中断和 pthread cancellation。

`native-fstack-tcp-connect-lifecycle` 先跑宿主参考，再运行原生客户端和服务端，与
独立 Linux 对端经 DPDK 连接。客户端仅创建一个非阻塞 socket 及其 dup alias；
连接未监听端口后，poll/epoll 必须报告错误，alias 读取 SO_ERROR 得到 ECONNREFUSED，
原 fd 随后读取为零，getpeername 返回 ENOTCONN。错误就绪清除后仍允许 HUP/可写就绪，
不把它们误当作 SO_ERROR 仍非零。

通过 AF_UNSPEC 将 socket 重置后，连接第一个监听端口并校验对端 tuple 与 echo。
再次 AF_UNSPEC 断开 live connection，服务端必须收到 ECONNRESET；客户端清除可能
遗留的本地 reset 错误，再用同一 socket 连接第二个端口。该断开/重连方式是本项
明确验证的 Linux 扩展，不是跨平台 POSIX 或 F-Stack 等价性声明。

整个过程不重新注册 epoll，64 位 event tag 必须保持。第二次接入后关闭原注册 fd，
仍存活的 alias 必须继续完成收发、epoll 通知、半关闭和 EOF。原生客户端要求至少
3 次 active open，原生服务端要求至少 2 次 passive open；两个端点均确认成功，且
DPDK TX/RX 非零、outstanding=0。连接拒绝、RST 与重连完全来自导入 Linux；本项
不新增协议或适配实现，也不覆盖并发 close 压力、宿主信号中断或 io_uring。

`native-fstack-tcp-defer-accept` 通过独立 control/data TCP 连接协调两个阶段，
先运行宿主参考，再分别运行原生客户端和服务端。监听端设置 TCP_DEFER_ACCEPT=31 秒，
查询值允许 Linux 按重传次数向上舍入；客户端 connect 完成并确认对端与 SO_ERROR 后，
通过 control 通知服务端，但等待明确许可才发送 data。此时 listener 的 100ms poll、
即时 epoll 和非阻塞 accept 分别必须无事件、无事件及 EAGAIN；数据到达后，两种就绪
接口与 accept 必须成功。此窗口只验证短期不就绪，不验收延迟定时器的到期行为。

第一条 data 连接完成后，在同一 listener 将 TCP_DEFER_ACCEPT 清零。第二次连接
必须在客户端尚未发送 payload 时就能触发 poll/epoll 并被 accept。两个阶段都核对
完整 echo、双向半关闭和 EOF，接入队列排空后不再报告可读；64 位 epoll tag 保持。
每个原生实例至少要求三次对应的 TCP open、DPDK TX/RX 非零和 outstanding=0。
这是 F-Stack host bridge 场景的 Ker/Linux 扩展，不是上游 F-Stack 对该选项的支持声明；
仅新增测试，TCP 延迟接入行为仍由原始 Linux 执行。

`native-fstack-tcp-reuseport` 在宿主参考、原生客户端和原生服务端三种模式下，
通过独立 Linux 对端验证 SO_REUSEPORT。两个非阻塞 listener 在 bind 前启用选项并
查询确认，共享同一地址和端口；仅设置 SO_REUSEADDR 的第三个 socket 必须绑定失败，
返回 EADDRINUSE。独立 control 连接协调批次，不依赖固定 sleep。

首批八条连接使用不同 token，poll/epoll 驱动接入并逐条验证 echo 与唯一性。
保留 token=1 的已接受连接，关闭恰好接入它的 listener，再要求该连接继续完成
收发和半关闭/EOF。下一批四条连接必须全部由另一个 listener 接入并完成精确 echo、
半关闭和 EOF；队列排空后 epoll 不再就绪。测试保留完整 64 位事件标签，不要求哈希
均匀分配，也不要求首批一定命中两个 listener。

每个原生实例至少要求十三次对应 TCP open（control 加十二条 data 连接）、DPDK
TX/RX 非零和 outstanding=0。本项是 F-Stack host bridge 场景的 Ker/Linux 扩展，
不声明上游 F-Stack 的 SO_REUSEPORT 等价性；未覆盖跨进程 worker、不同 UID、BPF
选择器或尚在队列中的连接迁移。端口分组、选择和 TCP 行为全部来自原始 Linux。

`native-fstack-tcp-fd-modes` 使用独立 control/data TCP 连接，依次运行宿主参考、
原生客户端和原生服务端。两个端点轮流作为接收者，在数据发送前完成所有空队列
探测，不依赖固定 sleep：阻塞 fd 上的 MSG_DONTWAIT 必须 EAGAIN，但不能改变
F_GETFL；alias 的 FIONBIO=1 必须使原 fd 和 alias 都带 O_NONBLOCK，普通 read 和
recvmsg 随即返回 EAGAIN。原 fd 经 F_SETFL 清除非阻塞后两者恢复阻塞；alias 再经
F_SETFL 开启非阻塞后，才能通知对端发送首段数据。

poll/epoll 就绪及完整 64 位 tag 必须保持，alias 收到准确首段后，通过原 fd 的
FIONBIO=0 再次恢复两者阻塞。通知对端发送后续数据，alias 上两段 iovec 的
recvmsg(MSG_WAITALL) 必须返回完整 17 字节，两个 fd 最终均收到 EOF。

FD_CLOEXEC 与上述共享文件状态分开验证：初始原 fd 带 CLOEXEC、dup 不带；无第三
参数的 FIOCLEX/FIONCLEX 和 F_SETFD 必须只影响指定描述符，两者的标志在后续
模式切换与收发后保持。每个原生实例要求至少两次对应 TCP open、DPDK TX/RX 非零
和 outstanding=0。本项是 F-Stack host nonblocking/dup/message 场景的 Ker/Linux
扩展；仅增加测试，不修改原始 Linux 或适配实现。标志位验收不表示已支持 exec
继承；未覆盖并发 F_SETFL、阻塞调用期间切换模式或所有 no-argument ioctl。

`native-fstack-tcp-urgent` 将既有 loopback 基础 OOB 验证扩展到独立 Linux
对端，依次运行宿主参考、原生客户端和原生服务端。两条 data 连接分别关闭与开启
SO_OOBINLINE，且每条连接双向执行：普通六字节前缀、单字节 MSG_OOB、普通五字节
后缀。独立 control 连接确保接收方已设置选项并注册 EPOLLPRI，且在验证 urgent
边界之前发送方不会发送后缀；测试不用固定 sleep。

poll/epoll 必须报告 POLLPRI/EPOLLPRI 并保持 64 位 tag。读取前缀前 SIOCATMARK
必须为零，读完前缀后必须为一；每次同时调用 POSIX sockatmark 并要求结果一致。非 inline 模式通过 MSG_OOB|MSG_PEEK 查看 urgent
byte 后，再用 MSG_OOB 消费，普通流中不能重复出现该字节；inline 模式要求
MSG_OOB 返回 EINVAL，然后通过普通 recv 读取该字节。完整后缀和 EOF 到达后，
urgent mark 及 PRI 清除，同时允许 EOF/HUP 保留就绪。

每个原生实例要求至少三次对应 TCP open、DPDK TX/RX 非零和 outstanding=0。
本项是 F-Stack host bridge/readiness 场景的 Ker/Linux 扩展，不声明上游 F-Stack
urgent API 等价性。未覆盖 SIGURG、异步信号所有者、多个未消费 urgent pointer
相互覆盖。新增 sockatmark 导出入口复用 ioctl 适配，修复 libc 内部 ioctl 绕过
原生 fd 分流的问题；同时核对非法 fd 的 EBADF、宿主 pipe 的 ENOTTY 及宿主 socket
参考行为。未修改原始 Linux urgent 处理。

`native-fstack-tcp-receive-queue` 验证协议解析器依赖的接收队列行为，运行宿主
参考、原生客户端和原生服务端。每个方向发送 16 KiB + 37 字节的确定性数据并
半关闭，独立 control 连接和 SO_RCVLOWAT 协调完整队列就绪，不依赖固定 sleep。
在检查前将低水位恢复为 1，后续调用不依赖大低水位设置。

先通过 dup alias 执行两段 iovec 的 recvmsg(MSG_PEEK|MSG_WAITALL)，再从原 fd
peek 6001 字节；两次均逐字节核对，且原 fd 与 alias 的 FIONREAD 始终不变。
随后 Linux TCP recv(MSG_TRUNC) 丢弃 257 字节，返回消费长度但不修改目标缓冲区，
队列长度必须相应减少；recvmsg(MSG_PEEK|MSG_TRUNC) 查看 513 字节长度时，目标
缓冲区和队列长度都必须保持不变。这是明确的 Linux TCP 扩展，不套用 UDP 的
报文截断语义，也不声称是可移植 POSIX 行为。

剩余字节通过 alias 的 readv 分段读取并逐字节校验，每次读取后核对原 fd 的
队列长度；最终两个 fd 均看到 EOF，普通 peek 也返回零，FIONREAD 不把 FIN 算作
数据。每个原生实例要求至少两次对应 TCP open、DPDK TX/RX 非零和 outstanding=0。
本项是 F-Stack host message/vector 场景的 Ker/Linux 扩展；仅增加验收，不修改
Linux 或适配实现，也未覆盖并发 reader、SO_PEEK_OFF 或 recvmsg 错误指针恢复。

`native-fstack-tcp-shutdown-write` 在宿主参考、原生客户端和原生服务端模式下，
验证本地发送半关闭，与既有对端 RST 场景分开。原 fd 和 dup alias 共享连接；非法
shutdown how=42 必须返回 EINVAL，随后正常发送仍可成功。通过 alias 执行 SHUT_WR，
对端尚未发送 FIN 时，原 fd 重复 SHUT_WR 仍成功；双方 FIN 已被确认后允许 Linux
返回 ENOTCONN。两个 fd 上的后续写入均受关闭状态约束。

send/sendto/sendmsg/单条 sendmmsg 使用 MSG_NOSIGNAL 时必须 EPIPE 且不触发
SIGPIPE；这四种 API 不带该标志以及 write/writev 各自必须 EPIPE，并使已安装的
SIGPIPE handler 计数增加一次。每端共验证六次信号，SO_ERROR 保持零。
独立 control 连接确保对端完成这些探测前，接收 socket 仍保持打开，不用固定 sleep。

客户端发送正常请求并关闭发送方向后，仍必须通过 alias 完整接收服务端的反向回复。
服务端随后同样执行半关闭和写入错误矩阵；两端 poll/epoll 必须报告 EOF 的
POLLIN/EPOLLIN 与 POLLRDHUP/EPOLLRDHUP，并保持完整 64 位 tag。每个原生实例
要求至少两次对应 TCP open、DPDK TX/RX 非零和 outstanding=0。本项是 F-Stack
host shutdown/message/vector/dup 场景的 Ker/Linux 扩展；未覆盖 SHUT_RD、阻塞或
忽略 SIGPIPE、默认终止动作、异步信号所有者及部分成功 sendmmsg 的信号行为。
仅增加验收，半关闭/EPIPE 仍来自原始 Linux，SIGPIPE 仍复用既有 Ker 适配。

`native-fstack-tcp-listener-restart` 在宿主参考、原生客户端和原生服务端模式下，
验证已有连接存活时替换 listener。监听 socket 启用并查询 SO_REUSEADDR，同时
SO_REUSEPORT 必须为零，避免将重启与共享 listener group 混为一谈。

服务端创建 listener 及 dup alias，通过 alias 接受第一条连接并完成 echo。
此时带 SO_REUSEADDR 的候选 socket 仍必须 bind 失败（EADDRINUSE）。关闭原 fd 后，
alias 的 SO_ACCEPTCONN 仍为一，绑定冲突仍存在；关闭最后一个 alias 后，已接受的
旧连接仍保持打开，此时不带 SO_REUSEADDR 的候选也必须绑定失败，带该选项的新
listener 则必须成功 bind/listen 同一端口。控制连接在新 listener ready 后才通知
客户端推进，不依赖固定 sleep。

旧连接在替换后继续完成 echo，新连接由同一 epoll 中带新 64 位 tag 的 listener
接入。关闭第二代 listener 后，两条已接受的连接仍分别完成后续内容校验、半关闭
和 EOF；epoll 不应残留监听就绪。每个原生实例要求至少三次对应 TCP open、DPDK
TX/RX 非零和 outstanding=0。

这是 F-Stack host fd/readiness 场景的 Ker/Linux 扩展，不是上游 F-Stack listener
重启测试或等价性声明。仅增加验收，绑定和连接生命周期来自原始 Linux；未覆盖
TIME_WAIT 的状态/持续时间、多进程接管、未接入连接迁移或跨 UID 端口策略。

独立的 [原生 UDP 验证](native-udp-validation.md) 另行检查 UDP socket，使用原生 UDP 计数证明路径。

这些测试运行的是完整导入内核的 TCP，区别于基础库的 F-Stack 报文 view、checksum 和生命周期适配用例。`--stats` 同时输出 Ethernet、重试/丢弃/mbuf 与原生 TCP 计数，便于追溯。

正常退出先关闭应用原生 fd，再让原始 Linux 处理待确认发送队列，默认等待最多 5 秒，可用 `--shutdown-timeout-ms 0..60000` 调整。超时或启动/设备/退出不完整返回 125；其余正常应用返回值保留。SIGKILL、`_exit` 和宿主崩溃不能进行正常排空。应用应正常关闭连接后退出。

## 首版兼容范围

支持 x86_64 Linux/glibc 的动态链接应用，IPv4 TCP、常用 socket option、普通及 vectored/message I/O、dup/fcntl/ioctl/fstat、poll/select/epoll 及上述信号掩码等待接口。宿主文件等非网络 fd 继续走宿主。其他网络协议未作为本次交付验收范围，内核已启用 IPv6，用于已验证的 IPv6 loopback 和 IPv4-mapped 双栈 TCP socket。同链路 IPv6 Ethernet 地址和 NDP 接收现已通过上面的 net_tap 验收；IPv6 默认路由与单跳跨网段转发已通过上述独立路由器验收；路由更新/故障切换等扩展仍未验收。

以下边界尚未兼容，迁移应用时必须核对：

- 不支持初始化后 fork/daemonize，child 明确退出 125。服务使用前台模式；Redis/Valkey 测试关闭需要 fork 的持久化功能。每个新进程应由独立 `ker-run` 启动，不能通过 exec 或 SCM_RIGHTS 继承原生 fd。
- 静态链接、直接 syscall、io_uring、libc 内部未导出的 I/O 入口无法由 LD_PRELOAD 完整适配。`fdopen`/stdio、sendfile/splice、close_range 不支持原生 fd；这些入口可能得到占位 fd 的错误，不能将其视为已兼容。guard 拒绝直接创建宿主 TCP，启动握手保证未加载原生库时不能成功验收。
- 阻塞原生 socket 操作由 Linux 执行，宿主信号尚不能打断这类调用。适配入口也尚未实现 libc 的 pthread cancellation point 兼容（包括这些入口上的宿主 fd I/O）。需要中断控制的服务使用非阻塞 socket 加事件等待，或 socket 超时。SIGIO/O_ASYNC 明确返回 EOPNOTSUPP。
- 不支持嵌套的混合域 epoll，明确返回 EOPNOTSUPP。select 受宿主 FD_SETSIZE 限制，原生应用 fd 上限 65536（同时受宿主 RLIMIT_NOFILE 限制）。混合等待采用轮询桥接，不承诺亚毫秒唤醒。
- 原生内核与宿主的 namespace、路由、loopback、sysctl、文件系统和 PID 不相同；应用访问宿主 `/proc` 不会自动重定向到原生内核。第一版只公开启动参数与诊断计数，不提供宿主网络管理工具的透明重定向。

本次构建与验收环境见 [首版验收记录](native-tcp-validation.md)。此范围已覆盖前台运行的普通非阻塞 POSIX TCP 应用和上述现有程序。多进程透明兼容、零拷贝、多队列、IPv6 路由扩展与物理网卡的交付验收属于后续扩展。

## SO_LINGER、dup 与最后一次 close

`native-fstack-tcp-linger` 在宿主参考、native 主动端和 native 监听端组合中验证共享 `SO_LINGER` 与最后一个 fd 引用的关闭行为。六条数据连接覆盖两种关闭方向和三种模式：启用零 linger 后通过副本禁用，正常结束为 EOF；保留零 linger，通过 recv 消费 ECONNRESET；或先通过 SO_ERROR 消费 ECONNRESET。

独立 TCP 控制连接确认原 fd 已关闭后，接收方须在 100 ms poll 窗口内保持无可读事件，epoll 无事件且非阻塞读取到 EAGAIN；发送方随后仍能通过副本发送准确的 17 字节内容。接收方确认内容消费完成，才允许关闭最后一个副本。验证最终 poll/epoll RDHUP、完整 64 位 tag，以及复位时 ERR/HUP。两种错误消费者各自读取并清除共享错误，随后两个接收方 fd 都读到 EOF。native 每端须有七次匹配方向的原始 Linux TCP 打开、DPDK 收发和零未释放缓冲区。

这是固定 F-Stack host shutdown/dup 桥接场景的 Ker/Linux 扩展，不是上游 linger 测试或等价声明。仅增加测试；不修改 Linux 或 Ker 适配代码。未覆盖正数 linger 等待期限、未读数据关闭、进程退出、并发 close/read 或跨进程 fd 传递。

## TCP 接收低水位、现有数据就绪与 FIN

`native-fstack-tcp-lowwater` 在宿主参考、native 主动端和 native 监听端组合中双向验证四个阶段。通过 dup 设置 `SO_RCVLOWAT=64` 并查询共享值；独立 TCP 控制连接协调发送 17 字节，再以最多五秒的 FIONREAD 条件检查确认数据确实排队（每轮让出一毫秒），避免把网络尚未到达误判为低水位抑制就绪。poll/select/epoll 此时均须无事件。

第一阶段先以 `MSG_PEEK|MSG_DONTWAIT` 验证已有 17 字节且不消费，再以 `MSG_DONTWAIT` 读出，保持 fd 为阻塞模式。第二阶段通过副本将低水位降到 1，已有数据须立即可读，保留原 epoll 注册及完整 64 位 tag；再升回64时必须抑制就绪，再降到1须恢复。第三阶段先确认17字节低于阈值，再由控制连接允许对端补齐47字节；达到64字节时须可读，消费后清除，期间没有降低阈值或发送FIN。第四阶段确认低于水位的数据排队后才允许对端半关闭；FIN 须使 poll/epoll 报告 IN/RDHUP，`MSG_WAITALL` 的 96 字节读取返回 17 字节尾部，之后两个 alias 都返回 EOF。各阶段核对内容、未写入区域和队列计数。native 每端须有两次匹配方向的原始 Linux TCP 打开、DPDK 收发及零未释放缓冲区。

这是固定 F-Stack host shutdown/dup/readiness 桥接场景的 Ker/Linux 扩展，不是上游测试或等价声明。仅增加测试，不修改协议或适配代码。未覆盖并发读者、ET/ONESHOT rearm、信号中断或低水位性能；TCP 和 UDP 的低水位语义须分别验证。

## Worker 日志文件

可传入 `--log-dir DIR`，在现存目录中追加 `ker-io-<worker-PID>.log`。
该文件接收 DPDK 日志及 `ker.io` 生命周期消息；应用输出与显式 stderr 错误保持原通道。
`--log-level 1..8`（emergency 到 debug）在 EAL 启动后覆盖全局与 Ker 分类级别；
启动期 EAL 消息仍由 `--eal` 内日志选项控制。日志 I/O 失败最终返回 125。
未启用日志目录时保留既有输出行为；本功能没有文件轮转。

## Launcher INI 配置

`ker-run --config /path/to/launcher.ini -- PROGRAM ARGS...` 可读取
[示例配置](../config/native-launcher.example.ini)。网络和 DPDK 必需参数可以来自
文件或命令行；显式 CLI 选项优先。相对 `directory` 和 `stats` 路径以配置文件的
实际目录为基准，CLI 路径仍以当前工作目录为准。目录必须事先存在。

| Section | 支持的键 |
|---|---|
| network | address、gateway（IPv4） |
| dpdk | port、eal、all_multicast |
| logging | directory、level |
| capture | directory、snaplen、max_bytes、nsec |
| runtime | shutdown_timeout_ms、stats |

支持 `=`/`:`、`#`/`;` 整行注释、空白前的 `;` 行内注释、UTF-8 BOM 和缩进续行；
续行合并成字符串，EAL 再由 shlex 分词，不执行 shell。`%` 不插值。
键和 section 区分大小写，重复项、未知项、默认项继承及无 section 的全局项会拒绝。
`--no-all-multicast`、`--no-pcap-nsec` 可覆盖文件中的 true 值。
应用命令仍由 CLI 给出，`--` 后的 `--config` 等选项属于应用，不会被 launcher 消费。
该格式是 Ker 运行时配置，不是 F-Stack 配置文件/API 的直接兼容层。

### DPDK lcore mask

`--lcore-mask 0x5` 或 INI `[dpdk] lcore_mask=0x5` 将十六进制位图传给原始 EAL `-c`，每个位对应同编号 CPU/lcore。
接受 `0x`/`0X` 前缀、大小写十六进制及首尾空白；命令行覆盖 INI。空值、零和非十六进制在启动前返回配置错误 2。
使用该设置时，`--eal` 中不得同时出现 `-c`、`-l` 或 `--lcores`；需要逻辑核到物理核映射时继续直接使用 `--eal` 的 `--lcores`。
实际可用 CPU、主核是否在位图中及 DPDK 构建的 lcore 上限由 EAL 校验，失败保持基础设施错误 125。
多个选中 lcore 不会增加 Ker 的 RX/TX 队列或创建多进程数据面；目前仍由 worker 主线程处理报文。
READY/关闭统计的 `io` 对象包含 `lcore_count`、`main_lcore` 以及采样时主线程实际所在的 `main_cpu`。

### Worker 流量快照

关闭统计新增 `tx_bytes`、`rx_bytes`、`tx_dropped`、`rx_dropped`，原有 `tx`、`rx`、`dropped` 字段保留。
`KER_IO_DONE` 还报告 `stop_requests`（已读取的控制字节数）、`control_eof`（控制通道是否已观察到 EOF）和 `rx_startup_discarded`（显式关闭混杂模式后、READY 前为证明 RX 队列为空而丢弃的帧数）。
`tx`/`tx_bytes` 在 PMD 接受完整帧后增加；`rx`/`rx_bytes` 在完整帧成功送入原生 packet channel 后增加，重试不会重复计数。
字节数包含 Ethernet 头和负载，不含 virtio channel 头或 Ethernet FCS。
`tx_dropped` 统计适配层拒绝的帧长度/元数据；`rx_dropped` 还包括 `rx_startup_discarded`，即显式关闭混杂模式时在 READY 前清理的 RX 帧。聚合值仍为 `dropped=tx_dropped+rx_dropped`，不包含硬件丢包或设备关闭时丢弃的排队 RX 帧。
`outstanding` 继续表示 ethdev 关闭后仍被占用的 mbuf 数，成功关闭必须为零。

### 原生内核熵初始化

应用启动前，Ker 从宿主 `SYS_getrandom(..., 0)` 系统调用获取 32 字节；直接系统调用避免应用或 preload 对 `getrandom` 符号的替换，并通过原始 Linux `RNDADDENTROPY` 向私有内核 RNG 注入 256 位熵，再调用 `RNDRESEEDCRNG`，保证已就绪的 RNG 也立即重新派生输出状态。
临时字符设备节点只存在于 LKL 私有 rootfs，打开后立即 unlink；不写入宿主 `/dev/random`，不修改原始 Linux RNG 实现。
EINTR/短读继续获取剩余字节；读取、私有设备初始化或 ioctl 失败会中止启动。没有时间戳、PID 或固定字节替代路径。
临时 fd 随即关闭，包含种子的缓存在所有返回路径显式清除。POSIX 应用原有宿主随机数接口保持不变。

### 原生实时时钟同步

constructor 在私有内核启动后，将宿主 `CLOCK_REALTIME` 的 Unix epoch 同步给原始 Linux，供 socket 时间戳等功能使用。
这一操作只设置私有内核的实时时钟；协议定时器继续使用单调 clocksource，不设置宿主时钟。
宿主采样失败或原始 Linux 拒绝 settime 时，启动返回基础设施错误 125；不使用失败采样中的时间值。
`native-fstack-realtime` 通过实际同步函数验证 epoch、前进、单调时钟隔离和错误后的恢复。

### Worker 排空时钟错误

worker 排空仍以宿主 `CLOCK_MONOTONIC` 纳秒计算 5ms 空闲窗口及 500ms 上限。
采样失败或采样值无法表示为有符号纳秒时，打印 `ker: worker monotonic clock`，
返回非零状态，并执行正常的 capture、mbuf、ethdev、日志及 EAL 清理；不使用失败读取中的时间值。
这不改变原始 Linux 协议定时器，也不引入 TSC 频率换算或新的应用 API。

### READY 前的 worker 失败统计

若 worker 已完成 EAL 初始化但尚未 READY 就失败，仍可能输出 `KER_IO_DONE` 清理快照。
launcher 保留这一首行供 `--stats` 输出（`io` 为 null，因为尚未收到 READY），避免在读取首行后丢失资源清理证据。
启动仍返回基础设施错误 125，不执行应用；原生初始化/网络配置失败时也会停止并回收独立 worker。

### IPv4 VIP/附加地址

`--vip-address 198.18.0.3/24 --vip-address 198.18.0.4/24` 或 INI `[network] vip_addresses=198.18.0.3/24,198.18.0.4/24` 向同一原生接口添加地址。
CLI 提供的列表整体替换 INI 列表，不与它合并；省略 prefix 使用 `/32`，最多 32 项，空 INI 列表表示不添加。
重复主地址或 VIP、非法 IPv4/prefix 在启动前返回 2；原始 Linux 拒绝地址安装时返回基础设施错误 125。
launcher 清除 ambient `KER_NATIVE_VIP_ADDRESSES`，仅传递最终验证过的配置。
地址添加沿用原始 LKL netlink 接口和 Linux ARP/TCP，不替换主地址，不实现 VLAN、VRRP 或动态故障切换。

### MTU 部署上限

`--max-mtu 2000` 或 `[network] max_mtu=2000` 将当前 launcher 的 MTU 上限限制为 2000；默认 9000，合法范围 1280–9000。
`mtu` 大于 `max_mtu` 在设备/库初始化前返回 2；CLI 可分别覆盖 INI 中的请求值或上限。
此值同时限制启动配置与运行中的 primary interface MTU。large 模式按 max_mtu 预留完整帧容量，
以支持运行时增长而无需替换仍可能由 PMD 持有的 pool；默认 9000 因而比旧版固定 1500 的 pool 占用更多内存。
需要限制容量时显式设置较小的 max_mtu。scatter 模式仍使用标准大小 segment。
上限不是设备能力探测，实际 MTU 仍由原始 Linux 与 DPDK 设置并受真实 PMD 能力限制。

应用通过 native AF_INET/AF_INET6 socket 的 `SIOCGIFNAME`/`SIOCGIFMTU`/`SIOCSIFMTU`
操作主接口；MTU ioctl 在应用端串行，通过独立 SOCK_SEQPACKET 通道请求唯一 worker。
worker 校验 busy 状态、MTU 和 scatter 能力后停止 ethdev、重设 MTU、重建 RX queue 并启动；
队列仍持有本地未发送/未递交报文时返回 EBUSY，调用方可稍后重试。
PMD 拒绝时恢复原 MTU、RX queue 和运行状态，再回滚原始 Linux；无法证明一致或通道失联时终止后端。
停设备/重启可能丢包，不承诺并发报文无损、物理网卡支持或 native rtnetlink MTU 控制。
SIOCGIFMTU 也检查 worker 的 ethdev MTU 缓存与 Linux 是否一致；TAP 验收另独立读取宿主设备真实 MTU。
`--stats` 保留启动时 `io.mtu`，并提供最终 `mtu_final`、`max_mtu` 和成功变更次数 `mtu_changes`。

`native-fstack-live-mtu` 验证 large/scatter 的1500→9000→1500、每一步双向 IPv4/IPv6 ICMP
和完整1514/9014字节抓包、DF超限错误、部署上限，以及 PMD 拒绝前/后回滚、后续恢复和回滚失败时终止。


### DPDK mbuf 存储模式

默认 `--mbuf-mode large` 为每个 DPDK mbuf 预留 max_mtu 范围的完整帧空间。
`--mbuf-mode scatter`（INI：`[dpdk] mbuf_mode=scatter`）使用标准大小 pool 和链式大帧；
PMD 必须同时支持 RX scatter 和 TX multi-segment，否则启动失败。
可与 `--mtu 9000` 一起使用，对端链路也必须设置对应 MTU。
该设置仅改变 Ethernet 缓冲表示，不启用协议 offload。
验收运行 `ctest --test-dir BUILD -R '^(worker-mbuf|native-fstack-mbuf-scatter|native-fstack-jumbo-mtu)$' --output-on-failure`。


### 802.1Q VLAN

`--vlan ID=IP/PREFIX[,IP/PREFIX...]` 可重复指定最多 16 个 VLAN，每个最多 8 个地址。
INI 使用 `[vlan.ID] addresses=...`；CLI 整体替换 INI VLAN 列表。父接口仍由 `--address` 配置。
原始 Linux 创建 `ker.ID` 子接口，负责标签和地址语义；应用可用 `SO_BINDTODEVICE` 绑定它。
需要以当前 defconfig 重新构建 native Linux 产物（启用 `CONFIG_VLAN_8021Q`）。
已验证 net_tap、IPv4/IPv6、MTU1500、两个 VLAN 和 VLAN VIP；IPv6 及混合地址验证见下文，其它部署边界见 `docs/fstack-migration.md`。

### 自动本地端口范围

`[network] ephemeral_ports=40000-40007` 或 `--ephemeral-ports 40000-40007`
设置应用私有 Linux 的 `net.ipv4.ip_local_port_range`，同时作用于 TCP/UDP 和
IPv4/IPv6 自动端口分配。格式为 `FIRST-LAST`，端点在 1024..65535 且不得倒置。
CLI 覆盖 INI；不指定则保留内核默认。不能同时通过 `[sysctl]`/`--sysctl` 指定
同一 key，也不能将专用选项与 `net.ipv4.ip_unprivileged_port_start` sysctl 组合。
Linux 要求非特权端口边界不高于 `ip_local_port_range` 的下界；若需同时提高两项，
只用通用 sysctl，并先写端口范围、再写边界。例如先设 `ip_local_port_range=50000 50007`，
再设 `ip_unprivileged_port_start=50000`。CLI `--sysctl` 覆盖 INI 同名项时，该项按 CLI
出现顺序重新应用；未覆盖的 INI 项仍保持文件顺序。专用选项固定采用 1024 下限。所有设置
只作用于本实例，受原始 Linux 的端口保留、冲突和分配规则约束；显式 bind 的固定端口不受自动范围限制。



## IPv6 VLAN 地址

既有 `--vlan ID=IP/PREFIX,...` 与 `[vlan.ID] addresses` 现在可使用 IPv4、
原生单播 IPv6 或混合列表。每个 VLAN 最多八个地址，总共最多 16 个 VLAN；
CLI 替换整个 INI VLAN 列表，IP 不能与主接口、VIP 或其他 VLAN 重复。
无需配置主接口 `address6`，IPv6 VLAN 本身会触发必需的 multicast 接收；
不带 scope 的接口地址由配置中的 VLAN ID 确定作用接口。

例如 `[vlan.100] addresses=198.19.100.2/24,2001:db8:100::2/64,2001:db8:100::3/128`。
Ker 使用原始 LKL rtnetlink helper 配置地址、MTU 和 UP 状态，先启动所有 VLAN 的
Linux DAD 再逐个确认，应用启动前必须全部成功。IPv6 VLAN 默认网关见下文。

`native-fstack-ipv6-vlan` 验证 VLAN 100/200 的双向 IPv6 TCP/UDP、VIP、
同一 VLAN 的 IPv4 UDP、设备绑定、IPV6_PKTINFO、NDP 和内核计数。
PCAP 必须具有完整的 1518 字节 tagged IPv6 UDP 帧及有效校验和；错误 VLAN 和
untagged 探测不能交给设备绑定 socket。另验证 16×8 地址上限及宿主占用地址的 DAD 拒绝。


## IPv6 VLAN 默认网关

`[vlan.100] gateway6=fe80::1` 或 `--vlan-gateway6 100=fe80::1` 在原始 Linux
主路由表安装带显式输出接口 `ker.100` 的 IPv6 默认路由。对应 VLAN 必须配置 IPv6
地址；不要求父接口 `address6`。全局与 link-local 下一跳均可，scope 由 VLAN ID
确定，配置值不能包含 `%interface`。CLI 整体替换 INI 的 VLAN 网关列表；VLAN 地址
列表仍由 `--vlan` 独立替换，覆盖后必须保留网关引用的 IPv6 VLAN。

本接口只允许一个显式 IPv6 默认网关，不能与父接口 `gateway6` 或其他 VLAN 默认
网关并用；这避免隐式 ECMP/策略路由。不能使用本实例配置的本地 IP 作为网关。
下一跳可达性由原始 Linux 检查；off-link 网关在应用 main 前失败并回收 worker。
未指定网关会清除继承的配置环境，保留无默认路由的行为。
IPv4 VLAN 网关见下节；多个路由表/同一地址族多个默认网关和 RA/SLAAC 尚未实现。

`native-fstack-ipv6-vlan-route` 运行四个真实 native 实例：省略网关、off-link 拒绝、
INI 全局网关、CLI link-local 网关覆盖。独立宿主路由器连接另一网络命名空间中的
远端，双向 TCP/UDP 必须跨网段并保持源地址和载荷；UDP hop limit 必须由 64 减为
63，转发计数增加。PCAP 还必须证明 VLAN100 标签、下一跳 NDP、路由器 MAC 和
远端 IPv6 UDP 地址。没有上游协议源码修改或 Ker 自有路由/协议算法。


## IPv4 VLAN 默认网关

`[vlan.100] gateway=198.19.100.1` 或 `--vlan-gateway 100=198.19.100.1`
为配置了 IPv4 地址的 VLAN 安装原始 Linux 主表默认路由。路由明确指定
`ker.100` 输出接口；TCP/UDP、ARP 和转发语义均来自原始 Linux。
CLI 整体替换 INI IPv4 VLAN 网关列表，IPv6 VLAN 网关列表独立保留。
每个地址族只允许一个显式默认网关；IPv4 VLAN 网关不能与父接口 `gateway`
或另一个 VLAN IPv4 默认网关并用，但可以与一个 IPv6 默认网关共存。

配置拒绝无 IPv4 的 VLAN、不存在的 VLAN ID、配置的本地地址、零/组播/loopback/
有限广播和所选 VLAN 子网广播下一跳。`/31` 不按传统子网广播地址规则拒绝其对端。
是否 on-link 由原始 Linux 路由安装检查，off-link 网关在 main 前失败并回收 worker。
省略该选项会清除继承的 `KER_NATIVE_VLAN_GATEWAY`；不隐式创建默认路由。

`native-fstack-ipv4-vlan-route` 的四个实际 native 实例覆盖省略网关、off-link 拒绝、
INI 网关和 CLI 更换网关。独立宿主路由器连接另一个网络命名空间，验证双方主动连接的
TCP/UDP、精确源地址/载荷、UDP TTL 64→63、宿主转发和原始内核计数及零 outstanding
mbuf。PCAP 必须证明 VLAN100 标签、ARP 查询配置的网关而非远端地址、路由器 MAC
和跨网段 IPv4 UDP。多路由表、每 VLAN 独立默认路由/策略规则仍未实现。


## PMD 混杂模式

`[dpdk] promiscuous=true/false` 或 `--promiscuous` / `--no-promiscuous`
显式选择 DPDK ethdev 的混杂接收模式。CLI 覆盖 INI，省略时保留 PMD 初始状态，
不改变现有默认策略。显式设置调用 DPDK enable/disable 后回读确认；失败或回读
不一致会在应用启动前报错并清理设备。`--stats` 的 `io.promiscuous` 记录实际回读
布尔值；未显式配置且 DPDK 查询返回错误时为 null。

这只决定哪些 Ethernet 帧可进入 worker。它不会将 Linux 接口设为混杂模式，也
不会绕过原始 Linux 的 MAC/IP/socket 接收检查。IPv6 所需的 all-multicast 配置
仍独立生效，不被显式关闭 promiscuous 所覆盖。

`native-fstack-promiscuous` 使用真实 net_tap 和独立宿主接口运行五个 native
实例：省略、INI 开/关以及两个方向的 CLI 覆盖。混杂开启时三个目的 MAC 不匹配的
有效 UDP 帧必须进入 PMD RX 抓包，关闭时不得出现；开启时 Linux UDP socket 也
不能收到这些载荷。相同 raw packet builder 构造的本机目的 MAC 控制帧必须成功
进入 UDP socket 并得到回复，避免把坏包丢弃误记为 MAC 过滤。另验证宿主 TCP
互通、PMD 状态回读、原始内核 TCP/UDP 计数和零 outstanding mbuf。
这些是软件 PMD 证据，不等同于物理 NIC、RSS 或硬件过滤验收。


## Worker 空闲等待

`[dpdk] idle_sleep=20` 或 `--idle-sleep-us 20` 设置 Ethernet worker 无进展时的
等待时间，单位微秒，范围 0..100000。默认 1000 保留既有 1 毫秒行为；CLI 覆盖
INI，0 使用不休眠的轮询。它只调整 Ker 的 I/O 调度，不改变原始 Linux 的协议定时器。

完全空闲时，宿主 `ppoll` 监听 native→worker 数据通道及控制通道，通道数据或关闭请求
可唤醒等待。仅保留待重试的发送帧时，worker 仅监听控制通道，并使用不超过 1000 微秒的重试
间隔；只要保留尚未送入 channel 的 RX 后缀（包括同时有待发送帧时），worker 就监听
channel 可写状态，并使用同样的有限超时作为 PMD 重试后备。任何待重试的 TX 或 RX 都
不会等待完整的配置空闲间隔。有意等待聚合的 TX 批次监听新输入，并将等待限制在首包
期限内，详见下方 TX 批次等待。
PMD RX 没有通道通知，因此新的网卡输入可能等到下一次空闲超时；较长设置可降低空闲
轮询频率，也会增加收包等待。微秒配置不保证宿主调度精度或端到端时延。

`--stats` 中 `io.idle_sleep_us` 记录配置值，`idle_waits` 记录实际等待调用次数，
`idle_timeouts` 记录其超时返回次数；这些统计也包括待处理 TX/RX 的短重试等待，0
等待的立即返回也计入超时。两项均为 worker 调度统计，不是内核协议计数。计数在每次
进程启动时从零开始。

`native-fstack-idle-wait` 启动五个真实 DPDK/native 实例，覆盖省略默认、INI 20 微秒、
CLI 零等待、INI 上限和 CLI 上限覆盖。应用先保持静默，再与独立宿主完成 TCP/UDP，
必须观察实际 idle timeout、正确配置值、原始 Linux socket 计数、控制关闭信号及零
outstanding mbuf。`worker-mbuf` 中的确定性等待计划用例验证空闲、待 TX、待 RX、TX/RX
同时待处理时的事件和超时选择；没有声称真实 PMD 背压场景的端到端计时证据。未迁移
F-Stack 的 generation、primary-slim 或 TX batching 调度。


## DPDK 内存通道参数

`[dpdk] channel=4` 或 `--memory-channels 4` 转为原始 EAL `-n 4`。
CLI 覆盖 INI；允许 1..2147483647（正 signed-int 范围），非法值在加载库前拒绝。
省略时不添加 EAL 参数，保留 DPDK 策略。显式设置与 `--eal` 内的 `-n`、
`-n4`、`--memory-channels`、`--memory-channels=4` 冲突时拒绝启动，避免多重配置权威。
只使用原始 EAL 参数而省略 typed 配置仍然允许。固定 DPDK 的 `--no-shconf` 与
`--in-memory` 会跳过通道初始化，因此与 typed 配置一起使用时也提前拒绝；不会将
返回 0 的未知通道状态当作成功生效。

`--stats` 的 `io.memory_channels` 来自实际 `rte_memory_get_nchannel()`，不只是回显 CLI。
`native-fstack-memory-channels` 的五次真实 net_tap/native 启动验证省略（本固定 EAL
的值为 0）、INI4、CLI2 覆盖 INI4、原始 EAL 短参数3及长参数1。
每次都验证独立宿主 TCP/UDP 回显、原始 Linux 计数、控制停止与零 outstanding mbuf。
该参数是 EAL 内存分布配置，数值不代表检测到的物理通道数；此处 no-huge 测试不声称
物理拓扑、NUMA 放置、hugepage 分布或性能认证，上游源码保持不变。

当 `--eal` 原始参数包含 `--` 时，typed memory、page、channel 和 lcore 选项会放在
第一个分隔符之前；分隔符及其后的原始参数保持原顺序。此后缀属于 EAL 的应用参数，
不参与 typed 选项的重复配置冲突检查。


## DPDK NUMA 分配策略

`[dpdk] numa_on=yes` 或 `--numa` 将 worker mbuf pool 和 RX/TX 队列分配目标设为
当前 lcore 的 DPDK socket；`numa_on=no` 或 `--no-numa` 统一使用 socket 0。
默认开启以保持 Ker 已有行为，CLI 覆盖 INI。布尔语法与其他 INI 开关一致，非法值在
库加载前返回 2。此映射遵循固定 F-Stack
[`ff_dpdk_if.c`](https://github.com/F-Stack/f-stack/blob/646a641cfff77f4815e1e29829a09e1ed15a2999/lib/ff_dpdk_if.c)
的 `numa_on` 分配选择，不改变原始 Linux 的内存分配策略。

`io.numa` 显示开关，`io.lcore_socket_id` 显示实际 lcore socket，
`io.allocation_socket_id` 是传给 pool 和两个队列 setup 的共同分配目标，
`io.pool_socket_id` 读取返回 pool 的 socket 元数据。这些字段不是物理页放置证明，
队列字段也不是驱动内部内存分布的回读。原有 `io.socket_id` 仍表示 ethdev 的节点。
无法分配或 setup 失败时沿现有失败路径退出，不降级成成功。

`native-fstack-numa-policy` 启动五个真实 net_tap/native 实例，覆盖默认、INI 开/关及
CLI 双向覆盖，核对策略、分配目标和 pool 元数据，并要求独立宿主 TCP/UDP 回显、
原始 Linux 计数、控制停止与零 outstanding mbuf。测试环境只有一个 DPDK NUMA 节点，
未认证跨节点放置、内存回退或性能；不修改 Linux/LKL/DPDK/F-Stack 上游代码。


`native-fstack-startup-failures` 还覆盖直接接口激活错误。测试专用、不安装的
`ker-posix-startup-failure` 与生产库使用相同适配器源代码和原始 liblkl，额外链接
LKL 初始化、设备注册、内核启动和接口激活入口的 `--wrap` 包装；成功控制仍调用真实函数。loopback 失败必须阻止设备激活，设备失败
必须紧随真实 loopback 成功，且均在 native READY/main 前退出 125。每个实例验证实际
worker/EAL 清理与零 outstanding。生产 `libker-posix` 没有测试环境变量或故障入口。
该证据是测试注入返回错误，不认证自然硬件失败或 F-Stack 初始化 ABI。


## Ethernet TX 批次等待

`[dpdk] pkt_tx_delay=100` 或 `--tx-delay-us 100` 选择 0..100 微秒的 worker TX 批次等待，
CLI 覆盖 INI；非法值在加载库前返回2。默认0表示不主动等待，而不是照搬 F-Stack 默认值。
worker 最多保留32个完整 mbuf，首包确定单调时钟期限，满批提前刷新，stop/EOF 强制刷新。
等待聚合时监听新 TX 输入，并将 ppoll 超时限制在剩余期限内；PMD 返回未接收的后缀时，
保持 FIFO、所有权和已有短重试策略，不将它当作新的聚合等待。

PMD 接收的前缀转移所有权，未接收的后缀仍属于 worker。长度及 scatter 标志在调用前保存，
统计只计实际接受的帧，避免读取已释放 mbuf 或重复累计重试。错误退出只释放保留后缀，
设备停止后仍要求零 outstanding。捕获仍在所有权转移前执行一次，不在重试时重复捕获。
原始 Linux 继续负责所有协议和重传，协议时钟不受该参数控制。

`io.tx_delay_us` 显示有效配置。`tx_flushes` 是 PMD 批次发送尝试次数；
`tx_timer_flushes` 计非满批、非重试、非停止的定时刷新；`tx_full_flushes` 与
`tx_drain_flushes` 分别计满批及停止刷新尝试，两者可能重叠。这些计数不是包数。

`native-fstack-tx-delay` 的五次真实 net_tap/native 启动验证默认、INI及CLI覆盖，
在 idle wait=100ms 时仍要求非零延迟触发实际 timer flush，并通过独立宿主 TCP/UDP、
原始内核计数和零 mbuf 验证。`worker-mbuf` 用真实 mbuf 和受控回调验证零/部分接受、
FIFO、字节/scatter计数、期限边界、满批与清理；不将受控回调称作真实PMD背压测试。
`native-fstack-worker-batched-stop` 在暂停的真实 worker 通道中放入三帧及stop/EOF后恢复，
要求三帧按序到达独立宿主、精确计数、实际停止刷新及资源回收。
微秒值控制等待策略，不保证宿主调度延迟或吞吐；也不等价于 F-Stack 周期TSC刷新或多进程模型。


## EAL 内存大小和页模式

`[dpdk] memory=128` 或 `--memory-mb 128` 请求初始 EAL 内存，单位 MiB，转为原始
EAL `-m 128`。范围1..2147483647是正 signed-int 表示边界，不代表宿主一定有足够容量；
实际不足仍由 EAL 明确失败。省略时不添加分配参数。显式配置与 raw EAL 的 `-m`、
`--memory-size`、`--numa-mem`、`--socket-mem` 冲突时，加载库前返回2。

`[dpdk] no_huge=yes` 或 `--no-huge` 选择普通页；`no_huge=no` 或 `--hugepages`
要求 EAL 的 hugepage 模式。CLI 覆盖 INI；省略保留 EAL 参数。typed 页模式与 raw
`--no-huge` 同时出现时拒绝，普通页与 raw `--in-memory` 组合也提前拒绝。
不对宿主 hugepages 进行配置，不在资源不足时静默退回普通页。

`io.memory_bytes` 从 `rte_eal_get_physmem_size()` 读取 EAL 实际分配字节，
`io.hugepages` 从 `rte_eal_has_hugepages()` 读取 EAL 页模式。前者不是 CLI 回显，
也不包括独立原生 Linux 实例的内存；这些字段不证明具体 NUMA 放置或性能。
`native-fstack-eal-memory` 使用七次真实 net_tap/native 启动，覆盖32/64/128MiB、
INI、CLI覆盖及原始EAL长短参数；另验证 CLI 与 INI typed 设置在原始 EAL `--` 前生效，
即使分隔符后保留不同的 `-m` 值及 `--no-huge` 参数。每次要求实际字节数、普通页模式、独立宿主TCP/UDP、
原始内核计数和零mbuf。额外以私有非hugetlbfs目录验证 required-hugepages 返回125，
不发布READY或成功统计，不静默回退。当前环境未验证 hugepage 分配成功。


EAL 启动全局日志级别可用 `[dpdk] log_level=4` 或 `--eal-log-level 4` 设置（1..8，
1为emergency，8为debug）。省略时保留原始 EAL 日志策略；CLI 覆盖 INI。
若原始 `--eal` 已指定 numeric/named global `--log-level`，typed 全局级别会在启动前拒绝；
原始 `--log-level=pattern:level` 和 `--log-level=regexp,level` 类型规则可与 typed 全局级别共存。
原有
`[logging] level` / `--log-level` 仍在 EAL 初始化后覆盖全局与 Ker worker
级别，因此不能回溯改变启动日志。每类型 pattern/regex 策略仍通过原始 EAL 传入。
`io.eal_log_level` 是 EAL 初始化后的实际全局级别快照，`io.log_level` 是
READY 时的实际级别；两者均通过 DPDK API 回读。

`native-fstack-eal-log-level` 用七个真实实例检查 warning/info、INI/CLI 覆盖，
启动 warning 后运行 info，以及 typed 全局级别配合原始 component warning/info 规则时的
IOVA INFO 过滤。每次同时验证宿主 TCP/UDP 互通、native 计数与零 outstanding mbuf。


`[dpdk] file_prefix=mytest` / `--file-prefix mytest` 设置 EAL 运行文件命名空间。
CLI 覆盖 INI；省略保留原始 EAL。Typed prefix 插入首个 raw EAL `--` 之前；仅分隔符前的 raw `--file-prefix` 与 typed 值冲突，分隔符后的参数原序保留且不参与冲突检查。
名称限制为1..64个ASCII字母、数字、点、下划线或连字符，并以字母/数字开头，
不接受路径、空白或百分号。Ker 原样传递名称，不添加 F-Stack 的 `container-` 前缀。

`native-fstack-eal-file-prefix` 在私有 RUNTIME_DIRECTORY 中核对真实的
`dpdk/<prefix>/config` 文件，四个真实配置覆盖 raw/INI/CLI、覆盖未使用的命名空间以及 typed prefix 位于 raw terminator 前。
首个 native 应用存活时，同名前缀 primary 必须被原始 EAL 配置锁拒绝；另一
前缀的独立 TAP/native 实例必须正常启动和退出，然后首个应用继续 TCP/UDP 互通。
这只验证共享配置模式的运行命名空间和 primary 排他，不声称 shared hugepages
或 secondary 进程支持。原始 `--no-shconf` / `--in-memory` 绕过共享配置，
不能用此前缀推断 primary 排他。


`[dpdk] base_virtaddr=0x200000000` / `--base-virtaddr 0x200000000` 为原始 EAL
提供虚拟地址提示。CLI 覆盖 INI，省略保留 raw EAL；只接受带0x前缀的正十六进制，
并预留16MiB向上对齐空间，避免uint64回绕。DPDK会将未对齐地址向上对齐到16MiB，
且可能选择其他地址；这不是固定地址映射保证。typed 与 raw 有效选项中的同名设置
冲突时启动前拒绝；typed 插入第一个 `--` 前，后缀不参与冲突检查。

`io.memory_base` 用 `rte_memseg_walk` 回读已映射内存段的最低虚拟地址，
不是配置回显，也不代表物理/DMA地址或原始 Linux 实例的内存。
`native-fstack-eal-base-virtaddr` 的五组实例验证 raw/INI/CLI 覆盖、16MiB对齐和
终止符边界；在这些地址可用的测试进程中，实际映射必须位于提示区域的1GiB窗口内，
并完成宿主TCP/UDP、native计数和零mbuf退出。未验证地址冲突回退、hugepage
映射、NUMA/硬件拓扑或secondary进程，不修改原始DPDK分配器。


## TCP Fast Open 运行验证

`native-fstack-tcp-fastopen` 使用同一 POSIX 测试程序，分别运行宿主参考、native
客户端和 native 服务端。显式在测试私有网络命名空间设置 `net.ipv4.tcp_fastopen=519`
（原始 Linux 客户端/服务端及无 cookie 的 SYN 数据标志），不改变默认部署策略或
全局宿主配置。监听 socket 设置并回读 `TCP_FASTOPEN=4`。客户端首个连接通过
`sendto(MSG_FASTOPEN|MSG_NOSIGNAL)` 发送，第二个连接用普通 connect/send 对照。
双方检查完整 payload、peer 名称、双向半关闭与 EOF。

独立宿主 AF_PACKET 抓包必须同时看到携带完整精确请求的 SYN（无ACK）及普通空SYN，
因此仅普通握手成功不能代替 TFO 证据。native 两种角色均要求原始 Linux TCP open
计数、真实 DPDK TX/RX 和零 outstanding mbuf。协议行为全部来自固定原始 Linux，
本批只补齐覆盖，不新增 Ker 协议实现或修改上游代码。

这是 pinned F-Stack message/name/shutdown bridge 场景的 Linux 扩展，不是上游已注册
TFO 用例的完整迁移。该无 cookie CTest 不验证 cookie 协商/缓存、默认策略、非阻塞 EINPROGRESS 回退、
丢包重传、TCP_FASTOPEN_CONNECT、IPv6 或性能。


`native-fstack-tcp-fastopen-cookies` 单独覆盖 cookie 协商和复用，同样运行宿主参考、
native 客户端和 native 服务端。只在私有测试命名空间设置 `tcp_fastopen=3`，
启用客户端/服务端而不启用无 cookie 标志。每个角色走三条独立连接：首次
MSG_FASTOPEN、再次 MSG_FASTOPEN、普通 connect/send，均验证精确回显、peer、
双向半关闭和 EOF。native 角色要求至少三次原始 Linux TCP opens 及零mbuf。

独立 AF_PACKET 抓包解析实际 TCP options，必须观察首次空 SYN 的 option34
cookie 请求、对应 SYN-ACK 返回的4..16字节 cookie、另一客户端端口的新 SYN
复用完全相同 cookie 并携带完整请求，以及不带 TFO option 的普通空 SYN 对照。
这验证原始 Linux 实际协商/复用，不以 socket 选项或普通握手成功代替线路证据。
无效 cookie、密钥轮换、缓存过期、非阻塞回退、丢包重传、IPv6 和性能仍未验证。

`native-fstack-tcp-fastopen-nonblocking` 补齐非阻塞 Fast Open 发起与无 cookie 回退：
宿主参考、native 客户端及 native 服务端三种角色均要求首次 O_NONBLOCK
MSG_FASTOPEN 返回 EINPROGRESS，经 POLLOUT 和 SO_ERROR=0 后由调用者重发完整请求；
另一连接复用 cookie 时必须立即接受正数字节。独立抓包要求 cookie 请求/返回、
新端口携 cookie 和完整请求的 SYN，以及普通 connect 空 SYN 对照。
发起完成后恢复阻塞模式验证精确流、peer、半关闭和 EOF，因此不宣称覆盖通用
非阻塞流读写。协议仍完全使用原始 Linux，未修改运行时或上游源码，来源案例计数不变。
无效 cookie、密钥轮换、缓存过期、丢包重传和 IPv6 仍待验证。

`native-fstack-tcp-fastopen-key-rotation` 补齐监听端更换密钥后的旧 cookie 回退。
测试通过原始 Linux TCP_FASTOPEN_KEY 设置并读回16字节密钥；首次连接收到请求后，
服务端先更换为另一个单密钥，再发送回显，以确定顺序而不依赖睡眠。
宿主参考、native 客户端和 native 服务端均依次完成首次协商、旧 cookie 发起、
新 cookie 发起和普通 connect 对照四条连接，检查精确流、peer、半关闭与 EOF。

独立抓包要求旧 cookie SYN 携带完整请求，但 SYN-ACK 只确认 SYN 并返回不同的
cookie；客户端在建立后的流中以相同起始序号重发完整请求。下一条连接必须
用新 cookie 携数据发 SYN，服务端须确认 SYN 加完整数据长度。native 角色同时
要求至少四次原始 Linux opens、DPDK TX/RX 和零遗留 mbuf。
这属于 F-Stack host bridge 场景的 Linux 扩展，不新增来源案例计数，也不修改
运行时或上游协议源码。仅覆盖不保留备用密钥的单密钥替换；双密钥重叠轮换、
缓存过期、丢包重传、IPv6 与性能仍未验证。

`native-fstack-tcp-fastopen-backup-key` 覆盖双密钥重叠轮换：监听端先设置 A，
用两个源地址建立独立的原始 Linux TCP Fast Open cookie 缓存后，改为主密钥 B
加备用 A，再移除备用 A 仅保留 B。每次 TCP_FASTOPEN_KEY 均读回检查精确内容和
16/32/16字节长度；密钥更改发生在发送上一连接回显之前，以确定后续连接顺序。
宿主参考、native 客户端和 native 服务端各完成六条精确流，并检查 peer、半关闭
和 EOF：两个缓存先各取得 A cookie；B 源地址在 B+A 重叠期间携 A cookie 发 SYN，
服务端确认全部 SYN 数据并返回 B cookie；移除备用 A 后，未刷新过的 A 源地址仍
携 A cookie 发 SYN。独立抓包必须观察到此 SYN 携带完整请求、SYN-ACK 只确认 SYN
并返回不同的 B cookie；客户端在建立后的流中须以 SYN 数据起始序号（原 SYN 序号
加一）重发完整请求。
B 源地址随后须用已缓存的 B cookie 携数据发 SYN并获得完整确认；另有普通连接
对照。native opens、DPDK TX/RX 与零遗留 mbuf 同样必须通过。这是 F-Stack host
bridge 场景的原始 Linux 扩展，不改变来源案例计数或运行时/上游协议代码。缓存
过期、丢包重传、IPv6 与性能仍未验证。

`native-fstack-tcp-fastopen-connect` 覆盖原始 Linux TCP_FASTOPEN_CONNECT。
宿主参考、native 客户端和 native 服务端均先用未缓存 cookie 的选项式 connect
协商 cookie，再用带缓存的新连接检查延迟 SYN，最后走普通 connect 对照。
两条选项式连接均设置并读回选项；缓存连接的 connect 必须返回0，TCP_INFO
必须仍为 SYN_SENT。客户端报告本地端口后等待协调器通过 stdin 放行首次写入。
协调器在这一屏障处排空独立抓包，要求该连接尚无 SYN；放行后必须观察同一
端口携已协商 cookie 和完整请求的 SYN。既有 cookie 请求/返回/复用、普通空 SYN、
精确流、peer、半关闭、EOF、native opens 与零遗留 mbuf 检查同时保留。
此测试不依赖睡眠，验证明确的写入前屏障，不宣称任意时长的空闲行为。
不修改运行时或上游协议实现，来源案例计数不变；非阻塞延迟 connect、写前取消、
缓存过期、丢包重传、IPv6 和性能仍未验证。

`native-fstack-tcp-fastopen-cancel` 补齐首次写入前关闭延迟连接的边界。
宿主参考、native 客户端和 native 服务端均先协商 cookie，再创建缓存 cookie
连接，要求 connect 返回0且 TCP_INFO 仍为 SYN_SENT；不写入即 close，随后
fcntl 必须返回 EBADF。客户端在关闭后等待 stdin 屏障，协调器检查独立抓包中
该连接没有任何 TCP 报文，再放行下一条不同本地端口的缓存 cookie 连接。
下一连接继续使用写前屏障，随后要求携原 cookie 和完整数据的 SYN、精确回显、
peer、半关闭和 EOF，并保留普通 connect 对照。抓包直到双方退出都不得出现
已取消连接的 TCP 报文（包括 SYN、FIN、RST）；native 角色要求至少三条成功
流的 opens、DPDK TX/RX 和零遗留 mbuf，不把取消尝试算作成功流。
这是原始 Linux 对 F-Stack host bridge 场景的扩展，来源案例计数不变，未修改
运行时或上游源码。仅验证明确屏障及测试流生命周期，不宣称任意时长无报文或
SYN 已发送后的取消行为；非阻塞延迟建连、缓存过期、丢包重传、IPv6 与性能仍待覆盖。

`native-fstack-tcp-fastopen-connect-nonblocking` 补齐选项式延迟建连的非阻塞发起。
宿主参考和 native 双向互通均设置并读回 TCP_FASTOPEN_CONNECT，再设置 O_NONBLOCK。
未缓存 cookie 时 connect 必须返回 EINPROGRESS，随后经 POLLOUT 与 SO_ERROR=0
完成连接；已缓存时 connect 必须返回0，零超时 poll 立即报告 POLLOUT 且无
错误/挂断，同时 TCP_INFO 仍为 SYN_SENT、O_NONBLOCK 仍有效。
已有 stdin 屏障和独立抓包验证写入前无 SYN，放行后该端口所有 SYN 必须携
cookie 与完整请求；还要求 cookie 请求/响应/复用、普通空 SYN 对照、精确流、
peer、半关闭、EOF、native opens、DPDK TX/RX 与零遗留 mbuf。
连接发起完成后恢复阻塞模式完成流检查，因此不宣称通用非阻塞读写。
协议仍由原始 Linux 处理，来源案例计数不变，无运行时或上游修改；
缓存过期、丢包重传、IPv6 和性能仍待覆盖。

宿主 mutex 初始化与失败清理：`native-fstack-thread-runtime` 现在还覆盖普通/递归
mutex 的 malloc、属性初始化/类型设置、mutex 初始化、属性销毁故障。Ker 在
`host-thread.c` 内提供私有 mutex 表示，失败返回 NULL 并保留 pthread 错误码，
完整销毁已初始化资源；成功路径始终使用真实 pthread 锁，保留上游源码不变。
测试通过仅测试线程有效的链接器 wrapper 注入错误，检查分配、属性和 mutex
全部归零，再验证下一把真实锁可用及递归锁可重复持有。四线程共享计数与原始
Linux 启动/关闭同时执行，并要求内核实际分配适配后的 host mutex。
无返回值的 lock/unlock/free 回调发生 pthread 错误时明确 abort；子进程验证
销毁仍持有的锁不会静默释放。

DPDK worker 的单核收发不代表 LKL 宿主运行时单线程：原始 LKL `cpu.lock`
保护虚拟 CPU owner/count，内核线程和 SIGEV_THREAD 定时器都参与宿主调度。
此处保留同步，不进行锁消除，也不宣称单 lcore 独占协议栈调度或性能结论。
这是 F-Stack thread 场景的 Ker 适配扩展，FreeBSD 线程上下文 ABI 缺口仍保留，
来源案例计数不变，无 TCP/UDP 协议实现修改。

宿主线程创建失败清理：`native-fstack-thread-runtime` 进一步覆盖 pthread_create
本身失败后的启动参数所有权。Ker 在 host-thread 适配层持有启动 wrapper，
pthread_create 返回错误时释放它，返回 LKL 的0句柄并把 pthread 错误号写入 errno；
成功时由真实子线程在执行用户回调之前释放 wrapper，再传递原始参数。
仅测试线程启用的链接器故障注入分别返回 EAGAIN/EPERM，要求未调用失败回调、
分配余额归零，且 errno 从不同的哨兵值变为预期错误。每次失败后都运行真实
create/join，检查参数、结果及回调入口之前恰好一次 wrapper 释放。
默认、DEBUG、NDEBUG 三个变体及原始 Linux 启动/关闭都验证实际适配器。
未修改上游源码、协议或调度实现，不进行应用 pthread 拦截；这不等同于真实
宿主线程资源耗尽或调度策略测试，FreeBSD 上下文 ABI 缺口和来源案例计数不变。

`native-fstack-thread-runtime` 进一步覆盖正常返回和显式 host thread_exit 后的
TLS 生命周期。真实子线程分别清空 TLS、让析构函数重设三次，或持续重设超过
宿主 `_SC_THREAD_DESTRUCTOR_ITERATIONS` 公布的最小次数；join 后检查0次、3次，
以及对超出最小值的请求至少执行公布次数且不超过请求次数。每次析构入口必须
观察到该 TLS slot 已被清空，thread_exit
不得返回到后续语句，join 必须等待析构完成。
同时验证父线程 TLS 不被子线程继承或修改，删除仍持有父线程值的 key 不调用
析构函数。默认、DEBUG、NDEBUG 均直接执行现有 Ker/LKL callbacks 和真实 pthread，
不新增运行时代码、协议或调度实现，也不提高来源案例计数。公布的最小次数和
允许的额外迭代属于宿主 pthread 合同；取消线程、detached 线程生命周期和
FreeBSD 上下文 ABI 仍未覆盖。

宿主信号量边界：Ker 的 host-thread 适配层现在持有私有 POSIX semaphore，
始终使用真实 sem_init/wait/post/destroy。负计数返回 EINVAL；分配或初始化
失败返回 NULL，保留 errno 并释放已分配存储。sem_wait 仅重试 EINTR；
无法由 void callback 返回的其他 wait/post/destroy 错误明确 abort，防止
同步失败后仍继续执行内核。DPDK 收发不改变这些宿主同步语义。

`native-fstack-host-semaphore-debug/release` 验证分配与初始化失败清理、
随后正常信号量恢复、真实 SEM_VALUE_MAX post 溢出及注入的 wait/destroy
错误。后三项在尚无宿主线程时 fork 子进程，必须观察 SIGABRT。
中断场景通过真实 pthread_kill(SIGUSR1) 和不带 SA_RESTART 的 handler，
直到转发给真实 sem_wait 的 wrapper 实际观察到 EINTR；等待线程必须重试，
且直到真正 post 才能返回。join 后检查参数/结果，并恢复信号 mask/handler。
原始 Linux 还必须实际分配适配后的信号量、启动并关闭；TCP/UDP 互通继续
通过真实 DPDK 验证。上游、协议及调度实现保持不变，来源案例计数不变。
这是 F-Stack thread 场景的 Ker 同步扩展，不宣称公平性、跨进程共享信号量、
线程取消、仍有 waiter 时销毁或性能结论。


宿主定时器适配由 Ker 持有 opaque timer_t 包装对象，保留 pinned LKL 的
相对 CLOCK_REALTIME/SIGEV_THREAD 行为和原始 Linux clock-event 实现。
分配或 timer_create 失败返回 NULL，保留 errno 并完整回收存储；
timer_settime 失败直接返回错误；void timer_free 无法报告删除失败，因此明确
abort，不能静默释放仍有效的 handle。0 纳秒解除定时，interval 始终为0。

`native-fstack-host-timer-debug/release` 使用真实 POSIX timer 验证失败恢复、
秒/纳秒换算、通过 timer_gettime 检查解除定时，以及把100秒期限重新设为1纳秒后的真实单次回调。
删除失败的子进程在父进程创建任何线程或 timer 之前 fork；成功路径不模拟。
原始 Linux 必须实际分配、设定、触发和释放这些 timer，并唤醒一次带超时 poll。
另以实际 DPDK TCP/UDP 和启动生命周期做回归。固定 F-Stack clock 案例仅为来源
动机，本批是 Ker 适配扩展，不增加迁移来源案例数，也不修改上游源码。
不宣称 timer_delete 等待已经执行中的 SIGEV_THREAD 回调结束；墙钟调整、周期
定时器、回调静止保证、精确延迟和性能仍未验证。


宿主线程完成边界：Ker 的 thread_join 继续使用真实 pthread_join，失败返回 -1，
并将 pthread 直接返回的错误码写入 errno。测试分别注入 EDEADLK、EINVAL、ESRCH，
每次保留真实 joinable 子线程，再执行成功的真实 join，确认回调完成。
void thread_detach 针对当前宿主线程调用真实 pthread_detach；失败明确 abort，
不继续假定线程已经 detached。尚未创建宿主线程时 fork 的独立子进程分别验证
真实 detached 属性和注入 EINVAL 后的 SIGABRT；不对已 detached 线程调用 join。
默认、DEBUG、NDEBUG 均验证这些边界，原始 Linux 启停和 TCP/UDP 互通继续回归。
这扩展 F-Stack thread 场景的 Ker 适配覆盖，不增加来源案例计数；不宣称取消、
detached worker 的并发回收或 FreeBSD pcurthread 继承合同。


宿主页分配与释放边界：Ker 安装真实匿名 mmap 的 page_alloc/page_free 回调，
保留页对齐、零填充和读写权限。分配失败返回 NULL 并保留宿主 errno；
void page_free 无法报告 munmap 失败，因此明确 abort，避免继续假定页已释放。
固定地址 mmap 在宿主忽略 MAP_FIXED_NOREPLACE、返回不同地址时，只释放新返回的
映射并以 EEXIST 返回失败；这一步清理失败也必须 abort，原有映射不得被解除。

`native-fstack-host-pages-debug/release` 注入 ENOMEM/EAGAIN 后验证真实两页
分配恢复、对齐、零填充、全部字节写入和 mincore 释放证据；验证真实零长度
EINVAL、固定地址冲突和旧宿主回退清理。失败释放在未创建线程的独立子进程
中注入 EINVAL，必须收到 SIGABRT。已有 host-runtime 的原始 Linux 启停及
TCP/UDP 互通继续验证安装后的适配层。来源案例计数不变，不宣称 hugepage、
共享/文件映射、MMU 内核或并发地址预留语义。


宿主线程栈查询：Ker 的 thread_stack 继续通过 pthread_getattr_np/getstack
查询当前宿主线程的真实栈范围，属性销毁也成功后才写入可选的 size 输出。
查询或清理失败返回 NULL，保留调用方 size，errno 接收 pthread 的错误码；
属性已初始化时，即使 getstack 失败也执行销毁，优先保留查询错误。

现有 `native-fstack-thread-runtime` 的默认、DEBUG、NDEBUG 变体分别在
主线程和真实子线程内验证：范围包含当前局部变量，与独立 pthread 查询一致，
并接受 NULL size 指针。逐阶段注入 EAGAIN/EINVAL/EIO，跟踪属性资源清理，
每次失败后必须恢复真实查询。来源计数不变，上游 Linux/DPDK 不变。
当前固定内核未启用 KASAN；测试仅验证已安装的宿主 callback，
不宣称 KASAN 栈去毒、自定义栈或备用信号栈覆盖。


INI 重复配置键采用最后一项生效，重复节继续同一节；CLI 覆盖最终 INI 值。
这适用于 network、dpdk、sysctl、VLAN 等已有支持字段，不引入未知配置项支持。
只转换并校验最终值，因此被覆盖的早期值不会单独触发类型错误；最终值非法、
未知键/节、DEFAULT 继承仍在启动前返回 2。每次加载使用独立对象，
不保留上一次加载的 sysctl、VLAN 或网关。
`native-fstack-config-lifecycle` 验证加载隔离和失败后恢复；
`native-fstack-launcher-config-interop` 以早期错误地址/EAL/日志目录加后续
有效值，验证真实 DPDK 与原始 Linux 在 TCP 两种角色下只使用最终配置，
CLI port/stats 仍优先。对应 F-Stack 重复键来源场景，不声称 C 内存分配 ABI 等价。


描述符命名空间共存：`native-fstack-fd-map` 在原始 Linux 内核内创建 TCP socket，
同时以宿主 syscall 创建 UDP loopback socket，再通过各自的 fcntl 使内部 fd
数值相同。Ker 导出原生 fd 时必须预留不同的真实宿主 O_PATH/CLOEXEC fd；
查表返回原始 native fd 和类型，宿主 socket 的 fd 必须仍被视为 unmanaged。
测试执行真实宿主 UDP 自发自收、原生 SO_TYPE 查询，并分别先关闭 native export
或宿主 socket，验证另一方继续可用。最后同时检查映射清除、宿主预留释放、
原生 fd 关闭。它适配 F-Stack 编码往返的命名空间隔离意图，
不声明固定偏移算术、helper ABI 或数值范围等价，不增加 Ker 自有协议路径。


TCP 写入聚合：`native-fstack-tcp-cork` 在宿主参考、原生客户端和原生服务器
中，以独立对端验证双向 TCP_CORK 与 MSG_MORE。前者设置 CORK、write 17 字节，
再通过 dup writev 31 字节并解除 CORK；后者以两段 sendmsg(MSG_MORE) 写入
17 字节，CORK 选项仍为 0，后续不带 MORE 的 send 提交 31 字节。
NODELAY 设为 1，验证 MORE/CORK 仍可暂缓小写入；别名查询选项必须一致。
完整 48 字节流、解除后的普通字节与半关闭 EOF 均必须验证。

负向就绪检查使用独立 TCP 控制通道，接收方 poll 20ms，并要求从发送前
宿主单调时间戳起累计小于 100ms，以避开 Linux 约 200ms 自动解除边界。
两端均使用未被 Ker 接管的宿主 CLOCK_MONOTONIC；超时样本排空后最多重试
八次，未获得有效观测则失败，不作为兼容通过。测试不认证自动解除精度、
报文数量或线速性能。原生实例要求至少五次 Linux TCP open、DPDK TX/RX
和零 outstanding mbuf。它扩展已有 socket/dup 场景，来源计数不变。


TCP_MAXSEG/MSS：`native-fstack-tcp-mss` 在宿主参考、原生客户端和原生服务器
中，分别在 connect 前设置客户端 600、握手前设置监听器 700。dup 查询必须
共享设置；-1、1、65536 返回 EINVAL 且保留之前值，0 重置合法，随后恢复
目标值。连接/accept 后有效 MSS 必须为正且不超过 600，TCP 选项开销可使其更小。
双方验证精确 16KiB 字节流、后续小消息、半关闭 EOF 与别名释放。

原生 worker 的完整 PCAP 必须显示 SYN 的 MSS600、SYN-ACK 的 MSS700；
检查 IPv4/TCP 长度和选项，拒绝目标连接的分片/截断记录。原生 TX 数据段
payload 不得超过 600，且至少 28 段、16385 数据字节；不对宿主 RX 的
GSO/GRO 聚合行为作等价要求。Linux TCP open、DPDK TX/RX 与零 outstanding
均需满足。该测试扩展已有 socket 场景，不增加来源计数，也不宣称 PMTU 变化、
IPv6、连接后重协商或硬件 offload 资格。上游和生产协议实现保持不变。


INI 长键名：`native-fstack-launcher-config` 使用实际 reader 验证两个前 59
字符相同、末尾不同的 60 字符 sysctl 键完整保留，A-B-A 最终顺序和 CLI 覆盖
仍使用完整名称。128 字符允许，129 字符在加载库/启动 worker 前返回 2。
`native-fstack-network-sysctl` 再从 INI 将 60 字符未知键传到原始 Linux，
要求错误显示完整 /proc/sys 路径、应用未执行、没有 native READY，真实 EAL
清理成功且无 mbuf 泄漏，宿主 sysctl 保持不变。此处验证解析和显式失败边界，
不把未知 sysctl 当作可用功能，也不声明 F-Stack 任意 handler ABI 等价。


TCP keepalive：`native-fstack-tcp-keepalive` 在宿主参考、原生客户端和原生服务器中，
验证 SO_KEEPALIVE 与 TCP_KEEPIDLE/KEEPINTVL/KEEPCNT 的 dup 共享、监听继承，
以及无效值返回 EINVAL 后保留原值。双方先交换字节，客户端保持四秒无应用数据的
poll；探测包不能成为应用可读事件，之后必须恢复精确字节收发、禁用选项并完成 EOF。
原生 TX 完整抓包必须出现零负载、ACK-only、序号为先前数据末尾减一的 keepalive
探测包，同时要求原生连接计数、DPDK TX/RX 和零 outstanding mbuf。
本项覆盖响应正常的空闲对端，不声明丢失探测后的超时断开、精确计时或 IPv6 覆盖。
协议处理完全来自原版 Linux，没有新增 Ker 自有 TCP 逻辑。


SO_PEEK_OFF：`native-fstack-tcp-peek-offset` 先探测宿主支持；仅当宿主返回
`EOPNOTSUPP`/`ENOPROTOOPT` 时跳过宿主参考，其他探测错误均失败。原生客户端和服务器
仍必须分别执行 SO_PEEK_OFF 游标断言；其宿主对端改用普通 MSG_PEEK，同时核对精确字节、
FIONREAD、完整读取和 EOF。支持该选项时也运行双端宿主参考。独立控制连接协调完整 16KiB+37 字节及 FIN 入队，
默认 -1 的重复 MSG_PEEK 必须返回相同字节；经 dup 设置偏移 17 后，recvmsg
跨两个 iovec 预览并推进共享游标，FIONREAD 不变。正常读取 257 字节后，
游标必须向后调整，下一次预览仍指向原来的数据位置。错误的选项长度返回 EINVAL
并保留游标；重置 0/-1 分别恢复队首预览和不推进模式。最后通过 readv 验证全部
剩余字节、游标归零及重复 EOF，要求实际原生连接、DPDK TX/RX 和零 outstanding。
行为来自原版 Linux；不声明越过队尾的游标或并发读取覆盖。


IPv4 TCP TOS/TTL：`native-fstack-tcp-ip-options` 在宿主参考、原生客户端和
原生服务器中验证 IP_TOS/IP_TTL 的监听继承与 dup 共享。客户端初值为
TOS0x28/TTL42，服务器为 TOS0x48/TTL43；TTL0/-2/256 必须返回 EINVAL
且保留旧值。双方精确交换 1024 字节后，通过别名更新为 TOS0x68/TTL52
和 TOS0x88/TTL53，再交换 P/A 字节并验证半关闭 EOF。
原生 TX 完整抓包必须确认握手和初始数据使用初值，后续字节使用新值；
TOS 检查仅屏蔽 ECN 两位，不替代 ECN 测试。同时要求实际原生连接、
DPDK TX/RX 和零 outstanding。该场景不覆盖路由 TTL 递减、ICMP 超时、
IPv6 或重传，未修改原版 Linux 或 Ker 协议实现。


TCP_USER_TIMEOUT：`native-fstack-tcp-user-timeout` 在宿主参考、原生客户端发送端
和原生服务器发送端中验证真实零窗口超时。握手前限制接收缓冲，独立 TCP 控制
连接阻止对端读取，发送端经 MSG_DONTWAIT 填满实际发送队列直至 EAGAIN。
选项默认 0，经 dup 设置 1000ms，负值返回 EINVAL 且保留旧值；重置 0 后再次设置。
10 秒保护范围内必须获得 POLLERR，别名读取 SO_ERROR 得到 ETIMEDOUT，原描述符
再次读取错误已清除，后续 MSG_NOSIGNAL 发送返回 EPIPE。此后才释放宿主对端，
核对已交付字节及 EOF/ECONNRESET；交付数必须为正且小于已接受发送数。
原生运行还必须具有 TCPWinProbe、实际 TCP 连接、DPDK TX/RX 和零 outstanding。
该项不声明精确 1000ms 墙钟、丢包重传期限、keepalive 失效或 IPv6 覆盖；
所有窗口探测和关闭行为来自原版 Linux，未修改协议实现。


TCP_NOTSENT_LOWAT：`native-fstack-tcp-notsent-lowat` 在宿主参考及原生客户端/
服务器发送端中验证未发送数据阈值。控制连接阻止宿主对端读取，发送端扩大
SO_SNDBUF 并设置 LOWAT4096，使用 MSG_DONTWAIT 填充至 EAGAIN。
必须观察到 SIOCOUTQNSD 至少 4096、无 POLLOUT，且已接受字节小于查询所得
发送缓冲的四分之一。保持对端不读取，仅经 dup 将阈值改为 UINT32_MAX 时
必须可写，恢复 4096 后必须再次不可写，以区分低水位背压与发送内存耗尽。
释放对端后，五秒内恢复可写，继续发送独立字节并半关闭；对端必须验证全部
已接受字节及 EOF，发送端也验证反向 EOF。另查默认值、共享选项、重置与
错误长度的 EINVAL 恢复，以及实际原生连接、DPDK TX/RX 和零 outstanding。
该项不承诺精确队列大小或通知期限，不覆盖并发发送、丢包重传或 IPv6。


IP_BIND_ADDRESS_NO_PORT：`native-fstack-bind-address-no-port` 将自动端口范围
限制为单个 40000，先证明普通 bind(address,0) 立即保留端口并导致第二次绑定
EADDRINUSE。启用选项后 bind 保留本地地址但端口仍为 0；listen 才分配端口，
显式绑定范围外的 40001 则仍立即生效。三个 socket 经 dup 检查选项共享和重置，
同时先绑定地址而不占端口，再连接三个不同目的端口，全部保持连接并共享本地
40000；独立宿主监听器必须观察到这三个准确源元组。每条连接校验独立的 16 字节
数据和半关闭 EOF，实际原生连接至少三个，DPDK TX/RX 有流量且 outstanding 为零。
非本地地址依旧返回 EADDRNOTAVAIL，随后可重试本地绑定；该选项不意味着 freebind。
宿主参考只修改隔离网络命名空间的端口策略并先行恢复；原生运行后再次确认宿主
策略未变。不声明 UDP 自动端口共享、相同目的元组复用、IPv6 或 RSS 队列能力。


TCP_WINDOW_CLAMP：`native-fstack-tcp-window-clamp` 在宿主参考及原生客户端/
服务器中固定 SO_RCVBUF65536，并在握手前配置 clamp4096。检查 dup 共享、
错误长度 EINVAL 后保留旧值、未连接时的零重置、监听/已连接时零值被拒绝，
以及过小正值的内核规范化。连接后的有效值须为正且不超过初值，别名读回相同；独立控制连接保证双方
完成该检查后才开始应用数据传输。
原生 TX/RX 完整抓包必须包含双向握手；原生 SYN/SYN-ACK 的初始通告窗口必须
在 1..4096。后续窗口按双方实际协商的缩放选项解码并记录，要求有正窗口 ACK、
至少 16385 个原生发送负载字节，应用逐字节验证双向 16KiB、后续小消息及 EOF。
数据后的 clamp 读回须为正且两别名一致，原生连接、DPDK TX/RX 与零 outstanding
均为必需证据。

这里不承诺整个连接永久保持 4096 上限。固定 Linux 源码的
`net/ipv4/tcp_input.c:tcp_measure_rcv_mss` 会在接收报文尺寸引起 scaling_ratio
变化时重新写入 window_clamp，即使应用已设置 SO_RCVBUF；实测后续窗口可增大。
测试保留该原版 Linux 行为，不增加 Ker 自有窗口逻辑，也不修改上游源码。
不覆盖动态缩小的时限、并发调参、丢包重传或 IPv6。


TCP_LINGER2：`native-fstack-tcp-linger2` 在宿主参考、原生客户端和原生服务器
中分别验证双方主动半关闭的路径。独立控制连接协调先发送字节再 SHUT_WR，
对端验证数据与 EOF；关闭方必须通过 TCP_INFO 看到真实 FIN_WAIT2，才关闭
原描述符。保留的 dup 别名仍须接收对端的后续字节，且状态保持 FIN_WAIT2；
最后关闭该别名时，负值 TCP_LINGER2 触发原版 Linux 的孤儿 socket 清理。
对端须观察到 POLLERR，并通过 SO_ERROR 读取 Linux 在 CLOSE_WAIT 收到 RST
时给出的 EPIPE；错误消费后共享状态清零，随后 EOF 与 MSG_NOSIGNAL 的 EPIPE
也必须正确。原生数据端口抓包必须在 TX/RX 均出现 FIN 和 RST，并具有至少三次
原生连接、实际 DPDK 收发及零 outstanding。另查 dup 共享、正值设置、零重置
和错误长度 EINVAL；SO_LINGER 保持关闭，避免混淆两组选项。
测试不声明正值 LINGER2 的孤儿定时器期限、TIME_WAIT 时长、丢包重传或 IPv6。


TCP_CONGESTION：`native-fstack-tcp-congestion` 在宿主参考及原生客户端/服务器
中记录新 socket 或监听器的默认算法，握手前经 dup 选择 Reno，并验证监听继承
和共享名称。空名称必须返回 EINVAL，不存在的算法返回 ENOENT，均须保留原选择。
设置使用按明确长度传递、不含终止 NUL 的名称，以覆盖字符串选项边界。
双方先在 Reno 下精确交换 16KiB，再通过连接中的别名恢复最初默认算法，交换
另一组不同的 16KiB；各阶段校验算法读回、TCP_INFO 的 ESTABLISHED 和正 snd_cwnd，
最后验证小消息恢复与半关闭 EOF。原生端必须明确报告恢复到固定内核的 CUBIC；
宿主参考和独立宿主对端使用自身默认值，不额外要求宿主提供 CUBIC。
原生连接、实际 DPDK TX/RX 和零 outstanding 为必需证据。算法全部来自固定的
原版 Linux；不声明拥塞窗口公式、吞吐/公平性、丢包重传或 IPv6 覆盖。


### 类型化 virtio-user vdev

INI 可以声明原版 DPDK virtio-user 设备，无需把设备参数拼入 EAL 字符串：

```ini
[dpdk]
nb_vdev=1
port=net_virtio_user0
eal=--no-huge --no-pci --no-shconf --iova-mode=va -m 64

[vdev0]
path=/run/example-vhost.sock
queues=2
queue_size=512
mac=00:11:22:33:44:55
cq=1
```

`nb_vdev` 支持 0..16，section 必须精确覆盖 0..N-1。path 必填，相对路径以
配置文件目录为基准；其余默认 queues=1、queue_size=256、cq=0，与固定 PMD 一致。
queues 范围 1..128，多对 queue 需要 cq=1；ring size 必须为 64..32768 的 2 次幂。
MAC 必须非零单播。可选 iface 最长 15 字符，原始 PMD 仅允许 vhost-kernel 使用它；
Unix socket 后端必须省略 iface，组合错误不会被静默转换或忽略。
重复键/section 以最终值为准。未知键、缺失 count、索引不连续和与原始 EAL --vdev
冲突在启动前拒绝；port 必须选择一个声明的 net_virtio_userN。

`[vdevN] queues` 只配置虚拟设备可提供的队列容量；实际启用的队列对数由
`--queues` 或 `[dpdk] queues` 指定，默认仍为 1。需要多队列接收时显式设置该选项，
行为和限制见下方“多队列接收和 RSS 配置”。内核/vDPA 后端仍受原始 DPDK 及设备权限限制。
`io.driver`、`io.max_rx_queues`、`io.max_tx_queues` 和 `io.rx_descriptors`
提供原始 ethdev 的诊断值；队列信息不可用时 descriptors 为 0。

`native-fstack-typed-vdev-config` 检查源配置映射及失败边界；
`native-fstack-typed-vdev` 使用独立 vhost/TAP 进程和宿主内核做真实双向 IPv4/IPv6
互通及 ownership 验证。测试需要固定 DPDK 的 net_virtio/net_vhost/net_tap PMD；
缺少模块时明确 skip，不作为运行通过。完整 F-Stack iface+socket fixture、bond 与
C 分配器合同尚未通过，详见迁移清单和 issue224。


### 类型化单 bond 与 LACP

`[dpdk] nb_bond=1` 启用 `[bond0]`，并要求 `port=net_bonding0`。
必须提供 mode=0..6 和 slave（逗号分隔、1..16 个不同的原始端口 ID/设备名）；
primary 可选但必须是成员之一。支持 socket_id=-1（`SOCKET_ID_ANY`）或
`0..max_numa_nodes-1`，其中 `max_numa_nodes` 由选中的 `--io-worker --dpdk-limits`
查询返回，并来自该 worker 编译时使用的 DPDK `RTE_MAX_NUMA_NODES`。launcher 会在
启动应用和 DPDK EAL 前验证该值及 socket_id；worker 不支持查询或返回无效上限时会明确报错。
还支持非零单播 MAC、xmit_policy=l2/l23/l34、lsc_poll_period_ms（正整数）、
up_delay/down_delay（非负整数），
时间最大 INT_MAX 毫秒。缺省 poll=100、up/down=0，最终重复键生效。
成员须先由 EAL 或类型化 vdev 声明；只启用选中的一个 bond，不承诺多 bond 调度。
`slave` 翻译成原版 PMD 的重复 `member=` 参数，其余设备设置交给原始 DPDK。

固定 DPDK 的共享库未导出所有公开 timing API。因此需要以
`-DKER_WITH_NATIVE_BOND=ON` 构建并安装额外的 `ker-io-worker-bond`，再通过
`ker-run --io-worker /path/to/ker-io-worker-bond` 选择它；原有共享库 worker 保留。
DPDK 必须包含 net/bonding、sched/ip_frag 及对应静态 archive。
该 worker 按 pkg-config --static 的原始顺序链接 PMD/依赖，不要为它 LD_PRELOAD
另一套共享 DPDK/PMD，以免混用两个 EAL 实例。缺失原始 API 会明确失败。
延迟由原始 setter/getter 应用和校验，不绕过 API 写私有结构或修改上游源码。

worker 通过原版 PMD 的 RX/零报文 TX burst 服务空闲 LACP，并将 bond 空闲等待
上限限制为 10ms；不提供实时调度保证。`io.bond` 保留启动读回，最终 `bond`
给出 mode、当前 primary、hash policy、timings、成员/active 数和 `lacp_distributing`。
LACP 状态来自原始公开 API，不能用虚拟 TAP 的 carrier 或 active 数冒充。
关闭 bond 后还会关闭其成员 queue，确保 pool 不再被成员持有。
`native-fstack-typed-bond` 以真实独立 Linux LACP 对端验证双向 IPv4/IPv6、
完整报文、成员路径丢失后的恢复及零 mbuf 泄漏；不是 active-backup 对 mode4 的替代测试。
物理 NIC、严格延迟基准和多接口调度仍未资格验证。


### 同一原始 Linux 中的附加接口

保留原来的 `[network]`/`[dpdk]` 主接口配置，再增加：

```ini
[interface.aux]
address=198.19.0.2/24
address6=2001:db8:2::2/64
vip_addresses=198.19.0.3/24,198.19.0.4/24,198.19.0.5/24
vip_addresses6=2001:db8:2::3/128,2001:db8:2::4/128
port=net_tap1
eal=--lcores=0@1 --no-huge --no-pci --no-shconf --iova-mode=va -m 64 --vdev=net_tap1,iface=keraux
mtu=1500
max_mtu=2000
mbuf_mode=large
```

NAME 是配置/日志标签；原生 Linux 接口名由 virtio 驱动分配，可用 native ioctl 查询。
最多 7 个附加接口。address/port/eal 必填；IPv6 主地址、各最多 32 个 VIP 及
mtu/max_mtu/mbuf_mode 可选，后三项默认继承最终主接口设置。每个附加接口使用
独立 EAL worker/报文/MTU 控制通道，必须选择自己独占的设备与 EAL 命名空间，
而不是共享原始进程配置；CPU 选择、memory/file-prefix 等 EAL 参数由该 section
显式提供。上面的 CPU 1 仅作例子，需选择允许的宿主 CPU。各原始 Linux 接口
仍在同一个内核中，共享 socket 表、路由、sysctl、TCP/UDP 协议与全局诊断计数。

地址必须唯一且为无 scope 的原生单播地址；附加接口与主接口/其他附加接口的主地址网络不得重叠。
附加 IPv6 VIP 要求对应 address6，启动等待原始 Linux DAD。当前默认网关与 VLAN
配置仍归主接口；附加 section 的未知选项会拒绝，不会默默当成有效配置。
各 native 接口的 MTU ioctl 按真实 ifindex 选取控制通道，分别执行原有读回/回滚协议。

任一 worker 启动失败会阻止应用运行；应用运行中任一 worker 退出会使整个后端失败。
关闭时先通知所有 worker，再等待回收；每个 pool 必须清空。根 `--stats` 保留原主接口
格式及唯一的 native 全局计数；`interfaces` 列表包含各附加接口的名字、PID、I/O/MTU
与独立 worker 信息，`worker_pid` 是主 worker PID。附加日志/pcap 放在同名子目录。
`native-fstack-multiport` 验证两接口、全部主地址/VIP、跨接口 TCP/UDP 路由、独立 MTU、
额外 worker/原始 DAD 失败及运行中退出的清理。它不代表 F-Stack 的全局多 lcore、
每端口多队列、硬件 RSS/thash 或完整多端口 ABI 已通过。

多队列接收和 RSS 配置

`--queues N` 或 `[dpdk] queues=N` 配置 1..16 对真实 ethdev RX/TX 队列，默认 1。
`[interface.NAME]` 可独立覆盖 `queues` 和 `rss`，否则继承主接口最终值。
这与 `[vdevN] queues` 的设备容量声明不同；声明两个队列不会自动启用两个队列。
worker 在同一线程上轮询全部 RX 队列，每次取得 burst 后轮换起点；通道拥塞时保留
当前 burst 的完整未交付后缀。应用数据仍从 TX 队列 0 发出，没有多 lcore 调度保证。
MTU 重配置会重建全部 RX 队列；退出先关闭设备全部队列，再核对 mempool 所有权。
队列总描述符需求增加时 pool 会相应增长，EAL 内存不足会使启动失败。

`--rss` / `[dpdk] rss=1` 要求至少两个队列，使用原版 PMD 的默认哈希算法和密钥。
当前接口要求 IPv4/IPv6 TCP/UDP 四种 RSS 类型、40..64 字节可读密钥，以及至多
4096 项、大小为 2 的幂的非空 RETA。启动通过原版 DPDK API 写入 `RETA[i]=i%N`，
逐项读回，并核对类型和密钥长度；任一 API 不支持、失败或读回不一致都会阻止应用启动。
MTU 停启后会再次核对密钥/类型和恢复、读回 RETA。`--no-rss` 保留默认关闭状态。
这不是 `symmetric_rss` 或 F-Stack `[rss_check]` / `rss_tbl` 的兼容实现。

`--stats` 的 `io.queues` 是启用的队列对数，`io.data_tx_queue` 当前为 0；
`rx_by_queue` 记录每个 RX 队列实际从 PMD 取得的报文数，包含随后丢弃或在退出时释放的
已取得报文，不包含启动阶段的 promiscuous backlog 丢弃；后者仍单独计数。
`rx_rss_metadata` 是 PMD 设置 RSS hash 标志的报文数。`io.rss` 在关闭时为 null，
启用时包含启动读回的密钥、类型、RETA 大小和已验证的映射；它不等于实际流落点认证。

`native-fstack-rx-queues` 使用独立 vhost/TAP 后端将报文送入队列 1，验证两个原版
Linux 内核的双向 IPv4/IPv6 ICMP、PCAP 和实际队列计数；该注入不依赖 RSS。
`native-fstack-rss-control` 使用原版 net_null PMD 验证生产适配器的密钥/RETA API，
并拒绝被故障夹具篡改的成功读回。null PMD 不提供实际流哈希落点证据。
当前可用 virtio-user/vhost 后端不支持全局 RSS，TAP 也没有本接口要求的 RETA/密钥读回
能力，因此 RSS 请求会明确失败。物理设备分流、对称哈希、thash 源端口调整及 80/443
表仍由 issue 220 跟踪，不计为完成迁移。所有 socket 端口和协议行为仍由原版 Linux 实现。

调用方回调与同步运行停止

`<ker/posix.h>` 导出 `int ker_posix_run(ker_posix_loop_func callback, void *arg)` 和
`void ker_posix_stop_run(void)`。在 ker-run 已启动的原生实例内，run 在调用线程反复
执行调用方回调，原样传递 arg；忽略回调整数返回值。NULL 回调等待另一线程请求停止。
stop 可从回调或其他线程调用，重复调用幂等，run 之外调用不影响后续启动。它不是
异步信号安全接口，也不会中断尚未返回的回调。嵌套/并发 run 返回 -1/EBUSY。

最后一次回调返回前，调用方必须停用其他原生 socket 使用者；不要取消 run 线程、
longjmp 或从回调跳过其返回路径。run 会关闭原生 fd、等待内核发送队列、移除接口、
停掉原版 Linux，再请求父 launcher 关闭、回收所有 DPDK worker。只有全部 worker
已退出、零缓冲区所有权、私有 packet/MTU/启动/确认 fd 已关闭且内核关闭完成才返回0；超时或失败返回-1/errno。一次 run
消耗当前实例，之后 capabilities 为0、kernel_release 为NULL，socket/再次 run 返回
ENETDOWN；应用仍可继续执行普通宿主操作。进程析构不会再次停内核。

接口依赖 launcher 继承的私有 SOCK_SEQPACKET 确认通道，该 fd 在原生构造时标记
CLOEXEC。它没有实现 F-Stack 同进程 ff_run/ff_dpdk_run 符号或多 lcore/耦合轮询 ABI；
业务回调仍完全由调用方提供。`--stats` 的 run_shutdown、run_shutdown_workers、
run_shutdown_ack 仅在使用本接口时记录监督者的实际清理结果。

原生设备通道边界

内部 packet-device 构造函数要求已连接的 AF_UNIX datagram/seqpacket 通道，不支持
字节流或宿主 Internet socket 作为 Ethernet record 通道。失败不接管 fd 或修改其标志；
成功后拥有传入端点和私有唤醒 eventfd，并设置 FD_CLOEXEC。TX/RX 的 iovec 是借用
缓冲区，NULL 上下文返回 EINVAL 且不释放、修改调用方的向量或数据。原版 LKL
设备移除/释放后才回收上下文；这些规则没有创建 F-Stack FreeBSD mbuf 所有权 ABI，
也不构成运行期设备热插拔 API。启动会保留上下文创建的实际 errno。
