# 原生 Linux UDP socket 验证

本批验证现有 POSIX 适配层中的 IPv4 UDP unicast 路径。socket、datagram 边界、
checksum、地址查询和事件就绪由完整导入的 Linux 6.12.113 实现；Ker 负责 API
转换、fd、packet I/O 和诊断。源码 pin 与构建方式沿用 [原生后端](native-tcp.md)。
不使用基础库的 UDP 报文构造器或 packet view 代替原生 socket。

```sh
ctest --test-dir build-native-tcp -R '^native-fstack-udp-interop$' --output-on-failure
```

测试用真实 DPDK net_tap/veth 连接独立宿主 Linux UDP 对端，三种 API 各运行
原生客户端和服务端两种角色，共六种组合。两个端点都必须报告逐字节校验成功。

| 验证 | 断言 |
| --- | --- |
| sendto/recvfrom | 每方向 0、1、33、257 字节的四个 datagram，保持边界与顺序，校验源地址/端口 |
| 零长度 datagram | epoll 通知就绪，接收返回 0 后同一 socket 继续收发非空报文，不当作 TCP EOF |
| sendmsg/recvmsg | scatter/gather、客户端 connected UDP 与 getpeername；FIONREAD 返回首报文长度 |
| MSG_PEEK/MSG_TRUNC | 短缓冲区 peek 返回完整报文长度并正确设置 MSG_TRUNC；报文仍在队列，随后完整读取不截断 |
| sendmmsg/recvmmsg | 按返回的消息数推进，逐项检查 msg_len、来源与报文内容；空报文仍占一个消息条目 |
| 队列清空 | 非阻塞 recv 返回 EAGAIN |
| 原生路径与回收 | 每实例 UDP InDatagrams/OutDatagrams 至少为 4，InErrors/NoPorts 为 0，DPDK TX/RX 非零且 outstanding=0 |

`--stats` 的 `native` 对象新增 `udp_in_datagrams`、`udp_out_datagrams`、
`udp_in_errors`、`udp_no_ports`，均读取原生 Linux `/proc/net/snmp` 的 `Udp:`
计数；既有 TCP 字段保持含义。UDP-only 实例不要求 TCP open 计数增长。

F-Stack 来源及文件 SHA-256 见 [provenance](../tests/fstack-provenance.json)。
上游 TX checksum 用例不验证 socket；其 UDP/epoll 示例是 API 使用参考且忽略
零长度 payload，本批明确覆盖这一差异，没有复制 ff_* 实现或测试 harness。

本次范围为小报文 IPv4 unicast。DNS resolver 透明兼容、IPv6、多播、fragmented
UDP 与异步 error queue 尚未由本批验收。公开能力位仍按 TCP 首版定义；本批
增加的是原生 UDP 路径验证和可追溯计数。
