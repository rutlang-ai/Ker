# 原生 Linux 后端的 PCAP 抓包

`ker-run --pcap-dir /existing/private/directory` 可选抓取实际 DPDK 包。
目录必须预先存在且由单个运行实例独占；现有同名滚动文件会被覆盖。
默认关闭，不改变协议处理、包所有权或 DPDK offload 配置。

- `--pcap-snaplen N`：每包最多保存 N 字节，默认 65535。
- `--pcap-max-bytes N`：单文件软阈值，默认 16777216；写完完整记录后，
  下一条记录开始前滚动，故文件可能超过阈值一个记录。
- `--pcap-nsec`：纳秒时间戳；默认微秒。使用宿主 CLOCK_REALTIME。

经典 PCAP 2.4，Ethernet linktype，各方向最多十个文件：
`ker-tx-0.pcap` 到 `ker-tx-9.pcap`，以及 `ker-rx-0.pcap` 到 `ker-rx-9.pcap`。
记录同时保留截断后长度和原始帧长，支持多段 mbuf 跨段截断。

TX 在第一次交给 PMD 前记录一次，后续队列重试不重复记录；它代表发送尝试，
不是物理发送成功证明。RX 在从 PMD 获取 burst 后、校验和投递前记录一次，
包括后续被适配层丢弃的帧。捕获时间代表软件观察时间，非 NIC 硬件时间戳。

文件打开、写入、滚动和最终刷新失败会终止 worker，并经 launcher 报告 125。
不静默丢失抓包记录；不提供故障后的抓包文件修复或并发写入支持。
失败时最后一条记录可能不完整。抓包同步写盘可能降低吞吐量。

`native-fstack-pcap` 用实际 DPDK mbuf 校验九项固定 F-Stack 源场景以及
畸形链和写入失败；`native-fstack-pcap-interop` 检查独立宿主对端的 TCP
收发、原生 Linux 计数器、文件记录、时间戳、Ethernet 字节及 snaplen。
