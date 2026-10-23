# Resident session 的原始 secondary PMD 验证

`ker-session --ring-pmd` 在原有共享控制 session 上增加一个固定的原始
`net_ring_ker` PMD。resident primary 配置一个 RX/TX queue pair；真实 EAL
secondary 附着原始设备。普通 `ker-run` 的 secondary 禁用边界保持不变。
此模式验证实际 PMD 附着和独占消费者，尚不向原始 Linux 网络栈交付数据包。

固定设备由工具补入 EAL 参数，用户传入的任意 `--vdev` / PCI allow 参数仍拒绝。
主次进程必须使用相同 DPDK、file prefix、hugetlbfs、地址布局和设备模式。
此模式需要可写共享 hugepages；测试不会修改宿主机设置。

```bash
ker-session serve --socket /owned-private-dir/control.sock --ring-pmd \
  --eal '--lcores=0@0 --no-pci --no-telemetry --iova-mode=va -m 64 --file-prefix=ker-test'
ker-session lease --socket /owned-private-dir/control.sock --ring-pmd --probe-count 64 \
  --eal '--lcores=0@0 --no-pci --no-telemetry --iova-mode=va -m 64 --file-prefix=ker-test'
ker-session device-status --socket /owned-private-dir/control.sock
```

`lease` 保持其 stdin 打开；输入 `P` 执行一批共享控制请求和 PMD 诊断帧，
其他输入或 EOF 结束。`probe` 可执行一次后退出。诊断帧是174字节 Ethernet
测试记录，使用实验 EtherType `0x88b5`，不实现任何 IP/TCP/UDP 协议。
原始 net_ring 默认 RX/TX 使用同一 ring，secondary 调用原始 burst API 并
逐字节核对返回帧，还要求原始设备的 RX/TX 计数分别恰好增加指定数量。

每个消费者授权受 session、epoch 和 slot/generation/process 坐标约束。
resident 在发送授权 ACK 前，先分配原始 mbuf、记入其私有 journal，再发布
原子 lease 和 owner 坐标。控制 mbuf 与 PMD mbuf 是两个不同对象，借用方
均不得归还原始 pool。其他 secondary 可以附着设备，但申请消费者时返回
`EBUSY`，不能调用生产代码中的 burst 路径。

master EOF 或死亡不撤销存活 secondary 的授权。只有精确 borrower pidfd
证明进程死亡后，resident 才能检查原始 PMD 队列、清除授权并归还其记录的
对象。resident 在消费者存活时不执行数据面 RX/TX。私有 journal 也覆盖
首次 TX 前和 RX dequeue 后的空队列死亡窗口；foreign/duplicate 对象、
不一致 lease/refcount 或未解释的 pool 占用会拒绝清理，不伪报成功。
这不提供对不遵循适配层授权的任意同用户 EAL 程序的安全隔离。

`native-fstack-session-ring-pmd` 验证两次64帧 burst、第二真实 secondary 拒绝、
owner 查询、死 master 与活 borrower 的排他性、新 epoch 的32帧收发、首次 TX
前和 RX 后 borrower 死亡，以及最终511个原始对象全部归还。现有 session
注册、控制消息、slot 回收和保守停止测试继续独立运行。

这增加了 #218 所需的原始 secondary PMD 证据，尚未完成原始 F-Stack 的固定
network dispatch ring、物理设备/no-hardware/KNI-owner 一致性、队列中死亡
故障注入、原始 Linux packet delivery 或完整 USR2 reload。源 TC-1/3 保持
partial，不能把诊断帧 loopback 等同于这些源断言。TC-2 使用原始 null PMD，
只要求自己的非零 epoch/slot/ring、真实 secondary 设备消费权和 primary 不消费；
这批实际原始 PMD 验证满足该单条场景，不能扩展为整个 reload 流程完成。
