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


## Live standby 与 epoch 查询

`lease --ring-pmd --standby` 在消费者申请返回 EBUSY 时保留真实 EAL secondary
和控制 mbuf；严格模式仍退出，不改变原有拒绝边界。输入 `P` 时继续共享控制
请求、重新申请实际 grant，并从 resident 获取一次序列化的完整 owner 快照。
只有持有实际 journaled PMD mbuf 且 owner 坐标匹配的 worker 能调用 burst。
`--probe-count 0`（默认值）只执行这些控制步骤，不声明实际帧收发；指定正数
时，owner 才执行该数量的原始 PMD 帧验证。非 owner 始终不执行数据轮询。

standby 不因 master 死亡、心跳缺失或 worker 冻结就抢占设备。只有 exact
borrower pidfd 证明旧消费者死亡、resident 回收旧 lease 后，同一个 standby
PID、原始 EAL attachment 和 epoch 才能在后续 `P` 请求取得新 grant。这里
没有新建一个独立 primary 来替代接管，也不承诺周期性自动晋升或业务 readiness。

```sh
ker-session lease --socket "$SESSION_DIR/control.sock" --ring-pmd --standby \
  --probe-count 16 --eal "$SHARED_EAL_OPTIONS"
ker-session epoch-status --socket "$SESSION_DIR/control.sock" --epoch 0
ker-session epoch-status --socket "$SESSION_DIR/control.sock" --epoch 123
```

`epoch-status` 直接查询 resident 的 exact-pidfd census。master 存活，或其任意
RESERVED/ATTACHED borrower 仍存活，该 epoch 就保持 live；注册已清除或精确
进程死亡后变为 non-live。epoch0 表示仍服务的 resident；未知 epoch 返回
non-live。slot 被更高 epoch 复用不会使旧 epoch 复活。这是 Ker 的明确进程
寿命机制，不复制 F-Stack 的 heartbeat/stamp 过期 ABI，也不将冻结当成死亡。

`native-fstack-session-standby` 同时保持两个不同 master 和两个 secondary
存活，先释放两边 `P` 屏障，再等待双方对同一 owner 的样本。测试还杀死旧
master、冻结并确认旧 borrower 的实际 T 状态，要求 standby 仍不得接管；
精确杀死并回收 borrower 后，原 standby 在原 PID/EAL/epoch 中实际收发，
计数/序列继续递增。旧 slot 的新 epoch、默认零数量控制、全部511对象归还
也有独立断言。

源 `test_it_a14_epoch_liveness_after_exit` 只要求旧 epoch 在进程退出后变为
non-live，且 primary epoch0 继续 live，本批完成这条场景。TC-3 新增双活
observer/owner 样本证据，但独立固定网络 dispatch、异常包路由及其 owner
一致性仍未实现，不能用 PMD grant 的数值替代源 KNI/exception-owner 断言。
