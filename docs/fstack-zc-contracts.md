# F-Stack 零拷贝源用例合同核对

固定源版本 `646a641cfff77f4815e1e29829a09e1ed15a2999`，
[原始 13 项](../tests/upstream/fstack/tests/unit/test_ff_zc_send.c)。该源文件明确说明
自己是 FreeBSD mbuf 算法镜像，发送部分只验证参数。Ker 验收使用实际原始 Linux
VMA、socket 和错误队列，不执行该镜像。

`native-fstack-zc-validation` 用原始 null PMD 启动真实运行时，数据走原始 Linux
loopback。每项实际断言通过后才输出对应 `BUFFER_SOURCE_CASE`。运行时显式停止，
必须收到 EAL 回执，所有 VMA、选项同步 guard 和 mbuf 均清零。原有
`native-fstack-native-buffers` 另行验证真实 virtio/vhost-kernel 路径和完整线上数据。

下表函数名均省略 `test_ff_zc_` 前缀。

| 原始用例 | 处置 | 实际验收或缺口 |
|---|---|---|
| mbuf_get_pkthdr_flag_set | architecture-specific | FreeBSD `M_PKTHDR` 无对应 Linux 字段，不伪造结构 |
| mbuf_get_initial_pkthdr_len_zero | architecture-specific | 断言头部长度字段；VMA 初始清零不能代替此字段 |
| mbuf_get_negative_len_returns_error | scenario-adapted | `-1`/`INT_MIN` 转 size_t 后实际分配拒绝，保留已有数据 |
| mbuf_get_zero_len_returns_minimal_chain | blocked | 源分配空 owned chain；native `buffer_alloc(0)` 拒绝 |
| mbuf_write_accumulates_pkthdr_len | blocked | 尚无 staged write cursor / owned head-length API |
| mbuf_write_overflow_returns_error | blocked | send 范围拒绝发生在不同阶段，不能代替 write 越界 |
| mbuf_write_null_data_returns_error | blocked | send NULL 拒绝不能代替 write NULL 拒绝 |
| mbuf_write_zero_len_noop | blocked | 尚无 write cursor，空 UDP 数据报不是 no-op |
| mbuf_write_multi_segment | blocked | 多 VMA sendmsg 不能证明 m_len/m_next/head 的写入变更 |
| send_mb_null_returns_einval | scenario-adapted | 实际 send/sendmsg/sendmmsg 拒绝非空长度 NULL 输入 |
| send_nbytes_overflow_returns_einval | scenario-adapted | 实际 send/sendmsg 拒绝单映射 INT_MAX+1 范围 |
| send_valid_args_proceeds | scenario-adapted | 实际 16 字节发送、逐字节接收、原始完成通知 ID 0 |
| send_zero_nbytes_returns_einval | blocked | 源拒绝零字节；Linux UDP 合法且产生完成编号，保持 Linux 语义 |

4 项参数边界是**场景适配**，不是 ff_zc ABI 等价：native 分配使用 `size_t`，
负数需经转换；无效发送范围返回 Linux `EFAULT`，源 validator 返回 `EINVAL`。
单映射上限为 `INT_MAX`，不声称 iovec 合计具有相同上限。拒绝发送还要求无数据投递、
无完成通知、已有映射内容不变；后续合法发送从 ID 0 开始，验证失败未占用完成编号。

源 `send_valid_args_proceeds` 仅用栈上 dummy 指针断言 mirror validator 返回 0，
未测试真实 owned-chain 转移；Ker 实际接收和完成证据超出该参数守卫断言，但不能
据此宣称实现 FreeBSD owned-chain handoff。剩余 9 项继续由
[issue #225](https://github.com/rutlang-ai/Ker/issues/225) 跟踪，两个结构特定处置也不计通过。

SO_ZEROCOPY、MSG_ZEROCOPY 和完成 code 0 均不是全链路无复制认证；
[原生缓冲区合同](native-buffers.md) 记录生命周期及后续传输复制边界。
不改变 Linux/DPDK 上游源码，不实现 Ker 自有协议状态机。


The two FreeBSD mbuf-header assertions (`test_ff_zc_mbuf_get_pkthdr_flag_set`
and `test_ff_zc_mbuf_get_initial_pkthdr_len_zero`) retain their existing
architecture-specific status. Their canonical follow-up is now
[#232](https://github.com/rutlang-ai/Ker/issues/232), so exclusion status and
group disposition agree. The seven blocked allocation/write-cursor/zero-send
contracts remain under [#225](https://github.com/rutlang-ai/Ker/issues/225).
This tracking correction changes no case status and claims no Linux mbuf ABI.
