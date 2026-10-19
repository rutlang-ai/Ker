# F-Stack 全量测试迁移清单

固定上游版本：`646a641cfff77f4815e1e29829a09e1ed15a2999`。

本清单覆盖整个上游 `tests/`：105 个文件，加原始 LICENSE 共 106 个文件，
保存在 [只读源快照](../tests/upstream/fstack)。保留原始内容、执行位、Git blob SHA-1
及 SHA-256；不是把快照作为 Ker 实现或自动执行上游脚本。

从实际注册代码得到 378 个 CMocka 用例、53 个 Python unittest 方法、
1 个 reload shell 入口和 1 个 MTU 手工检查入口，共 **433 项**。
上游 README 的 189+8 统计与此固定版本实际内容不一致，不能用作分母。

## 当前完成程度

| 状态 | 数量 | 含义 |
|---|---:|---|
| scenario-adapted | 40 | 有现存 Ker CTest 和来源映射；是场景适配，不是 API/实现等价认证 |
| partial | 9 | 有相关场景，但未满足完整源用例合同；remaining 字段记录缺口 |
| blocked | 321 | 没有完整可执行的 Ker 对应项；明确保留缺口，不计为通过 |
| architecture-specific | 8 | FreeBSD callout/内部 kqueue filter 断言，不适用于 Linux 内部结构 |
| harness-only | 55 | 53 个 F-Stack reload 工具链自测及 2 个 CMocka smoke；不计 Ker 网络覆盖 |

**全部原始测试已纳入；全部行为迁移尚未完成。**
完整逐项 ID、处置理由和 CTest 链接在 [机器清单](../tests/fstack-migration.json)。
一个 Ker CTest 可以适配多项上游场景；97 个既有 Ker 来源条目中还包含大量
Ker 自有扩展，不能把这些扩展数量当作已迁移上游用例数。

## 自动检查

```sh
python3 tests/fstack_migration.py
python3 tests/fstack_migration.py --require-complete
ctest --test-dir build -R '^fstack-migration-' --output-on-failure
ctest --test-dir build -R '^native-fstack-epoll$' --output-on-failure
```

默认检查只验证快照完整性、全部注册项没有遗漏、处置理由存在，以及适配项关联真实
CTest、精确源文件/用例 provenance 和 provenance 条目声明的 Ker CTest 绑定。它通过不代表
433 项行为通过。
`--require-complete` 在仍有 blocked 或 partial 项时返回 2，目前必须失败。
12 个 mutation/门禁用例验证快照与目录完整性、适配状态、存在且匹配来源的 CTest、源文件和源用例对应关系、provenance 到 Ker CTest 的显式绑定（包括拒绝无关现存 CTest、缺失绑定和无效绑定类型），以及未完成门禁；CI 将清单校验标为 provenance。

## 本批实际迁移与修复

补齐 `test_ff_epoll_ctl_null_event_non_del` 的 Linux 场景：ADD/MOD 的 NULL event
应返回 EFAULT（上游 F-Stack wrapper 为 EINVAL），失败不能破坏已有注册，
DEL 的 NULL event 合法。宿主参考先通过；native 修复前退出 139，修复后通过。
修复仅在 Ker epoll 适配层阻止 NULL 进入 LKL 的同地址空间 user-copy；
Linux/FreeBSD/DPDK 原始实现均不修改，不宣称支持任意坏指针。
既有 write-only、zero-maxevents、空 FIN 和零长度 UDP 场景补齐相应来源映射。

## 阻塞分类与边界

- 配置/INI、日志、pcap、IPC：当前没有对应 Ker 接口，不能把 F-Stack 库自测当作 Ker 已实现这些模块。
- KNI、RSS/源端口调整、完整设备注册、generation/epoch/热重载：需要实际适配器与运行环境；本地 FIFO 或 borrowed ethdev 用例只覆盖各自明确的子集。
- FreeBSD TLS、callout 和 mbuf 镜像：迁移必须尊重原始 Linux 结构和协议实现，不能为通过白盒测试复制 FreeBSD 协议算法。
- reload Python 工具自测：源文件保留，不自动导入/执行，不把工具链断言记为网络协议覆盖。
- `test_mtu.sh` 实际只打印手工步骤及无条件 ALL PASS 摘要；执行它不构成 jumbo、动态 MTU 或 IPv6 互通证据。

后续每完成一项，先提供真正的适配和测试证据，再修改该项状态；完整迁移门禁
继续显示未完成，直至全部阻塞都有明确实现或经过审阅的架构处置。

## 按源文件统计

| 上游入口 | 总数 | 场景适配 | 部分覆盖 | 阻塞 | 架构特有 | 工具自测 |
|---|---:|---:|---:|---:|---:|---:|
| [integration/test_ff_dpdk_if_integration.c](../tests/upstream/fstack/tests/integration/test_ff_dpdk_if_integration.c) | 20 | 7 | 8 | 5 | 0 | 0 |
| [integration/test_ff_gendir_mp_integration.c](../tests/upstream/fstack/tests/integration/test_ff_gendir_mp_integration.c) | 7 | 0 | 0 | 7 | 0 | 0 |
| [integration/test_ff_kni_integration.c](../tests/upstream/fstack/tests/integration/test_ff_kni_integration.c) | 8 | 0 | 0 | 8 | 0 | 0 |
| [integration/test_ff_reload_integration.c](../tests/upstream/fstack/tests/integration/test_ff_reload_integration.c) | 7 | 0 | 0 | 7 | 0 | 0 |
| [integration/test_graceful_reload.sh](../tests/upstream/fstack/tests/integration/test_graceful_reload.sh) | 1 | 0 | 0 | 1 | 0 | 0 |
| [integration/test_mtu.sh](../tests/upstream/fstack/tests/integration/test_mtu.sh) | 1 | 0 | 0 | 1 | 0 | 0 |
| [unit/test_ff_callout.c](../tests/upstream/fstack/tests/unit/test_ff_callout.c) | 6 | 0 | 0 | 0 | 6 | 0 |
| [unit/test_ff_config.c](../tests/upstream/fstack/tests/unit/test_ff_config.c) | 96 | 0 | 0 | 96 | 0 | 0 |
| [unit/test_ff_config_pa.c](../tests/upstream/fstack/tests/unit/test_ff_config_pa.c) | 2 | 0 | 0 | 2 | 0 | 0 |
| [unit/test_ff_dpdk_if.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_if.c) | 67 | 0 | 1 | 66 | 0 | 0 |
| [unit/test_ff_dpdk_kni.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_kni.c) | 25 | 0 | 0 | 25 | 0 | 0 |
| [unit/test_ff_dpdk_pcap.c](../tests/upstream/fstack/tests/unit/test_ff_dpdk_pcap.c) | 9 | 9 | 0 | 0 | 0 | 0 |
| [unit/test_ff_epoll.c](../tests/upstream/fstack/tests/unit/test_ff_epoll.c) | 21 | 18 | 0 | 1 | 2 | 0 |
| [unit/test_ff_host_interface.c](../tests/upstream/fstack/tests/unit/test_ff_host_interface.c) | 34 | 6 | 0 | 28 | 0 | 0 |
| [unit/test_ff_ini_parser.c](../tests/upstream/fstack/tests/unit/test_ff_ini_parser.c) | 25 | 0 | 0 | 25 | 0 | 0 |
| [unit/test_ff_init.c](../tests/upstream/fstack/tests/unit/test_ff_init.c) | 6 | 0 | 0 | 6 | 0 | 0 |
| [unit/test_ff_ipc.c](../tests/upstream/fstack/tests/unit/test_ff_ipc.c) | 12 | 0 | 0 | 12 | 0 | 0 |
| [unit/test_ff_log.c](../tests/upstream/fstack/tests/unit/test_ff_log.c) | 13 | 0 | 0 | 13 | 0 | 0 |
| [unit/test_ff_thread.c](../tests/upstream/fstack/tests/unit/test_ff_thread.c) | 5 | 0 | 0 | 5 | 0 | 0 |
| [unit/test_ff_zc_send.c](../tests/upstream/fstack/tests/unit/test_ff_zc_send.c) | 13 | 0 | 0 | 13 | 0 | 0 |
| [unit/test_hello.c](../tests/upstream/fstack/tests/unit/test_hello.c) | 2 | 0 | 0 | 0 | 0 | 2 |
| [unit/test_reload_harness.py](../tests/upstream/fstack/tests/unit/test_reload_harness.py) | 53 | 0 | 0 | 0 | 0 | 53 |

## NULL epoll 等待缓冲区适配

`native-fstack-epoll` 新增三个等待接口的 NULL 输出缓冲区场景，
覆盖无事件返回零、无效 maximum 返回 EINVAL、就绪后返回 EFAULT，以及
错误后 ET/ONESHOT 事件仍可读取。混合 epoll 中的宿主 pipe 也检查错误恢复。
这是 Linux POSIX 语义适配：上游 F-Stack 包装器对 NULL 一律返回 EINVAL。
任意不可访问指针及并发消费者竞争仍不在本次覆盖范围内。

## PCAP 抓包适配

新增 `native-fstack-pcap`，将 PCAP 文件创建、NULL 目录、禁用、打开失败、
微秒/纳秒精度、十文件滚动、追加、多段截断共九项源场景适配到 Ker 抓包器。
测试使用实际 DPDK mempool/mbuf，逐字段解析文件，检查内容及所有权不变。
`native-fstack-pcap-interop` 另行验证真实原始 Linux TCP 经 DPDK 的双向抓包。
文件名、错误处理和滚动触发点采用 Ker 语义，详见 [抓包说明](packet-capture.md)。
