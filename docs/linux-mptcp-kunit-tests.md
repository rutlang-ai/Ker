# 原版 MPTCP KUnit

固定 Linux stable 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 的两个原版 KUnit suite 直接编译进独立的 LKL 测试内核，在 Linux 原来的启动期位置执行。没有复制或改写测试、断言、MPTCP 实现和 KUnit 框架。

| Suite | 原版用例 | 覆盖 |
|---|---|---|
| `mptcp-crypto` | `mptcp_crypto_test_basic` | 原版 MPTCP HMAC-SHA256 的 3 组固定向量 |
| `mptcp-token` | `mptcp_token_test_req_basic` | request token 创建、非零 token 与查找边界 |
| 同上 | `mptcp_token_test_msk_basic` | connect token 建立、socket 查找、引用计数与销毁后查找 |
| 同上 | `mptcp_token_test_accept` | request token 转交 accepted socket，重复 request 清理不移除已转交 token |
| 同上 | `mptcp_token_test_destroyed` | 原版用例模拟移除竞争，引用计数为零的 socket 不得被查找到 |

计为 **2 个 suite、5 个 KUnit 用例**，不把 crypto 内部的 3 组向量另算成 3 个用例。这是原版内核内部 helper 的测试，不代表 TCP/MPTCP 完整传输状态机、MP_JOIN、多子流恢复或外部 DPDK 流量已全部验证。

## 独立测试内核

`tools/run-linux-mptcp-kunit.py` 在指定 build 目录中准备一个带所有权标记的小型输入快照，复用原封不动的 `tools/build-native-linux.py`。唯一配置差异来自 `config/native-linux-mptcp-kunit.config`，启用 `CONFIG_KUNIT=y` 和 `CONFIG_MPTCP_KUNIT_TEST=y`，禁止 `KUNIT_ALL_TESTS`、框架自测及默认自动执行。

组合后的 defconfig 按现有构建器的规则生成独立指纹、源码准备目录和内核产物；原有的完整 `net/`、`include/net/` 来源证明和 artifact/cache 锁仍生效。生产 defconfig 不变，生产内核继续关闭 KUnit。传入 `--production-manifest` 还会检查真实生产配置的摘要、生产输入指纹以及两套产物的隔离。

不安装的宿主 harness 直接复用生产启动使用的 Ker 内存、线程、时钟、计时器适配器及 usercopy 探测，随后调用 `lkl_init`、`lkl_start_kernel`、保留原始内核输出、`lkl_sys_halt` 和清理。启动参数 `kunit.enable=1 kunit.filter_glob=mptcp-*` 选择上述原版 suite；测试中的 token 表、RCU、引用计数和密码学函数都来自实际导入的 Linux。此处不创建 DPDK 设备或经过应用 socket facade。

## 执行和证据

```bash
PYTHONDONTWRITEBYTECODE=1 python3 tools/run-linux-mptcp-kunit.py \
  --build /path/to/native-mptcp-kunit \
  --cache /path/to/native-linux.git --jobs 2 \
  --production-manifest /path/to/native-linux-build/native-linux.json
```

工具使用固定源码中的原版 `kunit_parser.py` 解析内核 KTAP，额外要求精确的 2-suite/5-case 清单、完整 plan、每级 `SUCCESS`、零 skip/failed/crashed/parser errors，以及完整 boot/halt。不能只看宿主进程退出码。

同一测试内核还以 `kunit.enable=0` 启动一次：内核正常启动、退出，但必须没有测试结果，并被覆盖校验明确拒绝。这个对照不计测试通过用例数。

native CI 必须执行这个独立步骤，失败会使 native job 失败；它与原有完整 CTest 图分别执行和统计，不关闭或替代原来的协议 selftests。CI 上传 `linux-original-mptcp-kunit.json`、构建证明和两次原始启动日志，包含 Linux revision、测试/生产指纹、真实配置和静态库摘要、原版源码/解析器、Ker host 适配器、harness/二进制和日志摘要。

TCP-AO 原有 24 个入口仍独立统计。MPTCP 的完整注册 shell 入口在完整 diag.sh 接入后，剩余数量为 8，KUnit 不抵扣它们。
