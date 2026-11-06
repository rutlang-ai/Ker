# Linux packetdrill selftests

固定 Linux 6.12.113 revision `7fdb7c1824a1f9979d648d7ae28ac446bcee9c6e` 的 `net/packetdrill` 全部 24 个默认脚本通过原版 `ksft_runner.sh` 执行 IPv4/IPv6，共 48 个配置。脚本、defaults、sysctl restore helper、TAP helper、工具和协议源码保持原样，运行前后与 pinned Git blob 逐字节核对。Ker 不修改预期包、时间容差、syscall 返回值、TCP_INFO 或 Python 断言，也不设置 `KSFT_MACHINE_SLOW`。

`tools/ci/build_packetdrill.sh` 构建 Google packetdrill revision `8051382e6ac928c4c13a88b34832649d9b07abc2`。归档 SHA256 为 `7325318f2a07282ee457b23b1f84adc14928a6d719a8262607bb8dde4ce6133d`；provenance 包括全部原始工具文件和最终 binary hash。该版本的 TCP_INFO 布局与 Linux 6.12 匹配。工具按 GNU11 动态链接，仅调整构建参数以加载私有 syscall 适配器。工具默认 mlockall 保留；线程栈设为 1 MiB 以适配普通宿主的 8 MiB locked-memory 限额。

## 真实 native 路径

每次原版 packetdrill 运行创建独立 native network namespace。原版工具经私有 preload 打开导入 Linux 的 `/dev/net/tun`、配置原版 TUN offload，并在真实 AF_PACKET socket 上抓包、读取内核时间戳。原版 ip/tc 的路由、设备及 qdisc 操作通过 netlink 进入同一个内核。Ker 只传输操作参数与原始字节，不构造包或协议结果；网络 descriptor 的 native 类型在创建时验证，没有宿主 IP socket fallback。

工具的 epoll 调用进入 native epoll，保留原版 flags、event data 和 errno。sendmsg 保留原始 iovec 边界；MSG_ZEROCOPY 数据分配在注册 native VMA 中，保持不可变并留存至正常内核关闭，以覆盖原版关闭 socket 后完成的用例。最终必须释放所有缓冲区。此测试适配不声明跨进程通信端到端零拷贝。

Socket close 等待实际 Linux close 完成。Bash 重定向会复制管理 proc 通道到 stdout；这些 native proc 文件由最后一个 host 通道引用的 EOF 关闭，保证关闭重定向前的原始 fd 不会使 stdout 提前失效。每次 proc 写入仍等待内核返回，并在实际文件关闭后验证正常内核退出与零剩余资源。

原版 cat/grep 解析真实 native proc 快照。sysctl 命令适配斜杠和点号名称，执行实际 native 写入并读回验证。原版 `set_sysctls.py` 生成的 echo 和 restore 脚本保持不变：私有 Bash echo 适配把原始输出写入真正打开的 native proc descriptor，传播实际写入失败。数值读回接受等价十进制/十六进制格式。额外对照要求非法写入返回 EINVAL 且 native 值不变；该对照不计入原版 48 个配置。

## 内核与证据

`config/native-linux-packetdrill.config` 单独启用 TUN、FQ 和原版推荐的 HZ=1000。Pinned LKL 的 HZ 是不可由普通 config seed 改写的隐藏符号；配对的 `.Kconfig` 在生成目录的外部根输入中提供较早的默认值，利用 Kconfig 原有的 first-visible-default 规则。原始根 Kconfig 和 arch/lkl/Kconfig 都不改动。Builder 将 prelude 内容纳入 fingerprint，并记录生成根输入的 hash；CMake 验证 prelude hash、真实 CONFIG_HZ=1000 和 high-resolution timers。原版全部时间断言保持原样。

最终同步 close/HZ=1000 证据通过 `linux-original-packetdrill` CTest：24/24 原版 TAP plan，每个均为 IPv4/IPv6 2/2；48 个 family 配置全部返回 0、stderr 为空且没有 skip/error。每个配置都报告正数的真实 native TCP `InSegs` 和 `OutSegs`。报告记录 1,068 次 native sysctl 写入及读回、20 条原版 echo 记录；每个使用 `defaults.sh` 的配置均覆盖其默认项。实际记录 48 个 TUN、48 次 offload 配置、286 个 packet timestamp，以及 6 次 epoll 创建、8 次 ctl 和 30 次 wait。206 个 native buffer 在正常关闭时全部释放，49 个 namespace 创建/删除（48 个原版配置及一个拒绝对照）；结束时 live socket、packet outstanding 和 native buffer 均为 0，worker 返回 0，shutdown 未超时。

两个额外 proc 控制也通过：保留 Bash duplicate fd 的 alias 控制返回 0、stderr 为空并读回实际值 `1`；非法写入控制收到 `EINVAL` 且值未变。此对照占用第 49 个 namespace，不计入原版 48 个 family 配置。完整运行耗时 91.20 秒，使用 native Linux fingerprint `ca536f1483c5c65c4aeaec52ae6ea923e516c0170c0bb20a1c8ac4496d145f7d`。

`linux-original-packetdrill.json` 包括全部原版 TAP、每次工具的参数/输出/真实 TCP MIB、sysctl 写入读回、source/tool/library hash、内核 fingerprint、VMA 和退出证据。辅助命令错误即使被原版 shell 忽略也不能通过；每个 defaults sysctl 都要求有实际读回记录。宿主基线仅是工具/原版输入对照，单独记录，不计入 imported Linux 结果。

```bash
bash tools/ci/build_packetdrill.sh /tmp/packetdrill-tools
python3 tools/build-native-linux.py --build /tmp/native-packetdrill \
  --config-fragment config/native-linux-packetdrill.config
# Configure with KER_NATIVE_LINUX_BUILD, KER_PACKETDRILL_TOOLS_DIR and
# KER_MPTCP_DIAG_TOOLS_DIR pointing to the pinned kernel/tool artifacts.
python3 tools/ci/native_tests.py packetdrill-profile build-native-packetdrill /tmp/packetdrill.xml
```

CI 单独构建此内核及 unchanged 工具，强制检查完整 24/48 矩阵、JUnit、fingerprint 和错误传播。此批不表示 forwarding、netfilter、HSR、Open vSwitch 或 RDS 的其余完整入口已迁移；见[总清单](linux-network-selftests.md)。
