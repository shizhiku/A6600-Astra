# 10 · QEMU 实测结果与先前结论更正

## 结论

QEMU 已编译且实际执行了 a6600 官方更新包中的 ARM 内核、init/BusyBox 和 im.elf。没有显示菜单，没有证明最小垫片被调用，更没有完成 ASTRA UI 移植。

同条件原厂 /usr 对照与修改版 /usr 出现相同类别的初始化失败、内存映射失败和 im.elf 空地址异常。不能据此断定补丁安全或不安全，也不能把失败单独归因于补丁。

## 工具与输入来源

- QEMU 本地可执行文件报告版本 11.1.3。
- 源码来自 download.qemu.org 发布包，叠加 bionz-x-research 的 sony-a6400 overlay。不是本地校验过提交哈希的 Git checkout。
- overlay 仓库本地提交：d7e6ea9361fc61e4dc9172591917af72d5cfefea。
- 内核、initrd、av-cam：用户提供的 a6600 1.10 官方更新包。
- eMMC：依据更新包 partinf.conf 合成 SDM 头，分区镜像由更新包提供，其余部分为空白或格式化 fixture。
- Backup.bin：此前步骤造出的 1 MiB 零填充 fixture，只有地址和 cookie，不是真实设备的设置备份。它不能替代有效的备份结构、校验、单元表、校准数据。
- 不提供主机生成菜单或伪造成功响应。

## 两次运行

每次使用独立 qcow2 覆盖层；超时为主机时间 90 秒，TERM 后 5 秒允许强制结束；两轮 QEMU 都被 timeout 正常终止（124）。没有连接 USB、写相机或改物理 SD 卡。

| 项 | 补丁 /usr | 原厂 /usr 对照 |
|---|---|---|
| 日志目录 | a6600_port/emulation/20261120T150021Z-25296 | a6600_port/emulation/stock-20261120T150342Z-25683 |
| rootfs 挂载 | 观察到 | 观察到 |
| BusyBox shell | 观察到 | 观察到 |
| backup_init error (selct_path) | 观察到 | 观察到 |
| FixedAreaTop = FFFFFFFF | 观察到 | 观察到 |
| ERROR : Failed to mmap! | 观察到 | 观察到 |
| im.elf 空地址异常 | 观察到 | 观察到 |
| appFwBoot 调用证据 | 未取得 | 不适用 |
| 菜单画面 | 未取得 | 未取得 |

完整串口、标准错误、命令行和退出码已保存在上述目录。比较摘要见 a6600_port/emulation/comparison.json。补丁运行 receipt.json 记录内核/initrd/av-cam/合成输入哈希；原厂对照仅在独立覆盖层中替换 /usr 分区。

## 下一处验证边界

先补全身份匹配的真实 a6600 启动输入（至少有效的 Backup.bin，以及日志/配置文件的清单），让未修改的固件在模拟环境形成可复现基线，再重新跑补丁对照。缺失状态不可用静默成功、空函数或假设置消除。

当前日志支持“启动输入不完整与平台适配仍有缺口”，不支持“只差 Backup.bin 就一定能进 UI”。最早显著服务失败是 backup.ko，随后出现依赖该模块的服务缺失；各故障之间的因果关系仍需逐项验证。

## 更正此前的固件包状态

检查 build_full_image.py 和实际 tar 后发现，修改分区镜像时没有同步更新 part_image.sum：

- 清单保留原厂 CRC32：520fff36。
- 修改后分区实际 CRC32：129576f8。

因此“DAT 可以解密回读”只成立于容器往返，不代表包内所有校验一致。旧 nflasha15_astra.dat 是不完整实验产物，不可刷入。相邻 DO-NOT-FLASH.md 已标记。

另外：DT_NEEDED 文件名能找到不等于运行时符号闭包验证；同码函数也不自动具备跨库/跨代语义等价性；源码中使用相同密钥集名称不构成硬件和 ABI 兼容证明。

当前真实进度：原料已取得、静态候选已定位、最小镜像已构建；QEMU 已实际启动到用户态故障，但原厂基线未通过，最小垫片和 ASTRA UI 均未验证。
