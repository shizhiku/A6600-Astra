# 13 · GitHub 对照调查与 LIRO / SIO 观测

本轮仅做本地源码分析、只读 GitHub 搜索和离线 QEMU 原厂固件观测。没有连接或更改相机。

## GitHub 搜索结果

搜索日期：2026-11-20。查询了 BIONZ X 仓库中的 LIRO、a6600、0x170000、`"liro" "fault"`，以及两个移植仓库中的 a6600 / assert。

- [`ivica00/bionz-x-research#7`](https://github.com/ivica00/bionz-x-research/issues/7) 汇总 CXD90045 跨机型研究，并提到 a6400/a6600/ZV-E10。它报告：a6400 command table 285 项、a6600 286 项、ZV-E10 337 项；这些是应用命令表，不证明当前的 LIRO fault。issue 称其研究是基于官方更新包的离线分析，不代表 a6600 QEMU 启动完成。
- [`ivica00/bionz-x-research#22`](https://github.com/ivica00/bionz-x-research/pull/22) 和 #52 的记录说明：启动到 LIRO 后，a6100 模拟需要同机型副控制器输入；无 sub-micro 页面时，av-cam 不会创建 mode sequencer。此线索来自不同机身/运行，不能直接当作 a6600 故障证明。
- [`ma1co/Sony-PMCA-RE#597`](https://github.com/ma1co/Sony-PMCA-RE/issues/597) 分享 ILCE-6000 设置属性模板。它可用于理解 Backup.bin 表格式，但不含 a6600 属性 `0x00170000` 的语义结论。
- 精确搜索 `"0x00170000"`、`"63849f30"`、`"liro-kliro_66"` 未找到匹配的公开 Sony 故障记录。

GitHub 搜索结果是相关线索，不是经过本机复现的兼容性证据。

## 新的原厂 QEMU 观测

### 原始代码中的故障分支

a6600 原厂 `av-cam.bin` 在基址 `0x635c6000`、文件偏移 `0x283f30` 的指令为：

```text
63849f24  cmp  r3, #3
63849f26  bne  63849f3c
63849f28  movs r0, #9
63849f2a  bl   63d2aaf2
63849f2e  movs r3, #0
63849f30  str  r3, [r3]
```

用 GDB 硬件断点停在最后的原始存储指令之前，实测 `r3=0`，且对应字节与官方 `av-cam.bin` 完全一致。它在执行上表现为主动空地址写入；为何固件要走到该分支仍需分析。

### 设置属性来源

故障上下文从 `[r7+2]` 读取状态字节，值为 3。该目的结构由固件自己的启动复制代码从 captured Backup.bin 复制而来：

- 源区：运行地址 `0x62ee7f54`，对应 Backup.bin 偏移 `0x67f54`；
- 该来源的 96 字节与本地捕获备份相同；
- 原始 store 单步后，目标结构的第 2 字节从 0 变为 3；
- 用 PMCA BackupFile 验证过该备份整体 checksum；该来源落在 property id `0x00170000`，长度 256 B，属性标记 `0x08`。

这确认了设置状态的数据来源，但不证明属性含义、值 3 有错误或应当修改。没有改相机属性。

### 副控制器通信

在原始致命分支断点前，通过 QEMU `-d unimp` 记录到 SIO channel 3 的通信：

- 4 次传输；mode `0x30000000`；每次 128 B；请求类型首字节 `0x31`。
- 本次没给 machine 加载 `submicro-frames` 捕获数据。核对的本地 board overlay 对空输入会只记录然后返回，不会生成副控制器响应。
- 所以“缺少 sub-micro 响应是故障原因”仍是**待验证假设**。传输时间/返回值和故障条件尚未建立完整因果链。

## 下一实验建议

只在 QEMU 中对比**两个运行**：

1. 现状：不提供 `submicro-frames`，保留无响应行为；
2. 捕获一份身份匹配的 a6600 sub-micro 输入后，使用现有 QEMU 的 `-M sony-a6400,submicro-frames=...` 重放，并在相同 PC 上停下，比较设置状态、SIO 请求/回复次数和停止位置。

当前尚无 a6600 自己的 sub-micro 4 KiB 采集页，因此不能把 a6400 的帧冒充 a6600 原始输入，也不应据此宣称启动修复。下一步优先查现有安全、单页相机采集通道能否取得**授权范围内**的 a6600 sub-micro 数据；不使用 `/dev/stream` 或 bulk `/dev/mem` 扫描。

## 记录与边界

QEMU 观测目录：`a6600_port/emulation/observe-20261120T162220Z-30354/`，包含观察回执、串口日志、stderr、overlay 日志及受 32 MiB 上限限制的 SIO unimplemented 日志。

尚未识别 `0x00170000` 的语义，也没有证明单一缺失 SIO 回复造成该致命分支。原厂 UI 未启动，最小垫片和 ASTRA UI 仍未通过运行验证。
