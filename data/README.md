# 配置文件

这里只放**自有**的配置数据。所有索尼原始配置文件、镜像、容器都**不在此列**。

| 目录 | 内容 | 来源 | 是否可直接用 |
|---|---|---|---|
| `keymap/` | 物理按键 → 键码映射表、映射证据 | 本项目实测 + 静态分析推导 | ✅ 可直接读，JSON |
| `partitions/` | 分区布局（起止/大小/类型/分组） | 由设备内 `partinf.conf` **推导** | ✅ 事实数据，CSV |
| `runtime/` | QEMU 启动参数、内核命令行、环境变量 | 一次真实运行记录，已脱敏 | 🟡 需替换路径 |
| `probe/` | 只读探针的配置模块 | 本项目自写 | 🟡 需替换路径 |

---

## keymap/ — 按键映射

| 文件 | 说明 |
|---|---|
| `corrected_physical_key_table.json` | 修正后的完整物理键表（port / 电平 / 键码） |
| `mapping_evidence.json` | 映射的证据摘要（每个键的来源） |

**要点**：`MENU = 0x1AB`、`ENTER = 0x1AC`。早期文档写反过，见
[../docs/84a-完整按键映射表与MENU定义.md](../docs/84a-完整按键映射表与MENU定义.md) 顶部更正。

## partitions/ — 分区布局

`partition-layout.csv` 字段：

| 字段 | 含义 |
|---|---|
| `device` | 分区设备节点（如 `/dev/nflasha15`） |
| `start` / `size` | 起止偏移与大小（十六进制） |
| `size_mib` | 大小（MiB） |
| `type` / `flag` | 分区类型与标志位 |
| `group` / `label` | 分组与名称（System / Work / User / Customer） |
| `note` | 备注（size=0 为保留项） |

> **说明**：此表由设备内的 `partinf.conf` **推导**而来，只保留分区几何的**事实数据**
> （偏移、大小、类型），**未复制**原文件文本。原文件属索尼版权材料，不随本仓库分发。

关键分区：

- `nflasha3` —— SYSTEM(Main)：kernel / initrd
- `nflasha2` —— SYSTEM(Setting)：`Backup.bin`、`kemco.txt` 等运行状态
- `nflasha15` —— usr：`/usr` 只读镜像挂载点（移植的主战场）
- `nflasha5` —— Warm Boot Image

## runtime/ — QEMU 运行配置

| 文件 | 说明 |
|---|---|
| `qemu-run-example.json` | 一次成功运行的 `args` / `env` / `wall_limit`（`mode=front`） |
| `kernel-cmdline.txt` | 原厂 kemco 内核命令行（含 `norandmaps`） |

`env` 中的 `REA_*` 变量是自建 QEMU machine 的注入接口：

| 变量 | 作用 |
|---|---|
| `REA_FB_PATH` / `REA_FB_VSYNC` | 帧缓冲输出与 vsync 时序 |
| `REA_FRONT_BTN` / `REA_FRONT_T0` | 前面板按键注入（时间点 + 键值） |
| `REA_ADC_SEQ` / `REA_ADC_T0` | 前面板 ADC 序列注入 |
| `REA_BP_VA` / `REA_BP_MEMREG` / `REA_BP_MEMLEN` | 断点与内存转储 |

> 这些变量只对**自建**的 `sony-a6400` machine 有效，上游 QEMU 不认。
> 详见 [../docs/00-工作区总览.md](../docs/00-工作区总览.md) 与 `scripts/qemu_*.sh`。

## probe/ — 探针配置

`config.py` 是只读探针的路径与参数配置。使用前需把占位符改成你自己的路径。

---

## 为什么配置这么少

因为研究主体是**方法**，不是配置。真正关键的配置（分区几何、按键表、启动参数）
已在此；其余（固件内容、库、镜像）属于索尼材料，**刻意排除**。

完整排除清单见 [../NOTICE.md](../NOTICE.md)。
