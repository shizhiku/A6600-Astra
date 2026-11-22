# a6600 安全资料集 · ASTRA UI 移植研究笔记

> 把 Sony **ZV-1M2（第五代，ASTRA 触控 UI）** 的 UI 层移植到 **ILCE-6600（a6600，第四代）** 的
> 过程记录：方案、方法、实验设计、静态与运行证据的摘要，以及少量自有配置文件。
>
> **本仓库不含任何索尼固件、固件解包产物、索尼二进制库、解密密钥或运行日志。**

---

## ⚠️ 先读：安全与法律边界

这个仓库只适合**阅读、复现分析方法、写自己的工具**。它不是刷机包，也不能用来刷机。

| 事项 | 本仓库的立场 |
|---|---|
| 固件镜像 / 解包树 / `.so` / `.ko` / `.dat` | **完全不包含**。需要的材料请自行从你合法持有的设备与官方更新器取得。 |
| 固件解密密钥 | **完全不包含**。脚本中以 `REDACTED_KEY_*` 占位，见 [docs/SANITIZATION.md](docs/SANITIZATION.md)。 |
| 相机写入 / 刷写 | 未做，也不提供步骤。本仓库所有实验均为**离线 QEMU** 或**只读**采集。 |
| 可刷入固件 | **不存在**。研究中的修改镜像分区 CRC 清单未同步，本就不可刷入。 |
| 用途 | 兼容性研究与方法记录。请勿用于规避技术保护措施或商业分发。 |

> 索尼、ILCE、ZV-1M2 等为 Sony Corporation 商标。本项目与索尼无任何关联，未获其授权或背书。
> 若权利人认为本仓库内容不当，请通过 Issue 联系，我们会立即处理。

---

## 一、这个仓库是什么

**一句话**：a6600 原厂固件已在 QEMU 中跑到原厂菜单；ASTRA UI 移植卡在"五代绘制提交不触发"这一具体问题上。以下是完整的问题清单、方法与证据索引。

### 包含

- `docs/` —— **146 篇**研究记录（按轮次编号，含方案、假设、实验结果、被推翻的结论）
- `scripts/` —— **618 个**自有脚本与源码（静态分析、QEMU 补丁、注入/探针、镜像处理）
- `configs/` —— 少量**自有**配置：按键映射表、分区布局（推导值）、QEMU 运行参数、内核命令行
- `docs/assets/` —— 12 张界面截图（证明结论用）

### 不包含

- 任何索尼固件、分区镜像、`firmware.tar`、`BODYDATA.DAT`、更新器
- 任何从固件提取的库（`libObj.so`、`appFw.so`、`libIMDB.so`、`input.ko` …）
- 任何解密密钥
- 运行日志原始文件（上千份 `serial.log`）、第三方项目源码副本
- 早期实验产物（`nflasha15_patched.bin` 等）

---

## 二、当前状态（摘要）

| 项目 | 状态 |
|---|---|
| a6600 固件解包 → 重打包 | ✅ 可做到与原包**逐字节一致**（内容不变时的封装链路已验证） |
| QEMU 跑原厂固件 | ✅ 启动到**原厂菜单**（设置 4，4/7），两条独立路径各复现 2 次 |
| 按键注入 | 🟡 `/proc/udm/input` 可读；硬件 ADC 注入可达驱动但**不产生按键事件** |
| 五代 UI 加载 | ✅ 五代库可加载，`appFwBoot::Application_System_Init` 正常返回 |
| 五代 UI 绘制 | ⛔ `GraphicsEngine::drawFramebuffer` **从未被调用**（draw kick = 0） |
| 可刷入固件 | ⛔ 不存在 |

**已确认的关键事实**

- **MENU = `0x1AB`，ENTER = `0x1AC`**（早期文档写反，已在多篇文档中更正）
- 中文字体：`Backup` 属性 `0x810000` 指向 `/usr/share/app/fontlist.dat`；放入三个真机字体即可，**零代码改动**
- eMMC 停滞：`emmc.ko` 调优函数改为直接返回即可根除
- 显示：VPH ch53，640×480 双缓冲；draw kick 实测 100+ 次
- UI 是**用户态进程**（PID 144，172 线程，`libObj` 基址 `0x057E3000`）

**已撤回的错误结论**（保留在文档中作为教训）：UI 在内核态、UI 从不 draw kick、字体需调 `registerFontFaceFile`、`/var/fifo` 是输入通道、按键走 evdev、sdhci 参数可修 eMMC。

最新的具体卡点与可复制的提问材料见
[docs/135-第二十二轮基线恢复与fbrm补丁无效.md](docs/135-第二十二轮基线恢复与fbrm补丁无效.md)。

---

## 三、目录结构

```
.
├── README.md               # 本文件
├── README.en.md            # English summary
├── LICENSE                 # GNU GPL v3.0
├── NOTICE.md               # 来源、归属、排除清单
├── SECURITY.md             # 安全边界与负责任披露
├── CONTRIBUTING.md         # 贡献规则（勿提交固件/密钥/日志）
├── docs/
│   ├── README.md           # 文档导航与推荐阅读顺序
│   ├── INDEX.md            # 全部文档清单（自动生成）
│   ├── SANITIZATION.md     # 脱敏说明：占位符与如何自备密钥
│   ├── 00-工作区总览.md      # 十节权威总览（建议从这里开始）
│   ├── 001…135-*.md        # 按轮次的研究记录
│   ├── menu-92/            # 原厂菜单打通专题（6 篇 + 交付说明）
│   ├── appendix/           # 静态分析文本
│   └── assets/             # 界面截图
├── scripts/
│   ├── README.md           # 脚本分类与前缀约定
│   ├── INDEX.md            # 全部脚本清单（自动生成）
│   ├── check_repo_hygiene.py
│   ├── (数字前缀).py/.sh    # 各轮实验脚本
│   ├── tools/              # 早期工具与 port/preload/probe 子目录
│   ├── preload/            # LD_PRELOAD 注入/探针的 C 源码
│   └── menu-92/            # 菜单专题的脚本与源码
└── configs/
    ├── README.md
    ├── keymap/             # 物理按键 → 键码映射（自有产物）
    ├── partitions/         # 分区布局（推导值，非原文件）
    ├── runtime/            # QEMU 参数、内核命令行
    └── probe/              # 探针配置模块
```

---

## 四、如何阅读

推荐顺序（详见 [docs/README.md](docs/README.md)）：

1. [docs/00-工作区总览.md](docs/00-工作区总览.md) —— 十节总览：状态、基线、事实、撤回结论、问题、路线、边界
2. [docs/01-方案总览.md](docs/01-方案总览.md) —— 目标与 S0–S5 路线图
3. [docs/02-已验证事实.md](docs/02-已验证事实.md) —— 可复现的事实
4. [docs/04-风险与安全边界.md](docs/04-风险与安全边界.md) —— 风险清单
5. [docs/03-缺口与原料清单.md](docs/03-缺口与原料清单.md) —— 还缺什么
6. [docs/menu-92/README.md](docs/menu-92/README.md) —— 原厂菜单打通专题
7. [docs/88-待求助问题清单.md](docs/88-待求助问题清单.md) —— 开放问题

> 文档按轮次编号，**后期结论会推翻早期结论**。每篇文档顶部都标注了撰写时间与当时的证据强度；
> 引用前请先看最新一轮（编号最大）与 `00-工作区总览.md`。

## 五、复现需要自备什么

本仓库只有方法，没有原料。要让脚本真正跑起来，你需要：

| 材料 | 获取方式 |
|---|---|
| a6600 官方更新器 | Sony 官网（你所在地区） |
| 原厂固件镜像 | 从更新器解包（仓库内有解包脚本，但不含数据） |
| QEMU + 自定义 `sony-a6400` machine | 自建，参考 `scripts/tools/qemu_*.sh` 与公开的 ma1co QEMU 分支 |
| ZV-1M2 五代库 | 需自行合法取得；本仓库**不提供**，也不提供密钥 |
| 真机（可选） | 只读采集；`scripts/98_pmca_*.py` 为 PMCA 服务模式只读工具 |

**不要把本仓库的脚本直接指向你的相机。** 多数脚本绑定原作者路径，已脱敏为占位符，需自行改写。

## 六、证据分级

文档中混有三类陈述，请严格区分（这也是本项目反复强调的纪律）：

- **观察**：日志、截图、寄存器读数等可直接复核的结果
- **推论**：由观察推导，可能被后续推翻
- **未完成检查**：计划、待验证项、失败尝试

失败与被推翻的结论**全部保留**，不删除。

## 七、参与贡献

见 [CONTRIBUTING.md](CONTRIBUTING.md)。提交前请运行：

```bash
python scripts/check_repo_hygiene.py
```

它会检查是否混入了固件类文件、密钥或未脱敏的个人路径。

## 八、许可

本项目整体采用 **GNU General Public License v3.0（GPL-3.0）**，协议全文见 [LICENSE](LICENSE)。

```
Copyright (C) 2026 a6600 ASTRA research contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

### 这意味着什么

| 你可以 | 你必须 |
|---|---|
| 自由使用、修改、分发本仓库的代码与文档 | **保留版权声明与许可证**，并注明修改 |
| 用于商业目的 | **以 GPL-3.0 开放你修改后的衍生作品源码** |
| 分发编译后的产物 | 随产物**提供完整对应源码** |

> **注意**：GPL-3.0 是**强著佐权**协议。如果你把本仓库的脚本或文档并入自己的项目并对外分发，
> 你的整个衍生作品也必须以 GPL-3.0 授权。仅在本地阅读、学习或内部使用不受此限制。

### 与上游材料的关系

- 本仓库**不包含**任何索尼固件、索尼二进制库或解密密钥，因此不涉及对索尼作品的再许可。
- 致谢的上游项目（ma1co/Sony-PMCA-RE、fwtool.py、nolan2628/ZVE10-Astra-Public 等）均为 MIT，
  与 GPL-3.0 兼容；本仓库**未收录其代码**，仅引用方法与思路。
- `PCIEARIA/A6400-Extra-Menu` 采用 PolyForm Noncommercial 1.0.0，**与 GPL-3.0 不兼容**；
  本仓库同样**未收录其任何代码**，仅致谢其支持与方法启发。

### 转载与引用

转载或引用请保留出处与上述许可声明，并**不要附带任何索尼固件或二进制**。

## 九、致谢

### 特别致谢：PCIEARIA / A6400-Extra-Menu

[**PCIEARIA/A6400-Extra-Menu**](https://github.com/PCIEARIA/A6400-Extra-Menu)
（Sony A6400 / A6100 自制触控浮层菜单与 LUT 管理研究）对本项目提供了**关键支持**，
特此郑重致谢：

- **持续的技术支持与经验分享** —— 在 a6xxx 平台的调试思路、实验设计与"哪些路走不通"上
  给了大量直接帮助，让本项目少走了很多弯路；
- **H100 服务器算力支持** —— 静态分析与大规模批处理任务在其 H100 服务器上完成，
  这是本项目能在合理时间内跑完多轮符号扫描、符号闭包与批处理实验的重要前提；
- **相机 root 与漏洞提取方法** —— 其 PMCA 服务模式部署链与
  `/etc/a6400-autoexec.so` 开机挂载钩子的思路，是我们打通真机只读访问、
  验证"root 可达性"的直接来源；本项目中关于真机分区布局与只读提取的结论，
  建立在这套方法之上。

> `A6400-Extra-Menu` 采用 **PolyForm Noncommercial 1.0.0**（非商业用途）许可，
> 与本仓库许可不同。本仓库**未包含其任何代码或二进制**，仅在此致谢与引用其方法思路；
> 如需使用其成果，请遵守其原始许可。

### 其他公开研究

本项目的分析思路与工具还参考了以下公开研究（仅致谢，未包含其代码）：

- [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) —— 相机服务模式与固件容器
- [ma1co/fwtool.py](https://github.com/ma1co/fwtool.py) —— FDAT/SDM 格式
- [ma1co/uniq](https://github.com/ma1co) 及 ma1co 的 QEMU 分支 —— a6xxx 模拟
- [nolan2628/ZVE10-Astra-Public](https://github.com/nolan2628) —— 同方案在 ZV-E10 上的公开实现（本项目的主要参照）
- anlock6600 相关公开研究 —— a6600 固件解包与 CRC 链路
- Oein/a5000-cfw —— 早期 CFW 实践

---

*本仓库为研究记录归档。作者不对任何因使用这些方法造成的设备损坏、保修失效或法律后果负责。*
