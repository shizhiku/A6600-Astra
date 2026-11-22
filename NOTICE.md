# NOTICE · 来源、归属与排除清单

## 1. 这个仓库的性质

本仓库是一份**研究过程归档**：记录把 Sony ZV-1M2（第五代，ASTRA UI）的 UI 层移植到
ILCE-6600（a6600，第四代）的方法、方案与实验结果。

它**不是**固件分发渠道，也**不是**破解工具包。所有原始索尼材料均被排除。

## 2. 明确排除的材料

以下内容在整理时被**刻意删除或从未纳入**，且不随本仓库分发：

| 类别 | 示例 | 排除原因 |
|---|---|---|
| 官方固件 / 更新器 | `Update_ILCE6600V110.exe`、`BODYDATA.DAT`、`firmware.tar`、`fdat_plain.bin` | 索尼版权材料 |
| 分区镜像 | `nflasha1/2/3/5/7/15`、`emmc.img`、`0700_part_image/*` | 索尼版权材料 |
| 固件内二进制 | `libObj.so`、`appFw.so`、`appFwBoot.so`、`libIMDB.so`、`input.ko`、`liro.ko`、`emmc.ko` | 索尼版权材料 |
| 从固件提取的字体 / 资源 | 真机字体、`share/app/*` 资源 | 索尼版权材料 |
| 修改后的产物 | `nflasha15_patched.bin`、`nflasha15_astra.dat`、`firmware_patched.tar` | 索尼材料衍生 |
| 解密密钥 | AES key 字面量 | 见第 4 节 |
| 运行日志 | 上千份 `serial.log` / `stderr.log` / 截图原始帧 | 体积大且含设备运行细节 |
| 第三方源码 | `Sony-PMCA-RE`、QEMU、`a5000-cfw` 等副本 | 各自有其许可证，见第 5 节 |

> 需要这些材料请自行从你**合法持有**的设备和官方更新渠道取得。本仓库不提供获取途径。

## 3. 保留材料及其来源

| 内容 | 来源 | 说明 |
|---|---|---|
| `docs/*.md` | 本项目研究记录 | 自有文字；含对索尼行为的**观察与推论** |
| `scripts/*` | 本项目自写脚本 | 自有代码；路径已脱敏 |
| `configs/keymap/*` | 本项目实测生成的按键映射 | 由公开协议交互与静态分析推导 |
| `configs/partitions/*` | 由设备内 `partinf.conf` **推导**的分区表 | 仅保留分区起止/大小/类型的**事实数据**，未复制原文件文本 |
| `configs/runtime/*` | 一次 QEMU 运行的参数与内核命令行 | 自有实验配置 |
| `docs/assets/*.png` | 本项目 QEMU 运行截图 | 自有截图 |

文档中引用的索尼字符串、函数名、地址、SHA-256 摘要，属于为**互操作与安全研究**所必需的
事实性引用（fair use / 互操作性研究惯例），不构成对索尼作品的复制分发。

## 4. 密钥已移除

若源文件（`decrypt_*`、`repack_*`、`build_full_image` 等工具）中出现 AES 密钥字面量，
已统一替换为 `REDACTED_KEY_<用途>` 占位符。

- 仓库**不分发**任何密钥。
- 需要运行这些工具时，请自行提供你合法获得的密钥（详见
  [docs/SANITIZATION.md](docs/SANITIZATION.md)）。
- 我们**不会**通过 Issue / PR / 私信提供密钥，请不要询问。

## 5. 第三方引用（仅致谢，未包含代码）

| 项目 | 用途 | 许可证 |
|---|---|---|
| [**PCIEARIA/A6400-Extra-Menu**](https://github.com/PCIEARIA/A6400-Extra-Menu) | **主要支持方**：技术支持与经验分享、H100 算力、相机 root 与漏洞提取方法（PMCA 部署链 + `/etc/a6400-autoexec.so` 开机挂载钩子） | PolyForm Noncommercial 1.0.0 |
| [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) | 相机服务模式、固件容器格式 | 见其仓库 |
| [ma1co/fwtool.py](https://github.com/ma1co/fwtool.py) | FDAT / SDM 结构 | 见其仓库 |
| ma1co QEMU 分支 | a6xxx 机型模拟 | GPL-2.0（QEMU） |
| [nolan2628/ZVE10-Astra-Public](https://github.com/nolan2628) | 同方案在 ZV-E10 的公开实现，本项目主要参照 | 见其仓库 |
| anlock6600 相关公开研究 | a6600 解包与 CRC 链路结论 | 见原文 |
| [Oein/a5000-cfw](https://github.com/Oein/a5000-cfw) | 早期 CFW 实践 | 见其仓库 |

**注意**：本仓库**没有**包含上述项目的任何源码副本。若你需要它们，请从上游获取并遵守其许可证。

本仓库整体采用 **GNU GPL v3.0**（见 [LICENSE](LICENSE)）。其中：

- `ma1co/Sony-PMCA-RE`、`ma1co/fwtool.py`、`nolan2628/ZVE10-Astra-Public` 均为 **MIT**，
  与 GPL-3.0 兼容；
- `PCIEARIA/A6400-Extra-Menu` 采用 **PolyForm Noncommercial 1.0.0**（非商业用途），
  **与 GPL-3.0 不兼容** —— 本仓库因此仅致谢其支持与方法启发，未收录任何代码；
- QEMU 为 **GPL-2.0**。本项目"给 QEMU 打补丁"的脚本仅以少量 QEMU 源行作为**补丁锚点**，
  未复制 QEMU 实现；若要向 QEMU 分发衍生作品，请遵循 QEMU 自身的 GPL-2.0 条款。

## 6. 商标

Sony、ILCE、ZV-1M2、α 等为 Sony Corporation 的商标或注册商标。
本项目与 Sony Corporation 无任何隶属、合作或背书关系。

## 7. 权利主张与下架

若您是权利人，认为本仓库某处内容侵犯了您的权利，请提交 Issue 说明具体文件与理由。
我们会在核实后**立即修改或删除**相关内容，无需法律程序。

## 8. 免责

本仓库内容按"现状"提供，不附带任何明示或暗示担保。作者不对因使用其中的方法、
脚本或结论而导致的设备损坏、数据丢失、保修失效或任何法律后果承担责任。
