# a6600 × ASTRA · 把 ZV-1M2 第五代触控菜单移植到 ILCE-6600

> 把 Sony **ZV-1M2（第五代 / ASTRA 触控 UI）** 的菜单层移植到 **ILCE-6600（a6600，第四代）**，
> 并在 QEMU 中运行、验证、逐步收敛的过程记录。
>
> **本仓库不含任何索尼固件、固件解包产物、索尼二进制库、解密密钥或可刷入镜像。**

---

## ⚠️ 先读：边界

| 事项 | 立场 |
|---|---|
| 固件镜像 / 解包树 / `.so` / `.ko` / `.uxc` / `.dat` | **完全不包含**。请从你合法持有的设备与官方更新器自行取得 |
| 固件解密密钥 | **完全不包含**，脚本中以 `REDACTED_KEY_*` 占位 |
| 可刷入镜像 | **不提供**。研究产物中含索尼二进制，不得再分发 |
| 真机写入 | 本项目**从未写入**任何相机。所有真机操作均为只读采集 |
| 用途 | 兼容性研究与方法记录。请勿用于规避技术保护措施或商业分发 |

> Sony、ILCE、ZV-1M2 等为 Sony Corporation 商标。本项目与索尼无关联、未获授权或背书。
> 权利人如有异议，请通过 Issue 联系，我们会立即处理。

---

## 一、结论先讲

**ASTRA 菜单已经在 QEMU 中跑起来了。**

| 能力 | 状态 |
|---|---|
| 启动 → 引导页 → 拍摄界面 | ✅ |
| MENU 开合菜单（52 页完整菜单树） | ✅ |
| 方向键 UP / DOWN / LEFT / RIGHT | ✅ |
| 菜单层级触摸导航 | ✅ |
| 触摸点击 / 拖动 | ✅ |
| 停止重绘后自动恢复（强制重绘看门狗） | ✅ |
| 切换到简体中文 | ✅ 可切换，但 QEMU 中不持久 |
| 常规使用稳定性 | ✅ 修复后菜单静置 4 分钟零错误 |
| **切换语言后** | ⚠️ 会触发已知缺陷（见 §四） |
| **刷入真机** | ⛔ **不做**：写 `/etc` 没有已验证的恢复手段 |

---

## 二、这个仓库是什么

**方法记录 + 可复现的工具**，不是刷机包。

### 包含

| 目录 | 内容 |
|---|---|
| `docs/` | 研究记录（按轮次编号，含被推翻的结论） |
| `docs/astra-port/` | **本轮移植的 6 篇核心文档**（交付总结、按键通道、卡死分析、救砖手册、固件恢复、根因分析） |
| `scripts/` | 自有工具：静态分析、QEMU 补丁、注入探针、镜像处理 |
| `scripts/port/` | **本轮移植工具链**：垫片构建、镜像组装、发布打包、审计、实时演示 |
| `configs/` | 自有配置：按键映射、分区布局（推导值）、QEMU 参数 |
| `docs/assets/` | 界面截图（证明结论用） |

### 不包含

- 任何索尼固件、分区镜像、`firmware.tar`、`BODYDATA.DAT`、更新器
- 任何从固件提取的库（`appFw.so`、`libObj.so`、`libMWF.so` …）
- 任何解码/解密密钥
- 原始运行日志（上千份 `serial.log`）
- 第三方项目源码副本

---

## 三、技术路线（一句话版）

```
/etc/ld.so.preload  →  /usr/lib/appFwBoot.so（自研垫片）
                        ├─ 代际偏移替换：五代 appFw 跑在四代宿主上
                        ├─ 触控邮箱：宿主写共享页 → 垫片轮询 → postMouse*
                        ├─ 按键直注：kind=3 → g5_send_internal_event（绕过已死的四代输入队列）
                        └─ 强制重绘看门狗：drawFramebuffer 停摆时主动补画
```

对 `im.elf` / `libObj.so` / `libMWF.so` / `libIMDB.so` **零二进制补丁**。

---

## 四、已知缺陷（诚实记录）

### 1. 屏幕朗读子系统的内存分配死循环

五代应用会反复调用 `adf_sys_set_text_speech_*` 并伴随 `dmm alloc_core` 失败：

```
adf_sys_set_text_speech_output  →  dmm alloc_core ERROR(-3)
                                →  dmm_free handle[0xffff]
                                →  adf_sys_set_text_speech_volume
（每 6 秒一轮，约 154 秒后 UI 停止重绘）
```

**根因**：五代 `/share/screenreader`（226 MB，10 种语言）在我们的 300 MiB 镜像里装不下，被裁掉了。

**缓解**：加入一个**空的** `/share/screenreader/simplifiedchinese/` 目录后，
菜单静置 240 秒内 `dmm` 错误 0 次（修复前 154 秒即开始刷屏）。

**未解决**：切换语言会让朗读引擎重新加载该语言数据，再次触发同样路径。

详见 [docs/astra-port/32-stall-root-cause-screenreader.md](docs/astra-port/32-stall-root-cause-screenreader.md)。

### 2. 输入动作偶尔不生效

即使 `dmm` 错误为 0、画面持续刷新，个别输入动作（如「关闭」按钮）只产生高亮而不发生跳转。
**"绘制活着"与"事件处理活着"是两件独立的事**，后者尚未定位。

### 3. `next=0` 不是损坏

早期误判为"屏幕栈损坏"的 `PCM_OPEN ... next=0x0`，实际是应用表示"关闭当前层、不指定替换目标"的**正常语义**。
强行改写它反而会破坏关闭流程。详见 [docs/astra-port/29-menu-close-analysis.md](docs/astra-port/29-menu-close-analysis.md)。

---

## 五、恢复通道评估（为什么不做真机刷写）

| 通道 | 前提 | 状态 |
|---|---|---|
| PMCA service shell | 系统能正常启动 | ✅ 已实测 |
| PMCA `updatershell -f` 刷官方固件 | 相机能进海量存储 | 🟡 工具存在，未实测 |
| SD 卡 + `BODYDATA.DAT` | 相机支持 SD 更新 | ❌ **a6600 不支持**（官方说明要求升级前取出存储卡） |
| 看门狗自动复位 | 整机挂起 | ❌ 实测 UI 冻结 160 秒未复位 |
| UART / BootROM | 测试点未定位 | ❌ 无 |

**⇒ 写 `/etc/ld.so.preload` 目前没有已验证的兜底手段，因此本项目不提供刷写方案。**

更安全的替代（未实施）：用真机 500 MiB 的 `/log` 分区 + `mount --bind` 覆盖 `/usr/lib/*`，
断电即恢复原厂。详见 [docs/astra-port/30-recovery-playbook.md](docs/astra-port/30-recovery-playbook.md)。

---

## 六、真机勘测结果（只读）

```
/dev/nflasha7  /          ext2  ro      4 MiB
/dev/nflasha15 /usr       ext2  ro    300 MiB   ← 普通 ext2，非压缩
/dev/nflasha10 /tmp + /etc vfat  rw    12 MiB   ← 与 /tmp 共用
/dev/nflasha11 /log       vfat  rw    500 MiB
/dev/nflasha2  /setting   vfat  rw     20 MiB
/dev/nflasha3  /system    vfat  rw     48 MiB
```

真机全程只读，仅向 `/log` 写入过两个分区备份，未改动任何系统分区。

---

## 七、如何阅读

推荐顺序：

1. [docs/astra-port/27-final-handover.md](docs/astra-port/27-final-handover.md) —— 交付总结
2. [docs/astra-port/28-key-injection-channel.md](docs/astra-port/28-key-injection-channel.md) —— 按键通道与映射
3. [docs/astra-port/32-stall-root-cause-screenreader.md](docs/astra-port/32-stall-root-cause-screenreader.md) —— 卡死根因
4. [docs/astra-port/30-recovery-playbook.md](docs/astra-port/30-recovery-playbook.md) —— 救砖手册
5. [docs/astra-port/31-firmware-and-sd-recovery.md](docs/astra-port/31-firmware-and-sd-recovery.md) —— 固件与 SD 卡恢复
6. [docs/00-工作区总览.md](docs/00-工作区总览.md) —— 早期十节总览（历史背景）

> 文档按轮次编号，**后期结论会推翻早期结论**。引用前请先看最新一轮与 `docs/astra-port/`。

---

## 八、复现需要自备

| 材料 | 获取方式 |
|---|---|
| a6600 官方更新器 | Sony 官网 |
| 原厂固件镜像 | 从更新器解包（仓库内有解包脚本，不含数据） |
| QEMU + 自定义 `sony-a6400` machine | 自建，参考 `scripts/port/patch_qemu_touch.py` |
| ZV-1M2 五代库 | 需自行合法取得；本仓库不提供，也不提供密钥 |

脚本中的路径已脱敏为 `${WORKSPACE}` / `${REPO}` / `${RUN}` 等占位符，需自行改写。

---

## 九、证据分级

本项目的记录混有三类陈述，请严格区分：

- **观察**：日志、截图、寄存器读数等可直接复核的结果
- **推论**：由观察推导，可能被后续推翻
- **未完成检查**：计划、待验证项、失败尝试

失败与被推翻的结论**全部保留**，不删除。这一点在本项目里尤其重要——多次误判都记在文档里，
包括「把静态画面当成卡死」「把 `next=0` 当成损坏」「把旧帧当成新证据」。

---

## 十、致谢

### 特别致谢：PCIEARIA / A6400-Extra-Menu

[**PCIEARIA/A6400-Extra-Menu**](https://github.com/PCIEARIA/A6400-Extra-Menu) 是本项目的**主要支持方**，
在此郑重致谢：

- **持续的技术支持与经验分享** —— 在 a6xxx 平台的调试思路、实验设计，以及"哪些路走不通"上
  给了大量直接帮助，让本项目少走了很多弯路；
- **H100 服务器算力支持** —— 静态分析与大规模批处理任务在其 H100 服务器上完成，
  这是本项目能在合理时间内跑完多轮符号扫描、符号闭包与批处理实验的重要前提；
- **相机 root 与漏洞提取方法** —— 其 PMCA 部署链与 `/etc/a6400-autoexec.so` 开机挂载钩子的思路，
  是我们打通真机只读访问、验证 root 可达性的直接来源；本项目中关于真机分区布局与只读提取的结论，
  建立在这套方法之上。

> `A6400-Extra-Menu` 采用 **PolyForm Noncommercial 1.0.0**（非商业用途）许可，与本仓库的 GPL-3.0 不同。
> 本仓库**未包含其任何代码或二进制**，仅在此致谢并引用其方法思路；如需使用其成果，请遵守其原始许可。

### 其他公开研究

| 项目 | 贡献 | 许可证 |
|---|---|---|
| [ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) | 相机服务模式、固件容器格式 | 见其仓库 |
| [ma1co/fwtool.py](https://github.com/ma1co/fwtool.py) | FDAT / SDM 结构 | 见其仓库 |
| ma1co QEMU 分支 | a6xxx 机型模拟 | GPL-2.0（QEMU） |
| [nolan2628/ZVE10-Astra-Public](https://github.com/nolan2628) | 同方案在 ZV-E10 的公开实现，本项目主要参照 | 见其仓库 |
| anlock6600 相关公开研究 | a6600 解包与 CRC 链路结论 | 见原文 |
| [Oein/a5000-cfw](https://github.com/Oein/a5000-cfw) | 早期 CFW 实践 | 见其仓库 |
| [cokeenet/zve10-qemu](https://github.com/cokeenet/zve10-qemu) | 同方案在 ZV-E10 的公开实现；**本仓库的目录组织与文档风格参照它** | 见其仓库 |

**以上项目均未收录其代码**，仅致谢方法与思路。详细归属与排除清单见 [NOTICE.md](NOTICE.md)。

### 许可

本仓库整体采用 **GNU General Public License v3.0（GPL-3.0）**，协议全文见 [LICENSE](LICENSE)。

```
Copyright (C) 2026 a6600 ASTRA research contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.
```

> **注意**：GPL-3.0 是**强著佐权**协议。若你把本仓库的脚本或文档并入自己的项目并对外分发，
> 你的衍生作品也需以 GPL-3.0 授权。仅本地阅读、学习或内部使用不受此限制。

---

*本仓库为研究记录归档。作者不对任何因使用这些方法造成的设备损坏、保修失效或法律后果负责。*
