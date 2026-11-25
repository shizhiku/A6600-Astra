# ASTRA 移植 · 本轮核心文档

> 把 ZV-1M2（第五代 / ASTRA）菜单层移植到 ILCE-6600 的最终阶段记录。
> 编号对应 `04-产物/a6600-port/docs/` 中的原始文件名。

| 文件 | 原始名 | 内容 |
|---|---|---|
| [27-final-handover.md](27-final-handover.md) | 27-最终交付总结.md | 交付总览：做了什么、验证到哪、边界在哪 |
| [28-key-injection-channel.md](28-key-injection-channel.md) | 28-按键直注通道.md | 按键事件通道原理、事件 ID 表、实测映射 |
| [29-menu-close-analysis.md](29-menu-close-analysis.md) | 29-关闭菜单卡死.md | `next=0` 语义辨析（一次被推翻的判断） |
| [30-recovery-playbook.md](30-recovery-playbook.md) | 30-救砖手册.md | 三类砖的分级与四步恢复顺序 |
| [31-firmware-and-sd-recovery.md](31-firmware-and-sd-recovery.md) | 31-救砖固件与SD卡恢复.md | 官方 `BODYDATA.DAT` 提取方法；a6600 不支持 SD 卡更新 |
| [32-stall-root-cause-screenreader.md](32-stall-root-cause-screenreader.md) | 32-卡死根因-屏幕朗读资源缺失.md | 停绘的根因：屏幕朗读资源缺失导致内存分配死循环 |

---

## 关键结论速查

**能力边界**

| 能 | 不能 |
|---|---|
| QEMU 中启动到菜单、触摸导航、按键操作 | 在没有可验证恢复通道的前提下刷真机 |
| 切换到简体中文（不持久） | 让语言设置在 QEMU 重启后保持 |
| 停止重绘后自动恢复画面 | 让应用重新处理事件（绘制与事件是两件事） |

**四条恢复通道的实测结论**

| 通道 | 结论 |
|---|---|
| PMCA service shell | ✅ 可用（要求系统能启动） |
| 看门狗自动复位 | ❌ UI 冻结 160 秒未复位 |
| SD 卡 + `BODYDATA.DAT` | ❌ a6600 不支持 SD 卡更新 |
| UART / BootROM | ❌ 测试点未定位 |

---

## 阅读建议

先看 27 号（全局），再看 32 号（当前最主要的技术问题），最后看 30/31（安全边界）。
28 和 29 属于具体机制与一次判断纠错，可按需阅读。
