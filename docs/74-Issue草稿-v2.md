# 拟提交 Issue 草稿（v2 · 2026-11-21）

> 目标仓库：`nolan2628/ZVE10-Astra-Public`
> 提交前请把末尾署名替换为你自己的 ID。

**标题：** ASTRA 移植到 ILCE-6600（同为 CXD90045）——已跑到 UI 框架，卡在副控制器字体链路，想请教几个标定细节

---

## 背景

我在做 **ILCE-6600（a6600）** 的移植预研。它与 ZV-E10 同为 **CXD90045 / Cortex-A5**，用户态结构同源（`im.elf` + `libObj.so` + `viewUnified2..8` + `mpr` 系列），想复用你们已有的方案。

目前已经能在 QEMU（`sony-a6400` 机型）里把**原厂固件重启到 UI 框架**，但停在字体加载，想请教几个问题。

## 已完成

**1. 固件解包 + 重打包（逐字节一致）**

`Update_ILCE6600V110.exe`（126,069,208 B）→ DAT → FDAT（`key_cxd90045`）→ tar → `nflasha3/5/7/15`。
重打包后与索尼亚原始包 SHA-256 相同。

**2. 相机侧只读通道**

WSL2 + usbipd + PMCA Senser 可拿到只读文件访问，已采集：

- `/usr/share/app/fontlist.dat`（360 B）
- `/lib/libc-2.11.2.so`（984,292 B）
- `/tmp/images/MYingHeiC-GB18030-SJ_wIcon.ltt`（1,958,432 B，中文字体）

**3. QEMU 启动到 UI 框架**

`nflasha3-Image` + `nflasha3-initrd`（ext2 根文件系统）+ emmc overlay + `Backup.bin` 作为 `/setting`。

日志可见：`im.elf(Appframework)` 运行、加载 `image_cmn_169.uxc` / `image_EVF.uxc` / `image_DSLR_Only_170.uxc`，并有 `[VPH]` 显示层输出。

**4. 崩溃点精确定位（可能对你们也有用）**

```
libObj::TextRM_loadFont("FONT_S_CHINESE")
  → 在「已注册字体链表」中按名字查找，未命中
  → 返回 -16
  → libObj 错误上报 → abort() → raise(SIGABRT) → tgkill(_,_,6)
  → Sony 异常监视器打印 "Illeagle Instruction"（措辞误导，实为 SIGABRT）
```

相关偏移（`libObj.so`）：

| 符号/函数 | 偏移 |
|---|---|
| `TextRM_loadFont` | `0x54ED58` |
| 字体查找助手 | `0x54E7A8` |
| 节点创建 | `0x54E7D4` |
| 注册函数 | `0x54E94C` |
| 字体链表头 | `0x13F64FC` |

注册函数只被调用一次，来自一次性初始化（`0x54F3A2`，带初始化标志位），**不遍历 `fontlist.dat`**。

## 观察到的关键事实

**字体不在固件里，而是运行期由副控制器提供：**

- 固件 `/usr` 里只有 3 个 `.ltt`（Univers / Heisei / KSX1001），**没有中文**；
- `fontlist.dat` 把 `FONT_S_CHINESE` 指向 `/tmp/images/MYingHeiC-GB18030-SJ_wIcon.ltt`；
- 相机运行时 `/tmp/images/` 里确实存在该文件（已采集）；
- 客户机内实测：**`/tmp/images` 在运行期不存在**（initrd 里预置也无效，`/tmp` 被重挂/清空）；
- `libsencore.so` 含这些 `/tmp/images/...ltt` 路径与 `Trans(to Subsystem)`、`resCode/Adrs/DataSize`、`Offset > 300Byte` 等报文线索。

即：**`/tmp/images` 的创建与字体落地，是副控制器传输链路的副产物**；仅放文件不会触发注册。

## 想请教的问题

1. 你们在模拟器里是否实现了副控制器（LSI / sub-micro）的**文件传输通道**？如果有，报文格式（命令码、`TransType`、0x300 分片、`resCode` 语义）能否指点一二？

2. `TextRM_loadFont` 之前，「字体注册」正常应由谁触发——是副控制器传输完成后的回调，还是 UI 侧的某个初始化序列？

3. a6600 的 `nflasha3`（SYSTEM Main，48 MB）在启动时会被挂载为 `/system`（vfat）。我们解包到的镜像（29.4 MB）里找不到对齐的 FAT32 引导扇区，`/system` 始终挂载失败。你们那边 `/system` 是怎么提供的？

4. 我们这边还有一个未解现象：改动 `/usr` 镜像的**文件内容**后（哪怕只改一个 360 字节的配置），启动会在客户机 3.27 s 后停滞，只剩 eMMC 调优重试；而同尺寸只更新超级块则启动正常。你们是否遇到过类似情况？

## 补充：我们能确认的「不是」原因

- 不是内核禁用 syscall 191（BusyBox 正常使用）
- 不是 CPU 处于 ARM 态误解释 Thumb 字节
- 不是 libc 版本问题（相机 libc 与我们手上的更新包确实是不同构建——仅 10/241 个 4 KiB 块相同——但换用相机 libc 后崩溃点不变）
- 不是 `TextRM_loadFont` 实现缺失（它就在 `libObj` 内部）

---

署名：[你的 ID]
