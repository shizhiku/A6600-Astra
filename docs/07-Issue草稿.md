# Issue 草稿：ILCE-6600 (a6600) 移植进展 + 几个标定问题

> 目标是发到 `nolan2628/ZVE10-Astra-Public` 的 Issues。
> 发之前把 `[你的ID]` 换掉。标题可直接用下面这行。

**标题：** 把 ASTRA 移植到 ILCE-6600（同 CXD90045 平台）——已完成 S0/S1，想请教几个标定细节

---

## 背景

我在做 **ILCE-6600（a6600，FW 1.10）** 的移植预研。它和 ZV-E10 同为 **CXD90045 / Cortex-A5**，
宿主结构同源（`im.elf` + `libIMDB` 模块表 + `libObj.so` + `viewUnified2..8`），
所以想复用你们的方案。先汇报我已经做完的部分，再问几个具体问题。

## 已完成

**1. a6600 固件解包 + 重打包（逐字节一致）**

- `Update_ILCE6600V110.exe`（326,069,208 B，SHA-256 `67a1d92b…`，Sony 签名有效）
- DAT → FDAT（`key_cxd90045`）→ tar → `nflasha3/5/7/15`
- 重打包：重加密 + 重建 DAT + 重算 DEND CRC，产物 `316,672,424 B`，**与索尼原包 SHA-256 相同**（6.3 秒）

**2. a6600 的 USB 服务通道（未拆机）**

用 WSL2 + usbipd + PMCA Senser 拿到 root shell：

- `/setting`（nflasha2）**可读写**，`/setting/mode/` 存在且 `0777`、空
- `im.elf` PID 149、`Uid: 0`；内核 `3.0.27_nl-rt106+`
- 写权限实测：`touch /setting/mode/.dsh_rw_test` → `RW_TEST_OK`

**3. ZV-1M2 2.01 完整解包**

用 `key_cxd90045_k8` 解开 `BODYDATA.DAT`（627,176,840 B），拿到：

```
appFw.so        64,273,528 B
libObj.so        3,931,624 B
libmpr.so        3,038,540 B
AdjChkConfig.so     82,440 B
appFwBoot.so         8,312 B
share/app/          232 个文件
```

体积和你们 `prod_image_manifest.json` 里的完全一致。

**4. 跨代符号冲突首扫**

| 对 | a6600 导出 | ZV-1M2 导出 | 同名冲突 |
|---|---|---|---|
| `libObj.so` → `libOb5.so` | 1,901 | 569 | **490** |
| `libmpr.so` → `libmp5.so` | 3,124 | 6,087 | **184** |

对照你们的 557（352 Ob5 + 190 mp5），量级基本一致。

**5. 一个和 ZV-E10 不一样的实测结论**

a6600 开机是 **warm boot**：`im.elf` 由 `/system/sabin/ssboot.bin` 的休眠快照恢复，
**不走 `execve`**（cmdline 里 `warm.mode=2`）。我实测了两件事：

- 写 `/setting/mode/{dmode=3p, preload=…so}` 后冷启动 → 全进程 `/proc/*/maps` 扫描，**没有任何进程加载它**
- 写 `/etc/ld.so.preload` 指向一个自制的 5 KB `.so`，并确认相机自己的 `ld-2.11.2.so` **含 `ld.so.preload` 字符串** → 冷启动后日志文件**没有生成**，说明没有进程被 exec 并加载

（顺带验证：**坏 preload 不会阻断启动**，相机照常进 UI。）

## 问题

**Q1｜版本对齐**
你们的 ZV-1M2 原料是哪个固件版本？我用的是 **2.01**（627,176,840 B）。
如果你们用的是更早的版本，符号表可能有差异，我需要换版本重做。

**Q2｜`im.elf` 补丁点怎么定位？**
你们在文件偏移 `0x175e`（VA `0x975e`）把 `02 46` 改成 `01 22`。
a6600 的 `im.elf` 不是同一个 build，这个位置肯定不同。
**你们当初是怎么找到它的？** 是跟着 `THREAD_APP` 的第 139 项加载逻辑反汇编出来的吗？
有没有可复用的定位方法（比如按指令序列搜索、或按模块表索引定位），而不是死记偏移？

**Q3｜`libIMDB` 模块表怎么逆向？**
a6600 的 `libIMDB.so` 是 **33,924 B**（ZV-E10 是 37,044 B，ZV-1M2 是 40,596 B），
三台机器的表布局都不一样。你们的 `generate_hybrid_imdb.py` 是硬编码偏移的：
**你们是怎么把这张表的结构（entry 大小、`psid`/`mode`/`file` 指针的相对位置）读出来的？**
有没有什么可复用的解析思路？

**Q4｜warm boot 这件事你们在 ZV-E10 上遇到过吗？**
如果 ZV-E10 也是 `warm.mode=2` + `ssboot.bin`，那 `bootin.elf` 的 preload 路径应该同样不生效——
但你们的方案根本不依赖 preload（靠 `libIMDB` 重定向 + `appFwBoot.so`），所以不受影响？
我想确认一下：**你们从来没打算用 preload 进 `im.elf`，对吗？**
（因为社区里 `anlock6600` 的 `preload-path.md` 假设它可用，而我在 a6600 上实测不成立。）

**Q5｜硬件差异怎么处理？**
a6600 有 **EVF**（0.39" XGA OLED）和 **5 轴 IBIS**，ZV-E10 两样都没有。
ASTRA 里没有对应的菜单项和数据结构。
**你们会建议怎么处理**：是在 UI 里隐藏/占位，还是必须给 `appFw.so` 补一套状态机？
另外 a6600 的 `av-cam` 命令表是 **286 条**（ZV-E10 是 337 条），缺的 51 条你们有兜底经验吗？

## 我能提供的

如果对你们有用，我可以整理并公开（不含索尼二进制）：

- a6600 1.10 的完整解包结构、分区表、`/usr` 文件清单（802 个文件）与关键偏移
- a6600 上已定位的站点：`libmpr.so` `0x87fe08`（`4f f4 87 63`）、`libAK8975.so` `.text@0x988`、
  `libObj.so` 里 A6400 的 12 字节 hook 串唯一命中于 `0x5f22b0`
- 我们的重打包工具（可逐字节重建 a6600 官方包）

感谢。

[你的ID]
