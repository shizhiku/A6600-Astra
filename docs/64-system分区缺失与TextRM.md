# 64 · 新缺口：/system 分区未挂载，TextRM 很可能在其上

本轮为离线镜像分析。无设备写入。

## 一、分区布局（来自 `partinf.conf`）

| 分区 | 用途 | 偏移 | 大小 |
|---|---|---|---|
| `nflasha2` | SYSTEM (Setting) | `0x00800000` | 20 MB |
| **`nflasha3`** | **SYSTEM (Main)** | `0x01C00000` | **48 MB** |
| `nflasha7` | Rootfs | `0x0A400000` | 8 MB |
| `nflasha15` | usr | `0x2D800000` | 300 MB |
| `nflasha16` | Android(system) | `0x40400000` | 140 MB |

启动日志显示：

```
init mount_partition: mounting1 /dev/dnflasha3 -> /system as vfat failed. errno(6)
```

**`/system` 在模拟环境中没有挂载成功。**

## 二、`nflasha3` 里确实内嵌 FAT32

对已解包的 `nflasha3`（29,458,432 B）扫描：

```
FAT32 字符串     位于 0x11A89F9
boot 签名 55AA   位于 0x21FBF8
```

说明该分区在「内核 + initrd」之后还包含一个 **FAT32 区域**（即 `/system` 的文件系统）。

而我们的模拟器只把这部分当作内核/initrd 来源使用，**从未提供 `/system` 的 vfat 内容**。

## 三、UI 资源在 `/usr`，但 TextRM 不在

对 `/usr` 镜像扫描：

| 字符串 | 结果 |
|---|---|
| `image_cmn_169.uxc` | 存在（0x8918564） |
| `.uxc` | 存在（多处） |
| `TextRM` | 存在 5 处（多为引用） |
| **`libTextRM`** | **不存在** |

即：**UI 素材在 `/usr`，但文本渲染库（`TextRM`，导出 `TextRM_loadFont`）在 `/usr` 中找不到实现**。

此前在全部 170 个 `.so` 中搜索 `TextRM_loadFont` 符号，只命中 `libObj.so` 的导入表，没有任何库导出它。

**结论：`TextRM_loadFont` 的实现很可能位于 `/system` 分区**，而该分区在模拟环境中缺失 → 字体加载必然失败 → `libObj` 主动 abort。

## 四、这解释了两件事

1. 为什么把字体文件放到 `/tmp/images/` 后 abort 位置**分毫未变**——因为失败发生在更上游（找不到实现/资源）；
2. 为什么改 `fontlist.dat` 会让启动更早卡住——相关组件在等 `/system` 侧数据。

## 五、下一步（剩余轮次的主攻方向）

1. **定位并提取 `nflasha3` 中的 FAT32 区域**（从 FAT32 引导扇区开始，按 BOOT/FSInfo 计算总扇区数）；
2. 把该 FAT32 内容写入模拟器 emmc 的 `nflasha3` 分区位置，使内核能挂载 `/system`；
3. 重新启动，观察 `/system` 是否挂载成功、`TextRM_loadFont` 是否可用、abort 是否消失。

这是目前最有依据的突破口：**缺失的不是字体，而是承载文本渲染实现的 `/system` 分区。**

## 六、证据

- 分区表：`05-原始固件/a6600_fw/extracted/0300_partconf/partinf.conf`
- 扫描脚本：`probe_system_partition.py`、`find_textrm_lib.py`、`find_textrm_in_initrd.py`
- 日志：`03-证据/模拟器运行/cmdline-20261120T213702Z-52908/serial.log`（`/system` 挂载失败行）

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；本轮无设备操作。
