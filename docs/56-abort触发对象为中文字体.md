# 56 · abort 的触发对象：中文字体 `FONT_S_CHINESE`

本轮为 QEMU 补丁、重编与离线扫描。无设备写入。

## 一、钩子增强

两处增强（均默认关闭，未设环境变量时零开销）：

1. `REA_BP_MEMVA/MEMLEN`：在命中时 dump 指定虚拟地址的内存；
2. `REA_BP_MEMREG/MEMLEN`：读取指定编号寄存器的值，并 dump 该地址的内存（用于动态指针）。

为了不影响整体速度，链式跳转的禁用改为**仅对 `s.pc == REA_BP_VA` 的那个 TB** 生效。
（此前尝试全局禁用链式，导致 120 秒仅跑到客户机 0.257 秒，不可用。）

## 二、命中结果

在 `libObj` 的 `TextRM_loadFont` PLT 桩（`libObj + 0xFF588`，运行期 `0x058E2588`）命中，寄存器：

```
R00=0x00130520  R01=0x119FD15C  R02=0  R03=1
R14=0x05E2A945  （返回地址，位于 libObj 0x647945 附近）
```

按 `R0` 指向的地址 dump 内存，解出 ASCII：

```
FONT_S_CHINESE\0 ... FONT_T_CHINESE\0 ...
```

**即 UI 正在请求加载中文字体。**

## 三、字体映射表（在 `/usr` 分区内找到）

在 `nflasha15`（`/usr`）偏移 `0x75E58B8` 附近发现字体表项：

```
... MYingHeiC-KSX1001-SJ_wIcon.ltt  0.0  FONT_S_CHINESE
    /tmp/images/MYingHeiC-GB18030-SJ_wIcon.ltt ...
... MYingHeiC-GB18030-SJ_wIcon.ltt       FONT_T_CHINESE
    /tmp/images/MYingHeiC-Big5-SJ_wIcon.ltt ...
```

即：

| 标识 | 期望路径 |
|---|---|
| `FONT_S_CHINESE` | `/tmp/images/MYingHeiC-GB18030-SJ_wIcon.ltt` |
| `FONT_T_CHINESE` | `/tmp/images/MYingHeiC-Big5-SJ_wIcon.ltt` |

**关键点：路径位于 `/tmp/images/`** —— 字体不是直接从 `/usr` 读取，而是需要**在运行时被解压/复制到 `/tmp/images`**。

`nflasha7`、`nflasha5`、initrd 中均无这些标识。

## 四、推断

字体加载失败的可能原因（按可能性排序）：

1. **字体尚未被解出到 `/tmp/images`**（解压步骤未执行或失败）；
2. `/tmp` 不可写或空间不足；
3. 字体源文件（`.ltt`）在 `/usr` 中的实际存放位置未被正确挂载/查找。

这与 av-cam、libc 的“构建/资源不一致”不是同一类问题，而是**运行期资源准备步骤**的问题。

## 五、下一步

1. 查找 `/usr` 中是否存放 `.ltt` 源文件（搜索 `MYingHeiC` 与 `.ltt` 的实际文件）；
2. 确认启动过程中是否有把字体复制到 `/tmp/images` 的步骤（可能与 `im.elf` 的初始化或某个服务相关）；
3. 在模拟器里检查设备启动后 `/tmp/images` 是否存在及内容；
4. 若源文件存在但未复制，可确认是哪个组件负责该步骤、为何未执行。

## 六、证据

- 钩子运行：`cmdline-20261120T210909Z-50147`（`REA_MEMREG` dump 出字体名）
- 字体表扫描：`02-脚本/search_font_resources.py`（`nflasha15` @ `0x75E58B8`）
- QEMU 补丁：`patch_bp_memdump.py`、`patch_bp_memreg.py`、`patch_targeted_chaining.py`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；相机本轮未接触。
