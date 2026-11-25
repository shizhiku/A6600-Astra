# 65 · 方法纠正：thunk 解析需按相对字面量；TextRM 确为导入但实现不在 /usr

本轮为离线解析。无设备写入。

## 一、纠正：ARM thunk 的槽地址计算

`libObj` 里的间接调用 thunk：

```
641910  push {r7,lr}
641912  add  r3, pc
641914  ldr  r3, [r3]
641916  add  r7, sp, #0
641918  cbz  r3, ...
64191a  blx  r3
```

字面量 `0x00D476A4` 是**相对偏移**，不是绝对地址。正确槽地址：

```
槽 = (0x641912 + 2 + 4) + 0xD476A4 = 0x641918 + 0xD476A4 = 0x1388FBC
```

查 `.rel.dyn`：`0x1388FBC -> abort`。

**确认：该 thunk 就是 `abort` 的调用点（与我此前判断一致），但槽地址算法必须改正。**

## 二、`libObj` 确实导入 `TextRM_loadFont`

此前用 `st_shndx == 'SHN_UNDEF'` 过滤未定义符号，得到 0 个 —— 这是**脚本判断写错了**（pyelftools 下该字段类型不同）。

但 `.rel.plt` 中确实存在把 `TextRM_loadFont` 填入 GOT 的重定位：

```
GOT 0x1371FB4 -> TextRM_loadFont
```

即：**`libObj` 确实导入并使用 `TextRM_loadFont`**，此前“字体加载失败”的判断成立。

## 三、但实现库在 `/usr` 与 initrd 中都不存在

- `/usr` 全部 801 个文件中，只有 `libObj.so` 含 `TextRM`/`loadFont` 字样（作为导入名）；
- 全部 170 个 `.so` 中没有任何库导出该符号；
- initrd 根文件系统（28 个文件）中也没有；
- `libObj` 的 `DT_NEEDED` 里也没有名字带 TextRM 的库（其依赖为 libInfraFsys/libmprctrl/libMWF/libmpr/libutil_date/libsencore 等）。

**结论：实现 `TextRM_loadFont` 的库不在 `/usr`、不在 initrd，极可能在未挂载的 `/system` 分区。**

## 四、`/system` 的来源仍不明

- 分区表：`nflasha3`（SYSTEM Main，48 MB）在启动时被要求挂载为 `/system`（vfat）；
- 我们解包到的 `nflasha3` 只有 29,458,432 B（内核 + initrd 部分）；
- 在其中**未找到对齐的 FAT32 引导扇区**（此前命中的 `FAT32` 字符串是内核 vfat 驱动的一部分，不是文件系统）。

因此 `/system` 的 vfat 内容可能：
1. 位于 `nflasha3` 分区剩余空间（解包镜像未包含）；
2. 或由设备在运行时生成/解密（`dnflasha` 前缀暗示“解密后的”设备）。

## 五、剩余轮次的建议

1. **核对 `nflasha3` 的分区边界**：`partinf.conf` 给出偏移 `0x01C00000`、大小 `0x03000000`；若更新包只提供前 29 MB，则 `/system` 部分可能缺失于我们手上；
2. **在相机上验证 `/system` 结构**：尝试读取 `/system/` 下的常见路径（如 `/system/lib/libMWF.so`）判断是否可访问；
3. 若相机可读，则采集 `TextRM_loadFont` 的实现库（先用 `libObj` 的 GOT 重定位确认符号名，再在相机 `/system/lib` 下匹配）；
4. 拿到后放入模拟器可加载路径（`/usr/lib`），观察 abort 是否消失。

## 六、证据

- `02-脚本/resolve_abort_thunk.py`（槽 `0x1388FBC -> abort`）
- `02-脚本/resolve_plt_exact.py`（`0x1371FB4 -> TextRM_loadFont`）
- `02-脚本/find_textrm_refs.py`、`largest_usr_files.py`、`find_textrm_in_initrd.py`
- `02-脚本/probe_system_partition.py`（nflasha3 无对齐 FAT32 引导扇区）

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；本轮无设备操作。
