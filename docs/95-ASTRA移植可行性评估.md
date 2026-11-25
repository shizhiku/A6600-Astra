# 95 · ASTRA（ZV-1M2 五代）UI 移植：可行性与第一步方案

> 第 83 轮。目标后半段启动。本轮为**纯静态评估**，未改动任何镜像。

---

## 一、结论先行

**五代 UI 的库层面几乎可以直接在 a6600 运行时上加载：**

| 检查项 | 结果 |
|---|---|
| glibc 版本壁垒 | **无**。6 个五代库全部只依赖 `GLIBC_2.4`，与 a6600 的 glibc 2.11 一致 |
| 依赖库齐全度 | **齐**。ZV-1M2 自己的 `/usr` 内含全部 14 个索尼依赖库 |
| 符号缺口（叠加 ZV-1M2 库后） | `appFw.so` **4** 个、`libObj.so` **4** 个、`libmpr.so` **5** 个、`libIMDB.so` **2** 个 |
| 其中弱符号可直接 stub | `_Jv_RegisterClasses`、`__gmon_start__` |
| **真正的硬约束** | **空间**：a6600 `/usr` 只剩 **9.3 MB**，五代一套约 76 MB |

---

## 二、五代库清单（`05-原始固件/zv1m2_fw/gen5/`）

| 文件 | 大小 | SONAME |
|---|---:|---|
| `appFw.so` | 64,273,528 B | appFw.so |
| `libObj.so` | 3,931,624 B | libObj.so |
| `libmpr.so` | 3,038,540 B | libmpr.so |
| `AdjChkConfig.so` | 82,440 B | AdjChkConfig.so |
| `libIMDB.so` | 40,596 B | libIMDB.so |
| `appFwBoot.so` | 8,312 B | appFwBoot.so |

### DT_NEEDED（五代需要的外部库）

`appFw.so`：`libNetCommon.so`、`libGOConnectionManager.so`、`AdjChkConfig.so`、`libopus.so.0`、`libSoundTouch.so.1`、`libqrencode.so`、`libInfraSKD.so` + 标准库

`libObj.so`：`libutil_date.so`、`dataflowInfraFramework.so`、`libcompassutil.so`、`libInfraUsbCmn.so`、`libsencore.so`、`libNetContUtil.so`、`libUsbControl.so`、`libBackupManager.so`、`libInfraMediaCommon.so`、`libbackup.so` + 标准库

`libmpr.so`：`libexpat.so.1` + 标准库

**以上依赖在 ZV-1M2 的 `/usr` 中全部存在**（仅 `libgcc_s.so.1` 需取自 a6600）。

---

## 三、符号缺口（关键数据）

方法：把 **a6600 `/usr/lib`（124 个 .so，13.0 万导出）+ a6600 rootfs `/lib`（110 个 .so，3,439 导出）+ ZV-1M2 `/lib`（141 个 .so，6.9 万导出）** 的导出符号合并，再与五代库的 UND 符号求差。

| 库 | 导入符号 | 仅 a6600 时缺 | **全带上后仍缺** |
|---|---:|---:|---:|
| `appFw.so` | 753 | 273 | **4** |
| `libObj.so` | 688 | 224 | **4** |
| `libmpr.so` | 304 | 121 | **5** |
| `libIMDB.so` | 6 | 6 | **2** |

### 仍缺符号明细

**appFw.so（4）**
- `_Jv_RegisterClasses` —— GCJ 遗留，弱符号，可空 stub
- `__gmon_start__` —— profiling 弱符号，可空 stub
- `_ZN16infra_wrapper_bb6detail12adf_ext_typeE...` —— 真符号
- `_ZN21infra_wrapper_imaging6detail15set_user_matrixE...` —— 真符号

**libObj.so（4）**
- `_Jv_RegisterClasses`、`__gmon_start__`（同上）
- `arch_phys_to_cache` —— 真符号
- `stm_system` —— 真符号

**libmpr.so（5）**
- `_Jv_RegisterClasses`、`__gmon_start__`
- `GpsMgr::SetAllInvalidDefStrGpsInfo(DefStruct::GpsInfo*)`
- `std::basic_regex<char>::_M_compile()`
- `std::regex_search<...>`（模板实例）

**libIMDB.so（2）**：`_Jv_RegisterClasses`、`__gmon_start__`

→ **需要真正补的符号约 5–6 个**，其余 2 个是弱符号 stub。

---

## 四、空间分析（硬约束）

| 镜像 | 文件总量 | 块大小 | 空闲 |
|---|---:|---:|---:|
| a6600 `/usr`（nflasha15） | 186.5 MB / 802 文件 | 1 KB | **9.3 MB** |
| ZV-1M2 `/usr`（nflasha15） | 425.5 MB / 49,986 文件 | 1 KB | 32.5 MB（但其镜像 505.8 MB，**放不进 a6600 的 205.5 MB 分区**） |

### a6600 `/usr` 构成

| 目录 | 大小 | 文件数 |
|---|---:|---:|
| `/lib` | 74.5 MB | 175 |
| `/share` | 68.0 MB | 321 |
| `/bin` | 13.5 MB | 54 |
| `/codec` | 12.4 MB | 6 |
| `/sabin` | 8.2 MB | 86 |
| `/kmod` | 4.8 MB | 101 |

a6600 `/lib` 中可被五代替换的大件：`libObj.so` 19.9 MB、`libmpr.so` 12.2 MB、`CautionConfig.so` 11.7 MB、`viewUnified2.so` 11.0 MB、`viewUnified4.so` 2.5 MB（合计 ≈ 57 MB）

### ZV-1M2 `/usr` 构成

| 目录 | 大小 | 文件数 |
|---|---:|---:|
| `/share` | 279.8 MB | 49,483 |
| `/lib` | **106.7 MB** | 207 |
| `/codec` | 12.4 MB | 6 |
| `/bin` | 8.7 MB | 44 |

**五代 `/lib` 只有 106.7 MB**，其中 `appFw.so` 61.3 MB 独占大半。

---

## 五、第一步实验方案：ASTRA-lite `/usr`

目标：**先验证"五代库能否在 a6600 运行时里被加载"**，不追求完整 UI 资源。

### 构建思路（在 a6600 `/usr` 副本上做）

1. 删除 4th-gen UI 大件：`libObj.so`(19.9)、`libmpr.so`(12.2)、`CautionConfig.so`(11.7)、`viewUnified2.so`(11.0)、`viewUnified4.so`(2.5) → **释放 ≈ 57 MB**
2. 放入 5th-gen：`appFw.so`(61.3)、`libObj.so`(3.7)、`libmpr.so`(2.9)、`libIMDB.so`、`appFwBoot.so`、`AdjChkConfig.so` + 依赖库（`libInfraSKD` 6.9、`libsencore` 0.38、`libInfraMediaCommon` 0.42 等）→ **占用 ≈ 76 MB**
3. 净增约 19 MB，而当前只有 9.3 MB 空闲 → **需再裁 `/share` 约 10–15 MB**（4th-gen 专用资源）

### 预期

- 若 `ld.so` 阶段报错（缺符号/缺库）→ 直接暴露隔离缺口，按第三节的清单补 stub
- 若加载成功但 UI 不出 → 说明卡在资源/初始化，进入下一阶段（`/share` 资源移植）

### 启动参数（沿用已验证配置）

```
-M sony-a6400,rear-controls=on,submicro-frames=<384B 回放文件>
-initrd nflasha3-initrd-nt
overlay 写入 ASTRA-lite /usr @ 771751936
norandmaps
```

---

## 六、风险与边界

- **不改真机、不刷写**：所有操作只在离线镜像副本与 qcow2 覆盖层内
- 五代 `/share` 279.8 MB 无法整体放入 205.5 MB 分区 → 完整 UI 资源移植需要"分区扩容"或"资源裁剪"两条路，本轮先不决策
- 符号存在 ≠ ABI 行为兼容：即使符号齐了，仍需运行期验证

---

## 七、证据与脚本

- `02-脚本/astra_survey_zv1m2.py` —— ZV-1M2 依赖库齐全度
- `02-脚本/astra_symbol_diff.py` —— 符号缺口 diff（本轮核心数据）
- `02-脚本/astra_space_check.py` —— 两个镜像的空闲空间
- `02-脚本/astra_zv_size.py` / `astra_a6_size.py` —— 空间分布

## 八、状态

| 目标项 | 状态 |
|---|---|
| 启动到菜单 | ✅ 已达成（见 94 号） |
| ASTRA · 五代库加载可行性 | ✅ **静态已确认基本可行**（glibc 无壁垒、依赖齐、符号缺口个位数） |
| ASTRA · 符号隔离 | ⏳ 待运行期验证（需补 5–6 个符号） |
| ASTRA · 界面渲染 | ⏳ 未开始（受 `/usr` 分区空间与 `/share` 资源限制） |
