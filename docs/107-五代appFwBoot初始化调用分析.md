# 107 · 五代 appFwBoot 初始化调用分析（Application_System_Init）

日期：2026-11-22。对象：ZV-1M2 五代 `appFwBoot.so`（8312 B，Thumb）。
方式：离线静态反汇编（Python elftools + capstone 5.0.7），**不运行 QEMU、不执行目标代码、不改任何现有镜像/脚本/文档**。

证据目录：`03-证据/静态分析/boot5/`；脚本前缀：`02-脚本/appfwboot_*.py`。

---

## 0. 结论摘要（先看这里）

1. `appFwBoot::Application_System_Init`（VA `0x1271`，284 B）**本身不调用任何“迁移前初始化”**（不碰 `MWF_Init` / `grm_init` / `DDSUserInit` / `uxengine_init` / `infra_input_init` / `WidgetLayouter::sys_initialize` / `dmp_allocator_*`）。它只做四件事：
   - 向 osal 队列 `0x8f013a` 发一条 `cmd=9` 的同步日志（内容 `"AC <本函数地址>"`）；
   - `dlopen("appFw.so") + dlsym("Application_Start")`（或 `AdjChkConfig.so` + `_ZN13app_adjchk_ui9main_loopEv`）；
   - 用 `osal_create_waitable_thread` 创建名为 `"AppFw"` 的线程，线程体是本文件内的 `Main`，参数是上一步 dlsym 得到的入口；
   - `osal_set_cpu(thread, 0xf)` 后返回。
2. 真正的五代 UX 初始化发生在 **AppFw 线程体 `Main`（`0x14d9`，120 B）**里，顺序固定：
   `uxengine_init2()` → `initializeArena()` → `Kernel::sys_setCurrentDirectory("/usr/share/app/")` → `AreaCheckExtensionManager::setCheckDataPath("/usr/share/app/area_check_data.dat")` + `setLogPath("/tmp/area_check_log.dat")` → `GraphicsEngine::setOverflowResizeFontAttribute(0x1c,0x15)` + `setOverflowResizeLayoutAttribute(0x22)` → `ResourceManager::setDatabase("global.xdb")` → `ResourceManager::sys_setFontNameWithNamespace(0x33)` → 调用 `Application_Start`。
   也就是说 **`uxengine_init2`、arena/资源管理器、字体命名空间等都在 appFwBoot 内部完成**，外部重复调用没有必要。
3. 原厂“迁移前初始化”的权威顺序在 **gen5 `libIMDB.so` 的 44 字节模块表**里（本次已完整解码，227 条，含 9 个 PHASE 分隔）。与本问题相关的条目顺序为：
   `libMWF.so::MWF_Init`(idx32) → `libInfraInput.so::infra_input_init`(idx35) → `libCoreSync.so::core_sync_user_init`(idx45) → **`libgrm.so::grm_init`(idx46)** → `libgpe.so::GpeInit`(idx47) → `libDDS.so::DDSUserInit`(idx48) → `libuxengine.so::uxengine_init`(idx49) → …infra 列表… → **`appFwBoot.so::Application_System_Init`(idx145)**。
   四代 a6600 表（197 条）同样是 `MWF_Init`(29) → `infra_input_init`(31) → `core_sync_user_init`(39) → `grm_init`(40) → `DDSUserInit`(41) → `uxengine_init`(42) → …→ `appFw.so::Application_System_Init`(123，带“静态并入 libObj”标志)。
   **当前桥接顺序（DDS→uxengine→sys_initialize→infra_input→MWF→grm）与原厂顺序基本相反**：原厂先 MWF、再 InfraInput，然后才是 core_sync/grm/DDS/uxengine；`grm_init` 排在 DDS/uxengine 之前，而不是最后。
4. 五代 `libObj.so` / `libMWF.so` 才是这些入口的实现者：`infra_input_init`、`grm_init`、`DDSUserInit`、`uxengine_init`、`uxengine_init2`、`dmp_allocator_*`、`WidgetLayouter::sys_initialize` 全在 **libObj**；`MWF_Init` 在 **libMWF**。`core_sync_user_init`、`GpeInit` **在两代 libObj 中都没有导出**，原厂 im.elf 对它们的 dlsym 会失败并被忽略（不作为独立 .so 文件存在于 ZV-1M2 / a6600 根镜像）。
5. `dmp_allocator_lib_init` / `dmp_allocator_mmap_init` **不在原厂模块表中**：`mmap_init` 在本次扫描中仅见 libObj 内部一个懒初始化单例调用（`sub_12f030`，pthread mutex + 计数）；`lib_init` 在 gen4/gen5 libObj、gen5 appFw/libmpr/libMWF 中都没有任何调用点或数据指针引用——属于**导出但未见使用的死入口**。
6. 因此，对桥接实验“更接近原厂”的建议是：
   - 在外部按序调用：`MWF_Init` → `infra_input_init` → `grm_init` → `DDSUserInit` → `uxengine_init`（`sys_initialize` 若要保留，放到 appFwBoot 之后由宿主驱动阶段，而不是放在 appFwBoot 之前）；
   - **不要外部调用** `uxengine_init2`、`initializeArena`、`sys_setCurrentDirectory`、AreaCheck 路径、overflow 属性、`setDatabase`、`setFontNameWithNamespace`——这些 AppFw 线程自己会做；
   - `dmp_allocator_lib_init` / `dmp_allocator_mmap_init`、`core_sync_user_init`、`GpeInit` 可以从预启动序列里删除；
   - 确保 `/usr/lib/appFw.so` 在 guest 中解析到**五代** appFw（appFwBoot 内部 dlopen 的是字面量 `"appFw.so"`；当前镜像里五代库改名为 `a5pFw.so`，需要软链/副本，或把该字符串等长改成 `"a5pFw.so"`）。

---

## 1. 对象、方法与证据

| 项 | 值 |
|---|---|
| 输入 | `05-原始固件/zv1m2_fw/gen5/appFwBoot.so`，8,312 B |
| SHA-256 | `187b335c5d59ebb581ef24eee2b8a92bdfce1af61ce7298e8466e645a6cdbe5e` |
| ELF | 32-bit ARM（EM_ARM=40），ET_DYN，e_entry=`0x11f4`，Thumb |
| 段 | `.text` `0x11f4`/0x504 B；`.PLT` 33 桩；`.rodata` 345 B；`.data.rel.ro` 60 B；`.init_array` 8 B |
| DT_NEEDED | libpthread.so.0, libstdc++.so.6, libm.so.6, libdl.so.2, libgcc_s.so.1, libc.so.6, librt.so.1（**不含** libObj/libosal——靠全局符号解析） |
| 导出 | `Application_System_Init`(0x1271,284)、`Main`(0x14d9,120)、`initializeArena`(0x138d,332) + 13 个 stella::BitArray 模板弱符号 |
| 工具 | Python 3.13 + pyelftools 0.33 + capstone 5.0.7（Windows 直跑，无 WSL 依赖） |

证据文件（全部在 `03-证据/静态分析/boot5/`）：

| 文件 | 内容 |
|---|---|
| `sections.txt` / `program_headers.txt` / `dynamic.txt` | ELF 段、动态表、DT_NEEDED |
| `dynsym.txt` / `relocs.txt` / `strings.txt` | 动态符号、重定位（GOT 槽→符号）、字符串 |
| `disasm_text.txt` | appFwBoot 全 `.text` 带符号注释反汇编（22 个函数） |
| `plt_map.txt` / `imports_used.txt` / `callgraph.json` | PLT→导入符号、每个函数用到的导入、逐函数调用/字面量 |
| `call_sequence.txt` | `Application_System_Init`/`Main`/`initializeArena` 按地址的调用序列 |
| `data_relro.txt` | `.init_array`/`.data.rel.ro`/`.got`/`.data` 指针内容（含 `mpMemoryHeap*`） |
| `libs_scan.json` | 四/五代 10 个库的 DT_NEEDED、目标初始化符号的定义/导入、字符串命中（另有 1 个候选路径缺失已跳过） |
| `libobj_probe_gen4.txt/.json`、`libobj_probe_gen5.txt/.json` | 两代 libObj 目标函数反汇编、init_array、PLT、调用点扫描 |
| `libobj_initcallers_gen5.txt` | libObj 内部对初始化入口的调用点上下文（含 PLT 间接） |
| `providers.txt/.json` | appFwBoot 36 个未定义导入的提供者闭包；IMDB 入口的定义者 |
| `imdb_gen5.txt/.json`、`imdb_gen4.txt/.json` | 原厂 44 字节模块表完整解码（227 条 / 197 条），含 type/psid/flag/file/init/exit/sus/res/inact/act |
| `imelf_info.txt` / `imelf_disasm.txt` / `imelf_focus.txt` / `imelf_strings.txt` | 五代原厂 `/bin/im.elf`（23,240 B）事实与反汇编，含 IMDB 遍历/加载语义 |
| `image/` | 从 ZV-1M2 ext2 根镜像只读提取的 `im.elf`/`libMWF.so`/`libosal_*` 等（见 `image/extract_manifest.json`） |
| `appstart_mwf_disasm.txt` | 五代 appFw.so `Application_Start`（72 B）与五代 libMWF `MWF_Init`（12 B）反汇编 |

脚本（`02-脚本/appfwboot_*.py`）：`elfinfo`（ELF 元数据）、`disasm`（反汇编+调用图）、`seq`（调用序列）、
`libs_scan`（库扫描）、`libobj_probe`/`initcallers`（libObj 深化）、`imdb_table`（模块表解码）、
`imelf`（原厂 im.elf 分析）、`extract`（根镜像只读提取）、`providers`（依赖闭包）、`appstart`（appFw/MWF 入口）。

---

## 2. `Application_System_Init` 反汇编走读（VA 0x1271，284 B）

关键字符串（`.rodata`）：`AC %p`(0x16fe)、`%4X %s %s`(0x1704)、`"B "`(0x170e)、`AppConfig.so`(0x1711)、
`appFw.so`(0x171e)、`Application_Start`(0x1727)、`AdjChkConfig.so`(0x1739)、`_ZN13app_adjchk_ui9main_loopEv`(0x1749)、
`AppFw`(0x1768)、`/usr/share/app/`(0x176e)、`/usr/share/app/area_check_data.dat`(0x177e)、
`/tmp/area_check_log.dat`(0x17a1)、`global.xdb`(0x17b9)。

按地址顺序（完整反汇编见 `disasm_text.txt`）：

| 站点 | 动作 |
|---|---|
| 0x1282 | `memset(frame, 0, 0x20)` 清 32 B 线程参数区 |
| 0x1294 | `snprintf(buf,0x20,"AC %p", &Application_System_Init)`（GOT 自指针，供日志） |
| 0x12a8 | `osal_valloc_msg_wait(0x8f013a, &msg, 0x34, 1)` 申请 osal 消息 |
| 0x12cc | `snprintf(msg+2,0x32,"%4X %s %s", 0x83, "B ", buf)`；`msg[0..1]=9`；`msg[0x33]=0` |
| 0x12d8 | `osal_snd_sync_msg(0x8f013a, msg)`；`osal_free_msg(0x8f013a, msg)`（队列 0x8f013a = im.elf 的 APP 日志队列） |
| 0x12e4–0x12f0 | 若 `config!=NULL`：`strcmp("AppConfig.so", config)` |
| 0x12fe/0x1310 | `dlopen("appFw.so", 0x101)` 或 `dlopen("AdjChkConfig.so", 0x101)`（0x101=RTLD_LAZY\|RTLD_GLOBAL） |
| 0x1318 | `dlsym(h, "Application_Start")` 或 `dlsym(h, "_ZN13app_adjchk_ui9main_loopEv")` |
| 0x131c–0x133e | 填线程参数结构：`+0x00 "AppFw"`、`+0x04 4`、`+0x08 &Main`、`+0x0c dlsym 结果`、`+0x10 0x1cf`(u16)、`+0x14 1`、`+0x18 0`、`+0x1c 0` |
| 0x1344 | `osal_create_waitable_thread(&param)`（线程体 = `Main`） |
| 0x134a | `osal_set_cpu(thread, 0xf)` |
| 0x1354 | `pop {r4,…,pc}` 返回 |

分支语义（两条互斥路径，均由 `config` 决定）：

- `config == NULL || config == "AppConfig.so"` → 加载五代 UI 主程序 `appFw.so`，入口 `Application_Start`（正常启动路径）；
- 其它（典型为 `"AdjChkConfig.so"`，表项 inact 模式）→ 加载调整检查 UI `AdjChkConfig.so`，入口 `app_adjchk_ui::main_loop`。

**该函数内部没有任何“迁移前初始化”调用**：`.PLT` 只用到 `memset/snprintf/osal_valloc_msg_wait/osal_snd_sync_msg/osal_free_msg/strcmp/dlopen/dlsym/osal_create_waitable_thread/osal_set_cpu`（见 `imports_used.txt`）。
它也不直接 `bl` 本文件内的任何业务函数——`Main`/`initializeArena` 是通过 osal 线程创建被**间接**调用的（线程回调），这是“反汇编 Application_System_Init 及其调用函数”时容易漏掉的一层。
其 `.init_array` 只有两个构造器：`frame_dummy`（`0x124c`）与一个把 `ux::core::ID::ZERO` 值拷进本地静态区的 C++ 静态构造（`0x16d4`，依赖 libObj 的 `_ZN2ux4core2ID4ZEROE`），均无初始化业务。
文件内其余函数是 `stella::BitArray` 模板弱符号（13 个 `isOn/set/clear/构造/析构`，内部用 `stella_print_log`+`raise` 做断言，初始化路径不引用）、CRT 的 `_init`/`_fini` 及上述两个构造器（完整清单见 `disasm_text.txt` / `exidx_functions.txt`）。

---

## 3. AppFw 线程体 `Main` 与 `initializeArena`

`Main`（`0x14d9`，120 B，`void Main(void *app_entry)`，r4=参数）：

| 顺序 | 站点 | 调用 | 说明 |
|---:|---|---|---|
| 1 | 0x14de | `uxengine_init2()` | 五代 UX 引擎一次初始化（**不是** `uxengine_init`；后者在 libObj 里是 6 字节空实现） |
| 2 | 0x14e2 | `initializeArena()` | 向 `UXEngine::resmgr` 注册 3 个 libra arena |
| 3 | 0x14ea | `ux::core::Kernel::sys_setCurrentDirectory("/usr/share/app/")` | 资源根目录 |
| 4 | 0x14ee–0x14f2 | `UXEngine::gfxeng()` → `getAreaCheckExtensionManager()` | 取 AreaCheck 管理器（可为空则跳过 5/6） |
| 5 | 0x14fe | `AreaCheckExtensionManager::setCheckDataPath("/usr/share/app/area_check_data.dat")` | 区域检查数据 |
| 6 | 0x1508 | `AreaCheckExtensionManager::setLogPath("/tmp/area_check_log.dat")` | 区域检查日志 |
| 7 | 0x150c–0x1514 | `GraphicsEngine::sys_getInstance()` → `setOverflowResizeFontAttribute(0x1c,0x15)` | 溢出重排字体属性 |
| 8 | 0x1518–0x151e | `GraphicsEngine::sys_getInstance()` → `setOverflowResizeLayoutAttribute(0x22)` | 溢出重排布局属性 |
| 9 | 0x1522–0x152a | `UXEngine::resmgr()` → `ResourceManager::setDatabase("global.xdb")` | 资源数据库（`/usr/share/app/global.xdb`，ZV-1M2 根镜像中存在 16,112 B） |
| 10 | 0x152e–0x1534 | `UXEngine::resmgr()` → `sys_setFontNameWithNamespace(0x33)` | 默认字体命名空间 |
| 11 | 0x1538 | `if (app_entry) app_entry()` | 调用 `Application_Start`（五代 appFw.so @0x54d581，72 B，见 `appstart_mwf_disasm.txt`） |

`initializeArena`（`0x138d`，332 B）：从 `.data.rel.ro` 复制 3 个堆描述（`mpMemoryHeap`/`mpMemoryHeap2`/`mpTextHeap`，各 20 B：`{name, 0x40803/0x256/0x4087b, 1, 1, 0}`），构造 3 个 `libra::ArenaParam`：
- param#0：acceptableType=2、priority=0xfe、min=0xc800、max=0xffffffff → `resmgr().addArena(0, param#0)`；
- param#1：acceptableType=2、priority=0xff、min=0、max=0xc800 → `addArena(2, param#1)`；
- param#2：acceptableType=1 → `addArena(1, param#2)`。

---

## 4. 导入符号与依赖闭包（谁提供什么）

appFwBoot 共有 36 个未定义导入（见 `providers.txt`），其提供者：

| 提供者 | 提供的导入 |
|---|---|
| **libObj.so（五代）** | `uxengine_init2`、`UXEngine::gfxeng/resmgr`、`GraphicsEngine::sys_getInstance/getAreaCheckExtensionManager/setOverflowResize*`、`AreaCheckExtensionManager::setCheckDataPath/setLogPath`、`ResourceManager::setDatabase/sys_setFontNameWithNamespace/addArena`、`libra::ArenaParam` 全套、`ux::core::Kernel::sys_setCurrentDirectory`、`ux::core::ID::ZERO`、`stella_print_log` |
| **libosal_uipc.so** | `osal_valloc_msg_wait`、`osal_snd_sync_msg`、`osal_free_msg` |
| **libosal_utm.so** | `osal_create_waitable_thread`、`osal_set_cpu` |
| libc/libdl/libgcc/libstdc++ | `memset/dlopen/dlsym/strcmp/snprintf/raise`、arm unwinder 等 |

**关键依赖结论**：appFwBoot 的 `DT_NEEDED` 只有标准库，因此**在 dlopen(appFwBoot) 之前，五代 `libObj.so` + `libosal_uipc.so` + `libosal_utm.so` 必须已加载到全局作用域**（原厂由 im.elf 的模块表在前面阶段完成：osal 三库在表 idx20–22，libObj 在第一个“静态并入”条目 idx35 时被 `dlopen("/usr/lib/libObj.so")` 载入）。五代 libObj 的 `DT_NEEDED`（libsencore、libInfraMediaCommon、libInfraUsbCmn、libbackup、libutil_date 等）在 ZV-1M2 根镜像 `/lib` 中均存在。

---

## 5. 与“迁移前初始化”清单的对照

| 入口 | 定义者 | appFwBoot 内部是否做 | 原厂模块表位置（gen5） | 桥接结论 |
|---|---|---|---|---|
| `MWF_Init` | libMWF.so（`0x20b3d`，12 B，尾跳内部初始化） | **否** | idx32（PHASE3） | **必须外部调用**，且在 infra_input 之前 |
| `infra_input_init` | libObj（`0x208135`，44 B） | **否** | idx35（PHASE3） | **必须外部调用**，紧跟 MWF_Init |
| `core_sync_user_init` | 无（gen4/gen5 libObj 均不导出） | 否 | idx45（列在表里但 dlsym 必失败） | **不调用**（原厂也加载失败跳过） |
| `grm_init` | libObj（`0x116ae5`，368 B） | **否** | idx46（PHASE5 首位组） | **必须外部调用**，位于 infra_input 之后、DDS/uxengine 之前 |
| `GpeInit` | 无（libObj 不导出；libgpe.so 镜像中也不存在） | 否 | idx47（表内残留） | **不调用** |
| `DDSUserInit` | libObj（`0x3db3d`，16 B） | **否** | idx48 | **必须外部调用**，在 grm 之后 |
| `uxengine_init` | libObj（`0xe280d`，6 B **空实现**） | 否 | idx49 | 需外部调用（工厂确实调），放最后（DDS 之后） |
| `uxengine_init2` | libObj（`0xe2815`，216 B，真实 UX 初始化） | **是**（Main 第一步） | **不在表内**（appFwBoot 内部） | **不要外部调用** |
| `dmp_allocator_lib_init` | libObj（`0x11c28d`，1032 B） | 否 | 不在表内；**libObj 内无任何调用点/指针引用** | 建议从预启动序列删除（死导出） |
| `dmp_allocator_mmap_init` | libObj（`0x11c845`，12 B） | 否 | 不在表内；仅 libObj 内部懒初始化单例 `sub_12f030` 调用 | 不必外部调用 |
| `WidgetLayouter::sys_initialize` | libObj（`0xd51b5`，68 B） | 否 | **不在表内**；libObj 内无调用点；appFw/AdjChkConfig/MWF/mpr 均不引用该符号 | 无“原厂调用”证据；若要保留实验，应放到 appFwBoot 启动之后 |
| `Application_System_Init` | **appFwBoot.so** | 入口本体 | idx145（PHASE8） | 桥接入口 |

补充证据：四代 a6600 的同名入口 `libObj.so::Application_System_Init`（`0x8436fc`，144 B）与五代 appFwBoot 的 `Application_System_Init` 结构几乎一致（memset→`AC %p` 日志→按 config 选择 app/adjchk→创建 AppFw 线程），只是四代把 AppFw 线程体也放在 libObj 内；五代把线程体拆成了 appFwBoot 的 `Main`。这解释了为什么五代 appFwBoot 看起来“什么都没初始化”——初始化被移到了它自己创建的线程里。

---

## 6. 原厂正常启动的顺序证据

### 6.1 五代 `libIMDB.so`（40,596 B）的模块表

`libIMDB.so` 的 `.text` 只有 296 B（`IMDB_find_entry`/`IMDB_get_entries`/`IMDB_find_target_bit`）；真正的启动数据是 `.data.rel.ro` 里的 **44 字节条目表**（`imdb_raw` 头 132 B + 条目；本次解码 227 条，末条 type=0x28）。字段布局（由 `IMDB_find_entry` 反汇编 + 解码交叉确认）：

```
+0x00 u32 type   (0x20000001..04=LIB/APPLIB, 0x10000001/2=LIRO 模型映射, 0x40000001=SHELL, 0x0800000N=PHASE 分隔, 1..=MODE)
+0x04 u32 version
+0x08 u32 target  (加载目标位掩码)
+0x0c u16 psid/me ; +0x0e u16 flag(0x07fb/0x07fa = 该库已静态并入 libObj)
+0x10 file, +0x14 init, +0x18 exit, +0x1c sus, +0x20 res, +0x24 inact, +0x28 act  (字符串指针)
```

其中的 phase 分隔与本次相关条目（完整表见 `imdb_gen5.txt`）：

```
MODE×6 | PHASE1 | dmm.ko, upm.ko | PHASE2 | stream/stream2/mcmn/ms/mmc/sata/msen/hdmi/cec.ko
PHASE3: libosal_uipc(20) libosal_utm(21) libosal_ulogio(22) ... libSysDef(31)
        libMWF.so::MWF_Init(32)  ← 关键
        libi2cuipc(33) libI2CRight(34)
        libInfraInput.so::infra_input_init(35)  ← 关键
        libInfraError(36) libJiritsu(37) libAtn(38) libGetLog(39) libread_refresh(40) libTestDriver(41)
PHASE4: /usr/kmod/liro.ko 模型映射(43)
PHASE5: libCoreSync.so::core_sync_user_init(45)
        libgrm.so::grm_init(46)   ← 关键
        libgpe.so::GpeInit(47)    libDDS.so::DDSUserInit(48)   libuxengine.so::uxengine_init(49)
        …50–138 其它 infra 服务…
PHASE6: libInfraMediaPwrMgr(140) libInfraCameraBackground(141)
PHASE7: libBizInitializer.so::BIZ_Init(143)
PHASE8: appFwBoot.so::Application_System_Init(145)   ← 应用入口
        subapp.so::subapp_init(146)  libVssApp.so::vssapp_init(147)  gui.so::DPro_App_UI_init(148)
PHASE9: …libJetControl / USB / 测试模式库(150+)…
```

说明：`libCoreSync.so`、`libgrm.so`、`libDDS.so`、`libuxengine.so`、`libInfraInput.so` 等条目的 flag=0x07fb/0x07fa，表示**已静态并入 libObj.so**，原厂加载器会改为 `dlopen("/usr/lib/libObj.so")` 再从 libObj 里 dlsym 这些名字；镜像里因此没有这些 .so 文件。`core_sync_user_init`/`GpeInit` 在 libObj 中未导出，dlsym 失败后原厂加载器记录错误并继续（不中断启动）。

口径说明：本次完整解码 gen5 得 227 条（其中**带 init 函数名的 184 条**）、gen4 得 197 条（**带 init 的 155 条**）；早期文档 08/97 里提到的 185/156 条应相当于“带 init 的条目”口径（差 1 条来自表头/空壳条目统计方式）。四代 a6600 表的 PHASE 标记是数值型（type=2,3,4,5,6,7,8），五代改为 0x0800000N；两侧相对顺序一致。

四代 a6600 表（197 条，`imdb_gen4.txt`）顺序一致且少了 libgpe：
`MWF_Init`(29) → `infra_input_init`(31) → `core_sync_user_init`(39) → `grm_init`(40) → `DDSUserInit`(41) → `uxengine_init`(42) → … → `appFw.so::Application_System_Init`(123，flag=0x07fb 静态并入 libObj)。

### 6.2 五代 `im.elf`（/bin/im.elf，23,240 B）如何执行这张表

- `DT_NEEDED`：`libIMDB.so, libosal_utm.so, libosal_uipc.so, libSTMcmdexecute.so, libjemalloc_ds, libbackup, libssl/libcrypto…`；导入 `IMDB_get_entries / IMDB_find_entry / IMDB_find_target_bit`。
- 表遍历 `sub_b9c8`：`IMDB_get_entries()` 取表基址，按 `0x2c` 步进；用 `entry+4 & mask(0xff)`、`entry+8 & ctx.target` 过滤；对命中条目调 `sub_b8bc(psid, mode=3, …)` 完成加载。
- 类型分派 `sub_b7b8`：
  - `0x10000001/2` → LIRO 模型映射：`open/mmap` 后 `syscall(0x80, addr, size, …)` 把模型文件交给内核（`sub_b658`），用于 av-cam/传感器等模型；
  - `0x20000001..3`（LIB）→ `sub_b5c0`：`dlopen(entry.file 或 "/usr/lib/libObj.so", ctx.dlopen_flags)` → `dlsym(entry.init)` → **无参调用**；
  - `0x20000004`（APPLIB）→ `sub_b4f8`：`dlopen(entry.file, flags)` → `dlsym(entry.init)` → **带一个参数调用**：参数 = `entry.act`（如 `"AppConfig.so"`）或 `entry.inact`（如 `"AdjChkConfig.so"`），由 ctx 标志位 0x8000 选择；这正好解释了 appFwBoot 接收的 `config` 来源；
  - `0x40000001` → shell 命令：组 `"%s %s &"` 消息投递给队列 `0x0094020a`；
  - 其他（type 3）→ `putenv(entry.file)`。
- 线程与阶段：`i_thread`（INFRA 线程）先 `sub_b9c8(0, PHASE5, 0)` 找到 PHASE5 下标（44），再用 `PHASE7` 为终点加载 **45–141**（即 core 组 + 全部 infra 服务，按表顺序）；`a_thread`（APP 线程）找到 PHASE8 下标 144 后，以 PHASE9 为终点加载 **145–148**（appFwBoot → subapp → libVssApp → gui.so）。其它 PHASE 由外部 STM 命令（`sub_9cd8`，命令字 0x940031..0x940037）逐段触发。

结论：**原厂顺序 = 模块表顺序**，且 `grm_init/DDSUserInit/uxengine_init` 都在 `i_thread` 上运行，`appFwBoot` 则在 `a_thread` 上、所有前置 init 完成后才被调用。桥接实验用自定义 preload/桥在 im.elf 的 Application 记录处接管，因此**必须自己复刻这份顺序**。

---

## 7. 对桥接实验的建议

### 7.1 当前顺序 vs 原厂顺序

当前（`04-产物/97_astra_bridge5.c` 及桥接文档）：
`dmp_allocator_lib_init → dmp_allocator_mmap_init → DDSUserInit → uxengine_init → WidgetLayouter::sys_initialize → infra_input_init → MWF_Init → grm_init → appFwBoot`

原厂（gen5 表）：
`MWF_Init → infra_input_init → [core_sync(实际不存在)] → grm_init → [GpeInit(实际不存在)] → DDSUserInit → uxengine_init → … → appFwBoot`

差异：MWF/InfraInput 应在最前而不是最后；grm 应在 DDS/uxengine **之前**；`dmp_allocator_*` 与 `sys_initialize` 不出现在原厂表里；`uxengine_init2/initializeArena` 等属于 appFwBoot 内部，不应由外部做。

### 7.2 建议的预启动序列（按原厂顺序，最小改动版）

1. 载入五代基础依赖（若还没有）：`libosal_uipc.so`、`libosal_utm.so`、`libosal_ulogio.so`、**`libObj.so`**，均 `RTLD_GLOBAL`；这一步完成后再 dlopen appFwBoot。libObj 自己的 107 个 `.init_array` 构造器由 dlopen 自动执行（其中没有任何“迁移前 init”入口，不必手工再跑）。
2. `MWF_Init`（`libMWF.so`）。
3. `infra_input_init`（libObj）。
4. `grm_init`（libObj）——按原厂位置紧随 infra_input；**不要放到整串最后**。
5. `DDSUserInit`（libObj）。
6. `uxengine_init`（libObj，空实现但原厂确实会调）。
7. `appFwBoot::Application_System_Init("AppConfig.so")`。

无需外部调用（删掉更接近原厂）：
`uxengine_init2`、`initializeArena`、`sys_setCurrentDirectory`、`setCheckDataPath/setLogPath`、`setOverflowResize*`、`setDatabase`、`setFontNameWithNamespace`（Main 内部固定顺序完成）；
`dmp_allocator_lib_init`、`dmp_allocator_mmap_init`（表中不存在；后者 libObj 内部懒初始化）；
`core_sync_user_init`、`GpeInit`（两代 libObj 均不导出，原厂 dlsym 失败后跳过）；
`WidgetLayouter::sys_initialize`（无任何原厂调用证据；若要实验，放到 appFwBoot 启动之后、宿主驱动渲染前，而不是预启动阶段）。

### 7.3 关于 `grm_init` 卡死

- gen4 与 gen5 的 `grm_init` 是同一份 368 B 代码（结构、常量、调试字符串一致；仅链接地址不同），原厂 a6600 能正常运行，说明**代码本身无死锁**，卡死更可能来自运行环境/前置状态。
- 原厂中 `grm_init` 运行在 INFRA 线程、位于 PHASE4 的 `/usr/kmod/liro.ko` 模型映射之后、`DDSUserInit/uxengine_init` 之前；它会做 GRM/GPU 资源初始化（内部调用集中在 libObj 0x115xxx–0x119xxx 的 GRM 段，含 `uiresp_init`、`GRM_*` 与 debug 文件/日志操作）。
- 当前桥接把它放到最后，且前面执行了 `dmp_allocator_*`、`WidgetLayouter::sys_initialize` 等非原厂调用；ASTRA 混合镜像里 4 代链可能已经初始化过同一套 GRM/GPU 内核资源，5 代 `grm_init` 再初始化存在阻塞/竞争风险。
- 建议顺序：先按 7.2 重排再测；若仍卡死，再用“跳过 grm_init，只做其余初始化 → 观察 appFwBoot 是否可继续”做对照，或用独立 INFRA 线程 + 超时（v5 已做）把卡死与其它初始化解耦。grm 侧根因另有并行分析（`03-证据/静态分析/grm/`）。

### 7.4 名称与参数注意

- `config` 参数：原厂正常模式传表项 `act` 字段 = `"AppConfig.so"`；调整检查模式传 `inact` = `"AdjChkConfig.so"`。桥接只需在后者做 `a5jChkConfig.so` 改名；前者应原样传 `"AppConfig.so"`。
- **appFwBoot 内部会 `dlopen("appFw.so")` 并 `dlsym("Application_Start")`**。在 ASTRA 镜像里五代 appFw 已被改名 `a5pFw.so`，必须保证 guest 的 `/usr/lib/appFw.so` 解析到**五代**库（建软链/同名副本，或把该 8 字符字符串等长改成 `"a5pFw.so"`）；否则会拉起四代 appFw，出现“初始化成功但 UI/模型不对”的假象。
- appFwBoot 创建线程名为 `"AppFw"`，并向 osal 队列 `0x8f013a` 发 `cmd=9` 日志；若 osal 队列/线程 API 不可用，会在这两处失败（不是 init 顺序问题）。

---

## 8. 局限与下一步

1. 本文全部为静态分析，未做运行期验证；`Application_System_Init` 的内部分支（app vs adjchk）按两条互斥路径给出，实际走哪条由 guest 的 config 决定。
2. `im.elf` 的线程/阶段调度结论来自反汇编与表结构（PHASE 分隔、`i_thread`/`a_thread` 的 `sub_b9c8` 起止下标），属于“静态可证但未运行验证”的推断。
3. `grm_init` 的阻塞根因未在本报告内证明（它与 GRM 内核驱动/GPU 初始化相关，且原厂顺序中前置状态不同）；建议与 `03-证据/静态分析/grm/` 的并行结论合看。
4. `dmp_allocator_lib_init` 在 gen5 闭包中“无调用者”的结论基于：两代 libObj 的 PLT 感知 BL 扫描（6 万函数）、数据指针扫描、以及 6 个五代库的字符串/导入扫描；若存在运行期 dlsym 的未知宿主（不在镜像闭包内），则为潜在例外。
5. 下一步建议：按 7.2 顺序重跑桥接；在 `grm_init` 前后打点记录返回值/阻塞点；确认 guest 内 `/usr/lib/appFw.so` 指向五代库；核对 `Application_Start` 是否被调用（可在五代 appFw 0x54d581 下断点/陷阱）。
