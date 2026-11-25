# 105 · 五代 libObj `grm_init` 在 QEMU 中不返回的阻塞分析

日期：2026-11-22
范围：ZV-1M2 五代固件 `/usr` 镜像中的 `/lib/libObj.so`（5 代 ASTRA libObj）
性质：**只读离线静态分析 + 既有 QEMU 运行日志复核**。本轮未运行 QEMU、未修改任何镜像/现有脚本/现有文档。

---

## 0. 结论（先看这里）

| 项 | 结论 |
|---|---|
| `grm_init` 地址 | **0x116AE5** 符号值（Thumb 位 bit0，函数起点 **0x116AE4**），size 368，下一函数边界 0x116C54 |
| 观察到的停点 | bridge4 日志停在 `[ASTRA97] init grm_init = 0x29d4aae5` 之后，仅打印 `!!! GLES Vecgen disabled.`，**没有** `===== DMP_2D_Initialize : %d`，也没有 `returned` |
| 静态上卡住的窗口 | `grm_init` 内 **0x116B6E ~ 0x116B7A**：`sub_116AA8(0x4000)`（位测试，不阻塞）→ **`sub_115078`**（GRM/DMP 子系统初始化）→ **`sub_1823D0 = DMP_2D_Initialize`** |
| 最可能的阻塞点 | **DMP_2D_Initialize（0x1823D0 → 0x1819B0）的 2D worker 同步握手**：函数创建 worker 线程后，在 **0x181A7C（另一处 0x181AD0）`pthread_cond_wait` 无超时等待 worker 完成初始化**；worker 的命令 1 处理链最终执行 **`rm_reg_init`（0x12C670，GPE/sugilite 硬件初始化）**，该链未完成 → 主调用线程永不返回 |
| 次可能 | `sub_115078` 的 GRM/DMP 子系统初始化（深层含 `osal_valloc_msg_wait(0x8F013A/0x8F0313)`、`osal_snd_sync_direct(0x910042)`；均在 GRM/DMP 依赖环境中才可靠） |
| 关键反证 | 同一份 `libObj.so`、同一批 QEMU 实验里，**只要把 `grm_init` 放到 DDSUserInit/uxengine_init/WidgetLayouter/infra_input_init/MWF_Init 之后调用（bridge5 顺序），它就会返回**：`GPE HW: PSC dummywrite disabled.`、`===== DMP_2D_Initialize : 0`、`init grm_init returned -1` 三行齐全；`-1` 是末尾 0x4000 就绪位测试的返回值，不是阻塞 |
| “缺哪个模块” | **不是缺 `libgpe.so`/`libDDS.so`/`libgrm.so`**（`libObj.so` 的 NEEDED 里没有这些，GPE/DDS/GRM 全部静态编在 libObj 内）。真正相关外部依赖：`/dev/dmpgles2`（`grm_gles.ko` 的 sugilite 设备）、`grm_ma.ko`（`/proc/modules` 检查，缺失会 abort）、OSAL/UIPC 队列（`0x8F013A/0x8F0313`）、utimer（`0x910042`），以及**五代 DDS/uxengine/MWF 的初始化前置**（bridge4 跳过它们直接调 grm_init） |
| 建议方案 | ①优先复刻 bridge5 的调用顺序（已实测返回）；②若必须保留 bridge4 顺序，把 `DMP_2D_Initialize` 包装函数 0x1823D0 改为 `movs r0,#0; bx lr`（文件偏移 0x1823D0 写 `00 20 70 47`），可让 grm_init 越过该点继续；③仍不行则在 0x116B76 把 `sub_115078` 调用改为返回 0；④要“直接返回”可在 grm_init 入口写 `00 20 70 47`。详见 §6 |

---

## 1. 样本、工具与方法

### 1.1 样本

| 项 | 值 |
|---|---|
| /usr 镜像 | `05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15`（530,345,984 B，ext2） |
| 提取出的 libObj | `03-证据/静态分析/grm/lib/libObj.so`，3,931,624 B |
| SHA-256 | `4cd654f1a8bc1aed40b6a4c87732263f6df960440d622574224ed687840aa77f` |
| ELF | ELF32 little-endian ARM EABI，`SONAME libObj.so`；`.text` 0x3D080/0x229DC8，`.plt` 0x3A45C/0x2C18，`.rodata` 0x266E50/0x8BF72 |
| 同镜像依赖模块（已一并提取作证据） | `/kmod/grm_gles.ko`（15,648 B）、`/kmod/grm_ma.ko`（24,800 B）、`osal_uipc.ko`、`osal_ulogio.ko`、`osal_utm.ko` |
| NEEDED | libutil_date.so、dataflowInfraFramework.so、libcompassutil.so、libInfraUsbCmn.so、libsencore.so、libNetContUtil.so、libUsbControl.so、libBackupManager.so、libInfraMediaCommon.so、libbackup.so、libgcc_s.so.1、libc.so.6 |

提取方式：复用 `02-脚本/a6600_usr.py` 的 `Ext2` 类，脚本 `02-脚本/grm_extract_libobj.py` 只读镜像并写 `03-证据/静态分析/grm/`。

### 1.2 方法

1. **ELF 结构**（pyelftools）：`.dynsym`/`.rel.plt`/`.plt` 映射；该 so 无 `.symtab`，用 **`.ARM.exidx`（17,605 条）** 还原内部函数边界（全部 Thumb：dynsym 中已定义 FUNC 的 bit0 全为 1；17,605 个起点中 11,430 个以 16-bit `push` 开头、6,005 个首字高位非 E/F、余 170 个按 Thumb 解码同为合法 `push`）。
2. **反汇编**（capstone Thumb-2）：解析 PIC 字符串（`ldr rX,[pc,#imm]` + `add rX,pc`，PC=指令地址+4，实测校准于 `0x116B3A → 0x29CB74 "!!! GLES Vecgen enabled.\n"`）、PLT 槽（含 Thumb↔ARM interworking 的 `bx pc` 桩）。
3. **调用图 BFS**：从 0x116AE4 起深度 6（116 个函数）；再对 0x115078 深度 16；并对全库 17,805 函数做“字符串引用 + 直接调用图 + `rm_reg_init` 可达性”扫描（`grm_xref.py`）。
4. **运行日志复核**：`03-证据/ASTRA-97/` 中 bridge4 卡住 run 与 bridge5 成功 run 的串口日志逐行对照（`grm_runtime_evidence.py` 生成摘录）。

---

## 2. `grm_init` 静态结构

### 2.1 地址与边界

- 符号：`grm_init`，`st_value = 0x116AE5`（bit0=1 表示 Thumb），实际代码起点 **0x116AE4**。
- 函数范围：`0x116AE4 – 0x116C54`（`.ARM.exidx` 下一函数起点），共 **368 B / 149 条指令**。
- 文件偏移：该 so 的 `.text`、`.plt`、`.rodata` 的 VMA 与文件偏移相同，`.text` 内地址可直接当文件偏移。

### 2.2 反汇编要点（完整见 `grm_init_disasm.txt`）

```
0x116AE4  查“已初始化/状态”全局（.bss 0x3C8330 附近），非 0 直接返回该值
0x116AFA  stat("/tmp/tv_gpe")     → 失败则 [r7+0x5C]=1
0x116B12  stat("/tmp/tv_log")     → 失败则日志文件名="/tmp/phi_ocp.txt"（默认 "/dev/null"）
0x116B24  stat("/tmp/tv_enable")  → r5=返回值
0x116B34  cbnz r0, 0x116B64       ; tv_enable 不存在 → disabled 分支
0x116B36…  enabled 分支：fputs("!!! GLES Vecgen enabled.")、fprintf(filename/hwctrl)，
           bl 0x156AC0（GPU mlock/hwctrl 路径）
0x116B64  fputs("!!! GLES Vecgen disabled.\n")     ← QEMU 实际走这里（/tmp/tv_enable 不存在）
0x116B6E  mov.w r0,#0x4000 ; bl sub_116AA8          ; 全局半字位测试，返回 0/-1，不阻塞
0x116B76  bl sub_115078                              ; GRM/DMP 子系统初始化
0x116B7A  bl sub_1823D0（= DMP_2D_Initialize）       ; ← 最可能阻塞处
0x116B7E  fprintf(fp,"===== DMP_2D_Initialize : %d\n", r0)  ; ← 运行日志缺这一行
0x116B8A  blx uiresp_init@plt
0x116B98  operator new(0x70) + ctor 0x115728
0x116BB4  bl sub_115824(global, 0) ; 若返回 0 → 直接收尾；
          否则：0x11902C/0x119064/0x115168/0x11519C/0x1169B4/0x117408/
                0x115884/0x11743C(FBResourceManager::initialize)/0x1158B8/
                0x115924/0x115824(global,1)/sub_116AA8(0x4000) 后返回
```

关键字符串（`.rodata`）：`/dev/null`(0x29CB32)、`/tmp/tv_gpe`(0x29CB3C)、`/tmp/tv_log`(0x29CB48)、`/tmp/phi_ocp.txt`(0x29CB54)、`/tmp/tv_enable`(0x29CB65)、`!!! GLES Vecgen enabled.`(0x29CB74)、`!!!   filename: %s`(0x29CB8E)、`!!!   hwctrl  : %d`(0x29CBA2)、`!!! GLES Vecgen disabled.`(0x29CBB6)、**`===== DMP_2D_Initialize : %d`(0x29CBD1)**、`grm`(0x29CBEF)、`EXEC_AUDIO_MULTI_SG`(0x2B179C)。

> 注意：QEMU 中 `/tmp/tv_enable` 不存在，走 disabled 分支，因此 0x156AC0 及其下游
> `ioctl 0xC0048211/0xC0048212`（grm mlock gain/release，0x12D400/0x12D470）**根本没有被执行**，
> 不是本次 hang 的原因。

### 2.3 根函数直接调用（前 3 层）

```
grm_init 0x116AE4
├─ sub_116AA8(0x4000)                      ; 位测试
├─ 0x156AC0（仅 enabled 分支；QEMU 未走）→ 0x12C0F0 → 0x12EDD0 → ioctl 0xC0048211/0xC0048212
├─ sub_115078                              ; ★ 嫌疑2：GRM/DMP 子系统初始化
│   ├─ 0x135770 → 0x12F010/0x12F120/0x134150/0x189520/0x12F130
│   ├─ 0x1357E0
│   ├─ 0x139800 / 0x139680 / 0x137F50 / 0x138610
│   └─ 深层：0x138610 → 0x12F090 → 0x11C694 → 0x12AEAC → 0x12A2E0
│            → 0x129480 → 0x1293A4 → osal_valloc_msg_wait(0x8F013A / 0x8F0313)
│                                      → osal_snd_sync_direct(0x910042)
├─ sub_1823D0 = DMP_2D_Initialize           ; ★ 嫌疑1（详见 §3）
│   └─ 0x1819B0：创建 2 个 2D worker 线程 + pthread_cond_wait 无超时
└─ 打印 "===== DMP_2D_Initialize : %d"
```

---

## 3. 最可能阻塞点：DMP_2D_Initialize 的 worker 同步

### 3.1 结构

- `0x1823D0` 只是包装：取全局对象指针后 `b.w 0x1819B0`（`DMP_2D_Terminate` 是相邻的 0x1823E0 → 0x181DE0）。
- `0x1819B0`（338 条指令）大意：
  1. `sub_181950` 构造命令请求（命令号 **1**）；
  2. `sub_181400` **两次**创建“2D 命令 worker 线程”（`pthread_attr_setstacksize(0x40000)`、detach、入口 **0x181890**）；
  3. `pthread_key_create`；
  4. 取全局队列（struct 0x3CEF28）加锁，`sub_1814C0` 入队命令，`pthread_cond_signal`；
  5. **`pthread_cond_wait`（0x181A7C，等待条件 0x3CEF28+0x68；另一处 0x181AD0）——无超时**；
  6. 完成后置状态、解锁、返回 0。
- worker 0x181890：等自己队列（`pthread_cond_wait` 0x181922，空闲时正常），取到任务后按状态调用 handler：**0x1813A0 / 0x1814F0**；对“命令完成(0x8001)”类任务，在调用 handler 后 `pthread_cond_signal` 0x3CEF28+0x68，主线程才会醒来。
- handler 0x1814F0（325 条指令）：按 `cmd-1 ≤ 5` 的 TBH 跳转表分发（cmd 1..6）；cmd 1（初始化）→ `sub_182A10` 等。

### 3.2 命令 1 的执行链（到 GPE 硬件初始化）

`grm_xref.py` 全库扫描得到的**直接调用链**：

```
0x1814F0 (DMP2D handler)
  → 0x182A10
    → 0x1849B0（初始化 DMP/图形上下文，调用 0x135770/0x1357E0/0x1376B0/0x139800…）
      → 0x1376B0
        → 0x13C740
          → 0x13D3F0
            → 0x12BE70
              → rm_reg_init 0x12C670   ← GPE/sugilite 硬件初始化
              → rm_rqueue_init
              → rm_kick_thread_init
```

`rm_reg_init`（0x12C670，`rm_reg_init@@Base`，752 B）实际动作：

| 步骤 | 证据 |
|---|---|
| `open("/dev/dmpgles2", O_RDWR)` | 字符串 0x2A1DA8；open@plt |
| `ioctl(0x80048263, …)` 取 GPE 寄存器物理地址/大小 | 0x12C81C~0x12C832（movw #0x8263/movt #0x8004） |
| `open("/dev/mem")` + `mmap` 到 GPE BAR | 字符串 `/dev/mem`；`mmap@plt`；失败打印 `mmap to register area with /dev/mem failed` |
| `dmp_allocator_get_physical_base / get_logical_base` | 0x11CA24 / 0x11CA98（内部断言 `e == MA_ErrNone`） |
| 打印 **`!!! GPE HW: PSC dummywrite %s.`**（enabled/disabled） | 0x12C84A；字符串 0x2A1E64 |
| 打印 `GPE HW: dummywrite buf …` | 0x12C8DC；字符串 0x2A1E84 |
| 之后 0x12BE70 再做 `rm_rqueue_init`、`rm_kick_thread_init`（创建 `grm_gpe`/`grm_result` 类线程） | 0x12BE70 的 PLT 导入 |

### 3.3 为什么判断卡在这里

1. **运行时缺口**：bridge4 运行日志里，`!!! GLES Vecgen disabled.` 出现后，**五代自己的那条 `===== DMP_2D_Initialize` 行从未出现**（全日志只有 1 次 DMP 行，属四代 stock，在 1.26 s）；而成功 run 中该行在第二组三行日志里出现。
2. **唯一无超时等待**：在 0x116B64 打印之后、0x116B7E 打印之前的全部调用中，静态可见的**无超时**等待只有 DMP2D 的 `pthread_cond_wait`（0x181A7C / 0x181AD0）。`sub_116AA8` 是纯位测试；`sub_115078` 深层只有 `osal_valloc_msg_wait`（若消息池不枯竭会返回）和 `osal_snd_sync_direct(0x910042)`（utimer 时间戳，四代运行证明该通道在 QEMU 可用）。
3. **成功 run 的对照**：bridge5 在 DDSUserInit/uxengine_init/WidgetLayouter/infra_input_init/MWF_Init 之后调用 grm_init，其中 **`GPE HW: PSC dummywrite disabled.` 先于 `DMP_2D_Initialize : 0` 出现**，说明 `rm_reg_init` 就在 DMP2D 命令 1 链内、并成功完成；换言之：**同一段代码在依赖就绪时能跑通**。
4. **证据强度**：静态只能证明“DMP2D 主线程在无条件 cond_wait”；worker 侧是否卡在 `rm_reg_init` 的 open/ioctl/mmap、还是更早的 0x182A10/0x1849B0 链，需要运行期陷阱区分（见 §7）。日志里没有 `failed to open sugilite device`/`mmap … failed` 等错误行，但这类日志不一定带换行/被缓冲，不能单独据此排除。

> 结论置信度：**DMP_2D_Initialize 路径（P=高）**；具体到 rm_reg_init 的哪个系统调用（P=中）；`sub_115078` 为次要嫌疑（P=低-中）。

---

## 4. 运行时对照证据（摘自 `grm_runtime_evidence.txt`）

### 4.1 bridge4：卡住

`03-证据/ASTRA-97/m1-init4-20261121T202636Z-13268-1/serial.log`

```
10305  ... EMMC warning ...
10306  [ASTRA97] init grm_init = 0x29d4aae5
10307  !!! GLES Vecgen disabled.
10308  ... EMMC warning ...
（此后到日志末尾 10491 行：没有 DMP_2D_Initialize 第二行，没有 init grm_init returned）
```

- 全日志统计：`!!! GLES Vecgen` = 2 次（1.216 s 四代 stock + 2.838 s 五代），`===== DMP_2D_Initialize` = **1 次**（只有四代 stock 的 1.259 s）。
- 没有内核 abort/SIGSEGV/SIGABRT 记录，进程/系统继续响应 shell 探针 → 更像**无限等待**而非崩溃。

### 4.2 bridge5：返回

`03-证据/ASTRA-97/m1-init5-20261121T202852Z-13324-1/serial.log`

```
10525  [ASTRA97] init MWF_Init start
10560  [ASTRA97] init MWF_Init returned 4882632
10561  [ASTRA97] init grm_init start
10562  !!! GLES Vecgen disabled.
10589  !!! GPE HW: PSC dummywrite disabled.
10591  ===== DMP_2D_Initialize : 0
10592  [ASTRA97] init grm_init returned -1
```

- 初始化顺序（bridge5）：`dmp_allocator_lib_init` → `dmp_allocator_mmap_init` → **`DDSUserInit`** → **`uxengine_init`** → **`WidgetLayouter::sys_initialize`** → **`infra_input_init`** → **`MWF_Init`** → `grm_init`（每个都在独立 pthread 中调用，2.5 s 超时保护）。
- 同样的三行 + `returned -1` 在 `m1-init5-retrap`、`m1-init5-threads`、`m1-threads3` 中复现。
- `returned -1` 的语义：grm_init 末尾 `sub_116AA8(0x4000)` 检查“就绪位”，未置位返回 -1；**它已经正常返回**（不是超时，bridge5 超时会打印 `TIMEOUT`）。
- `m1-threads3` 成功 run 中的 grm 线程名（`/proc` 采样）：
  `grm_dn_vdf_if`（`osal_rcv_msg_tmo`）、`grm_result`（futex）、`grm_gpe`（futex）、`THREAD_INFRA0`（`sugilite_ioctl`）。

### 4.3 差异分析

| 因素 | bridge4（卡住） | bridge5（返回） |
|---|---|---|
| 调用顺序 | grm_init 紧跟 dmp_allocator 两个 init，**之前没有任何 DDS/uxengine/WidgetLayouter/MWF init** | grm_init 放在 DDSUserInit/uxengine_init/WidgetLayouter/infra_input_init/MWF_Init 之后 |
| 调用线程 | 4 代 IMDB 的 Application 线程内**直接调用** | 每次 init **新建独立 pthread**（run_init，带 2.5 s 超时） |
| 结果 | 停在 `GLES disabled` 后 | 完整打印 GPE HW + DMP_2D_Initialize:0 并返回 |

因此阻塞不是“静态缺一个 .so”，而是**五代图形/DMP 运行环境未建立**（最可能由 DDSUserInit/uxengine_init/MWF_Init 建立）时，DMP 2D worker 初始化链无法完成；也可能叠加“在 4 代 Application 线程上下文里直接调用”的线程/OSAL 状态问题。两者可在 QEMU 里用 §7 的 A/B 实验区分。

---

## 5. 依赖判定（需要什么，不需要什么）

### 5.1 需要的内核/驱动侧

| 依赖 | 证据 | 若不满足 |
|---|---|---|
| `/dev/dmpgles2`（`grm_gles.ko`，sugilite GPU） | `rm_reg_init` `open("/dev/dmpgles2")`；启动 0.366 s 有 `!!! GPE HW: bar remapped 0xf1000000->0xf1000000 size 4000`（模块加载时映射 BAR） | open 失败时打印 `failed to open sugilite device` 并返回错误（不 hang）；若驱动 open/ioctl 内部等待则可能 hang |
| `grm_gles.ko` ioctls：`0x80048263`（PSC dummywrite/寄存器信息）、`0xC004820D`（等 sugilite 信号）、`0xC004820E`（发信号）、`0xC0048203`（GPU 事件等待） | 0x12C670 / 0x12D340 / 0x12D3A0；公开参考（a5000 五代同族）把 0x63 记为 PSC dummywrite 开关、0x820D/0x820E 记为跨进程 kick 等待/唤醒 | ioctl 返回错误通常走错误分支；若语义不符可能死等（例如 0x820D 等待一个永不到来的 0x820E） |
| `grm_ma.ko` | 0x12ACE4 `fopen("/proc/modules")`+`strstr("grm_ma ")`，找不到直接 `abort()`（FBResourceManager 路径，DMP 打印之后） | 进程 SIGABRT（不是 hang） |
| OSAL/UIPC 与 utimer | `osal_valloc_msg_wait(0x8F013A/0x8F0313)`、`osal_snd_sync_direct(0x910042)`；公开参考：0x8F013A 由 `osal_ulogio.ko` 服务、0x910042 由 utimer 服务 | 消息池/服务未就绪时可能等待；队列无消费者时同步消息不返回 |
| `/dev/mem` | 0x119F30 `BitmapBase::initialize` open `/dev/mem`，失败 `__assert_fail` | abort（不是 hang） |

### 5.2 需要的用户态前置（重点）

- `DDSUserInit`（libObj 导出，0x3DB3D，实际初始化 DDS 用户层）；
- `uxengine_init`（0xE280D，空桩；真正的 `uxengine_init2` 在 0xE2814）；
- `WidgetLayouter::sys_initialize`（`_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv`）；
- `infra_input_init`（0x208135，建立五代 InfraInput 单例）；
- `MWF_Init`（在 `a5bMWF.so`，bridge5 从该库 dlsym）。

### 5.3 不需要 / 不存在的

- **不存在单独的 `libgpe.so`、`libgrm.so`、`libDDS.so` 依赖**：libObj 的 NEEDED 列表（§1.1）中没有；GPE（`rm_reg_init`/`rm_rqueue`/`rm_kick`）、DMP2D、DDS、GRM 均静态编进 libObj。
- `grm_gles.ko`/`grm_ma.ko` 在镜像里存在（`/kmod/`），且启动早期已有 grm_gles 模块的 BAR remap 日志；因此“模块文件缺失”不是根因，关键是**加载/初始化次序与运行环境**。
- `/tmp/tv_enable`、`/tmp/tv_gpe`、`/tmp/tv_log` 在 QEMU 中不存在 → enabled/hwctrl 分支被跳过，mlock ioctl 不参与本次 hang。

---

## 6. 绕过 / Stub 建议（按侵入性从小到大）

> 所有补丁仅用于**离线诊断镜像**，不要写回真机/原厂镜像。文件偏移 = VA（`.text`），改完需重算/绕过镜像校验，由 QEMU 实验侧负责。
>
> 已提供补丁生成器 `02-脚本/grm_patch_libobj.py`，运行后在 `03-证据/静态分析/grm/patched/` 生成
> `libObj.B_no_dmp2d.so`、`libObj.B2_skip_dmp2d_call.so`、`libObj.BC_no_dmp2d_no_115078.so`、
> `libObj.D_skip_grm_init.so` 四个变体及 `patch_manifest.json`（原镜像未被修改）。

### 方案 A（推荐，零代码改动）：复刻 bridge5 的调用顺序/上下文

在 `Application_System_Init` 里按以下顺序、且**每个 init 在独立 pthread 中**调用（bridge5 已验证）：

```
dmp_allocator_lib_init
dmp_allocator_mmap_init
DDSUserInit
uxengine_init
_ZN2ux6wgtlay14WidgetLayouter14sys_initializeEv
infra_input_init
MWF_Init               (a5bMWF.so)
grm_init               ← 此时返回 -1（正常返回，非超时）
```

预期日志：`GLES Vecgen disabled` → `GPE HW: PSC dummywrite disabled.` → `===== DMP_2D_Initialize : 0` → `init grm_init returned -1`。
若目标是“grm_init 必须返回”，这一条即可；若还要继续推进 UI，再评估后续 `FBResourceManager` 等初始化。

### 方案 B（隔离实验优先）：把 DMP_2D_Initialize 改成返回 0

在**文件偏移 0x1823D0** 写入 4 字节：`00 20 70 47`（Thumb：`movs r0,#0; bx lr`）。

- 原始字节：`03 48 80 b4 78 44 00 af bd 46 80 bc ff f7 e8 ba`（0x1823D0 起）。
- 效果：所有调用者拿到的 `DMP_2D_Initialize` 都立即返回 0；grm_init 会打印 `===== DMP_2D_Initialize : 0` 并继续后面初始化。
- 风险：2D worker/GPE 硬件层没有初始化，后续 `GRM_gpermFillrect/Rectblit` 等 2D 绘制路径可能失败或断言；适合“先让初始化序列走完/定位下一个阻塞点”。
- 若改后 **grm_init 仍不返回**，说明阻塞在 `sub_115078`（方案 C）。

### 方案 C：跳过 grm_init 内的 `sub_115078`

在**文件偏移 0x116B76** 写入 4 字节：`00 20 00 bf`（`movs r0,#0; nop`），即把 `bl sub_115078`（原字节 `FE F7 7F FA`）改为空操作。
可与方案 B 同时使用；两个 4 字节补丁互不影响。

### 方案 D：让 grm_init 立即返回（仅用于启动实验）

在**文件偏移 0x116AE4** 写入 `00 20 70 47`（`movs r0,#0; bx lr`）。
风险最高：grm 全部初始化被跳过，后续依赖 GRM 的路径会失败；只建议用于“验证调用链是否只因 grm_init 卡住”。

### 方案 E（功能方向）：补齐环境而不是打补丁

1. 在 QEMU 模型中保证 gen5 `grm_gles.ko` 加载并实现 `open /dev/dmpgles2`、`ioctl 0x80048263`（返回 PSC dummywrite=0 即 “disabled”）、`0xC004820D/0xC004820E` 信号对语义、`0xC0048203` 事件等待；保证 BAR 映射（启动日志的 `bar remapped 0xf1000000 size 0x4000` 已说明内核侧做过映射）。
2. 保证 5 代 OSAL 队列：`0x8F013A`（trace/ulogio）有消费者、`0x910042`（utimer）有应答；必要时先跑五代 IMDB 的 `osal_ulogio`/`utimer` 相关 init。
3. 先跑 `DDSUserInit`/`uxengine_init`/`MWF_Init`，再调用 `grm_init`（同方案 A）。
4. 注意：`/tmp/tv_enable` 在真机上是否存在会影响“enabled/hwctrl/mlock”路径，QEMU 里缺该文件时走 disabled 分支（当前情况）。

### 方案 F（先定位再补丁，强烈建议）

在 bridge4 顺序下用现有 UDF/SIGILL 陷阱工具（参考 `02-脚本/98_*` 系列）依次布点，记录命中顺序：

| 布点 | 含义 |
|---|---|
| 0x1819B0 入口 / 0x181A7C（`pthread_cond_wait` 调用点） | DMP2D 主线程是否进入无超时等待 |
| 0x181890（worker 入口）/ 0x1814F0（handler 入口） | worker 是否创建、是否收到命令 |
| 0x182A10、0x1849B0、0x13C740、0x13D3F0、0x12BE70 | 命令 1 链走到哪一步 |
| 0x12C670（rm_reg_init 入口）/ 0x12C820（mmap 后）/ 0x12C848（GPE 打印前） | GPE 硬件初始化走到哪一步 |
| 0x12D340 / 0x12D3A0 | 是否进入 sugilite 等待/发信号 ioctl |

命中最后一个点即锁定真正的阻塞系统调用；再决定是补 QEMU 驱动语义还是打 stub。

---

## 7. 验证与后续风险

1. 打方案 B 后重跑 bridge4：日志应为
   `init grm_init = …` → `!!! GLES Vecgen disabled.` → **`===== DMP_2D_Initialize : 0`** → **`init grm_init returned …`**。
2. 若返回后出现 `__assert_fail`（`/dev/mem`、`e == MA_ErrNone`、`grm_ma` 缺失）或继续无日志，则下一个阻塞点大概率在：
   - `0x11743C grm::FBResourceManager::initialize()`：`grm::Thread::start`（`osal_create_waitable_thread`）→ `0x11918C` → `BitmapBase::initialize` open `/dev/mem`；
   - `0x1158B8 → 0x1161DC` 的 `grm_gpe` 模块对象构造；
   - `GRM_gperm*`/`GRM_fbrm*` 系列（0x11902C、0x119064、0x115168、0x11519C、0x1169B4、0x117408…）。
3. 若采用方案 A 且 UI 仍不绘制，问题已不在 `grm_init`，应转向 `key_status` 事件结构（见 103/108 文档）与 VDF/OSD pin 连接。

### 边界与未决

- 本轮未运行 QEMU，无法给出“卡在 cond_wait 还是某个 ioctl”的运行时栈证据；结论基于静态调用图 + 既有运行日志的差异对照。
- bridge4 与 bridge5 的运行使用不同补丁镜像（bridge 代码本身不同），严格隔离“顺序 vs 线程上下文”需做 §6 方案 F 的 A/B 实验（bridge4 顺序 + 独立 pthread；bridge4 顺序 + 仅补 DDSUserInit）。
- `grm_init` 返回 `-1` 的含义是末尾 0x4000 就绪位未置位，不代表本次分析失败；只要出现 `returned` 即已越过阻塞。

---

## 8. 产物路径

| 类别 | 路径 |
|---|---|
| 报告 | `01-文档/105-grm_init阻塞分析.md`（本文件） |
| 证据目录 | `03-证据/静态分析/grm/` |
| 提取的样本 | `03-证据/静态分析/grm/lib/libObj.so`（+ NEEDED 库、kmod） |
| 证据索引 | `03-证据/静态分析/grm/grm_证据索引.md` |
| 反汇编/调用图 | `grm_init_disasm.txt`、`grm_init_calltree.txt`、`grm_callgraph.json`、`grm_blocking_paths.txt`、`grm_string_xrefs.json`、`grm_dep_paths.txt`、`grm_dump_0x*.txt` |
| 补丁点字节 | `03-证据/静态分析/grm/grm_patch_sites.txt` |
| 诊断用补丁变体 | `03-证据/静态分析/grm/patched/`（B/B2/BC/D 四个 libObj 副本 + `patch_manifest.json`） |
| 运行日志摘录 | `03-证据/静态分析/grm/grm_runtime_evidence.txt` |
| 脚本（均 `grm_` 前缀） | `02-脚本/grm_extract_libobj.py`、`grm_disasm.py`、`grm_xref.py`、`grm_probe_funcs.py`、`grm_probe_exidx.py`、`grm_probe_modes.py`、`grm_patch_libobj.py`、`grm_runtime_evidence.py` |

未改动：`05-原始固件/` 下任何镜像、`02-脚本/` 现有脚本、`01-文档/` 现有文档。
