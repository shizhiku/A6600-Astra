# 108 · key_status 事件结构还原：UPM boot-factor 同步消息、OSAL 队列 API 与生产者

日期：2026-11-22。范围：`03-证据/静态分析/97_abi/a5pFw_actual.so`（运行时实际加载的五代 appFw 镜像副本）、
`05-原始固件/{a6600_fw,zv1m2_fw}` 的两代 `upm.ko`、`03-证据/静态分析/{input_drv,grm}` 的 libObj/libosal_uipc。

只读边界：本轮**没有运行 QEMU、没有访问真机、没有修改任何镜像/现有脚本/现有文档**。
所有结论都由字节级静态证据 + 既有运行期记录（文档 103）交叉得到；补丁方案只写进证据文件，未落地。

---

## 0. 一句话结论

`0x2BBA4CC` **不是按键事件消费者**，而是 `infra_wrapper_upm::detail::upm2model_convert_boot_key(...)`
一族 **UPM→model 枚举转换分发器**。它用 **OSAL uipc 同步消息** 向 qid `0x00924127` 发一条
`mid = 0x00920111` 的 **0x28 字节请求**，然后读取内核模块 `upm.ko` 就地在同一缓冲区回填的
**UPM boot-factor 状态**，并逐字段做枚举合法性检查；任一字段越界就 `notify_model_system_error()`。

进入错误分支的字段是 **`+0x20`**，原因不是"事件来源缺失"，而是 **四代生产者（a6600 的 `upm.ko`）
只回填 0x1C 字节**，而五代 appFw 按 0x28 字节结构读取：
`+0x1C / +0x20 / +0x24` 是五代新增的 3 个字，四代内核根本不写，
`+0x20` 处留下池内残留 `0x005081e8` → 越界 → 断言。这是**同一消息的 4 代/5 代 ABI 长度差异**，
与四代输入事件布局无关。

---

## 1. 0x2BBA4CC 的真实身份

函数代码 `0x2BBA4CC..0x2BBA9CA`（最后一条 `pop.w` 在 0x2BBA9C6，随后 NOP），
内嵌字面量池 `0x2BBA9CC..0x2BBAA47`；下一个 exidx 函数从 `0x2BBAA48` 开始。
Thumb-2，未导出符号。反汇编见 `03-证据/静态分析/keystatus/01_disasm_key_functions.txt`。

### 1.1 入口序列（已把 ARM 长跳 veneer 解析到导入符号）

```
02bba4d6  ldr r0, =0x00924127          ; qid（uipc 消息队列 id）
02bba4d8  add.w r1, r7, #0x34          ; &msg（栈上 0x28 字节缓冲的指针槽）
02bba4dc  movs r2, #0x28               ; size = 0x28
02bba4de  movs r3, #1                  ; 标志/等待位 = 1
02bba4e0  blx  <veneer 0x2CE8498>      ; -> osal_valloc_msg_wait(qid,&msg,0x28,1)
02bba4e6  cmp r0,#0 ; bne.w 0x2BBA9B0  ; 失败 -> 收尾（r5+4=0x1B, r5+8=4）
02bba4ec  ldr r1,[r7,#0x34]            ; r1 = msg
02bba4ee  ldr r3, =0x00920111
02bba4f2  str r3,[r1]                  ; msg[0] = 0x00920111（message id）
02bba4f4  blx  <veneer 0x2CE7E5C>      ; -> osal_snd_sync_msg(qid,msg)  同步发送/等待回填
02bba4fa  cbz r0, 0x2BBA506            ; 失败 -> osal_free_msg 后收尾
02bba4fc..02bba500  osal_free_msg(qid,msg)   ; 仅失败路径
02bba506  ldr r1,[r7,#0x34]            ; 成功：从同一缓冲区读应答
          ... 拷贝 msg+4/8/0xC/0x10/0x14/0x18/0x20/0x24 到局部
02bba528  blx <veneer 0x2CE8420>       ; -> osal_free_msg(qid,msg)
```

veneer 解析证据：`0x2CE8498` 处是 ARM 长跳板
`ldr r12,[pc,#0]; add pc,pc,r12; .word (PLT-addr-(V+12))`，目标 `0x52A93C` 是 `.plt` 条目，
其 GOT 槽经 `.rel.plt` → `.dynsym` 得到 `osal_valloc_msg_wait`。同法得到
`osal_snd_sync_msg`、`osal_free_msg`、`usleep`、`printf`（见 `01_disasm_key_functions.txt` F–I 节）。
这也纠正了文档 103 把 `0x2CE8498` 猜测为"接收函数"的说法：它是**发送端的分配函数**。

### 1.2 断言字符串说明它是 UPM 包装层

函数内 7 个错误块（行号 0x119/0x136/0x150/0x164/0x178/0x1A0/0x1B7）都按同一模式：
`log(file,line)`（文件 = `infra_wrapper_upm.cpp`）→ `log("function:%s", <签名>)` →
`printf` 两行 → `usleep(100000)` → `notify_model_system_error()`。
解出的签名（证据 `08_function_strings.txt`）：

| 行号 | 签名串 | 被检查字段 |
|---:|---|---|
| 0x119 (281) | `model::upm_boot_key_t infra_wrapper_upm::detail::upm2model_convert_boot_key(uint32_t)` | msg+4 |
| 0x136 (310) | `model::upm_boot_type_t ... upm2model_convert_boot_type(uint32_t)` | msg+8 |
| 0x150 (336) | `model::upm_eecap_info_t ... upm2model_convert_boot_eecap(uint32_t)` | msg+0xC |
| 0x164 (356) | （同族转换器；该块还打印 `in.result_value:%d` 片段） | msg+0x14 |
| 0x178 (376) | （同族转换器） | msg+0x18 |
| 0x1A0 (416) | `model::upm_boot_after_apo_t ... upm2model_convert_boot_after_apo(uint32_t)` | **msg+0x20** |
| 0x1B7 (439) | （同族转换器） | msg+0x24 |

> 文档 103 之所以把这里归到 `key_status`，是因为相邻字符串池里有 `10key_status` /
> `000_main/key_status.cpp` / `virtual void key_status::inhbit_key_strobe(...)`。
> 那些字符串属于 `key_status` 自己的断言块（同一 `notify_model_system_error` 助手被多处复用）；
> **本函数自身的文件串是 `infra_wrapper_upm.cpp`，签名是 `upm2model_convert_*`**。
> 因此准确表述是：这是 `key_status` 之外、但同属"模型状态转换"的 UPM 路径，
> 不是按键事件处理函数。

### 1.3 输出结构（r5 = 实参 r1）

`r5+0x00`=状态（成功 0；失败由 `0x2BB6410` 计算），`r5+0x04`=boot_key 模型枚举，
`r5+0x08`=boot_type 模型值，`r5+0x0C`=eecap 模型值，`r5+0x10`=msg+0x10 直传，
`r5+0x14`=msg+0x14 映射(0/1)，`r5+0x18`=msg+0x18，`r5+0x1C`=msg+0x20 原值，
`r5+0x20`=msg+0x24 映射。失败时另有 `r5+0x04=0x1B`、`r5+0x08=4`（错误码形态）。

---

## 2. 0x28 字节消息结构（字段表）

消息 = `osal_valloc_msg_wait(qid,&msg,0x28,1)` 返回的 payload 指针。调用方只写 `msg[0]`，
其余 0x24 字节由**服务端（内核 `upm.ko`）就地回填**。字段语义由
① 客户端检查集合、② 内核回填代码（`g_bf` 偏移）双向对齐得到：

| 偏移 | 生产者源 | 客户端检查 | 客户端去向 | 说明 |
|---:|---|---|---|---|
| +0x00 | 回填时写入 `ip = mid`（`g_bf+4` 暂存） | 不检查 | 不读 | message id；请求时由客户端写 0x00920111，回填后等于请求 mid |
| +0x04 | `g_bf+0x08` | 集合 `{0,1,2,4,6,7,8,9,0xB,0xD,0x10,0x11,0x12,0x14,0x16,0x18,0x1A,0x1C,-1}` | `out+4` | `model::upm_boot_key_t`（启动按键/开关因子） |
| +0x08 | `g_bf+0x0C` | 集合 `{1,2,4,8,-1}` | `out+8` | `model::upm_boot_type_t` |
| +0x0C | `g_bf+0x10` | `1..4`（`tbb` 跳表） | `out+0xC` | `model::upm_eecap_info_t` |
| +0x10 | `g_bf+0x14` | 不检查 | `out+0x10` | 直传值 |
| +0x14 | `g_bf+0x18` | `1` 或 `2` | `out+0x14` | 映射 0/1 |
| +0x18 | `g_bf+0x1C` | `0` 或 `1` | `out+0x18` | 标志位 |
| +0x1C | `g_bf+0x20` | **客户端不读取** | — | 保留/对齐字 |
| +0x20 | `g_bf+0x24` | **`0` 或 `1`** | `out+0x1C` | 五代新增字段（运行时 0x005081e8 即此处） |
| +0x24 | `g_bf+0x28` | **`0..2`** | `out+0x20` | 五代新增字段 |

读取顺序证据（`02bba506..02bba526`）：`+0xC,+0x10,+4,+0x14,+0x18,+8,+0x20,+0x24`；
注意 `+0x1C` 从未被 `ldr`。逐字段检查顺序：`+4 → +8 → +0xC → +0x14 → +0x18 → +0x20 → +0x24`。

---

## 3. 队列 API

### 3.1 用户态（appFw 直接链接者）：`libosal_uipc.so`

镜像里 `a5pFw.so` 的 `DT_NEEDED` 明确包含 `libosal_uipc.so` / `libosal_utm.so`；
`a5bObj.so` 等五代库不提供这些符号。实际实现就是 `libosal_uipc.so`（26 KB，`/dev/uipc` + `mmap` + `ioctl`），
证据 `03-证据/静态分析/keystatus/03_libosal_uipc_disasm.txt`（含符号表反汇编）。

| 符号 | VA(Thumb) | 形状（据反汇编） |
|---|---|---|
| `osal_valloc_msg_wait` | 0x3FEC | `int osal_valloc_msg_wait(int qid, void **msg, unsigned size, unsigned flag)`；qid 位 15 选择代理/本地路径，低 15 位是槽索引；`size>0x1000` 或 qid<0 返回负错误码；成功写 `*msg` |
| `osal_snd_sync_msg` | 0x3EC8 | `int osal_snd_sync_msg(int qid, void *msg)`（16 B thunk，转 `0x1A68` 内核接口） |
| `osal_free_msg` | 0x4088 | `int osal_free_msg(int qid, void *msg)`；msg 头在 payload 前 12 字节，引用计数在 payload-6 |
| `osal_msg_size` | 0x4B80 | `unsigned osal_msg_size(void *msg)`：读 `[msg-8]` size class → `0x14` 或 `class*32-0xC` |
| `osal_reg_msg_queue_cb` / `osal_reg_sync_msg_queue_cb` | 0x4300 / 0x3AE0 | 注册队列回调（服务端用）；`*out` 回写 cb 句柄 |
| `osal_rcv_msg_tmo` | 0x3ED8 | 收消息 + 超时（`0x1B7741` 上限） |
| `osal_dynamic_id` | 0x2914 | 生成/查表 id（upm 框架初始化时用 `osal_dynamic_id(0x2A,0x92,off)`） |

返回码是负的错误域：`0xFFFFFC00`(-0x400) 参数/句柄类、`0xFFFFFC01`(-0x3FF) 内存类、
`0xFFFFFC02`(-0x3FE) 队列空、`0xFFFFFC04`(-0x3FC) 无回调等。

### 3.2 qid / mid 是什么

- qid 是 **uipc 共享内存里的 32 位静态 id**（不是进程内 fd）。它出现在用户态 `.text` 字面量、
  内核模块 `.text`/`.data`（框架表）和 LIRO 镜像 `AV-CAM.BIN` 里，说明是跨处理器/跨进程约定的常量。
- 同族常量（来自 `g4_upm.ko` framework 表与它的客户端引用）：
  `0x920021`（通知消息头字）、`0x920111/0x920112/0x920113/0x920123..0x920128`
  （boot-factor 子命令 mid）、`0x924127`（**boot-factor 框架队列 qid**）、`0x924224`、
  `0x92026F`、`0x920277`、`0x920524`、`0x924551`、`0x910040`，以及 input.ko 的
  `0x720018/0x8F013A/0x910042/0x8F0313/0x7A0020`。
- 内核侧同名 API 由 `osal_uipc.ko` 提供；`upm.ko` 的 `.symtab` 直接导入
  `osal_valloc_msg_wait / osal_snd_sync_msg / osal_free_msg / osal_reg_msg_queue_cb /
  osal_reg_sync_msg_queue_cb / osal_rcv_msg_tmo / osal_dynamic_id`。

### 3.3 服务端队列表（生产者注册点）

`upm.ko` 的 `upm_framework_init` 遍历一张静态描述表（`g4` 在 `.data+0x3A4`，`g5` 在 `.data+0x3B8`；
25 项 × 0x24 字节，`+0xC` 是 qid），逐项 `osal_reg_(sync_)msg_queue_cb(qid, …, cb, …)`。
**两代该表完全相同**，其中：

| case idx | qid | 用途 |
|---:|---:|---|
| 4 | **0x00924127** | **UPM boot-factor 框架队列**（请求由 `k_upm_framework_boot_factor` 处理） |
| 0/1 | 0x00924126 | — |
| 2 | 0x00924222 | — |
| 7 | 0x00924224 | — |
| … | … | （完整 25 项见 `06_upm_abi.txt`） |

---

## 4. 生产者 / 完整路径

```
硬件/传感器 & LIRO(AV-CAM.BIN) ──> upm.ko 内部状态 g_bf(.data+0x40)
      │  k_upm_setup_boot_factor / setters(k_upm_set_boot_factor_*)
      ▼
upm.ko  k_upm_framework_boot_factor(case 4, msg)         ← 服务端（同步请求/就地回填）
      │  mid 分派：0x920111/0x920113 → 回填 g_bf；0x920123/24/25/26 → 写单字段；
      │           0x920127 → k_upm_...；0x920128 → 由 msg+4 批量写 g_bf；其它 → 0x9200BB 错误
      │  回填后（mid 0x920111）再调 k_upm_notify_boot_factor(mid)
      ▼
k_upm_notify_boot_factor(r0=因子值) → g_bf+4=r0 →
upm_notify_wrapper_async(qid=0x924127, &g_bf+4, g4=0x1C / g5=0x28)
      │  valloc(qid) → msg[-4]=0x920021 → memcpy → snd_sync → （失败才 free）
      ▼
客户端（appFw `infra_wrapper_upm`、gen4 libObj、im.elf、mcmn_suspend…）
      osal_valloc_msg_wait(0x924127,&msg,size,1); msg[0]=0x920111;
      osal_snd_sync_msg(0x924127,msg); 读 msg+…; osal_free_msg
```

关键反汇编（均已落证据）：

- `k_upm_framework_boot_factor`：`g4` 0x7F64/396 B，`g5` 0x9878/416 B（`05_upm_g4_vs_g5.txt`）。
  mid 表：`0x920111→回填应答+触发通知`、`0x920112→只触发通知`、`0x920113→只回填`、
  `0x920123→g_bf+8`、`0x920124→g_bf+0xC`、`0x920125→g_bf+0x10`、`0x920126→g_bf+0x14`、
  `0x920127→[msg+4] 调子函数`、`0x920128→7/10 字批量写`、其它→`0x9200BB`（错误日志）。
- `k_upm_notify_boot_factor`：`g4` 0x7F38 / `g5` 0x984C，44 B；
  `str r0,[g_bf,#4]` + `mov r2,#0x1C/0x28` + `bl upm_notify_wrapper_async`。
- `upm_notify_wrapper_async`：0x142D0(g4)/0x168AC(g5)，136 B；
  `valloc → [msg-4]=0x920021 → memcpy → snd_sync_msg → free(失败时)`。
- 更上游：`upm_c3p_msg_async/sync`、`upm_task_call_req`（C3P = 与副处理器的命令通道）、
  `k_upm_set_boot_factor_for_oriks`（内核内部客户端，同样发 0x924127/0x920111）；
  LIRO 镜像 `AV-CAM.BIN` 中同时存在 `boot_factor` 字符串与 0x924127/0x920111 常量，
  说明 boot-factor 的原始来源在 LIRO/传感器/电源子系统一侧。

**性质判定**：这条消息**不是五代内部事件**；它是**外部（内核驱动/LIRO 电源子系统）状态查询**。
四代/五代的差异只在"消息结构长度与字段数"，不在"事件来源是否存在"。

客户端分布（`04_qid_xrefs.txt`）：gen4 `libObj` 有 9 处 0x924127 引用 + 26 处 0x920111，
其中 0x11F80C 是典型 gen4 客户端：

```
sub sp,#0x28; memset(local,0,0x1C)
osal_valloc_msg_wait(0x924127,&msg,0x1C,1); msg[0]=0x920111;
osal_snd_sync_msg(0x924127,msg); osal_free_msg(...)
```

即**四代客户端只要 0x1C 字节、且不解析回复**（fire-and-forget 通知语义）；
`im.elf`、`mcmn_suspend` 也是同样形态。五代 appFw 改成 0x28 并开始解析 8 个字段。

---

## 5. 四代 → 五代 ABI 差异（根因）

| 项 | 四代 `a6600` `upm.ko` | 五代 `zv1m2` `upm.ko` |
|---|---:|---:|
| `g_bf`（boot-factor 状态结构） | `.data+0x40`，**36 B** | `.data+0x40`，**48 B** |
| notify 发送长度 `r2` | **0x1C** | **0x28** |
| 同步回填字数（每段） | **7 字 = 0x1C B**（mid+6 数据字） | **10 字 = 0x28 B**（mid+9 数据字） |
| framework 表 entry4 qid | 0x00924127 | 0x00924127（相同） |
| mid 集合 | 相同（0x920111..0x920128） | 相同，另加 0x920127 子功能 |
| 客户端（四代 libObj） | size=0x1C，不解析 | — |
| 客户端（五代 appFw） | — | size=0x28，读 +4..+0x24（跳过 +0x1C） |

越界示意：

```
四代内核实际写:   msg[0x00..0x1B]  (0x1C 字节 = mid + 6 个数据字)
五代 appFw 读:    msg+0x04,08,0C,10,14,18  ← 命中
                  msg+0x20, +0x24          ← 超出 0x1C，未定义
                                 ^^^^^^^^^^ 运行期实测 0x005081E8 → 断言
```

这与文档 103 §六的运行期现象完全吻合：`+4=0`、`+8=4` 都属于各自合法集合，
流程走过了前 6 个字段检查，最后停在 `+0x20`（行号 0x1A0，`upm2model_convert_boot_after_apo` 块）
——因为该字在四代生产者眼里根本不存在。

> 注意：`g_bf` 前 4 个可写字段（`+8/+0xC/+0x10/+0x14`）在两代由同样的 mid
> （0x920123/0x920124/0x920125/0x920126）写入，偏移一一对应；差异集中在尾部新增的
> 3 个字（`+0x1C/+0x20/+0x24`，其中前 2 个 appFw 会读）。

---

## 6. 可行方案对比

### 方案 A（推荐）：客户端宽容默认值，4 字节补丁

把两个"四代不存在、五代新增"的字段在读取处直接固定为合法默认 0：

```
文件: 03-证据/静态分析/97_abi/a5pFw_actual.so（以及目标镜像里的 a5pFw.so 同偏移）
偏移: 0x02BBA520
原字节: 0A 6A 4B 6A     ; ldr r2,[r1,#0x20] ; ldr r3,[r1,#0x24]
新字节: 00 22 00 23     ; movs r2,#0       ; movs r3,#0
```

- 后续 `str r2,[r7,#0x20]` / `str r3,[r7,#0x1C]` 原样保留（`0x2BBA524/0x2BBA526`），
  于是 `+0x20 → 0`、`+0x24 → 0` 通过检查并写入输出结构；
- 不影响 `r1`（消息指针）后续用于 `osal_free_msg`；
- 风险：把五代新增语义（疑似"按键有效/APO 后启动"标志）统一取默认 0。若该值在五代有业务含义，
  表现为该功能默认态，而不再 abort。**这是目前最小、最可控、不需要动内核的修法。**
- 证据/校验：`07_patch_plan.json`、`07_synthetic_event.txt`（脚本会核对原字节，并已用 capstone
  复验补丁后两条指令解码为 `movs r2,#0; movs r3,#0`）。

### 方案 B：生产者侧补齐（改四代 `upm.ko` 回填 0x28）

- 把 `k_upm_framework_boot_factor` 的回填从 7 字扩到 10 字，并在 `g_bf` 后追加 3 个零字
  （`g_bf` 从 36 B 扩到 48 B，或让新增两字读自一个全零常量区）。
- 需要：内核模块重定位/重打包（.ko 有 `.rel.text`，不能只改字节）、保持 vermagic/
  符号与目标内核一致 → 风险与工作量都显著高于 A；且会改变**所有**四代 UPM 客户端看到的
  消息长度（四代客户端只要 0x1C，长度变长通常无害，但需回归）。
- 另一种 B'：直接换用**五代 `upm.ko`** —— 它同样注册 0x924127 且回填 0x28，
  但五代 `.ko` 与四代内核版本/符号闭包不同，必须先核对 vermagic/内核符号；
  属于"换驱动"而不是"改 ABI"，验证成本最高。
- 证据：`05_upm_g4_vs_g5.txt`、`06_upm_abi.txt`。

### 方案 C（任务书设想的"在四代输入事件上做转换"）：不适用

- 本轮已证明这条消息与 `input.ko`/`_InfraInputEvent`/uipc 按键事件**不是同一条链路**：
  它是 UPM 电源/启动因子服务的同步模型查询，服务端是内核 `upm.ko` 而不是输入驱动；
  输入事件转换不会改变 `+0x20` 的值。
- 输入事件转换（四代 `InputService::createEvent` → 五代 key_status 事件）仍是文档 103
  第 6/7 节的另一个问题，应继续按那条线做，与本错误点解耦。

### 方案 D（仅实验用，不落盘）：preload 拦截

在 preload 里包 `osal_snd_sync_msg`：当 `qid==0x924127 && *(u32*)msg==0x920111` 时，
真实调用返回后把 `msg+0x1C/+0x20/+0x24` 覆盖为合法默认值。
适合做 A/B 对照实验（验证"只差 3 个字"这一结论），但每次运行都要带 preload，
且会改变目标进程行为，不建议作为最终形态。

**结论**：优先 A（4 字节、客户端侧、可解释、可回退）；若要彻底对齐，做 B'（换五代 upm.ko）
并单独验证内核侧兼容性；C 不适用。

---

## 7. 合成一条合法事件的最小字段值

把 `osal_snd_sync_msg` 的应答缓冲按 0x28 字节理解，全部取最小合法值
（完整表见 `07_synthetic_event.txt`；完整 0x28 字节 hex 也写入 `07_patch_plan.json`）：

```
+0x00  0x00920111   mid（回填后等于请求 mid）
+0x04  0x00000000   upm_boot_key_t ∈ 接受集合
+0x08  0x00000001   接受集合 {1,2,4,8,-1}
+0x0C  0x00000001   tbb 表 1..4
+0x10  0x00000000   直传，不检查
+0x14  0x00000001   必须 1/2
+0x18  0x00000000   必须 0/1
+0x1C  0x00000000   appFw 不读
+0x20  0x00000000   必须 0/1  ← 四代生产者缺此字
+0x24  0x00000000   必须 0..2 ← 四代生产者缺此字
hex: 11 01 92 00 | 00000000 | 01000000 | 01000000 | 00000000 |
     01000000 | 00000000 | 00000000 | 00000000 | 00000000
```

如果要在**不改 appFw** 的前提下让四代内核产出这个结构，需要方案 B；
如果只要求"不再报模型错误"，方案 A 等价于把 `+0x20/+0x24` 强制成上表的 0。

---

## 8. 残余未知（必须如实标注）

1. **谁订阅/持有 qid 0x924127 的用户态一方**：`upm.ko` 自身在 framework 表里注册该 qid 作为
   服务端；但内核还会把 boot-factor 变化 `notify` 到同一 qid，说明还有用户态订阅者
   （gen4 `libObj` 里只找到客户端形态）。其具体模块/线程未在静态上闭合，
   可用运行期 `/proc/osal/uipc`、`osal_stat_msgq` 或 uipc_stat 打印确认。
2. `g_bf+0x24 / +0x28`（五代新增两字）的**业务语义**未知；只知道客户端要求的合法集合
   （0/1 与 0..2），取 0 是"最保守合法默认"，不等于恢复原厂语义。
3. 两代 `g_bf` 前 6 个数据字的语义一一对应关系是**偏移证据**（同 mid 写同偏移），
   尚未做五/六代客户端符号级对照的逐字段确认。
4. 本轮没有运行期验证（只读约束），方案 A 的实际效果需要在 ASTRA 离线镜像上按文档 103
   的流程复跑；若复跑仍出现新的字段越界，说明还有其它 4→5 代消息差异（可用同一方法扫描
   其它 `upm2model_*` 调用点）。
5. `0x2BBA4CC` 的断言块 4/5/7 的签名串未能全部解出（其中两块是 `in.result_value:%d`
   一类片段），但字段-行号-检查集合对应关系已由反汇编确认。

---

## 9. 产物与复跑

脚本（全部只读，`02-脚本/keystatus_*.py`）：

```powershell
python 02-脚本/keystatus_disasm.py          # 四个关键地址反汇编（含 veneer/字符串解析）
python 02-脚本/keystatus_strings.py         # 0x2BBA4CC 的断言字符串
python 02-脚本/keystatus_dump_libosal.py    # libosal_uipc.so 队列 API 反汇编
python 02-脚本/keystatus_find_qid_users.py  # 0x924127/0x920111 跨镜像引用点
python 02-脚本/keystatus_extract_upm.py     # 从两代 usr ext2 提取 upm.ko（只读镜像）
python 02-脚本/keystatus_compare_upm.py     # g4/g5 upm.ko 关键符号与反汇编
python 02-脚本/keystatus_upm_abi.py         # framework 队列表 + 回填字数/发送长度
python 02-脚本/keystatus_patch_plan.py      # 补丁 A 字节校验 + 合法消息样例
python 02-脚本/keystatus_dump_region.py <elf> <hex_va> <hex_len> [thumb|arm] <name>  # 通用区间反汇编
python 02-脚本/keystatus_elfutil.py         # 公共库（ELF/exidx/PLT/veneer/注解）
```

证据（`03-证据/静态分析/keystatus/`）：

| 文件 | 内容 |
|---|---|
| `00_extracted_files.txt` | 两代从 ext2 镜像提取的 kmod 清单与 SHA-256 |
| `01_disasm_key_functions.txt` | 任务书四个地址 + 相邻函数 + veneer 反汇编 |
| `03_libosal_uipc_disasm.txt` | OSAL 队列 API 实现反汇编（含符号） |
| `04_qid_xrefs.txt` | 0x924127 / 0x920111 在 appFw/两代 libObj/两代 im/libInfraMediaCommon 的引用点 |
| `05_upm_g4_vs_g5.txt` | 两代 upm.ko 关键符号、0x92xxxx 常量表、boot-factor 函数反汇编 |
| `06_upm_abi.txt` | framework 25 项 qid 表（entry4=0x924127）、发送/回填长度 |
| `07_patch_plan.json` / `07_synthetic_event.txt` | 补丁 A 字节与合法消息样例 |
| `08_function_strings.txt` | 0x2BBA4CC 内全部字符串引用 |
| `g4_upm.ko` / `g5_upm.ko`（及 `g4_/g5_input.ko`、`liro.ko`、`mcmn_drv.ko`） | 提取件 |
| `upm_k_framework_boot_factor*.txt`、`upm_framework_attach.txt`、`upm_notify_wrapper.txt`、`upm_framework_init.txt`、`libObj4_11f80c.txt` 等 | 定点区间反汇编 |

## 10. 对文档 103 的更正建议

1. `0x2CE8498` 不是"接收函数"，是 `osal_valloc_msg_wait` 的 ARM 长跳 veneer；
   `0x2CE7E5C`=`osal_snd_sync_msg`，`0x2CE8420`=`osal_free_msg`，`0x2CE8654`=`usleep`，
   `0x2CE8790`=`printf`。
2. `0x2BBA4CC` 属于 `infra_wrapper_upm` 的模型转换，不是 `key_status.cpp` 的事件处理；
   `key_status` 相关字符串是同一 `notify_model_system_error` 助手的其它调用者。
3. 根因不是"四代输入事件布局与五代 key_status 期望不一致"，而是
   **四代 `upm.ko` 的 boot-factor 回填长度 0x1C ≠ 五代 appFw 期望的 0x28**；
   `+0x20` 越界是这条同步消息尾部的缺失字，不是输入事件字段错位。

---

# 附录 108b · 运行期验证后的补丁全集、新断言归属与 size 改小评估

日期：2026-11-22。输入：`/root/astra/97/m1-verified/astra-m1-upmfix-b5.img`（实际加载
`03-证据/静态分析/97_abi/a5pFw_upmfix.so` = a5pFw_actual.so + 4 字节补丁 A）。
只读：本轮未运行 QEMU、未修改镜像；新增产物只落在 `01-文档/108*`、`02-脚本/keystatus_*`、
`03-证据/静态分析/keystatus/`。

## 11. 新断言归属：不是 upm2model 家族，是 BT classic 的 IM_open 失败

运行期 FWRA：`0x2B359F7、0x2B20821、0x2B20DA9、0x1D58FC1`（notify 内返回地址 `0x2BC318B`）。
FWRA 是返回地址（奇数 = Thumb），其"归属函数"是包含它的函数，而不是它本身。

| FWRA | 归属函数 | 函数身份（字符串/调用证据） | 帧内角色 |
|---|---|---|---|
| `0x2B359F7` | `0x2B3571C..0x2B35AD8` | `infra_wrapper_bt_classic::detail::load_im()`（文件串 `infra_wrapper_bt_classic.cpp`；行号 0x400；日志 `%s%s(%d) Failure IM_open() [Error:0x%08X]`）；同函数内还有 `create_msg_qid()`（`Failure alloc_msgq_id()`） | notify 直接调用者（call site `0x2B359F2`） |
| `0x2B20821` | `0x2B20810..0x2B20880`（112 B） | BT classic 初始化**相位包装**：`sched_lock(0x30,0)` → `bl 0x2B3571C` → `sched_unlock(0x30,0)` | 调用 `load_im/create_msg_qid` |
| `0x2B20DA9` | `0x2B20CE0..0x2B21026`（838 B） | **应用初始化序列**：连续 ~50 个 `bl` 初始化步骤，`0x2B20810` 是其中一步 | 调用 BT 相位 |
| `0x1D58FC1` | `0x1D58F98..0x1D5A3D8`（5184 B） | appFw **顶层初始化函数**；`0x1D58FBC` 调用初始化序列 | 调用初始化序列 |

**与 UPM 家族的对照**（证明不同族）：

| 项 | UPM boot-factor 路径（之前） | 本次新断言路径 |
|---|---|---|
| uipc qid | `0x00924127`（`upm.ko` framework 表 entry 4） | `0x0094016A`（`im.elf` 的 IM 服务） |
| 请求 mid/命令 | `0x00920111`（get boot factor） | `0x00940021`（IM_open） |
| 消息长度 | 请求 0x28；四代内核只回填 0x1C → 越界读 | 0x10，恰好填满，无越界读 |
| 失败判据 | 应答字段不在枚举集合 → notify | helper 返回码 ≠0 或应答[+4] ≠0 → notify |
| 直接调用者 | `infra_wrapper_upm::detail::upm2model_convert_*` | `infra_wrapper_bt_classic::detail::load_im()` |

IM 服务侧证据（四代 `im.elf`，与 appFw 同进程宿主）：

- `im.elf main()` @`0x9F58`：`0x9FB4` 走 helper `0x91CC` 使用 qid `0x0094016A`，随后进入消息循环；
- IM 服务分发 @`0x9634`：按 `msg[0]` 分派 `0x009400E1`（应答[4]=`0x12345678`，版本/握手）、
  `0x00940021`（**IM_open**：`ldrh r0,[msg+4]` = id `0x19F`，`r1=msg[8]`=3 版本，`r2=msg[0xC]` 参数，
  再调 `0xB4E0` 查全局对象表）、`0x00940022`（IM_close）；
- appFw 侧 helper `0x2B355C4`：`valloc(qid=0x0094016A, size=0x10)` → 填
  `{code=0x940021, id=0x19F, ver=3, arg}` → `snd_sync` → 拷回 4 字应答；
- `load_im()` 判定：helper 返回码非 0 **或** 应答[+4] 非 0 → `Failure IM_open()` → `notify`。

**结论**：新断言属于 `infra_wrapper_bt_classic` 的 IM 服务调用失败，**不是**"读 0x28 字节、
检查五代新增字段"的同一族；它与 UPM 补丁没有调用/数据关系。补丁 A 生效后 UPM 路径的断言消失，
初始化继续推进到这里，这是**被 UPM 断言掩盖的下一个独立阻塞点**（级联暴露，不是补丁引入的回归）。
静态只能判定"IM_open 失败"；失败具体是服务不可达还是对象 `0x19F` 不存在/未初始化，
需要运行期打印 helper 返回码与应答 4 字（`/proc/osal/uipc` 或 preload 打印）才能定论。

## 12. UPM boot-factor 越界检查点全集（已全 .text 扫描）

**入口补充**：`0x2BBA4CC` 在全 `.text` 中只有 **1 个直接 BL 调用者**：
`0x2B1E4D0`（返回地址 `0x2B1E4D5`），即**事件 9 thunk 本体**——
`0x2B1E4BC` 先 `sched_lock(0x1A,9)`、`bl 0x2BBA4CC`、再 `sched_unlock(0x1A,9)`。
这与文档 103 的运行期观察一致；同组相邻 thunk（如 `0x2B1E408`，phase 4）调用的是
`0x2BB8D14`，属于另一族转换器，不读 boot-factor 0x28 消息。

方法（`02-脚本/keystatus_family_scan.py`）：对 41 MB `.text` 向量化式提取 Thumb-2 32 位指令候选
（首半字 `0xF000–0xF7FF`），按 S/I1/I2/J1/J2 位域解 BL/BLX 立即数，匹配固定目标
（`notify=0x2BC3174`、`valloc veneer=0x2CE8498`、`snd_sync=0x2CE7E5C`、`free=0x2CE8420`）。

扫描结果（证据 `09_family_scan.txt`）：

- 全 `.text` 命中 `notify` 调用 **4190 处 / 1349 个函数**；
- `osal_valloc_msg_wait` 调用点 **18 处 / 18 个函数**（含 qid/长度推断）；
- 其中 **qid=`0x00924127` 且 size=`0x28` 的只有 1 处**：`0x2BBA4E0`（函数 `0x2BBA4CC`，
  即 UPM 转换分发器）——**这就是 UPM boot-factor 越界问题在 appFw 中的全部入口**；
- 同 qid 另有一个 `size=0x8` 的 setter helper `0x2BBA480`（mid `0x00920125`，只发不读），
  不越界、无需补丁。

`0x2BBA4CC` 的 8 个字段读取与 7 个检查点（只有最后两个超出四代 0x1C 回填）：

| msg 偏移 | 读取指令 | 检查集合/语义 | 超出四代 0x1C |
|---:|---|---|---|
| +0x04 | `0x2BBA50E` | `upm_boot_key_t ∈ {0,1,2,4,6,7,8,9,0xB,0xD,0x10,0x11,0x12,0x14,0x16,0x18,0x1A,0x1C,-1}` | 否 |
| +0x08 | `0x2BBA518` | `upm_boot_type_t ∈ {1,2,4,8,-1}` | 否 |
| +0x0C | `0x2BBA50A` | `upm_eecap_info_t ∈ 1..4`（`tbb` 跳表） | 否 |
| +0x10 | `0x2BBA50C` | 不检查，直传 `out+0x10` | 否 |
| +0x14 | `0x2BBA514` | `∈ {1,2}` | 否 |
| +0x18 | `0x2BBA516` | `∈ {0,1}` | 否 |
| **+0x20** | **`0x2BBA520`** | `∈ {0,1}` ← 运行期 `0x005081E8` 即此处 | **是** |
| **+0x24** | **`0x2BBA522`** | `∈ {0..2}` | **是** |

### 12.1 全族补丁清单（字节已逐项核对，`07_patch_plan.json`）

| ID | 文件/偏移 | 原字节 | 新字节 | 指令变化 | 覆盖/语义 |
|---|---|---|---|---|---|
| **A**（已验证） | `a5pFw_actual.so` +`0x2BBA520` | `0a 6a 4b 6a` | `00 22 00 23` | `ldr r2,[r1,#0x20]; ldr r3,[r1,#0x24]` → `movs r2,#0; movs r3,#0` | 一次覆盖 +0x20 / +0x24 两个越界点；后续 `str r2,[r7,#0x20]`、`str r3,[r7,#0x1C]` 原样保留，输出结构得到确定默认 0 |
| A1（等价拆分） | +`0x2BBA520` | `0a 6a` | `00 22` | `ldr r2,[r1,#0x20]` → `movs r2,#0` | 仅 +0x20；单用需叠加 A2 |
| A2（等价拆分） | +`0x2BBA522` | `4b 6a` | `00 23` | `ldr r3,[r1,#0x24]` → `movs r3,#0` | 仅 +0x24；单用需叠加 A1 |

- 三者的 `bytes_match_actual` 全为 `true`（脚本对 `a5pFw_actual.so` 逐字节核对）；
- `a5pFw_upmfix.so` 在 `0x2BBA520` 已是 `00220023`，即补丁 A 已应用
  （`07_patch_plan.json → image_patch_status`）；
- **UPM 全族只需补丁 A，不存在第二个需要同类处理的 0x28 客户端**（全扫描证据见上）。

## 13. 方案 B 评估：把请求 size 从 0x28 改成 0x1C —— 不可行

站点：`0x2BBA4DC`，原字节 `28 22`（`movs r2,#0x28`）→ 改成 `1c 22`（`movs r2,#0x1C`）。
这是 `osal_valloc_msg_wait(qid,&msg,size,flag)` 的 size 实参，全 appFw 只有这一处 valloc
使用该立即数（影响面：仅 `0x2BBA4CC` 这一个调用者）。

**结论：不可行，不能消除越界断言。** 理由：

1. 客户端在 `snd_sync` 之后**无条件**读取 `msg+0x20`（`0x2BBA520`）与 `msg+0x24`（`0x2BBA522`）；
   缩小请求 size 不会删掉这两次读取。
2. OSAL 消息按 size class 分配：`osal_msg_size = class*32-0xC`，payload `0x1C` 与 `0x28`
   都需要 class 2（`0x34 ≥ 0x28`），**分配块类别相同** → 复用的陈旧字节相同，
   `+0x20/+0x24` 仍是未定义值，断言照旧。
3. 四代 `upm.ko` 的 `k_upm_framework_boot_factor` 固定回填 7 字（0x1C），
   **不读取请求 size**，请求改小不会让内核多写/少写任何字节。
4. 改小后"请求声明 0x1C"与"代码按 0x28 使用"的契约更不一致，且可能改变复用池块内容，
   结果更不可复现。

若要"少读"，等价且更安全的就是补丁 A（把两次越界读取改成常量 0）；
若要"让服务端多写"，属于方案 B（改四代 `upm.ko` 回填 10 字 / 换五代 `upm.ko`），不是 size 问题。

## 14. 下一步（BT/IM 阻塞点）与诊断补丁

新断言不是 UPM ABI 问题，处理它需要 IM 服务/BT 对象层的信息。可选：

| 选项 | 内容 | 评价 |
|---|---|---|
| 运行期定位（推荐先做） | 在 `0x2B355C4` 返回处打印 helper 返回码与应答 4 字；对比 `0x00940021` 在 im.elf 中的分派（`0x9634`）与对象 `0x19F` 的注册来源 | 不改变镜像，能区分"服务不可达"与"对象不存在/未初始化" |
| 诊断跳相位 D1 | `a5pFw.so +0x2B20DA4`：`ff f7 34 fd`（`bl 0x2B20810`，BT classic 相位）→ `00 bf 00 bf`（nop;nop） | 仅用于确认"跳过 BT 后是否还有其它阻塞"；BT 完全不初始化，非最终方案 |
| 诊断绕断言 D2 | `a5pFw.so +0x2B359F2`：`8d f0 bf fb`（`bl notify`）→ `00 bf 00 bf` | 只掩盖日志；`load_im` 失败状态仍在，后续可能以别的方式崩，非最终方案 |
| 修 IM/BT 本身 | 定位 `0x19F` 对应对象由哪个初始化任务注册（很可能是被跳过的五代初始化序列之一），补上该任务 | 与本项目"补 5 代初始化链"的主线一致 |

D1/D2 字节已核对（`bytes_match_actual=true`，`07_patch_plan.json`），但均标注为"仅诊断用"。

## 15. 本轮新增/更新产物

| 文件 | 内容 |
|---|---|
| `02-脚本/keystatus_family_scan.py` | 全 `.text` BL/BLX 立即数扫描（4190 notify / 18 valloc 的证据生成器） |
| `02-脚本/keystatus_bt_chain.py` | FWRA→归属函数、断言字符串、IM 服务证据（生成 `10_bt_assert_chain.txt`） |
| `02-脚本/keystatus_patch_plan.py`（更新） | 全族补丁清单 + size 改小评估 + BT 诊断补丁；核对 `a5pFw_actual.so` 与 `a5pFw_upmfix.so` 字节 |
| `03-证据/静态分析/keystatus/09_family_scan.txt` | 全 `.text` 扫描：notify/valloc/snd_sync/free 命中、按函数聚合、valloc 的 qid/size 推断 |
| `03-证据/静态分析/keystatus/10_bt_assert_chain.txt` | 新断言归属分析全文（FWRA 表、函数串、IM 服务、对比表） |
| `03-证据/静态分析/keystatus/family_2b3571c.txt`、`family_2bba480.txt`、`bt_IM_open_helper.txt`、`bt_alloc_msgq_id.txt`、`caller_2b20810.txt`、`caller_2b20ce0.txt`、`family_1d58f98.txt` | 定点反汇编 |
| `03-证据/静态分析/keystatus/07_patch_plan.json`（重写） | `family_upm_boot_factor`（检查点/补丁 A/A1/A2/验证状态）、`option_size_0x28_to_0x1C`、`new_assert_bt_classic`（FWRA/IM 服务/诊断补丁） |
| `03-证据/静态分析/keystatus/07_synthetic_event.txt` | 上述内容的人类可读摘要 |

复跑：

```powershell
python 02-脚本/keystatus_family_scan.py
python 02-脚本/keystatus_bt_chain.py
python 02-脚本/keystatus_patch_plan.py
```

