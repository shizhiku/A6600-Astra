# 92 · InfraInput 键映射静态分析（MENU = 0x1AC → event_code）

> 目标：`03-证据/静态分析/libObj.so`（20,889,004 B，ELF32 ARM EABI5，`ET_DYN`，Thumb-2）。
> 方法：**纯静态**（pyelftools + capstone 5.0.7），不运行 QEMU、不修改任何固件/镜像文件。
> 全部地址均为**文件内虚拟地址（VA）**。本库第一个 `PT_LOAD` 满足 `vaddr == p_offset`，
> 故 `.text`/`.rodata`/`.data` 的 VA 与文件偏移相等；第二个 `PT_LOAD`（`0x1304580` 起）`vadelta = 0x8000`，
> 已在工具里按段表换算。
> 分析脚本：`02-脚本/libobj92_tools.py`、`92_infra_key_map_scan*.py`、`92_dumpfn.py`、`92_plt3.py`、`92_keylist_args.py`、`92_locate.py`。

---

## 一、结论摘要（先看这里）

| 问题 | 结论 | 置信度 |
|---|---|---|
| **Q1** `key_code=0x1AC` 的 `event_code` | **`0x1AC`（原值直通，无查表重映射）**。`InfraInput::MainThread` 在构造派发用事件时执行 `event.event_code = phy.key_code`；随后 `InputService` 直接以该值作 UI 事件 ID：`createEvent(event_code, 4)`。 | 已确证（代码路径逐条对齐） |
| **Q2** 启用条件 | ①`config_pos >= 0`（该键必须存在于运行时 key config 表，否则记 `unknown key` 丢弃）；②必须已注册**含该 key_code 的 key_list**（`[instance+0x9c]` 链表），否则不派发；③`internal_flag`/callback `flags` 决定 4 类抑制（`do not` / `same event` / `event inh` / `no group`）；④inhibit 由 `SetKeyInh` 独立控制；⑤repeat 由 `RepeatThread` 单独产生。 | 已确证（判定分支）/ 部分推测（status 具体数值） |
| **Q3** 默认键表初始化 | **libObj 内没有内置的 key_code→event_code 表**。键表在运行时由 UIPC 命令 `INFRA_INPUT_UIPC_SETEVENTKEYLIST` 下发（处理器 `0x85E5C4`）；`keyName/keyCode/localCode` 那套配置表来自 UIPC `key_conf`（`init/get/alloc key_conf`）。库内唯一内置的键相关静态表是**按键名表**（37 项，`0x13F0898`），只有"名字 + key_code"，**没有 event_code 列**。 | 已确证（穷举扫描 + 调用点） |

**对外最重要的实用结论**：把 MENU 送进 UI 所需的事件 ID 就是 **`0x1AC`**，
即 `InputService::createEvent(0x1AC, 4)` / 或让 `InfraInput` 走一遍物理键路径。
`0x1AC` 的官方符号名是 **`KEY_TACT_MENU`**（静态表实证，见 §3.1）。

---

## 二、关键结构体（全部已确证，均是反汇编直接推出的偏移）

### 2.1 `_InfraInputEvent`（24 = 0x18 字节，回调收到的就是它）

字段顺序由 `InfraInput::SendAttachEvent` 尾部的自证式 dump 反推（打印语句与字段一一对齐）：
dump 串位于 `.rodata`：`0x1012958 event_code`、`0x1012982 tp_x/tp_y`、`0x10129C2 status/prev_status`、`0x1012A09 ex_info/repeat`。

| 偏移 | 类型 | 名称 | 证据 |
|---|---|---|---|
| +0x00 | u32 | **event_code** | 0x8609E4 处 `ldr r3,[r4]` → `event_code = 0x%08X` |
| +0x04 | s16 | tp_x | 0x8609F8 `ldrsh.w r3,[r4,#4]` |
| +0x06 | s16 | tp_y | 0x8609FC `ldrsh.w r2,[r4,#6]` |
| +0x08 | u32 | status | 0x860A16 `[r4+8]` → `status = %d = 0x%08X` |
| +0x0c | u32 | prev_status | 0x860A16 `[r4+0xc]` |
| +0x10 | u32 | ex_info | 0x860A30 `[r4+0x10]` |
| +0x14 | u32 | repeat | 0x860A34 `[r4+0x14]` |

> ⚠️ 注意：**该结构里没有独立的 `key_code` 字段**。任务书里所说的"物理按键码"是上一级
> `InputPhyKeyInternal`/`_InfraInputPhyKeyData` 的字段，进了 `_InfraInputEvent` 之后
> 只剩 `event_code`。这正是"两个不同字段"的真实含义（不是两套编号，而是两个结构里的两个字段名）。

### 2.2 物理键消息（24 = 0x18 字节，`MainThread` 从 uipc 队列收到的）

`InfraInput::RecvThread`(0x862D60) 的 dump 串：`0x101332A InputPhyKeyInternal data {`、
`0x1013352 InfraInputPhyKeyData key {`、`key_code/sub_key_code/status/ex_info`、`config_pos`、`internal_flag`。
`MainThread` 逐字段取值（基址 `r7+0xdc`）：

| 偏移 | 类型 | 名称 | 证据（`MainThread` 0x862430） |
|---|---|---|---|
| +0x00 | u32 | **key_code** | 0x862668 `ldr r3,[r7,#0xdc]` |
| +0x04 | u32 | sub_key_code（低16=tp_x，高16=tp_y） | 0x862670 / 0x86267C `lsrs r1,r2,#0x10` |
| +0x08 | u32 | status | 0x862678 |
| +0x0c | u32 | ex_info | 0x862662 |
| +0x10 | s32 | **config_pos**（`<0` ⇒ 未知键） | 0x8624EC `ldr sb,[r7,#0xec]` + `cmp sb,#0; bge` |
| +0x14 | u32 | **internal_flag**（bit0 / bit2 参与抑制判定） | 0x86251E `tst r8,#1`；0x8625D2 `ands r1,#5` |

### 2.3 `InfraInputKeyList`（外部注册用，12 = 0xC 字节）

`InfraInput::SetEventKeyList`(0x861AA8) 内部对新表按 **0xC 步长**遍历：
0x861ADC `ldr r2,[r7,#8]` → 0x861B40 `adds r2,#0xc`，循环上界为第 4 个参数（count）。

| 偏移 | 名称 | 证据 |
|---|---|---|
| +0x00 | key_code | 0x861AEE `ldr.w r8,[lr]`（与已有表条目 +0 比较） |
| +0x04 | **event_code** | 内部条目 +4；dump `event_code = ...` |
| +0x08 | status | dump `status = ...` |

内部落地结构是 **0x44 字节/项**（0x861B48 `adds r3,#0x44`、0x861B7E `movs r8,#0x44`）：
`+0x00 key_code`、`+0x04 event_code`、`+0x24 s32 slot（<0 视为空）`、`+0x40 u8`、`+0x41 u8`。

### 2.4 其它相关结构（`this = InfraInput` 实例，`new(0x224)`）

| 偏移 | 含义 | 用法证据 |
|---|---|---|
| +0x18 | 回调数组基址，项 **0x30** 字节 | 0x86278A `ldr r2,[r4,#0x18]`；0x862792 `mla r2,0x30,r1,r2` |
| +0x24 | 每键状态缓存数组，项 **0x28** 字节，按 `config_pos` 索引 | 0x862526 `ldr r1,[r4,#0x24]`；0x86252E `mul r6,0x28,sb` |
| +0x9c | **已注册 key_list 链表头** | 0x861AC4 `ldr.w r5,[r2,#0x9c]`；0x862650 |
| +0x7c | 消息计数器（++） | 0x862468 `ldr r3,[r4,#0x7c]; adds r3,#1` |

回调项（0x30）：`+0x08 key_code`、`+0x10 priority`、`+0x14 callback_id`、`+0x18 osal_id(队列)`、
`+0x1c 回调函数指针`、`+0x20 flags`、`+0x24 group 位掩码`。
（`EventThread` 0x860A68 / `0x8609A4` 0x8609C4-0x8609CC：`r3=[r5+0x1c]; r0=[r5+0x14]; r1=event; blx r3`）

每键状态（0x28）：`+0x04 sub_key_code`、`+0x08 status`、`+0x14 status(GetEventStatus 输出)`、
`+0x20 u8`、`+0x24 flags`。

---

## 三、Q1：`key_code = 0x1AC` 对应的 `event_code` 是多少

### 3.1 静态表实证：0x1AC = `KEY_TACT_MENU`

在 `.data` 找到**按键名表**：`0x13F0898 … 0x13F09C0`，共 **37 项**，每项 8 字节
`{ char* name; u32 key_code; }`（无 xref，属于"被整体取址/或仅调试用"的静态常量表，见 §7）。

```
0x013F0898  key=0x0003 (  3)  KEY_TACT_POWER
0x013F08A0  key=0x0013 ( 19)  KEY_TACT_UP
0x013F08A8  key=0x0015 ( 21)  KEY_TACT_PNTLTMENU
0x013F08B0  key=0x0020 ( 32)  KEY_TACT_LEFT
0x013F08B8  key=0x0030 ( 48)  KEY_TACT_FINDER
0x013F08C0  key=0x0041 ( 65)  KEY_TACT_DOWN
0x013F08C8  key=0x0047 ( 71)  KEY_JACK_MULTILANC_LANC
0x013F08D0  key=0x004B ( 75)  KEY_JACK_HP_OUT
0x013F08D8  key=0x004C ( 76)  KEY_JACK_MICJACK_IN
0x013F08E0  key=0x004D ( 77)  KEY_JACK_MICJACK_OUT
0x013F08E8  key=0x0050 ( 80)  KEY_JACK_HP_IN
0x013F08F0  key=0x0051 ( 81)  KEY_JACK_MULTIJACK_IN
0x013F08F8  key=0x0066 (102)  KEY_JACK_MULTIJACK_OUT
0x013F0900  key=0x00A7 (167)  KEY_TACT_CUSTOM
0x013F0908  key=0x00A7 (167)  KEY_TACT_CAP
0x013F0910  key=0x01A4 (420)  KEY_RELEASE_CAP
0x013F0918  key=0x01A5 (421)  KEY_JACK_MICJACK_MONO_IN
0x013F0920  key=0x01AB (427)  KEY_JACK_MICJACK_MONO_OUT
0x013F0928  key=0x01AC (428)  KEY_TACT_MENU          ← ★ MENU
0x013F0930  key=0x01AD (429)  KEY_TACT_ENTER
0x013F0938  key=0x01AF (431)  KEY_JACK_MULTILANC_DPLUG
0x013F0940  key=0x01BF (447)  KEY_TACT_RIGHT
0x013F0948  key=0x01D1 (465)  SLIKEY_ZOOM
0x013F0950  key=0x01D2 (466)  SLIKEY_SLI_POWER
0x013F0958  key=0x01D5 (469)  SLIKEY_SLI_POWER_OFF
0x013F0960  key=0x01D6 (470)  SLIKEY_EVF_OPEN
0x013F0968  key=0x01F0 (496)  SLIKEY_EVF_CLOSE
0x013F0970  key=0x01F1 (497)  KEY_TACT_STARTSTOP
0x013F0978  key=0x01F1 (497)  KEY_TACT_LOCK
0x013F0980  key=0x01F3 (499)  KEY_RELEASE_LOCK
0x013F0988  key=0x01F4 (500)  KEY_TACT_WIDE
0x013F0990  key=0x01F5 (501)  KEY_TACT_FOCUS
0x013F0998  key=0x01F7 (503)  KEY_TACT_TELE
0x013F09A0  key=0x01F8 (504)  KEY_TACT_PLAY
0x013F09A8  key=0x01F9 (505)  KEY_TACT_DELETE
0x013F09B0  key=0x01FB (507)  KEY_TACT_DISP
0x013F09B8  key=0x01FF (511)  KEY_TACT_CONTSHOT
```

名称串本体在 `.rodata`（如 `0x1014593 = "KEY_TACT_MENU"`）。
与 `input.ko` 的 ADC 键表完全对得上（`port f-0 / 0..0x5B → 0x1AC`；`0x1F8 = PLAY`；`0x30 = FINDER`；
`0x15 = PNTLTMENU`；`0x3 = POWER`），**互相独立地确认了 0x1AC = MENU**。

### 3.2 `event_code` 的产生代码（已确证：直通）

`InfraInput::MainThread`（`0x862430`，size `0x780`）在把事件发给回调队列前，逐字段填 `_InfraInputEvent`：

```
00862662  ldr.w  r2,[r7,#0xe8]     ; r2 = phy.ex_info (+0x0c)
00862668  ldr.w  r3,[r7,#0xdc]     ; r3 = phy.key_code (+0x00)  ← 0x1AC
0086266C  str.w  r2,[r7,#0xd4]     ; event.ex_info  (+0x10)
00862670  ldr.w  r2,[r7,#0xe0]     ; r2 = phy.sub_key_code (+0x04)
00862674  str.w  r3,[r7,#0xc4]     ; ★ event.event_code (+0x00) = phy.key_code
00862678  ldr.w  r3,[r7,#0xe4]     ; phy.status (+0x08)
0086267C  lsrs   r1,r2,#0x10       ; tp_y = sub_key_code >> 16
0086267E  strh.w r2,[r7,#0xc8]     ; event.tp_x (+0x04) = low16(sub_key_code)
00862686  strh.w r1,[r7,#0xca]     ; event.tp_y (+0x06)
00862690  str.w  r3,[r7,#0xcc]     ; event.status (+0x08)
...
00862698..0x8626AC  bl 0x8623d8 / bl 0x85f398   ; 计算 repeat, 投递 0x18 字节到回调队列
```

即 **`event.event_code = phy.key_code` 是一条赋值，中间没有任何查表**。
再往 UI 侧（`InputService`，同在 libObj）：

```
0x3D2EA6  InputService::callback_direct(cbId, ev)
0x3D2EAC  bl 0x3D2D1C                      ; 转换器
   0x3D2D84  ldr r1,[r5]      ; r1 = ev->event_code
   0x3D2D82  movs r2,#4       ; dest = 4
   0x3D2D8E  blx #0x100E94    ; = InputService::createEvent(unsigned long, unsigned char)
```

`0x100E94` 经 `.plt → .got → .rel.plt` 解析确为 **`_ZN12InputService11createEventEmh`**（已核对
`0x104530 = SetEventKeyList`、`0xFE8EC = pushFilterEvent` 等，共 2547 个桩全部对上）。
所以 **UI 事件 ID = `event_code` = `0x1AC`**。

### 3.3 为什么"看起来应该有映射表"却没有：穷举结果

| 检查 | 结果 |
|---|---|
| 全文件搜 `ac 01 00 00`（LE 0x1AC） | 42 处命中；`.text` 内 0 处，`.ARM.extab` 里是无关数据；`.rodata`/`.data` 命中已逐条人工判读，**没有一处是 `{key_code, event_code}` 成对表** |
| 按 8 / 12 / 16 字节步长扫"首字段=0x1AC 且次字段像 event_code"的数组 | **0 命中** |
| `InfraInputKeyList`（12B）表 | 只有运行时下发（见 §5），文件内无静态实例 |
| `SetEventKeyList` 的 13 个调用点传入的指针 | 已逐点核（`92_keylist_args.py`）：`0x85E846` 取 **uipc 报文 `+0x10`**、`0x86231C` 是**函数内现算的数组**、`0x3D4644` 取自栈帧；`0x3D3A5A`/`0x660DBA` 从"注册描述符数组"里 `ldm` 出 `{listNo, 表指针, count}`，该描述符数组本身是 `.data/.bss` 的运行时结构，**其表指针指向的数组在文件里不含 0x1AC**（由上一条穷举保证） |

被排除的 4 个"疑似表"（列出以免后人重复踩坑）：

| 地址 | 形态 | 判读 |
|---|---|---|
| `0x00F9B210…`（`.rodata`） | 单字降序序列 `0x264,0x25E,…,0x1AC,0x1A9,…`（步长 −2/−3） | 是"合法键码集合/查表索引"用的**有序键码数组**，单列无 event_code |
| `0x010D835C` 附近（`.rodata`） | u16 对 `1A8,1A9,1AA,1AB,1AC,1AB,1AC,1AB,1AC,0000,…` | 16 位值的往返序列，非 12B 结构 |
| `0x0138331A` 附近（`.data`） | 连续 19 条 u16 对 `(0x1AC,4),(0x1AC,3),(0x1AC,0),(0x1AC,5),(0x1AC,2),(0x1AC,2),(0,7),(0x1AC,10),(0x1AC,9),(0x1AC,6),(0x1AC,11),(0x1AC,8),(0x1AC,3),(0,0xD),(0x1AC,0x10),(0x1AC,0xF),(0x1AC,0xC),(0x1AC,0x11),(0x1AC,0xE),(0x1AC,0x1000)` | **未确定**。若是 `{u16 key, u16 event}` 则"一个键→19 个不同值"，**不构成函数映射**，因此不可能是 key→event 表；第二列 0..0x11 的连续序号更像"索引/枚举/测试序列"。且**无 xref**（`0x138331A/0x1383322/0x138332E` 均为空） |
| `0x0134B440/0x0134B568`（`.data.rel.ro`） | 指针数组夹 `0x1AC` | 与 0x1AC 相邻的是代码指针，语义无关 |

> **结论**：`event_code` 不是"查表得来"，而是物理键码直通。
> `InfraInputKeyList` 那套 `event_code` 字段是**另一条（UIPC 下发、用于筛选/声明的）注册通路**，
> 在本库的派发代码里**没有**用它改写 `_InfraInputEvent.event_code`（`0x8626F2` 处只把它当日志参数读）。

---

## 四、Q2：这条 key 的启用条件

### 4.1 派发主链（`InfraInput::MainThread` 0x862430）

```
osal_rcv_msg_tmo(队列)                       ; 0x862464 blx PLT 0x1042F8
  ├ 消息为空 → 丢弃
  ├ config_pos = msg[+0x10];  < 0  → 打印 "unknown key"(0x100DB7C) → 丢弃      ★条件1
  ├ internal_flag = msg[+0x14]; bit0=1 →
  │    memcmp(msg, state[0x28*config_pos], 0x10) != 0 → 打印 "do not"(0x1013002) → 丢弃  ★条件2
  ├ 预处理 0x864164(this,&msg,flags)
  ├ 回调项 = callbacks[+0x18] + 0x30*n
  │    (cbflags & 1) && msg.status == 0x7FFFFFFF → 打印 "keep_unknown"(0x1013014)
  │    (cbflags & 2)==0 && (internal_flag & 5)==0 →
  │         state[+4]==msg.sub_key_code && state[+8]==msg.status → "same event"(0x1013021) → 丢弃 ★条件3
  ├ 更新状态 0x86239C；加锁 PLT 0x102BBC；把 24B msg 拷进 state[0x28*config_pos]；state[+0x14]=0
  └ 遍历已注册 key_list 链 this[+0x9c]：
        entry[+0x00] != msg.key_code → 下一个                         ★条件4（必须已注册）
        entry[+0x40] != 0 → 跳过
        entry[+0x41] != 0 → 记日志后跳过
        否则 ChangeEventStatus(...) → 返回 idx<0 → 记日志跳过
              → 命中回调 → 投递 24B _InfraInputEvent 到 list[+0x18] 队列 (0x85F398)
```

### 4.2 `status` 字段的取值含义

**已确证部分**：
- `status` 是 32 位有符号量，从物理消息 `+0x08` 原样进 `_InfraInputEvent.status(+0x08)`，
  旧值同时进 `prev_status(+0x0c)`（`SendAttachEvent` 的 dump 串即 `status/prev_status`）。
- 有一组**哨兵值**：`0x7FFFFFFF`、`0x7FFFFFFE`、`0x7FFFFFFD`、`0x7FFFFFFC`
  （`0x8616CA` 之后连做 4 次 `add lr,#-1; cmp`；`0x8625A6 mvn r1,#0x80000000` 即 `0x7FFFFFFF`；
  `GetEventStatus` 0x860FD4 里 `0x7FFFFFFE` 与 `0x7FFFFFFF` 分别表示"默认/无事件"和"无效"）。
- `status` 参与**去重判定**（条件3），说明"按下/抬起"分别对应不同 `status` 值，同值重复才被判 `same event`。

**未确定**：`status` 的完整枚举（哪一个是按下、哪一个是抬起）。理由：`ChangeEventStatus`
里的 `max_on / max_off / max_invalid`（`0x1012C51`）等字符串在**本构建里无任何引用（死串）**，
静态代码里也没有"status == 常量"的开关表；这些数值来自运行时 key config / 副控制器。

### 4.3 inhibit（抑制）

- 独立 API：`InfraInput::SetKeyInh`(0x8613FC)、`InfraInput::GetKeyInh`(0x8612E2)。
  `GetKeyInh` 先 `bl 0x861278`（按键码查槽位）→ `state = this[+0x24] + 0x28*idx`，再读该槽的 inhibit 位。
- 调试串 `D:GEInh` / `D:SEInh`（`0x1012ACA` / `0x1012AD2`，函数 `0x860EA8`）即 Get/Set Inhibit 的入口日志。
- 另有 **event 级 inh**：`0x101302C "event inh"` 作为抑制原因串出现在派发函数里（`0x862702` 读 `entry[+4]`）。
- 结论：**inhibit 是"按键级 + 事件级"两层**，默认不抑制（要显式 `SetKeyInh(true)` 或配置表 flag 才抑制）。

### 4.4 repeat（重复）

- `InfraInput::RepeatThread` 相关函数 `0x863158`（自证串 `start repeat` / `exit repeat`，size `0x1D4`），
  `SKeyRepRst` 在 `0x8636F4`，`rep over` 在 `0x862C54`。
- `_InfraInputEvent.repeat(+0x14)` 由 `0x8623D8` 的返回值写入（`0x8626A6 str.w r0,[r7,#0xd8]`）。
- 每键状态里 `+0x14` 在每次派发后被清 0（`0x86264E`），即"重复计数/上次重复时刻"。
- 结论：**repeat 是"按住后由 RepeatThread 周期性再投递"，不是边沿触发**；单次按下只产生一次
  `repeat=0` 的事件，长按会追加 `repeat=1,2,…`。

### 4.5 edge（边沿）与"是否要先注册"

- **必须先注册**（条件4，已确证）：`MainThread` 只在 `this[+0x9c]` 链表中找到
  `entry[+0x00] == msg.key_code` 的项才会派发。链表的插入者是 `SetEventKeyList`，
  而它的 13 个调用点里**只有一个是 UIPC 下发**（`0x85E846`，`INFRA_INPUT_UIPC_SETEVENTKEYLIST`），
  其余在库内（`0x3D3A5E`/`0x3D4644` = InputService 侧、`0x86231C` = 分组筛选后转发、`0x85E846`、
  `0x86609A`、`0x8691E8`、`0x8692CA`、`0x9D0D86`、`0xA0B70A`、`0xA0BB0A`、`0xD7A69A`、`0xDBBDB4`）。
  **推论（推测）**：若 UI 进程没有把含 0x1AC 的 key_list 注册进来，MENU 事件会被静默丢弃——
  这与"注入 ADC 电平后驱动侧有值、但 UI 无反应"的既有现象一致（见 `84a` 文档）。
- **边沿**：`ChangeEventStatus`(0x861578) 用 `prev_status` 与 `status` 的差异做"变化/保持"判断，
  并有 `CES_cause1 / CES_keep / CES_cause2 / CES_done`（`0x1012C98…0x1012CB7`）四个状态名（本构建为死串）。
  即：**同一通道的连续相同 status 会被判为 keep/重复**，只有变化才产生新事件。
  另外 `internal_flag & 1`（条件2）是一条"只允许完全相同的重复帧继续"的特例。

---

## 五、Q3：默认键表是怎么初始化的

### 5.1 结论：**没有内置默认键表，全部来自 UIPC（副控制器 / 客户端进程）**

`InfraInput::RecvThread`(0x862D60) 是 uipc 命令分发器，从 `.rodata` 的自证日志串可以完整枚举它支持的命令：

| UIPC 命令（日志串） | 串地址 | 处理函数 |
|---|---|---|
| `INFRA_INPUT_UIPC_SETEVENTKEYLIST (callback_id, list_no)` | `0x101144E` | `0x85E5C4`（内部 `blx 0x104530` 即 `SetEventKeyList`） |
| `INFRA_INPUT_UIPC_RMEVENTKEYLIST (callback_id, list_no)` | `0x10114A6` | 同上区域 |
| `INFRA_INPUT_UIPC_SENDEVENTINITDATA (callback_id)` | `0x10114FD` | `0x8610FC` 的调用者（0x85E5C4 内） |
| `INFRA_INPUT_UIPC_SETOSALID (osal_id)` | `0x1011364` | `0x860D8C` |
| `INFRA_INPUT_UIPC_RMCALLBACK (callback_id)` | `0x10113F3` | `0x8600B0` |
| `debug display config_table` / `[%04d]: key_code=…, local_code=…` | `0x1011300` / `0x1011327` | key_conf dump（`0x8638AC` 一带） |

`0x85E5C4` 里下发的表**就在 uipc 报文自己身上**：

```
0085E83C  mov  r3,r6            ; count
0085E83E  mov  r1,r8            ; cbId   (= [r4+8])
0085E840  add.w r2,r4,#0x10     ; ★ list = 报文缓冲 + 0x10（12B/项的数组）
0085E844  mov  r0,r5            ; this
0085E846  blx  #0x104530        ; InfraInput::SetEventKeyList
```

### 5.2 `SendEventInitData`(0x8610FC)

`bool SendEventInitData(int cbId)`：打印 `send ini_eve`(`0x1012B46`) → 清 `0x1c` 字节栈结构 →
`bl 0x85FD20` 取该回调的"初始事件/未决事件" → 失败打印 `seid-errUpmBootFactor`(`0x1012B66`)，
成功打印 `seid-UpmBootFactor`(`0x1012B53`)，随后把该初始事件投递给 `cbId`。
**它不读任何文件、不读 Flash、不解析内置表**——只是把 InfraInput 内部缓存的"当前键状态"
（`GetEventStatus` 同源的 `_InfraInputPhyKeyData`）当成 init data 发给新注册的回调。
所以 Q3 的"数据来源"= **UIPC 报文（副控制器 UIPC 帧）→ RecvThread → 内部状态缓存 → SendEventInitData 回灌给回调**。

### 5.3 `key_conf`（`keyName/keyCode/localCode` 那套表）也是运行时的

| 函数 | 地址 | 作用 |
|---|---|---|
| `init key_conf` | `0x8637C0` | 把字符串 `"config"`(`0x100E308`) 存全局 `0x13F05BC`，调 PLT 建链（返回句柄存 `0x142C184`） |
| `exit key_conf` | `0x86384C` | 释放 |
| `get key_conf` | `0x8638AC` | 取配置（配合 `0x1011300 debug display config_table`） |
| `alloc key_conf` | `0x863960` | 分配/扩容 |

`KeyConfigInfraInput` 的 dump 字段（`0x10130AF` 起，本构建**整段无引用=死串**）：
`keyName / infraName / keyCode / localCode / yuusen / repeat_time0 / repeat_time / group / flag / osalId / dummy1 / dummy2`
——即"配置表项有 keyCode→localCode，但**没有 event_code**"，进一步佐证 §3 的结论。

---

## 六、关键地址 / 偏移速查表

### 6.1 段与全局

| 项 | 值 |
|---|---|
| `.text` | `0x00104A30`，size `0x00D3A6F0` |
| `.rodata` | `0x00E3F128`，size `0x003567A2` |
| `.ARM.exidx` | `0x01287E10`，size `0x00074770`（恢复出 **59,630** 个函数入口） |
| `.rel.plt` | `0x000F7CC0`，size `0x00004F98`（**2,547** 条） |
| `.plt` | `0x000FCC64`，size `0x00007DC8`（**12 字节/桩**） |
| `.data.rel.ro` | `0x013049C0`，size `0x0006C758` |
| `.data` | `0x0137AD20`，size `0x00078AFC` |
| `.bss` | `0x013F3820`，size `0x0003E7C8` |
| 直接调用边 | 285,742 条（BL/BLX，见 `libobj92_tools.build_bl_map`） |

### 6.2 InfraInput 函数

| 函数 | VA | 大小 | 备注 |
|---|---|---|---|
| `InfraInput::GetInstance` | `0x0860874` | 184 | `new(0x224)` |
| `InfraInput::SetCallback` | `0x0860DF8` | 108 | 存 `this[+0x1c]=fn`、`*out=this[+0xA0]` |
| `InfraInput::GetEventStatus` | `0x0860FD4` | 296 | 从 `this[+0x24]+0x28*idx` 拷 24B |
| `InfraInput::SendEventInitData` | `0x08610FC` | 304 | Q3 入口 |
| `InfraInput::GetKeyInh` | `0x08612E2` | 32 | → `0x861278` 查槽 |
| `InfraInput::SetKeyInh` | `0x08613FC` | 268 | |
| **`InfraInput::ChangeEventStatus`** | **`0x0861578`** | **0x444** | status/prev/优先级 判定 |
| `InfraInput::RmEventKeyList` | `0x08619BC` | 236 | |
| **`InfraInput::SetEventKeyList`** | **`0x0861AA8`** | 1968 | 12B/项 外部表 → 0x44B/项 内部表 |
| `InfraInput::SendAttachEvent` | `0x086092C` | 0x38(包装) | `_InfraInputEvent` 字段 dump 在其尾段 `0x8609A4` |
| 回调投递 `notify` | `0x08609A4` | 196 | `cb=this[+0x1c]`、`cbId=[+0x14]` |
| **`InfraInput::EventThread`** | **`0x0860A68`** | 0x1C0 | 队列→回调，拷贝 24B 事件 |
| **`InfraInput::MainThread`** | **`0x0862430`** | **0x780** | ★ 派发主逻辑（Q1/Q2 核心） |
| 分组筛选助手 | `0x0862258` | 0x10C | "no group"，并把筛选结果 `SetEventKeyList` 转发 |
| 状态更新 | `0x086239C` / `0x08623D8` | — | repeat/prev_status |
| `InfraInput::RepeatThread` 区 | `0x0863158` | 0x1D4 | `start repeat`/`exit repeat` |
| `SKeyRepRst` | `0x08636F4` | — | |
| `InfraInput::RecvThread` | `0x0862D60` | 0x3F8 | UIPC 命令分发（Q3 核心） |
| `0x8637C0 / 0x86384C / 0x8638AC / 0x863960` | | | `init/exit/get/alloc key_conf` |
| UIPC `SETEVENTKEYLIST` 处理器 | `0x085E5C4` | — | 表 = 报文 `+0x10` |

### 6.3 InputService（UI 侧）

| 函数 | VA | PLT 桩 | 备注 |
|---|---|---|---|
| `InputService::createEvent(unsigned long, unsigned char)` | `0x03CFAEA` | `0x100E94` | `new(0x14)` + `Event::Event(id,dest,1)` |
| `InputService::pushFilterEvent(Event*)` | `0x03D1818` | `0x00FE8EC` | 进 UI 事件总线 |
| `InputService::callback_direct` | `0x03D2EA6` | — | → `0x3D2D1C` → `createEvent(ev[0],4)` |
| 转换器（`callback_direct` 内调） | `0x03D2D1C` | — | `0x3D2D84 ldr r1,[r5]` = event_code |
| `InputService` 侧注册 key_list | `0x03D3924` / `0x03D451C` | — | 调用 `SetEventKeyList` 的站点 `0x3D3A5E` / `0x3D4644` |
| `InputService::m_pMyInstance` | `0x13F5E6C` | — | 全局单例指针（OBJECT, 4B） |

### 6.4 重要字符串

| VA | 内容 |
|---|---|
| `0x1012FB2` | `[INFRAINPUT][%3d]: key_code = 0x%08X, event_code = 0x%08X`（**本构建无引用**） |
| `0x1012D8D / 0x1012DAB / 0x1012DD3 / 0x1012DFD / 0x1012E27` | `InputEventList {` / `InfraInputKeyList event {` / `key_code` / `event_code` / `status`（在 `SetEventKeyList` 内） |
| `0x1012958 / 0x1012982 / 0x10129C2 / 0x1012A09` | `_InfraInputEvent` 的 `event_code` / `tp_x,tp_y` / `status,prev_status` / `ex_info,repeat` |
| `0x101144E` | `received INFRA_INPUT_UIPC_SETEVENTKEYLIST (callback_id, list_no)` |
| `0x10114FD` | `received INFRA_INPUT_UIPC_SENDEVENTINITDATA (callback_id)` |
| `0x1013002 / 0x1013009 / 0x1013014 / 0x1013021 / 0x101302C / 0x1013036 / 0x1012FF9` | 抑制原因：`do not` / `repeat key` / `keep_unknown` / `same event` / `event inh` / `no_send` / `no group` |
| `0x100DB7C` | `unknown key` |
| `0x1014593` | `KEY_TACT_MENU` |

---

## 七、已确证 / 推测 / 未确定

### 已确证（代码或静态数据直接支撑，可复现）
1. `_InfraInputEvent` 为 24 字节，`+0x00 = event_code`，`+0x04/+0x06 = tp_x/tp_y`，`+0x08 = status`，`+0x0c = prev_status`，`+0x10 = ex_info`，`+0x14 = repeat`。
2. `InfraInput::MainThread` 把物理 `key_code` **原值**写入 `event_code`（`0x862668`/`0x862674`），无查表。
3. `InputService` 用该值直接作 UI 事件 ID：`createEvent(event_code, 4)`（`0x3D2D84`→`0x3D2D8E`→`createEvent`）。
4. `0x1AC = KEY_TACT_MENU`（`0x13F0928` 静态表 + `0x1014593` 字符串）。
5. 全文件**不存在** `{key_code, event_code}` 静态表；`InfraInputKeyList` 无静态实例。
6. 键表由 UIPC `INFRA_INPUT_UIPC_SETEVENTKEYLIST` 下发（表体在报文 `+0x10`，12B/项）。
7. 派发前必须已注册含该 `key_code` 的 key_list（`this[+0x9c]` 链表匹配）。
8. `config_pos < 0` ⇒ 该键不在运行时 key config 表 ⇒ 记 `unknown key` 并丢弃。
9. 抑制链：`internal_flag&1` 的 16B 比对（`do not`）、`(cbflags&2)==0 && (internal_flag&5)==0` 的 `(sub_key_code,status)` 去重（`same event`）。
10. 每键状态缓存 0x28B、回调项 0x30B、内部键表项 0x44B（步长与索引方式均反汇编可见）。

### 推测（结构/行为合理，但缺一条直接证据）
- `status` 的具体"按下/抬起"取值：倾向"成对数值 + `0x7FFFFFFC..FF` 为无效/保留"，但**没有**常量表可证。
- "UI 未注册含 0x1AC 的 key_list" 是"注入了 ADC 却无 UI 反应"的原因（与既有运行现象一致，但需运行时验证）。
- `InfraInputKeyList.event_code` 的实际用途（推测用于 init data / 老事件 API），因为派发侧未见其被读取改写。

### 未确定（明确未解决）
- `status` 完整枚举（按下/抬起/长按各是多少）。
- `0x0138331A` 那张 `(0x1AC, 0..0x11)` 的 u16 表语义（无 xref，形态不像 key→event）。
- `0x013F0898` 按键名表由谁使用（表首 3 处取址引用均未命中；可能整体按索引 + 基址访问，或仅调试）。
- `num` 与 `list_no` 的取值约定（`SetEventKeyList` 的 `listNo` 参数在注册表中如何分配）。

---

## 八、若要从运行时确认（具体到地址与内存结构）

即便静态已给出 `event_code = 0x1AC`，若要 100% 排除"某条 UIPC key_list 改写"，可按下列顺序验证：

1. **断点看传入的 event_code（最直接）**
   - 断点 `0x03D2D84`（`InputService` 转换器，`ldr r1,[r5]`）或 `0x03D2D8E`（`blx createEvent`）。
     命中后读 **`r1`** = `event_code`；读 `r5` 指向的 24B 结构：
     `+0x00 event_code, +0x04 tp_x(s16), +0x06 tp_y(s16), +0x08 status, +0x0c prev_status, +0x10 ex_info, +0x14 repeat`。
   - 或断点 `0x0862674`（`str.w r3,[r7,#0xc4]`），命中即 `r3 = event_code`、`[r7,#0xdc] = 物理 key_code`。
2. **读 InftraInput 单例与状态**
   - `InfraInput::GetInstance()`（`0x0860874`）→ 返回值 `this`（`0x224` 字节）。
   - `this+0x24` → 每键状态数组指针，项 0x28B，按 `config_pos` 索引；
     关心 `+0x04 sub_key_code`、`+0x08 status`、`+0x14 上次 status`、`+0x20 u8`、`+0x24 flags`。
   - `this+0x9c` → key_list 链表头；每节点 `+0x14 listNo`、`+0x28 count`、`+0x2c 项数组(0x44B/项)`；
     遍历项找 `+0x00 == 0x1AC`，读 `+0x04 event_code`、`+0x24 slot`。**若链表为空或找不到 0x1AC，
     就说明 §4.5 的"必须注册"条件不满足，这本身是最重要的运行时结论。**
   - `this+0x18` → 回调数组，项 0x30B（`+0x14 cbId`、`+0x18 osalId`、`+0x1c fn`、`+0x20 flags`、`+0x24 group`）。
3. **看 UIPC 下发内容**
   - 断点 `0x085E846`（`SetEventKeyList` 的 UIPC 调用）：`r2` = 表指针（报文 `+0x10`），`r3` = 项数，
     `r1` = cbId（`[r4+8]`）。把 `r2` 起 `12 * r3` 字节按 `{u32 key_code, u32 event_code, u32 status}` 打印，
     即可直接得到**副控制器实际下发的 (key_code → event_code) 映射**（这是唯一可能的"真表"来源）。
   - 若想拿到副控制器的原始帧：`RecvThread 0x0862D60` 的 `0x10114xx` 各命令日志（日志级别 `0x7A`）会打印 cbId/list_no。
4. **注入路径的最短方案**（不需要物理键）
   - 直接 `InputService::m_pMyInstance`(0x13F5E6C) → `createEvent(0x1AC, 4)` → `pushFilterEvent(ev)`；
     等价于绕开 InfraInput。若 UI 仍无反应，则问题在"UI 侧未注册该事件的 handler"，
     与 InfraInput 的 key_list 无关。

---

## 九、对"让 MENU 进 UI"这件事的直接含义

1. **数值问题已经不存在**：UI 侧事件 ID = `0x1AC`（= `KEY_TACT_MENU`），不需要"转换"。
2. **真正的门槛是注册/派发条件**，而不是码值：
   - `config_pos >= 0`（键必须在副控制器下发的 key config 表里）；
   - `this[+0x9c]` 链表里必须有含 `key_code=0x1AC` 的 key_list 项（否则 `MainThread` 直接跳过）；
   - `status` 必须与缓存不同（否则 `same event` 被去重）；
   - `internal_flag` 的 bit0/bit2 与回调 `flags` 的 bit1 会改变抑制行为。
3. 因此"用 ADC 电平模拟按键"即便驱动侧有值，也可能因为上述 1~2 条而**根本不产生事件**；
   更稳的做法是直接走 UI 侧 `createEvent(0x1AC,4)+pushFilterEvent`（见 §8.4）。

---

## 十、方法论备注（供后续复用）

1. **`libObj.so` 的字符串访问是"大偏移 PC 相对"**：惯用式
   `ldr rD,[pc,#imm]`（字面量是**偏移**）+ `add rD,pc`。
   **Thumb-2 的 `add rD,pc` 基址 = 指令地址 + 4，且不做 4 字节对齐**（本库实测；
   若按 `Align(A+4,4)` 算会差 2 字节，导致约一半字符串"看起来无人引用"——这是本次最大的坑）。
2. 静态字符串地址在 `.rodata`（`0xE3F128` 起），代码在 `.text`，相距可达 8 MB，
   所以**字面量池里存的是偏移而非绝对地址**；直接搜"字符串 VA 的四字节字"会 0 命中。
3. **内部调用全部走 PLT**：`SetEventKeyList` 等导出符号的直接 `BL` 数为 0，
   必须解析 `.plt`（12 字节/桩：`add ip,pc,#imm1; add ip,ip,#imm2; ldr pc,[ip,#imm]!`）
   → `.rel.plt` → `.dynsym` 才能找到调用者。**BLX 立即数的 imm10L 在第二半字的 bits[10:1]**，
   用 `hw2 & 0x3FE` 是错的（会漏掉全部 BLX 边，导致"没有调用者"的假结论——本次第二大坑）。
4. 判断"死串"要谨慎：本库有大量**编译进去但无引用**的 dump 串（如 `max_on/off/invalid`、
   `chg/rep/inh/flags`、`KeyConfigInfraInput {}` 整段），不能据此推断"功能不存在"，
   只能推断"该日志路径在本构建未启用"。

---

## 十一、脚本清单（均只读，不含 QEMU/写固件）

| 脚本 | 作用 |
|---|---|
| `02-脚本/libobj92_tools.py` | 工具库：VA/偏移换算、`.ARM.exidx` 函数表（59,630）、PC 相对引用索引、BL/BLX 调用图、反汇编 |
| `02-脚本/92_infra_key_map_scan.py` | ELF 段/节表与 InfraInput 字符串聚类 dump |
| `02-脚本/92_infra_key_map_scan2.py` | 全文件 `0x1AC` 扫描 + 原始字符串引用尝试（含失败原因） |
| `02-脚本/92_infra_key_map_scan3.py` | 候选表上下文 dump |
| `02-脚本/92_dbg_xref.py` / `92_dbg_xref2.py` | xref 机制定位（PC 相对/字面量假设的否证过程） |
| `02-脚本/92_dbg_infra.py` | InfraInput 函数反汇编 + 字面量解析 |
| `02-脚本/92_dumpfn.py` | **单函数反汇编 + PC 相对字面量/字符串自动解析**（最常用） |
| `02-脚本/92_locate.py` | 用自证签名串定位 static 函数（EventThread/MainThread/RecvThread/…） |
| `02-脚本/92_plt3.py` | `.plt`→符号解析 + 任意导出符号的调用点 |
| `02-脚本/92_keylist_args.py` | `SetEventKeyList` 全部 13 个调用点的参数准备反汇编 |
| `02-脚本/92_plt_xref.py` / `92_plt2.py` | PLT 解析的中间迭代（保留以说明过程） |

复现示例：
```powershell
cd '<WORKSPACE>\02-脚本'
python -X utf8 92_dumpfn.py 862662 C0        # MainThread 里 event_code = key_code 的赋值段
python -X utf8 92_plt3.py                     # 导出符号调用点
python -X utf8 92_keylist_args.py             # 13 个 SetEventKeyList 调用点
```
