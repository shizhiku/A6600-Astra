# 112 · a6600 四代内核输入模块 input.ko 的用户态事件通道
## —— 兼判四代/五代 InfraInput 在同一进程里的队列争用与事件定向方案

日期：2026-11-22。**纯静态分析**：只读 ext2 镜像与 ELF，不运行 QEMU、不修改任何现有镜像/脚本/文档。
本轮新增文件：本报告、`02-脚本/inputdrv_*.py`、`03-证据/静态分析/input_drv/`。

---

## 零、结论（TL;DR）

1. **`/kmod/input.ko` 是"按键扫描 + 事件通知"驱动，不产生 `/dev/input` 事件**。它对用户态只有两个接口：
   - **proc**：`/proc/udm/input`（udif/udm 框架落地，描述符里的相对名是 `input`；写 `table|get|adc|front|gpio|vgrip|multi_selector_soft` 选择模式，读回键表/ADC/GPIO/front/vgrip 的当前值）；
   - **OSAL/UIPC 消息队列**：驱动在 `0x00410025` 上注册自己的同步消息回调 `getkey_cb`（服务端），并向外部 qid 发送 4 类消息（客户端）。
2. **事件只走一条队列：`qid = 0x007A0020`，16 字节消息 `{u32 code, u32 0, u32 value, u32 opt}`，异步 `osal_snd_msg`**（失败时错误路径另发日志）。驱动同时把同一组 `{type, code, value, opt}` 写进日志服务 `0x008F013A`（`0x008F0313` 为同步回退）、时间戳取自 `0x00910042`——**这三个 qid 是 tlog/FileControl/时间服务，不是按键事件通道**（`libsencore.so`、`libObj.so` 里大量模块都在用同一组 qid 写日志）。
3. **OSAL 队列是"点对点单消费者"模型，不是广播，也不是共享内存环**：
   - qid 是**固定常量**（不是按 open 顺序分配）；
   - 队列对象只有一条按优先级排序的消息链 + 等待者链；`osal_rcv_msg_tmo` 每次**取走一条**（非阻塞 pop，或在等待链上排队后被唤醒）；
   - `osal_reg_sync_msg_queue_cb` 每个队列**只有一个槽**，重复注册返回 `-1024`；`osal_reg_msg_queue_cb` 的普通回调链虽然可挂多个，但 InfraInput 的收发**不使用回调注册**，只 poll `osal_rcv_msg_tmo`；
   - `osal_set_msgq_broadcast_mode` 需要显式调用才置位，这两个消费路径都**没有**调用。
4. **四代与五代的 InfraInput 使用完全相同的两条队列**（静态确证）：
   - `InfraInput::MainThread` 读 **`0x007A804C`**（`bit15=1` → 进程本地队列）；
   - `InfraInput::RecvThread` 读 **`0x007A0020`**（`bit15=0` → `/dev/uipc` 内核队列）；
   - RecvThread 收到输入驱动通知后，把解析出的 24 字节 `_InfraInputEvent` 通过 `0x85F398(qid=0x7A804C, …)` 投回 **MainThread 的本地队列**，由 MainThread 分发回调。
   - 四代 `libObj.so`：MainThread `0x862430`、RecvThread `0x862D60`；五代 `a5bObj`：MainThread `0x209C58`、RecvThread `0x20A588`（指令序列相似度 0.64 / 0.52，qid 完全相同）。
5. **双消费者影响**：**只要同一进程里四代与五代 InfraInput 实例都被创建，它们就必然抢同一条队列**——两边各 4 条 `I-Input*` 线程用无限超时阻塞在同一个 qid 上，每条事件只会被其中一个线程取走，**不会双方都收到**。谁先拿到由线程调度/启动顺序决定；四代由 im.elf 早期链路创建、通常先到，所以 MENU/ENTER 多数会被四代取走。
   **即使只有四代实例**，由于 ASTRA 里四代 `InputService` 没启动、MainThread 没有已注册的 key_list，事件即使被四代取走也会被**静默丢弃**（文档 92 §4.1 条件 4）。这能解释"五代 key_status 只收到 2 条早期事件"。
6. **让五代收到 MENU/ENTER 的优先级建议**：
   - **A（首选，已存在可复用补丁）**：阻止四代 InfraInput 取事件——`03-证据/静态分析/imdb4/imdb4_libObj_noInputThreads.so` 把四代构造器里 4 处 `BLX osal_create_waitable_thread` 改成 `nop`（偏移 `0x8606A0/0x8606E4/0x860728/0x86076C`），单例/API 保留；或更外科式：把四代 Main/Recv 的 qid 字面量改到死 qid（偏移 `0x86270C`、`0x86301C`、`0x863150`，见 §7.1）。
   - **B**：给五代独立队列（内核 `input.ko` 补丁 + 五代 `a5bObj` 补丁，改 1+3 个 dword）；代价是需重打包 usr 镜像。
   - **C**：进程内直接向五代实例派发（LD_PRELOAD，dlopen `a5bObj` + `dlsym` 五代 `InfraInput::GetInstance`，再调用其内部 event 派发/投递函数）；适合诊断与 A 之后的补充注入，单独使用仍会被四代抢。
   - **D**：驱动层新增"第二目标 qid"（最侵入，不推荐）。
7. 四代与五代的内核输入模块 `/kmod/input.ko` **代码完全相同**（33768 B，仅 `.note.gnu.build-id` 与 `.comment` 不同；第 5 代镜像里的同名文件与四代仅有 36 字节差异）。所以"代差"不在驱动，而在**同进程内两个 InfraInput 实例共用同一条固定 qid**。

---

## 一、对象、提取与可复现数据

| 对象 | 四代 a6600 镜像内路径 | 五代 zv1m2 镜像内路径 | 大小 | SHA-256（四代） |
|---|---|---|---|---|
| 内核输入模块 | `/kmod/input.ko` | `/kmod/input.ko` | 33 768 | `71cbca3d5a1bb2c2f35b4ba1ca296f717cbc4eb63a78b900b30d1a87df48cc32` |
| OSAL 内核模块 | `/kmod/osal_uipc.ko` | 同 | 38 872 / 39 028 | `e727ab20606557fb9976ab16e1b7085e6bdd11e8f3b0218981dbde590a17eedb` |
| OSAL 用户态库 | `/lib/libosal_uipc.so` | 同 | 26 644 / 26 692 | `eecc322b81ebf63b…`（见清单） |
| 四代 UI/输入库 | `/lib/libObj.so` | — | 20 889 004 | `ebb6cd0475ebfdb5…` |
| 五代 UI/输入库 | — | `/lib/libObj.so`（ASTRA 里改名 `a5bObj.so`） | 3 931 624 | — |
| 副控制器传输 | `/lib/libsencore.so` | — | 349 760 | `bebdf7ba6fc14b27…` |
| 引导进程 | `/bin/im.elf` | `/bin/im.elf` | 21 820 / 23 240 | — |

- 提取脚本：`02-脚本/inputdrv_extract.py`（复用 `02-脚本/a6600_usr.py::Ext2`，只读）→
  `03-证据/静态分析/input_drv/{g4,g5}_*.{ko,so,elf}` + `input_drv_manifest.json`。
- 镜像：`05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15`（ext2，215 517 184 B）与
  `05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15`（ext2，530 345 984 B）。
- **四代/五代 `input.ko` 对比**：逐字节 diff 只有 36 B（`.note.gnu.build-id` 20 B + `.comment` 16 B）；
  `.text/.init.text/.rodata/.data` 完全一致 → **同一份驱动代码**。

---

## 二、input.ko 的结构（符号与接口面）

`input.ko` 是 **ET_REL / ARM(ARM 模式) / Linux 3.0.27** 内核模块，**未 strip**，`.symtab` 完整：

| 节内地址 | 大小 | 符号 | 作用（本轮确认） |
|---|---:|---|---|
| `.init.text+0x0000` | 3104 | `kbd_init` | 读 Backup 键表/配置、初始化定时器、注册消息回调 |
| `.init.text+0x0C20` | 48 | `init_module` | `udif_driver_register(&udif_input, 1)` |
| `.text+0x0000` | 188 | *(static)* | ADC 服务同步 RPC 包装（qid `0x720018`，40 B 消息，两段请求） |
| `.text+0x00BC` | 152 | *(static)* | front 服务同步 RPC 包装（qid `0x280132`，24 B），失败打印 `kbd: front uipc error` |
| `.text+0x0154` | 80 | *(static)* | vgrip 服务同步 RPC 包装（qid `0x18A04D1`，8 B），失败打印 `kbd: vgrip uipc error` |
| `.text+0x01A4` | 732 | `kbd_write_proc` | `/proc/udm/input` 写回调（模式选择） |
| `.text+0x0480` | 1344 | *(static)* | 键表/配置处理组（含 `kbd_set_config_*` 字符串） |
| `.text+0x0A20` | 384 | *(static)* | **事件日志信封发送器**（到 `0x8F013A`，回退 `0x8F0313`） |
| `.text+0x0BA0` | 368 | *(static)* | **按键事件通知器**（到 `0x7A0020`；同时写日志信封） |
| `.text+0x0D10` | 356 | *(static)* | 按键类型分派（ADC/GPIO/front/vgrip 跳转表） |
| `.text+0x121C` | 32 | `getkey_cb` | 驱动自有队列 `0x410025` 的同步消息回调（getkey 服务） |
| `.text+0x123C` | 3868 | `kbd_read_proc` | `/proc/udm/input` 读回调（dump 键表/当前值；可主动触发 getkey 拉取） |
| `.text+0x21E4` | 5872 | `kbd_timer_hndlr` | 定时器主循环：拉取 3 路键数据 → 查表 → 事件通知 |
| `.text+0x3A58` | 376 | `kbd_close` | 注销 `0x410025` 回调（`osal_unreg_msg_queue_cb`）、删定时器、释放 |
| `.text+0x3BD0` | 64 | `kbd_suspend` | suspend |
| `.text+0x3C10` | 1132 | *(static)* | open/注册路径：`osal_reg_sync_msg_queue_cb(qid=0x410025, cb=getkey_cb)` |
| `.text+0x407C` | 68 | `kbd_resume` | resume |
| `.text+0x40C0` | 124 | `kbd_probe` | `udif_create_proc(...)` |
| `.text+0x413C` | 396 | `free_infmb` | 释放 |
| `.exit.text` | 492/48 | `kbd_exit`/`cleanup_module` | 注销驱动、删 proc、释放键表 |

驱动描述符对象 `udif_input` 在 `.data+0x2C`（100 B）：
- `.data+0x18`：proc 描述符 `{ name="input"(.rodata.str1.1+0x237), read=kbd_read_proc, write=kbd_write_proc, priv=.bss+0x5C }`；
- `.data+0x34`：`"input"`，`.data+0x40`：`"1.5.2"`（版本串）；
- `.data+0x00..0x0C`：四个 `0x7FFFFFFF`（键状态初值），`.data+0x14`：`-1`。
- 模块参数（`.rodata` 里 `is_representative_entry` / `key_tbl` / `Input_debug` / `multi_selector_soft`）只影响调试打印与键表选取，**不决定 proc 节点是否出现**（与文档 84c 一致）。

**proc 节点真实路径**：Sony UDIF 框架把相对名挂到 `/proc/udm/` 下 → **`/proc/udm/input`**（文档 84c 已由运行日志确认，与本轮 `.data` 描述符一致）。
写命令（`kbd_write_proc` 用 `strncmp` 逐个匹配，然后用 `simple_strtoul` 取值）：
`table`、`get`、`adc`、`front`、`gpio`、`vgrip`、`multi_selector_soft`（另含 `check-only` 调试串）。
读回内容由 `kbd_read_proc` 按当前模式 dump 键表与实测值（`*** ADC/GPIO/FRONT(CA)/VGRIP KeyConfig ***`、`getkey_adc/gpio/front/vgrip %08x, %08x` 等）。

> **注意**：`/proc/udm/input` 是**键表/诊断**接口，不是事件推送接口。经它 `echo adc/get` 只能读当前电平并按需触发一次事件；它本身不保存事件队列。

---

## 三、input.ko 的 OSAL/UIPC 接口（本轮核心）

### 3.1 驱动注册的队列（服务端）

`.text+0x3C10` 的注册路径（两代相同）：

```
osal_reg_sync_msg_queue_cb(qid = 0x00410025, &cb_desc, getkey_cb, 0x00410025)
```

- `0x00410025` = 驱动自己的**同步回调队列**，`getkey_cb`（`.text+0x121C`，32 B）是唯一处理函数；
- `kbd_close`（`.text+0x3A98`）用同一 qid `osal_unreg_msg_queue_cb` 注销；
- 这是驱动对外的 **getkey RPC 服务端**：对端向 `0x410025` 发同步消息，`getkey_cb` 在消息里回填按键/ADC/GPIO 数据（与 `kbd_read_proc` 的 `getkey_*` dump 同源）。

### 3.2 驱动发送的 4 类消息（客户端）

`kbd_timer_hndlr` 每轮先**同步拉取**三路键数据，再对发生变化的键**异步通知**事件：

| 目标 qid | 消息大小 | 发送 API | 来源/失败日志 | 作用 |
|---|---:|---|---|---|
| `0x00720018` | 40 (0x28) | `osal_valloc_msg_wait` + `osal_snd_sync_msg` ×2（`.text+0x0000` 包装） | `osal_alloc_msg(liro_adc)`/`*** ADC UIPC data ***` | ADC 键数据拉取（两段子请求） |
| `0x00280132` | 24 (0x18) | `osal_snd_sync_msg`（`.text+0x00BC`） | `kbd: front uipc error` | front(CA) 键数据拉取 |
| `0x018A04D1` | 8 | `osal_snd_sync_msg`（`.text+0x0154`） | `kbd: vgrip uipc error` | vgrip 键数据拉取 |
| **`0x007A0020`** | **16 (0x10)** | **`osal_snd_msg`（异步）**（`.text+0x0BA0`） | `input(kbd):osal_snd_msg err` / `ERR:SND` | **按键事件通知（唯一事件通道）** |
| `0x008F013A`（回退 `0x008F0313`） | `0x18+len` | `osal_snd_msg` / `osal_snd_sync_msg`（`.text+0x0A20`） | — | **日志/FileControl 信封**（不是事件） |
| `0x00910042` | 32 | `osal_snd_sync_direct` | — | 取时间戳（日志信封 +0x10 的 8 B） |

> 三个"拉取"目标 qid（`0x720018/0x280132/0x18A04D1`）的队列 owner 不在本轮定位范围内（不在 libObj/libsencore 中；应是其它内核任务/模块）。它们与事件通道**无关**——事件只从驱动发往 `0x7A0020`。

### 3.3 事件通知消息布局（`0x7A0020`，16 字节）

由 `.text+0x0BA0` 静态还原（调用参数 `(type, code, value, opt)`，r8/r5/r4/r6）：

```
偏移   类型    值/来源                         证据
+0x00  u32    code        = arg1            0xc34: str r5,[msg]
+0x04  u32    0                             0xc38: stmib {r1,r4,r6}，r1=0
+0x08  u32    value       = arg2            同上
+0x0C  u32    opt         = arg3            同上
块头 -0x04    0x00410025（发送方 qid 标签，推测：驱动自己的服务队列）  0xc20: ldr r2,=0x410025; str r2,[msg,#-4]
```

> `msg-4` 写入的是驱动自己的回调队列 qid `0x00410025`。结合 OSAL 的同步消息约定（文档 78 §4.5：请求里带回复 qid），
> 合理推测它的语义是"发送方/回复队列标签"；接收侧如何使用它未逐行确认（见 §8 不确定项 1）。

- 发送前 `osal_valloc_msg_wait(0x7A0020, &msg, 0x10, 1)`（1 = 带超时分配）；
- `osal_snd_msg(0x7A0020, msg)` 失败时：`osal_free_msg` + 打印 `input(kbd):osal_snd_msg err:%d`，并额外把错误串 `ERR:SND` 作为日志负载发往 `0x8F013A`；
- 成功时：把 `{arg0=type, arg1=code, arg2=value, arg3=opt}` 这 16 B 作为**日志负载**再发往 `0x8F013A`，并在调试开关下打印
  `kbd send osal type:%d code:%x value:%x opt:%x`。

`kbd_timer_hndlr` 的 4 个事件发送点（均取"键表项 + 状态缓存"两处字段）：

| 调用点 | 参数来源 |
|---|---|
| `.text+0x2764` | `arg0=[键表项+0x04]`, `arg1=[键表项+0x24]`, `arg2/arg3=[r4]/[r4+4]` |
| `.text+0x2ADC` | 同上（GPIO 分支，前有 `GPIO act:%d data:%02x(%02x)` 日志） |
| `.text+0x2FA4` | 同上（另一套键表，配合 `.text+0x2B58` front 拉取） |
| `.text+0x3744` | 同上（配合 `.text+0x3068` vgrip 拉取） |

> §3.3 的**字段偏移**由代码写入顺序确证；`type/code/value/opt` 的**业务命名**来自同函数调试串。
> `code` 与 `InfraInput` 里 `key_code`/事件码的对应关系见 §5.2 与 §8 的不确定项。

### 3.4 日志信封（`0x8F013A`）—— 与事件无关

`.text+0x0A20` 构造 40 B 固定头 + 负载：

```
+0x00 u16 = 2（正常）/ 0x0F（回退路径）
+0x02 u16 = 0x41
+0x04 u32 = 0
+0x08 u32 = len（负载长度）
+0x0C u32 = （未显式写，保持 valloc 初值）
+0x10 u64 = 时间戳（由 0x910042 的 32 B 同步直发取回，取缓冲 +0x18 的 8 B）
+0x18 ... 负载（len 字节）
```

交叉证据：`libsencore.so` 中 `FileControl(SenserPacket)`、`tlog_update_file`、`Blog::write` 都在向 `0x8F013A/0x8F0313/0x910042` 发消息；`libObj.so` 里共有 162 处 `0x8F013A` 字面量，绝大多数是各模块的**日志**调用。所以驱动的这条链是"把按键诊断写进 tlog"，**不是事件分发**。

---

## 四、UIPC/OSAL 队列语义（点对点判定，静态确证）

对象：`03-证据/静态分析/input_drv/g4_osal_uipc.ko`（保留 `.symtab`，91 个函数）与
`g4_libosal_uipc.so`（88 个 PLT 项）。五代两份文件与四代**逻辑同源**（关键函数归一化后逐指令相同，仅字符串/偏移不同）。

### 4.1 qid 位域与双路由（用户态库 `libosal_uipc.so`）

```
qid (28 位有效) = [ group(12) | bit15 | index(15) ]
   bit15=0 → 跨进程：ioctl(/dev/uipc) 交给内核 msgq
   bit15=1 → 进程本地：libosal_uipc 内部的 msgq 表（index = qid & 0x7FFF）
```

- `osal_snd_msg`/`osal_rcv_msg_tmo`/`osal_reg_msg_queue_cb` 开头均有 `tst r0,#0x8000` 分支（`inputdrv_libosal_uipc_g4_osal_*.dis.txt`）；
- 内核侧 `osal_snd_msg`/`osal_rcv_msg_tmo` 等反过来要求 **bit15=0**（bit15=1 直接返回 `0xFFFFFC00`），即内核队列只承载跨进程 qid。

### 4.2 队列对象与投递

```
struct msgq {
  +0x04 u8 flags（bit0 日志 / bit1 忙 / bit3 qid 校验）
  +0x08 cb 链头（注册的 msg 回调）
  +0x0C head  消息链头
  +0x10 tail  消息链尾
  +0x14 ...   （等待者/统计）
  +0x18 同步回调槽（单槽）
  +0x1C 注册的完整 qid（校验用）
}
```

- 发送：按 `pri`（消息块 `+0x05`）插入 `head/tail` 单链表；随后唤醒"一个"接收方；
- 接收（用户态 `osal_rcv_msg_tmo`，VA `0x3ED8`，见 `inputdrv_libosal_uipc_g4_osal_rcv_msg_tmo.dis.txt`）：
  - 队列非空 → `*out = q->head + 0xC`；`q->head = block->next`；**取走一条**；
  - 队列空 → 构造 32 B 等待者结构挂到 `q+8` 等待链，`do_sleep_tmo(…, timeout)`；被唤醒后要么拿到消息，要么超时；
- 内核侧 `osal_rcv_msg_tmo`（VA `0x34F0`）同构（`__rcv_msg_cb` 把 `q->head+0xC` 写给等待者并 `wake_up_process`）。
- **没有"复制给所有消费者"的逻辑**；等待链被唤醒时只服务一个等待者。

### 4.3 注册语义

- `reg_sync_msg_queue_cb`（内核 VA `0x2FFC`）：若 `q+0x18` 已有同步回调 → **返回 `0xFFFFFC00`（-1024，"已存在"）**；否则占槽。
  → 同一 qid 的"同步回调注册"是**独占**的。
- `osal_reg_msg_queue_cb`（内核 VA `0x3B50`）：分配 cb 对象、`cb+0x14=fn`、`cb+0x18=arg`、`cb+8=__default_cb`，再经 `0x2EEC` 挂到 `q+8` 回调链；若已有回调且新 cb 未标记，会打印告警但**仍挂链**（普通回调链可多挂）。
- `osal_set_msgq_broadcast_mode`（内核 VA `0x3D04`）：仅置 `flags` 某位并清 `q+0x14`，需要显式调用；**驱动与两代 InfraInput 都不调用它**（本轮扫描 `osal_calls` 里无该符号调用点）。
- 本轮两个消费路径（`InfraInput` Main/Recv）**都不注册回调**，只 `osal_rcv_msg_tmo` 轮询/阻塞等待 → 走 §4.2 的"单条取走"语义。

### 4.4 判定结论

| 问题 | 结论 |
|---|---|
| 点对点还是广播？ | **点对点（单消费者）**。没有共享内存环；队列只有一条消息链，取走即消失。 |
| 两个实例都登记会都收到吗？ | **不会**。两个线程阻塞在同一 qid 的等待链上时，一条消息只唤醒/交付其中一个；轮询模式下同样只有一个 `rcv` 拿到。 |
| 谁先读谁拿？ | 由调度决定；启动早、优先级高、先进入等待的线程概率更大（四代通常先启动）。 |
| 队列 ID 固定还是按 open 顺序分配？ | **固定常量**（`0x7A0020`、`0x7A804C` 直接编译进代码；不是动态分配）。`osal_dynamic_id` 只用于请求/应答的临时 qid，与本通道无关。 |

---

## 五、消费者侧：两代 InfraInput 的队列与事件链

### 5.1 四代 libObj（`/lib/libObj.so`）—— 文档 92 的地址在本轮被独立复核

| 角色 | 地址 | 读/写队列 | 证据 |
|---|---|---|---|
| `InfraInput::MainThread` | `0x862430`（size 0x780） | `osal_rcv_msg_tmo(0x007A804C, &msg, -1)`；`osal_free_msg(0x7A804C,msg)` | `inputdrv_qidmap_g4.json` / `inputdrv_qid_confirmed.json` |
| `InfraInput::RecvThread` | `0x862D60`（size 0x3F8） | `osal_rcv_msg_tmo(0x007A0020, &msg, -1)`；`osal_free_msg(0x7A0020,msg)` | 同上 |
| 事件回投 | RecvThread 尾部 `0x863120-0x86313E` | 调 `0x85F398(this, qid=0x7A804C, &event24, 24, 0, …)` | `0x863136 ldr r1,=0x7A804C` |
| 通用投递器 | `0x85F398` | 内部：`valloc(qid, &m, len, 1)` → `memcpy` → `osal_snd_msg/snd_sync_msg(qid,m)` | Thumb 反汇编（见 §9 证据） |
| 日志（不是事件） | `0x862A76/0x862AB2` | `valloc/snd_sync_msg(0x8F013A, 0x34)` | 同上 |

`MainThread` 对每条 24 B `_InfraInputEvent` 的约束（文档 92 §4.1）：
`config_pos = msg+0x10`、`internal_flag = msg+0x14`、去重(条件3)、**必须已在 key_list 链表中登记 key_code（条件4）**，否则**取走并丢弃**。

### 5.2 RecvThread 的事件转换（四代，`0x862D60`）

- 收到 `0x7A0020` 的 16 B 记录后，按 `{command, size, params…}` 记录格式 dump；
- 用记录第 1 个字（= 驱动写入的 `code`）作为 **key_code** 去内部键表找槽（`0x861278`）；
- 取 `GetPhyKeyStatusCache/GetPhyKeyStatus`（`0x861534`）得到当前物理键状态；
- 组装 24 B `_InfraInputEvent`（`event_code = key_code` 直通；`tp_x/tp_y`、`status`、`prev_status`、`ex_info`、`repeat`），
  再经 `0x85F398` 投到 **进程本地队列 `0x7A804C`**，由 MainThread 取走并分发回调。
- 驱动 16 B 记录与 `_InfraInputEvent` 的字段对应只到"`code`→key_code、`value/opt`→状态缓存输入"这一级；`+0x04=0` 的用途未定（见 §8）。

### 5.3 五代 `a5bObj`（`/lib/libObj.so`，3 931 624 B）—— 同队列

| 角色 | 地址 | 读/写队列 | 证据 |
|---|---|---|---|
| `InfraInput::MainThread` | `0x209C58` | `osal_rcv_msg_tmo(0x007A804C)`；日志 `valloc/snd_sync_msg(0x8F013A,0x34)` | `inputdrv_qidmap_g5.json`；与四代 `0x862430` 归一化指令序列相似度 **0.64**（次优 0.17） |
| `InfraInput::RecvThread` | `0x20A588` | `osal_rcv_msg_tmo(0x007A0020)`；回投 `0x20A978 → 0x7A804C` | 同上；相似度 **0.52**（次优 0.13） |
| `RepeatThread` | `0x20A980` | `osal_snd_sync_direct(0x910042/0x910041)` | 与四代 `0x863158` 同构 |
| `InfraTp` 等兄弟端点 | `0x201A6C` 等 | 读 `0x7B0026`、`0x7B80CF`、`0x7C8075` 等自身队列 | 与四代同名端点队列**逐一相同** |

**五代 `infra_input_init` 的差异**（`imdb4/a5bObj_infra_input_init_dis.txt` 已确认）：
- 四代 `infra_input_init`（`0x8603A5`）：只打日志，**不创建实例**；
- 五代 `infra_input_init`（`0x208134`）：打日志后 `b.w 0x3A5A0`，该 PLT 桩的 GOT 槽解析为
  **`_ZN10InfraInput11GetInstanceEv`** → **调用即创建五代单例并启动 4 条 `I-Input*` 线程**。
- 因此 ASTRA 桥接器里 `run_init(a5bObj, "infra_input_init")` 这一步本身就会把**五代** InfraInput 拉起来（`04-产物/97_astra_bridge5.c:106`）。

### 5.4 完整事件链（四代，静态还原）

```
input.ko::kbd_timer_hndlr
  ├─ 同步拉取 ADC/front/vgrip 帧（0x720018 / 0x280132 / 0x18A04D1，msg-4=0x410025）
  └─ 状态变化 → input.ko::.text+0x0BA0
        ├─ osal_snd_msg(0x007A0020, {code,0,value,opt})        ← 唯一事件通道
        └─（日志）0x008F013A 信封 + 0x00910042 时间戳
                       │
             ┌─────────┴───────── (跨进程内核队列 0x7A0020)
             ▼
        libObj::InfraInput::RecvThread  (0x862D60)
             ├─ 解析 16B 记录 → 查内部键表 → 取当前物理键状态
             └─ 0x85F398(this, 0x007A804C, &event24, 24)      ← 进程本地队列
                       │
             ┌─────────┴───────── (bit15=1 本地队列 0x7A804C)
             ▼
        libObj::InfraInput::MainThread  (0x862430)
             ├─ config_pos/internal_flag/去重/key_list 过滤
             └─ 已注册回调（InputService::callback_direct 等）
                       │
                       ▼
             libObj::InputService → createEvent / pushFilterEvent → UI
```

五代 InfraInput 是**同一条链的另一个副本**（RecvThread→`0x7A804C`→MainThread→appFw 注册的回调）。
**注意**：`RecvThread` 与 `MainThread` 之间是 `0x7A804C` 这个"bit15=1 的进程本地队列"——所以即使驱动侧只发一份，只要**同进程**有两个 InfraInput 实例，它们的 RecvThread 抢 `0x7A0020`、MainThread 再抢 `0x7A804C`，两层都会出现"单条消息只归一个消费者"的竞争。

---

## 六、双消费者影响判断（回答任务问题 2）

### 6.1 会不会抢同一条队列？

**会，且有两处竞争点**（前提：同一进程内两个 InfraInput 实例都被创建）：

1. `0x7A0020`（驱动→RecvThread，跨进程内核队列）：两侧 RecvThread 各有一条线程以 `-1`（无限）超时阻塞在该 qid；内核 `wakeup` 只服务一个等待者 → 驱动每条事件只交一边。
2. `0x7A804C`（RecvThread→MainThread，进程本地队列）：两侧 RecvThread 都会往里投、两侧 MainThread 都在等；同样单条取走。

### 6.2 两边都会收到吗？

**不会。** 机制上不存在 fan-out：队列只有一条消息链，无广播副本；`osal_set_msgq_broadcast_mode` 未被调用；回调注册模式也未被 InfraInput 使用（且 sync 回调槽是独占的，重复注册返回 -1024）。

### 6.3 谁先读谁拿？队列 ID 固定吗？

- 队列 ID 是**固定常量**，不是按 open 顺序分配；两代代码里是同一组数字。
- "谁拿"= 调度竞争：先进入等待/先被唤醒的一方拿走。四代 InfraInput 通常由 im.elf 的早期 4 代链路（`libBizFw2.so`/`libNetRemote.so`/`libUsbChargingApp.so` 等导入 `InfraInput::GetInstance`，见 `imdb4/imdb4_usrscan.txt`）先创建 → 大概率四代先阻塞、先拿走 MENU/ENTER。
- 五代侧只拿到"注册回调时的 `SendEventInitData` 初始化事件 + 初始化阶段的少量事件"（对应运行期观测到的"key_status 仅 2 条早期事件"）是**符合该竞争模型**的解释。

### 6.4 即使只有四代实例，也会丢事件

`MainThread` 分发前要求 `this[+0x9c]` 的 key_list 链表里有该 `key_code` 的登记（文档 92 §4.1 条件 4）。ASTRA 镜像里四代 `InputService` 没有被启动（`createEvent` 70 s 内 0 次），key_list 多半为空 → **四代取走的事件被静默丢弃**。这也是"五代没收到"的另一条独立原因。

### 6.5 需要运行期确认的一点

静态上"两代实例都会创建"的两条链路都成立：
- 五代：`a5bObj::infra_input_init` → `GetInstance()`（桥接器显式调用）；
- 四代：多个 4 代库/模块导入 `InfraInput::GetInstance`，任一在 ASTRA 进程内执行即创建四代实例。

但两代线程同名（`I-InputMain/I-InputRecv/I-InputEvent/I-InputRepeat`），仅凭线程名无法区分"3 条线程"属于哪一代。建议的运行期判定：
1. `grep -c I-Input /proc/<im.elf pid>/task/*/comm` —— 单代应为 4 条，双代应为 8 条；
2. 在 `0x862464`（四代 MainThread rcv）与 `0x209C8C`（五代 MainThread rcv）分别下断点，看谁命中；
3. `cat /proc/osal/uipc` 看 `0x7A0020` 的队列/等待者计数（两代都会出现在等待链上）。

---

## 七、让五代 InfraInput 收到 MENU/ENTER 的可行方案（按优先级）

前提事实（来自文档 92/92_menu_map）：**MENU 的 key_code = `0x1AC`，ENTER = `0x1AD`**；`_InfraInputEvent` 24 B：
`+0x00 event_code、+0x04 tp_x(u16)、+0x06 tp_y(u16)、+0x08 status、+0x0C prev_status、+0x10 ex_info、+0x14 repeat`。
注入的目标是让五代 `InfraInput::MainThread` 在**它自己的**实例上取到事件并分发给 appFw/key_status 注册的回调。

### 7.A（首选）阻止四代 InfraInput 消费

**A1 · 直接复用既有补丁（最低风险，已生成）**
`03-证据/静态分析/imdb4/imdb4_libObj_noInputThreads.so`：
- 四代 `InfraInput` 构造函数中 4 处 `BLX osal_create_waitable_thread` → `nop;nop`；
- 偏移（文件偏移 = VA，四代 libObj `.text` 满足 VA==文件偏移）：`0x8606A0`、`0x8606E4`、`0x860728`、`0x86076C`；
- 效果：四代单例与 `SetCallback/SetEventKeyList/GetEventStatus` 等 API 全部保留（其它四代库不会空指针崩溃），但**4 条取事件线程不再创建** → 不再有人读 `0x7A0020/0x7A804C`；
- 代价：五代侧接管全部事件；若有四代代码依赖这些线程的信号量/等待，需要实测（该补丁尚未在 ASTRA 上验证，见 §8）。
- 关联补丁（仅供定位）：`imdb4_libObj_noInputInstance.so` 使 `GetInstance` 直接返回 NULL（偏移 `0x860874` 改成 `movs r0,#0; bx lr`），会崩未判空的四代调用方，**不建议进主线**。
- 若想连"记录 31 的 infra_input_init"也一起跳过：`imdb4_libIMDB_rec31_noinit.so`（record31 init 指针清零，偏移 `0x6128`）。因四代 `infra_input_init` 本身只是日志桩，这一步不是必需。

**A2 · 更外科式：把四代 InfraInput 的两条队列改成死 qid（本报告新给出）**
只 patch 四代 `libObj.so` 中 InfraInput 自己的 3 个 qid 字面量（VA==文件偏移）：

| 文件偏移 | 原值 | 含义 | 建议改为 |
|---:|---|---|---|
| `0x86270C` | `0x007A804C` | 四代 MainThread `osal_rcv_msg_tmo` 队列 | `0x007A8060`（bit15=1，本地 index 0x60，无人使用） |
| `0x86301C` | `0x007A0020` | 四代 RecvThread `osal_rcv_msg_tmo` 队列 | `0x007A0030`（bit15=0，内核队列，无生产者） |
| `0x863150` | `0x007A804C` | 四代 RecvThread 回投 MainThread 的目标 | 同 `0x007A8060` |

- 一致性：四代实例内部自洽（RecvThread 投到自己 MainThread 的新 qid，但没人再发事件给它），行为=永久空闲；
- 不影响五代（五代 `a5bObj` 自有同名常量，文件不同）；
- 注意：四代 `ReleaseInstance`/析构里也会用到 `0x7A0020` 派生值（`0x7A0027/28/29`，见 `0x8600F0`），它们不是事件路径，可不动；
- 验证：patch 后四代 MainThread/RecvThread 应阻塞在新 qid 上（`/proc/<pid>/task/*/wchan`），五代 MainThread 应开始命中。

**A3 · 运行期隔离（仅诊断）**：QEMU 断点/信号暂停四代 4 条 `I-Input*` 线程；或用 gdb 改四代实例里的 qid。不能用于交付镜像。

### 7.B 给五代独立队列（需改内核驱动 + 五代库）

1. **驱动侧**：把 `input.ko` 事件目标 qid `0x007A0020` 改为新值（例如 `0x007A0030`）。
   - 字面量在 `.text` 内 VA `0x0CF0` → 文件偏移 **`0x0D24`**（`.text` sh_offset=0x34）；该 dword 唯一，`0x0BA0` 的 `valloc` 与 `snd_msg` 共用；
   - `kbd_read_proc` 的诊断路径另有一份 `0x720018/0x280132/0x18A04D1` 字面量（`0x16xx~0x20xx` 附近），与事件无关可不改。
2. **五代库侧**：把 `a5bObj` 的 3 个 qid 字面量改为同一新值：
   - `0x20A844`：五代 RecvThread `osal_rcv_msg_tmo(0x007A0020)` → 新 qid；
   - `0x209F34`：五代 MainThread `osal_rcv_msg_tmo(0x007A804C)` → 新的本地 qid（如 `0x007A8060`）；
   - `0x20A978`：五代 RecvThread 回投 MainThread 的目标 → 同上新本地 qid。
   - 五代的 `0x7A804C` 必须保持 bit15=1（进程本地），`0x7A0020` 改为 bit15=0 的新内核 qid；两者不能混。
3. 风险：`/kmod/input.ko` 在 usr 分区，需重打包 usr 镜像；项目历史上 usr 改动曾导致启动问题（文档 60–63），所以优先级低于 A。

### 7.C 进程内直接向五代派发（LD_PRELOAD，诊断/补充注入）

思路（不改驱动、不改镜像）：
1. `dlopen("/usr/lib/a5bObj.so", RTLD_NOLOAD|RTLD_LAZY)` 拿到五代库句柄（或从 `/proc/self/maps` 找基址）；
2. `dlsym(handle, "_ZN10InfraInput11GetInstanceEv")` → 五代单例指针；
3. 按 24 B `_InfraInputEvent` 造事件（`event_code=0x1AC` MENU / `0x1AD` ENTER，`status` 取值需实测，见 §8），
   然后调用五代实例的内部事件派发/投递函数：
   - 优先：五代 `SendAttachEvent` 类函数（四代 `0x86092C`，可直接调用会把事件分发给已注册回调；五代对应地址需按 g4↔g5 相似度定位，本轮未逐一确认）；
   - 或：调用五代 RecvThread→MainThread 的投递 helper（四代 `0x85F398` 的同构函数）向**五代自己的** `0x7A804C` 投 24 B 事件——**单独使用会被四代 MainThread 抢**，因此必须配合 A（或先验证四代线程不存在）。
4. 这属于"运行期注入"，不能替代 A/B 的持久修复，但可作为**快速验证五代 key_status 是否通路正确**的手段（若 C 注入后 key_status 有反应，说明五代链路本身 OK，问题就是队列争用）。

### 7.D 驱动层扩展（不推荐）

在 `input.ko` 里增加"每个事件同时发第二个 qid"或"发给指定订阅者列表"，需要改内核模块并重打包；语义/风险都高于 A/B。

### 7.E 不建议的方向

- **把四代 `InputService` 补起来**：这只会让四代更完整地消费事件，五代仍然收不到；解决点是"别让四代 InfraInput 取"，不是"让四代有消费者"。
- **只改 `libIMDB` 跳过 record31**：四代 `infra_input_init` 是日志桩，跳过它不阻止四代实例被其它模块创建，单独使用无效。

### 7.F 验证矩阵（建议最小实验顺序）

| 实验 | 期望 |
|---|---|
| ASTRA + A1（noInputThreads libObj） | `/proc` 中 `I-Input*` 只剩 4 条（五代）；五代 `key_status` 在 MENU 注入后收到事件 |
| ASTRA + A2（改四代 qid） | 四代 4 线程仍在但阻塞在新 qid；五代收到事件 |
| 仅 ASTRA（现状） | 8 条（或部分）`I-Input*`、四代线程抢走事件、`createEvent=0` |
| ASTRA + C（直接注入五代） | 五代 key_status 有反应 → 证明五代链路 OK、问题在队列争用 |

---

## 八、不确定项 / 边界（明确标注）

1. **驱动 16 B 记录与 `_InfraInputEvent` 的字段级映射**：`code` 被 RecvThread 当 key_code 用（`0x861278` 查键表）已确证；`value/opt` 进入状态缓存的哪一字段、`+0x04=0` 的含义，只到"状态缓存/抑制条件"这一级，未逐字段证明。
2. **`0x720018/0x280132/0x18A04D1` 的队列 owner**（哪个内核任务/模块提供 ADC/front/vgrip 数据）本轮未定位；不影响事件通道结论。
3. **四代/五代实例是否同时创建**：静态链路两边都成立；运行期可用 §6.5 的三种方法确认（线程数 / 双断点命中 / `/proc/osal/uipc` 等待者）。
4. **`_InfraInputEvent.status` 的按下/抬起取值**：固件无静态枚举（文档 92 结论），本报告不假设具体值；A1/A2 修复后由真实驱动事件自动携带。
5. **A1 补丁的副作用**：`imdb4_libObj_noInputThreads.so` 尚未在 ASTRA 上实测；若四代代码等待这些线程的退出信号量，可能出现挂起（文档 92/103 的线程状态可参考）。
6. **五代 `SendAttachEvent` 等价地址**：C 方案需要 g5 内部偏移，本轮只按相似度给出定位方法，未最终定值。
7. 本报告所有 qid/地址均为**文件内 VA**：`libObj.so`/`a5bObj` 的 `.text/.rodata` 满足 `sh_addr == sh_offset`（可直接当文件偏移用），`input.ko` 是 ET_REL（文件偏移 = 节 sh_offset + 节内偏移）。

---

## 九、证据与复现

### 9.1 脚本（`02-脚本/`，均为只读分析）

| 脚本 | 作用 | 主要产物 |
|---|---|---|
| `inputdrv_extract.py` | 从两代镜像提取 input.ko/osal_uipc.ko/libosal_uipc.so/libObj.so/im.elf/libsencore 等 | `input_drv_manifest.json`、`g4_*`/`g5_*` 文件 |
| `inputdrv_ko.py` | `input.ko` 重定位感知反汇编 + 外部调用参数追踪 + qid 候选 | `inputdrv_ko_disasm_{g4,g5}.txt`、`inputdrv_ko_calls_*.tsv`、`inputdrv_ko_qids_*.json` |
| `inputdrv_flow.py` | 关键函数窗口（事件通知器/日志信封/注册/proc/getkey_cb/定时器发送点） | `inputdrv_ko_flow_{g4,g5}.txt` |
| `inputdrv_queue.py` | `osal_uipc.ko` + `libosal_uipc.so` 的队列/注册/收发函数反汇编 | `inputdrv_osal_uipc_ko_*`、`inputdrv_libosal_uipc_*` |
| `inputdrv_consumers.py` | 全 libObj 扫描：所有 osal 调用点 + 字面量加载 | `inputdrv_consumers_{g4,g5}_{osal_calls.tsv,qid_use.json,summary.txt}` |
| `inputdrv_qidmap.py` | 定向：目标 qid 字面量 → 引用指令 → 函数 → 该函数 osal 调用 | `inputdrv_qidmap_{g4,g5}.{json,txt}` |
| `inputdrv_qid_final.py` | 过滤"qid 被直接作为 osal r0"的确证使用 | `inputdrv_qid_confirmed.{json,txt}` |
| `inputdrv_match.py` | 五代静态函数 ↔ 四代已知线程函数的相似度匹配 | `inputdrv_match_g5_to_g4.txt` |
| `inputdrv_init.py` | init_array / NEEDED / infra_input_init 字符串线索 | `inputdrv_init_chain.txt` |
| `inputdrv_infra.py` | 两代 InfraInput 关键导出函数 + 四代构造函数反汇编 | `inputdrv_infra_{g4,g5}_funcs.txt` |
| `inputdrv_sencore.py` | `libsencore.so` 中 `0x8F013A/0x910042` 引用（证明是日志/时间服务） | `inputdrv_sencore_qid_ctx.txt` |

复现：
```powershell
cd "<WORKSPACE>"
python 02-脚本\inputdrv_extract.py
python 02-脚本\inputdrv_ko.py
python 02-脚本\inputdrv_flow.py
python 02-脚本\inputdrv_queue.py
python 02-脚本\inputdrv_consumers.py     # 约数分钟（20 MB libObj 全量扫描）
python 02-脚本\inputdrv_qidmap.py
python 02-脚本\inputdrv_qid_final.py
python 02-脚本\inputdrv_match.py
python 02-脚本\inputdrv_init.py
python 02-脚本\inputdrv_infra.py
python 02-脚本\inputdrv_sencore.py
```

### 9.2 关键证据文件（`03-证据/静态分析/input_drv/`）

- `input_drv_manifest.json`：7 个四代 + 7 个五代文件的镜像路径/inode/大小/SHA-256；
- `inputdrv_qid_confirmed.{json,txt}`：四个确证 qid 使用点（w/ 调用点、r0、字面量池地址）：
  - `0x7A804C` → 四代 `0x862430` MainThread / 五代 `0x209C58`；
  - `0x7A0020` → 四代 `0x862D60` RecvThread / 五代 `0x20A588`；
  - `0x8F013A` → 大量日志函数（含 MainThread 的日志路径）；
  - `0x910041/0x910042` → 重复键/时间服务；
- `inputdrv_ko_flow_g4.txt`：驱动事件通知器（`0x0BA0`）、日志信封（`0x0A20`）、注册（`0x3C10`）、`getkey_cb`、定时器 4 个发送点上下文；
- `inputdrv_libosal_uipc_g4_osal_rcv_msg_tmo.dis.txt` / `…osal_snd_msg…` / `…osal_reg_msg_queue_cb…`：单条取走 + 等待链 + 单槽同步回调；
- `inputdrv_osal_uipc_ko_g4_reg_sync_msg_queue_cb.dis.txt`：`q+0x18` 占用返回 `0xFFFFFC00`；
- `inputdrv_osal_uipc_ko_g4_osal_snd_msg.dis.txt`：内核消息队列插入 + 唤醒路径（无广播）；
- `imdb4/a5bObj_infra_input_init_dis.txt`：五代 `infra_input_init` → `GetInstance()` PLT；
- `imdb4/libObj_reach.txt`、`imdb4/imdb4_usrscan.txt`：四代 `InfraInput::GetInstance` 的调用方/导入方清单；
- `imdb4/imdb4_patch_manifest.json`：现有 `noInputThreads`/`noInputInstance`/`rec31` 补丁的偏移与含义（本轮建议 A1 复用）。

### 9.3 关键字符串（`input.ko` `.rodata.str1.1`，节内偏移）

| 偏移 | 字符串 |
|---:|---|
| `0x0000` | `kbd: front uipc error %d\n` |
| `0x0036` | `kbd: vgrip uipc error %d\n` |
| `0x053A/0x0564/0x058C` | `input(kbd):osal_alloc_msg err:%d` / `…osal_snd_msg err:%d` / `kbd send osal type:%d code:%x value:%x opt:%x` |
| `0x079F/0x07B7/0x07ED` | `*** ADC UIPC data ***` / `osal_alloc_msg(liro_adc) error:%d` / `osal_send_sync_msg(liro_adc) error:%d` |
| `0x0836/0x084F/0x0873` | `*** Front UIPC data ***` / `osal_alloc_msg(front_key) error:%d` / `FR_INPUT_MSG size:%d` |
| `0x09AB/0x09C4/0x09E8` | `*** Vgrip UIPC data ***` / `osal_alloc_msg(vgrip_key) error:%d` / `VGRIP_INPUT_KEY_MSG size:%d` |
| `0x0D7B/0x0D9E/0x0DF9` | `input(kdb):unregist osal callback` / `input(kbd):osal_reg_msg_queue_cb err:%d` / `input(kdb):regist osal callback` |
| `0x0E8B/0x0E98/0x0EA4` | `kbd: resume` / `kbd: probe` / `kbd: create_proc_entry() error` |

---

## 十、本轮状态

- 纯静态：未运行 QEMU、未改动任何镜像/现有脚本/文档；新增脚本与证据均在 `02-脚本/inputdrv_*`、`03-证据/静态分析/input_drv/`。
- 结论可信度：qid/队列机制/双消费者竞争为**高**（符号级+逐指令）；驱动 16 B 记录到 `_InfraInputEvent` 的细字段映射、四个外部 qid 的 owner 为**中**；A1 补丁的副作用、双实例运行期存在性为**待实测**。
