# 78 · `/dev/uipc` 协议逆向（主控 Linux ↔ 副控制器链路）

> 纯静态逆向，只读分析。本轮**未**运行 QEMU、**未**修改任何镜像。
> 分析对象来自 `nflasha15`（ext2）中的实际文件，均已用 `a6600_usr.py::Ext2` 取出并校验大小。

---

## 0. 摘要：三条最关键的发现

1. **`/dev/uipc` 不是"副控制器硬件通道"，而是 OSAL 消息队列（msgq）的用户态出口。**
   配套内核模块 `osal_uipc.ko` 才是真正的服务端：它实现了整套 OSAL（msgq / 信号量 / 内存池 / 动态 ID），
   通过 `/dev/uipc` 把队列暴露给用户态，并用一块**恰好 1 MiB 的共享内存**承载消息体。
   因此"副控制器协议"并不是在 `/dev/uipc` 上跑一个私有帧格式，而是**上层 OSAL 消息的 payload**。

2. **ioctl ABI 已完整还原**：`cmd = 0x80000000 | opcode`，`opcode` 只有 17 个（0..0x10），
   参数恒为一个指向 **8 字节** `{u32 a0; u32 a1}` 块的用户指针；
   其中 `opcode=0x10` 是 `connect`，**必须第一个调用**，之后必须 `mmap` 1 MiB 才能用其余 opcode。
   17 个 opcode 与 17 个 `__k_4u_*` 内核处理函数**一一对应**（下有对照表），互不歧义。

3. **`libsencore.so` 走这条路访问副控制器（LSI/senser）的"子系统"服务**，
   实测调用点为 `dmm_allocm` / `dmm_free`（动态内存）、`tlog_get_version/dest/date/serial_code`（日志/序列号）、
   `Blog::write`（日志），主队列 qid = **`0x61003C`**，另有 `osal_dynamic_id()` 分配的一次性回复队列。
   同时 `libsencore` 还有一条**独立的 USB 传输路径**（`usbif_initialize` / `usb_senif_pub` / `SenserIf*`，
   对应内核 `usbg_sen.ko`）。所以"伪装副控制器"有**两个层面**可下手，见 §6 建议。

---

## 1. 方法与工具（可复现）

### 1.1 取文件

`nflasha15` 是 ext2，用项目现成的 `02-脚本/a6600_usr.py` 的 `Ext2` 类按 inode 直读。
本轮新取出的相关文件（此前分析未覆盖）：

| 路径 | 大小 | 说明 |
|---|---|---|
| `/lib/libosal_uipc.so` | 26,644 | 用户态 OSAL 封装（**主目标**） |
| `/lib/libsencore.so` | 349,760 | 副控制器协议栈（senser / LSI） |
| **`/kmod/osal_uipc.ko`** | 38,872 | **OSAL 内核模块（本次最大突破：保留完整 `.symtab`）** |
| **`/kmod/usbg_sen.ko`** | 31,204 | USB gadget tty line-discipline 驱动（SEN 物理链路） |
| `/bin/sen.elf` | 19,164 | 副控制器侧可执行（未深入） |
| `/bin/ud_send_lsi.elf` | 4,276 | 向 LSI 发包的小工具（未深入） |
| `/lib/libInfraDevInfoSender.so` | 13,136 | 另一个 uipc 客户端 |
| `/lib/libInfraKikiLogSender.so` | 6,696 | 另一个 uipc 客户端 |

### 1.2 关键结论：两个 `.so` 的 `.text`/`.rodata` 中 **VA == 文件偏移**

```
libosal_uipc.so: .text  addr=0x1a84 off=0x1a84   .rodata addr=0x513c off=0x513c
libsencore.so  : .text  addr=0xf344 off=0xf344   .rodata addr=0x18de8 off=0x18de8
```
`osal_uipc.ko` 是 ET_REL（所有节 addr=0），故 **文件偏移 = `VA + 0x34`**（`.text` 的 `sh_offset`）。

### 1.3 指令集：ARM/Thumb 混编

`libosal_uipc.so`、`libsencore.so` 中 **`st_value` 为奇数的函数是 Thumb**（如 `u_osal_snd_msg @0x25b9`），
偶数的是 ARM。`osal_uipc.ko` 全部为 ARM。

两个必须注意的编码细节（本轮踩坑）：
* Thumb `ldr rX,[pc,#imm]`：基址 = `Align(addr+4, 4)`；
* Thumb `add rX, pc`：基址 = `addr + 4`（**不** 4 字节对齐），Thumb-2 大偏移惯用法。
  例：`do_init` 中 `add r0,pc` @0x2116 + `0x322e` = `0x5348` = 字符串 `/dev/uipc` ✓。

### 1.4 PLT 解析（ET_DYN）

ARM PLT 项 12 字节，`.plt` 起 `0x15f4`（`PLT0` 16 B + 1 个字面量）。逐 4 字节扫描
`add ip,pc,#imm` / `add ip,ip,#imm` / `ldr pc,[ip,#imm]!` 三元组，把算出的 GOT 地址用
`.rel.plt` 的 `r_offset`（**ET_DYN 中是 VA，不是节内偏移**）反查到符号名。
`libosal_uipc.so` 得 88 项。`.rel.plt` 的 `sh_info` 指向 `.plt`（不规范），不能按节名分组。

---

## 2. 分层架构（据代码还原）

```
  ┌──────────────────────────────────────────────────────────────┐
  │ 用户进程                                                       │
  │   libsencore.so        libInfraDevInfoSender.so  ...          │
  │        │  osal_snd_msg()/osal_rcv_msg_tmo()/...  (导出 API)    │
  │        ▼                                                      │
  │   libosal_uipc.so   ── open("/dev/uipc") / ioctl / mmap ──┐    │
  └───────────────────────────────────────────────────────────┼────┘
                                                              ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ osal_uipc.ko  （/dev/uipc 字符设备，udif 框架）                │
  │   msgq / sem / vpool / fblock / dynamic-id                    │
  │   1 MiB 共享内存：消息体（payload）存放区                       │
  └──────────────────────────────────────────────────────────────┘
                                                              
  另一条独立链路（副控制器物理口）：
  libsencore ── SenserIfSend/Receive ── usbg_sen.ko (USB gadget tty) ── USB ── 副控制器
                                     └─ (另有 SIO/串口帧，见文档 25/27)
```

**重要更正**：`/dev/uipc` 的服务端是内核里的**通用消息队列**，它与"哪条物理链路"无关。
副控制器消息之所以走 `/dev/uipc`，是因为**拥有该物理链路的进程是另一个进程**，
跨进程投递自然落到 uipc 上。这也解释了为什么 qid 有"本地/跨进程"两种路由（见 §3.4）。

---

## 3. 问题 1：`libosal_uipc.so` 的 API、open、mmap、ioctl

### 3.1 导出 API（`.dynsym`，`STB_GLOBAL` 且已定义，共 ~80 项）

**初始化/退出**

| 符号 | VA | 说明 |
|---|---|---|
| `u_osal_init` | 0x1b00 | 入口，转 `u_uipc_init` |
| `u_uipc_init` | 0x22e8 | → `do_init` + 建 proxy 线程 |
| `u_uipc_exit` | 0x2304 | 拆链 |
| `u_osal_exit` | 0x1b0c | |

**核心（"u_" 前缀 = 用户态/跨进程实现；无前缀 = 双路分发）**

| 导出符号 | VA | ioctl opcode |
|---|---|---|
| `u_osal_stat_sem` | 0x23e8 | 0 |
| `u_osal_wai_sem_tmo` | 0x2434 | 1 |
| `u_osal_sig_sem` | 0x2480 | 2 |
| `u_osal_stat_msgq` | 0x24d0 | 3 |
| `u_osal_snd_msg` | 0x25b8 | **4** |
| `u_osal_snd_sync_msg` | 0x2604 | **5** |
| `u_osal_snd_sync_direct` | 0x26a8 | 6 |
| `u_osal_rcv_msg_tmo` | 0x26f4 | **7** |
| `u_osal_reg_msg_queue_cb` | 0x2748 | 8 |
| `u_osal_reg_sync_msg_queue_cb` | 0x27ac | 8 |
| `u_osal_unreg_msg_queue_cb` | 0x2810 | 9 |
| `u_osal_valloc_msg_wait` | 0x2870 | **10 (0xA)** |
| `u_osal_free_msg` | 0x28c8 | **11 (0xB)** |
| `u_osal_dynamic_id` | 0x2914 | **12 (0xC)** |
| `u_osal_set_msgq_broadcast_mode` | 0x251c | 14 (0xE) |
| `u_osal_set_msgq_log_mode` | 0x256c | 15 (0xF) |
| `do_init` | 0x210c | **16 (0x10) = connect** |

**同库内实现的本地侧（不经 ioctl，被上面函数在"本地 qid"分支调用）**
`osal_snd_msg` 0x3c34、`osal_rcv_msg_tmo` 0x3ed8、`osal_valloc_msg_wait` 0x3fec、
`osal_free_msg` 0x4088、`osal_snd_sync_msg` 0x3ec8、`__osal_snd_sync_msg` 0x3db0、
`osal_snd_sync_direct` 0x4134、`osal_reg_msg_queue_cb` 0x4300、`osal_unreg_msg_queue_cb` 0x3b54、
`osal_reg_sync_msg_queue_cb` 0x3ae0、`osal_dynamic_id` 0x4840、`osal_set_msg_pri` 0x43dc、
`osal_get_msg_pri` 0x4408、`osal_msg_size` 0x4b80、`osal_stat_msgq` 0x4430、`osal_stat_sem` 0x2e34、
`osal_set_msgq_broadcast_mode` 0x4464、`osal_set_msgq_log_mode` 0x44e8、
`osal_set_msgq_rt_mode` 0x455c、`osal_get_uipc_stat` 0x4594、`osal_lock` 0x4fbc、`osal_unlock` 0x502c。

**内存池/调试（导出）**
`vpool`(obj) 0xefb8、`uipc_stat`(obj) 0xefa4、`uconf`(obj) 0xef80、`uipc_opt`(obj) 0xef60、
`vpool_alloc` 0x4d80、`vpool_free` 0x4e6c、`vpool_dump` 0x4f00、`fblock_init` 0x4ca4、
`alloc_fblock` 0x4ba4、`free_fblock` 0x4c60、`fblock_dump` 0x4d14、`msgq_dump` 0x45e0、
`bsem_dump` 0x2fdc、`did_dump` 0x4abc、`get_bsem` 0x2c88、`reset_msgq` 0x4780、
`reset_bsem` 0x314c、`uipc_oom` 0x2b7c、`print_task_info` 0x296c、`dump_trace` 0x29a8、
`do_sleep_tmo` 0x5064、`wakeup` 0x5100、`check_dynamic_sem_id` 0x47c0。

**导入（`.dynsym` UNDEF）**：
`open/mmap/ioctl/read/write/close/fcntl/munmap/perror/malloc/free/memset/memcpy/printf/snprintf/
pthread_*/prctl/getpid/abort/syscall/__errno_location/__register_atfork`。
注意：**没有** `socket`、`select`、`poll`——它只会用 ioctl/mmap。

### 3.2 打开 `/dev/uipc`

`do_init @0x210c`（ARM 语义下 Thumb，size 428）：

```
r0 = 0x5348  ("/dev/uipc")        ; add r0,pc 惯用法算得
r1 = 2                            ; O_RDWR
bl  open                          ; → uconf->fd (uconf+0x00)
```

字符串（`.rodata`，VA = 文件偏移）：

| 字符串 | VA |
|---|---|
| `/dev/uipc` | 0x5348 |
| `open /dev/uipc error: ` | 0x5354 |
| `ioctl :` | 0x536c |
| `mmap error: ` | 0x5374 |
| `[U]**UIPC ERROR** %s: ioctl error %d` | 0x5320 |
| `/proc/osal/uipc` | 0x5534 |
| `/tmp/uipc_stat_user.txt` | 0x551c |
| `/tmp/uipc_stat_kernel.txt` | （`osal_uipc.ko` 内 0x6310 附近） |

**已确证**：flags 就是 `2`（`O_RDWR`），没有 `O_NONBLOCK`，没有 `O_CLOEXEC`。

### 3.3 初始化序列（`do_init` 逐条还原）

```
 1  fd = open("/dev/uipc", O_RDWR)              ; 失败 → perror("open /dev/uipc error: ") → return -1
 2  req8[0] = 0                                 ; 局部 8 字节请求块
    req8[1] = <指向本地 16 字节缓冲的指针>
    ioctl(fd, 0x80000010, &req8)                ; ← CONNECT（opcode 16）
      ├─ 返回 <0 → perror("ioctl :") → close → return -1
 3  uconf[0x08] = <connect 应答第 1 字>          ; ← 被用作 mmap 长度
    uconf[0x10] = <应答第 2 字>
    uconf[0x14] = <应答第 3 字>
    uconf[0x1C] = <应答第 4 字>
 4  fcntl(fd, F_SETFD/F_SETFL 类, ...)          ; r1=2, r2=1 → 见 §7 说明
 5  p = mmap(NULL, uconf[0x08], 3 /*PROT_READ|WRITE*/, 1 /*MAP_SHARED*/, fd, 0)
      ├─ MAP_FAILED → perror("mmap error: ") → close → return -1
    uconf[0x04] = p                             ; 共享内存用户态基址
 6  若 uconf[0x0C] == 0:  (第一次)
        另一段 mmap(NULL, uconf[0x10]-uconf[0x14], 3, 0x22, fd, uconf[0x0C])
                    ; 0x22 = MAP_PRIVATE|MAP_ANONYMOUS? 见 §7
        perror("mmap error: ") on failure
 7  fblock_init(uconf[0x0C], len)
 8  vpool 各字段初始化；pthread_mutex_init(&(.bss:0xe308), 0)
 9  pthread_create("uipc_proxy", ...)           ; 线程名格式 "%s_%d" → "uipc_proxy_<pid>"
```

### 3.4 qid 的两条路由（这是理解全局的钥匙）

`osal_snd_msg/osal_rcv_msg_tmo/osal_valloc_msg_wait/osal_reg_msg_queue_cb` 四个入口开头都是同一句：

```c
if (!(qid & 0x8000))  return u_osal_xxx(...);   /* bit15 == 0 → 走 /dev/uipc，跨进程 */
else                  /* bit15 == 1 → 本进程内队列，纯用户态链操作，不碰内核 */
```

**已确证**（4 个函数一致）。所以：
* **bit15 = 1 → 本地队列**（进程内自收自发，如两个线程之间）；
* **bit15 = 0 → 跨进程队列**，经 `/dev/uipc` 交给内核，由目标进程（或内核驱动）取出。

`libsencore` 用的 qid `0x61003C` 的 bit15 = 0 → **确认走 `/dev/uipc`**。

### 3.5 `mmap` 共享内存

`__k_uipc_cdev_mmap @0x2a8`（`osal_uipc.ko`，文件偏移 0x2dc）：

```
r1 = vma->vm_start (vma+4), r2 = vma->vm_end (vma+8)
len = r2 - r1
if (len != 0x100000)  { printk("[K]**UIPC ERROR** ...");  return -EINVAL; }
... 由预置的物理页帧（.bss 里的全局）算 pfn ...
remap_pfn_range(vma, vm_start, pfn, 0x100000, vm_page_prot|0x40)
ctx->[0x14] = vma->vm_start          /* 记住用户态基址，后续做指针翻译 */
```

**已确证**：映射长度**必须恰好 1 MiB（0x100000）**，否则 `-EINVAL`；映射的是模块保留的物理内存；
`vm_flags |= 0x40`（`VM_IO`）。`vm_pgoff` 被忽略（代码里只把 offset 写死 0）。

**推测**：`osal_uipc.ko` 的 `/proc/osal/uipc` 输出里有 `sems`/`msgs`/`misc`、`- normal vblock`、
`- realtime vblock`、`- dynamic ids` 等分区字样，配合 `__k_4u_connect` 里内置的
**{0x100000, 0x40000, 0x8000, 0}** 四个数（先写入局部、再用 `copy_from_user` 覆盖），
判断这 1 MiB 是按**分区表**切分的：`[0, 0x8000)`、`[0x8000, 0x40000)`、`[0x40000, 0x100000)`。
用户态可以在 `connect` 时覆盖这 4 个字来改分区（默认值即上述数）。

### 3.6 `ioctl` ABI（已完全确证）

`__k_uipc_cdev_ioctl @0x5a8`：

```
/* udif 框架已把 VFS 的 (cmd, arg) 打包成 {u32 cmd; u32 arg;} 传进来 */
op  = req->cmd & 0x7FFFFFFF;
ptr = req->arg;
if (op > 0x10)                       return -EINVAL;
if (op != 0x10 && ctx->[0x14] == 0)  return -EINVAL;   /* 除 connect 外必须先 mmap */
if (ctx->[0x0C] != current->pid_field) { printk("called from different process"); return -EINVAL; }
if (!access_ok(ptr, 8))              goto efault;
if (copy_from_user(&local8, ptr, 8)) goto efault;
((void (*)(u32,u32,void*))disp_table[op])(local8[0], local8[1], ctx);
```

用户态侧（`libosal_uipc.so` 全部 16 个 `u_osal_*` 均一致）：

```
u32 blk[2] = { a0, a1 };
ret = ioctl(fd, 0x80000000 | opcode, blk);     /* 传的是 &blk */
if (ret == -1) ret = -errno;
while (ret == -1021 /*0xFFFFFC03*/) { /* 重试，EINTR 循环 */ }
```

* **VFS cmd = `0x80000000 | opcode`**（bit31 为标志，内核先 `bic` 掉）；
* **参数永远是 8 字节 `{u32 a0; u32 a1}`**，`a1` 常常是一个**二级指针/结构体指针**；
* 内核只 `access_ok(ptr, 8)` 并 copy 8 字节；处理函数内部再自行 `access_ok` + copy 更大的块。

### 3.7 opcode ⇄ 内核处理函数对照表（`osal_uipc.ko`，**已确证**）

分发基址 = `.rodata + 0x28`，`entry[op] = *(u32*)(.rodata + 0x28 + op*4)`
（`.rel.rodata` 里 0x28..0x68 共 17 个 `R_ARM_ABS32`；`.rodata+0x28+16*4 = 0x68` → `__k_4u_connect` ✓）。

| op | cmd | 内核函数 | VA | 用户态导出 | `a0` / `a1` |
|---|---|---|---|---|---|
| 0 | 0x80000000 | `__k_4u_stat_sem` | 0x41c | `u_osal_stat_sem` | `a1`→`{sem_id, out[?]}` |
| 1 | 0x80000001 | `__k_4u_wai_sem_tmo` | 0x1b4 | `u_osal_wai_sem_tmo` | 同上 |
| 2 | 0x80000002 | `__k_4u_sig_sem` | 0x1a0 | `u_osal_sig_sem` | |
| 3 | 0x80000003 | `__k_4u_stat_msgq` | 0x3a4 | `u_osal_stat_msgq` | `a1`→out 结构 |
| **4** | 0x80000004 | **`__k_4u_snd_msg`** | **0x1338** | `u_osal_snd_msg` | `a0=qid`, `a1=msg 用户指针` |
| **5** | 0x80000005 | **`__k_4u_snd_sync_msg`** | **0x1380** | `u_osal_snd_sync_msg` | `a0=qid`, `a1→{msg,len,tmo}` |
| 6 | 0x80000006 | `__k_4u_snd_sync_direct` | 0x8c8 | `u_osal_snd_sync_direct` | |
| **7** | 0x80000007 | **`__k_4u_rcv_msg_tmo`** | **0x11dc** | `u_osal_rcv_msg_tmo` | `a0=qid`, `a1→{&out, tmo}` |
| **8** | 0x80000008 | **`__k_4u_reg_msg_queue_cb`** | **0x784** | `u_osal_reg_msg_queue_cb` | `a0=qid`, `a1→16 B cb 描述` |
| 9 | 0x80000009 | `__k_4u_unreg_msg_queue_cb` | 0x594 | `u_osal_unreg_msg_queue_cb` | |
| **10** | 0x8000000A | **`__k_4u_valloc_msg_wait`** | **0x10e8** | `u_osal_valloc_msg_wait` | `a0=qid`, `a1→{&out, len, tmo}` |
| **11** | 0x8000000B | **`__k_4u_free_msg`** | **0x12f8** | `u_osal_free_msg` | `a0=qid`, `a1=msg` |
| **12** | 0x8000000C | **`__k_4u_dynamic_id`** | **0x6a4** | `u_osal_dynamic_id` | `a0=group`, `a1=?`；`a1` 块 `{type, max, &out}` |
| 13 | — | `__k_4u_wait_cb` | 0xe8c | （无导出） | 内部 |
| 14 | 0x8000000E | `__k_4u_set_msgq_broadcast_mode` | 0x18c | `u_osal_set_msgq_broadcast_mode` | |
| 15 | 0x8000000F | `__k_4u_set_msgq_log_mode` | 0x178 | `u_osal_set_msgq_log_mode` | |
| **16** | **0x80000010** | **`__k_4u_connect`** | **0x494** | `do_init` | `a0=0`, `a1→16 B 分区表` |

`__k_4u_connect` 的关键动作（**已确证**）：
```
local[4] = {0x100000, 0x40000, 0x8000, 0}          /* 默认分区表 */
if (!access_ok(a1, 0x10)) → for free
copy_from_user(local, a1, 0x10)                    /* 用户可覆盖分区表 */
ctx->[0x30] = 1;
ctx->[0x34] = local[3];                            /* 0 */
ctx->[0x0C] = <current task 的某个 id 字段>         /* 供后面 ioctl 的 pid 校验 */
mutex_lock(.bss+0x2c);
/* 把 ctx 挂进 .bss+0x28 为首的链表 */
ctx->[0x00] = <list tail>; ctx->[0x04] = &list_head;
mutex_unlock
osal_dynamic_id(0x2A, 0x3F, &ctx[?])               /* 为连接分配一个动态 id */
```
注意：`connect` **只下行（copy_from_user），不 copy_to_user**。
`do_init` 里 `uconf[8]` 被当成 mmap 长度使用，但内核并不回写 —— 见 §7「无法确定」。

---

## 4. 问题 2：消息帧格式

### 4.1 内存块：12 字节头 + 变长 payload

`osal_valloc_msg_wait` 分配到的**块**与返回给调用者的**消息指针**差 0xC：

```c
/* __k_4u_snd_msg / libsencore 侧一致：msg = block + 0xC */
struct osal_msgblock {          /* 16 字节对齐起见按 32 B 一个 size class */
    u32 next;                   /* +0x00  msgq 链表 next（单链）        [已确证] */
    u8  size_class;             /* +0x04  0 → 固定 20 B；否则 class*32-12  [已确证] */
    u8  pri;                    /* +0x05  bits[5:0] 优先级（≤4）          [已确证] */
    u8  pad[6];                 /* +0x06..0x0B                            [推测] */
    /* +0x0C 起为用户 payload（即 API 里的 "msg"） */
};
```

证据：
* `osal_msg_size @0x4b80`：`b = *(u8*)(msg-8); return b ? b*32 - 12 : 20;` 空指针返回 `0xFFFFFC00`。
* `osal_set_msg_pri @0x43dc`：`*(u8*)(msg-7) = bfi(old, pri, 0, 6)`，`pri > 4` → 错误。
* `osal_get_msg_pri @0x4408`：`*out = *(u8*)(msg-7) & 0x3F`。
* `osal_snd_msg @0x3c34`：`block = msg - 0xC`；`block->next = NULL`；
  按 `*(u8*)(q+5) & 0x3F`（优先级）在 `q->head(q+0xC)` / `q->tail(q+0x10)` 链上**有序插入**。

**容量**：`valloc` 里 `if (len > 0x1000) return 错误;` → **单条 payload ≤ 4096 字节**。
（`libsencore` 里见到的最大请求是 `0x608` 和 `0x140`，都在范围内。）

### 4.2 qid 位域

从 `osal_snd_msg` / `osal_valloc_msg_wait` 的掩码运算可确定（**已确证**）：

```
 qid (28 位有效，snd_msg 用 qid & 0x0FFFFFFF 做合法性校验)
 ┌───────────────┬──────┬─────────────────────────┐
 │ bits[27:16]   │ [15] │ bits[14:0]              │
 │ 12-bit group  │ 本地 │ 15-bit 队列索引          │
 └───────────────┴──────┴─────────────────────────┘
```
* `local_index = (qid << 17) >> 17  = qid & 0x7FFF`；
* `group = (qid >> 16) & 0xFFF`；
* `group == 0x3E || group == 0x8F` 是**特殊组**（`valloc` 里跳过 `uipc_oom` 检查）；
* `qid & 0x0FFFFFFF` 必须等于该 msgq 注册时登记的 id，否则
  `printf("[U]**UIPC ERROR** %s: snd to invalid qid %08x != %08x @ %p")`。

### 4.3 msgq 对象（用户态内，`osal_snd_msg` 里可见）

```
struct osal_msgq {            /* 由 get_msgq(local_index) 返回 */
  u32  unk0;                  /* +0x00 */
  u8   flags;                 /* +0x04  bit0=log, bit1=?, bit3=broadcast  [已确证] */
  u8   pad[7];
  u32  head;                  /* +0x0C  队列头（msg block 指针）          [已确证] */
  u32  tail;                  /* +0x10  队列尾                            [已确证] */
  u32  pending;               /* +0x14  等待者列表                        [推测] */
  u32  pad2;
  u32  qid;                   /* +0x1C  注册的完整 qid（用于校验）         [已确证] */
};
```
队列是**单链表 + head/tail**，按优先级插入，**不是环形缓冲**。
消息内存来自 `vpool`（大块）+ `fblock`（小块），不是每进程独立池。

### 4.4 共享内存承载消息体：指针翻译

跨进程时消息体必须放在那块 1 MiB 里。内核无法直接访问用户地址，所以做**双向线性翻译**：

```
/* __k_4u_snd_msg 调用：用户 VA → 共享内存句柄 */
sub_0x12C0(user_ptr, &handle, vm_start):
    off = user_ptr - vm_start;              /* 无符号 */
    if (off < 0x100000) { *handle = off + BASE; return 0; }
    return 错误码;
/* 接收侧：共享内存句柄 → 用户 VA */
sub_0x0E68(handle, vm_start):
    return vm_start + (handle - BASE);
```
`BASE` 取自模块全局（字面量重定位到 `.bss+0x28` 处，**具体符号未定**，`__k_4u_connect` 里同一地址
是用户链表头，推测是一个 `uipc_shm` 全局结构，`BASE` 是它的一个字段）。

于是：
* `__k_4u_snd_msg(a0=qid, a1=msg_user_ptr)`：`handle = to_handle(a1, ctx->[0x14])`，然后
  `osal_snd_msg(qid, handle)` —— 队列里存的是**句柄**，不是指针；
* `__k_4u_valloc_msg_wait`：分配后把句柄 `handle_to_user()` 还原成用户 VA，
  再 `access_ok` + `copy_to_user(用户块, &va, 4)` 回写给用户；
* `__k_4u_rcv_msg_tmo`：出队拿到句柄，翻译后 copy_to_user。

**这就是"1 MiB 共享内存"的唯一用途**：跨进程传递 ≤4 KiB 的消息体，避免内核拷贝。
所以：**消息体地址 = 用户态 mmap 基址 + offset**，offset ∈ [0, 0x100000)。

### 4.5 一次完整事务（请求/应答）

`libsencore` 的 `dmm_allocm` / `dmm_free` 是最干净的样板（**已确证**，`_Z9dmm_allocmPt @0x132ac`）：

```
/* 1) 申请一次性回复队列 */
osal_dynamic_id(type=0x2A, max=0x3D, &dyn_qid);        /* type 0x2A 高字节=类别, 0x3D=上限 */

/* 2) 在目标队列上分配消息（长度 0x18） */
osal_valloc_msg_wait(qid=0x61003C, &msg, len=0x18, tmo=1);

/* 3) 填请求 */
sub_12C74(msg, dyn_qid);        /* 把回复 qid 填进 msg（见下） */
*(u16*)(msg+0x00) = 1;          /* opcode: ALLOC                    */
*(u32*)(msg+0x04) = 0x192;      /* 请求长度 402                     */
*(u32*)(msg+0x08) = 0;          /*                                  */
*(u32*)(msg+0x0C) = 0x2710;     /* 10000（超时 ms）                  */
*(u16*)(msg+0x14) = arg0;       /* 调用者第 1 参数                   */
*(u16*)(msg+0x16) = 1;          /* 请求种类: 1=alloc                */

/* 4) 发送 */
osal_snd_msg(0x61003C, msg);    /* 返回值 0 = 成功 */

/* 5) 释放请求消息（发送后即可释放，内核/接收方已存句柄） */

/* 6) 在动态 qid 上等应答（10 s） */
osal_rcv_msg_tmo(dyn_qid, &rmsg, 10000);
  /* 失败/超时返回非 0；libsencore 用 cpp_log 记录后返回错误 */

/* 7) 解析应答 */
status = *(u16*)(rmsg+0x02);    if (status) → 错误
size   = *(u16*)(rmsg+0x04);    /* 回填给调用者 out 参数 */
addr   = *(u32*)(rmsg+0x10);    /* 分配到的地址（返回值） */

/* 8) 释放应答消息，释放动态 id */
osal_free_msg(dyn_qid, rmsg);
osal_dynamic_id(0x4A, 0, &dyn_qid);    /* type 0x4A = 释放/回收 */
```

`dmm_free` 同构：`msg[0]=4 (FREE)`、`msg[2]=handle`、`msg[0x16]=2`。

**请求 payload 布局（`dmm` 通道，24 B）—— 已确证**

| 偏移 | 类型 | 值/含义 |
|---|---|---|
| +0x00 | u16 | opcode：`1`=alloc，`4`=free |
| +0x02 | u16 | free 时：要释放的 handle |
| +0x04 | u32 | alloc 时：请求长度（样例 `0x192`=402） |
| +0x08 | u32 | 0（样例） |
| +0x0C | u32 | 超时 ms（`0x2710`=10000） |
| +0x10 | u32 | 由 `sub_12C74` 填（推测 = 回复 qid 或序列号；应答回显） |
| +0x14 | u16 | allocm 的第 1 参数（tag/类型） |
| +0x16 | u16 | 请求种类：`1`=alloc 请求，`2`=free 请求 |

**应答 payload 布局 —— 已确证**

| 偏移 | 类型 | 含义 |
|---|---|---|
| +0x00 | u16 | 推测 = 原 opcode/种类回显 |
| +0x02 | u16 | **status**，0 = 成功 |
| +0x04 | u16 | 分配到的长度（回填 out） |
| +0x10 | u32 | 分配到的地址（返回值） |

### 4.6 其它通道的 payload（`libsencore`，已确证到字段级）

`tlog_*` 系列用 `osal_valloc_msg_wait(qid, &msg, 0x140, tmo)` + `osal_snd_sync_msg`，长度固定 **320 B**：

| 函数 | 关键写入 | 值 |
|---|---|---|
| `tlog_get_version` | `*(u16*)(msg+0x18)` | `0x603` |
| `tlog_get_dest` | `*(u16*)(msg+0x18)`, `+0x1A` | `0x603` |
| `tlog_get_serial_code` | `*(u16*)(msg+0x18)`, `+0x1A` | `0x701` |
| `tlog_get_date` | 走 `osal_snd_sync_direct`，栈上 0x2C 字节请求 | — |

所以 tlog 的报文头在 **payload + 0x18** 处有 u16 命令字，`0x603` / `0x701` 是"读版本/序列号"类命令。
`0x0603` 高位字节 `0x06` 像 module id、低字节 `0x03` 像 command id（**推测**）。

`Blog::write` 用 `osal_valloc_msg_wait(..., 0xD)`、`(..., 0x20)` 和 `osal_snd_sync_msg(..., 0xF)`，
即 13 字节 / 32 字节 / 15 字节三种小报文。

---

## 5. 问题 3：`libsencore.so` 如何使用这套 API

### 5.1 导入列表（`.dynsym` UNDEF，相关部分）

```
osal_snd_msg, osal_snd_sync_msg, osal_snd_sync_direct,
osal_rcv_msg_tmo, osal_valloc_msg_wait, osal_free_msg,
osal_dynamic_id, osal_reg_sync_msg_queue_cb, osal_unreg_msg_queue_cb
```
**没有**直接 import `libosal_uipc.so` 的 `u_*` 函数，也没有 `ioctl`/`mmap` 用于 uipc
（`ioctl` 被 import 但用于别处）。它只用 OSAL 的 5 个高层 API：
**valloc → (填包) → snd → rcv_tmo → free**，另加 `dynamic_id` 做回复队列。

### 5.2 初始化序列

```
_Z14lsi_trans_initv:  osal_reg_sync_msg_queue_cb(qid, &cb_slot, cb_fn, 0)
                      /* qid 从 GOT 取全局变量；cb 挂在 libsencore 自己的同步回调槽 */
_Z14lsi_trans_exitv:  osal_unreg_msg_queue_cb(qid, &cb_slot)
```
即 **LSI 传输层是"注册回调 + 异步收包"模型**，不是轮询。
回调注册后，主线程/工作线程从 OSAL 收包并派发（`SenserThread` / `WorkerThreadManager`）。

### 5.3 两条链路并存（重要）

| 链路 | 代表符号 | 对端 |
|---|---|---|
| OSAL/uipc | `dmm_allocm`, `dmm_free`, `tlog_*`, `Blog::write`, `SubsystemCommunicationCommand` | 另一个 Linux 进程（或内核驱动）持有的 **LSI/子系统服务** |
| USB | `usbif_initialize`, `usb_senif_pub`, `SenserIfSend/Receive/SndPhys/RcvPhys`, `usb_receive_func_t` | 副控制器（SEN）物理口，内核侧 `usbg_sen.ko`（USB gadget **tty line discipline** + `fops_ioctl`） |

`libsencore` 的 `SenserPacket` / `Command` / `DispatchCommand` / `Parse` / `Serialize` 属于 USB 那条。
`dmm/tlog` 这类"子系统命令"走 OSAL。因此，如果目标是让 **UI 拿到中文字体**（文档 71 的 0x300 分片、
`FIN_SEND_DATA` 那套），它更可能在 **USB/senser 包** 那一层，而不是 uipc（见 §7）。

### 5.4 观测到的 qid 常量

| qid | 使用点 | 备注 |
|---|---|---|
| **`0x61003C`** | `dmm_allocm` / `dmm_free` 的请求队列 | bit15=0 → 跨进程；group=(qid>>16)&0xFFF=`0x61`；index=`0x3C` |
| `0x2A` / `0x3D` | `osal_dynamic_id(0x2A,0x3D,&id)` | 申请动态 ID：类别 0x2A，上限 0x3D |
| `0x4A` / `0x00` | `osal_dynamic_id(0x4A,0,&id)` | 释放动态 ID：类别 0x4A |
| 0x81 / 0x83 | `tlog_*` / `SubsystemCommunicationCommand` | 具体字面量需按 GOT 全局变量核对，**未能全部定值** |

> 说明：`0x61003C` 是从 `dmm_allocm` 的 `ldr r0,[pc,#0xfc]` 字面量直接读出的（文件 0x133d8，
> 值 `0x0061003C`），后面没有 `add rX,pc`，所以是**纯常量**，不是重定位地址。可信度高。
> 与之对应的 `osal_dynamic_id` 的常量 `0x2A/0x3D`、`0x4A/0` 同样是明文 `movs` 立即数。

---

## 6. 问题 4：最小桩的实现建议

### 6.1 两种做法与取舍

| 方案 | 工作量 | 侵入性 | 建议 |
|---|---|---|---|
| **A. 用户态替换 `libosal_uipc.so`（或 `LD_PRELOAD` 覆盖 `osal_*`）** | 小 | 不碰内核、不碰 QEMU | ★ **推荐** |
| B. 在 QEMU/内核侧实现 `/dev/uipc` 驱动（17 个 ioctl + 1 MiB remap） | 大 | 需要内核态 | 只在必须跑原版 `.so` 时做 |

**推荐 A**：因为 `libsencore` 只通过 9 个 `osal_*` 符号交互，而这些符号**全部由 `libosal_uipc.so` 导出**。
写一个同名 `.so`（导出同样的符号，内部用纯用户态队列 + 造应答），
`libsencore` 完全无法区分。连 `/dev/uipc`、`osal_uipc.ko`、1 MiB 映射都不需要存在。

### 6.2 方案 A：需要实现的最小符号集

必须导出（否则 `libsencore` 加载失败）：

```
osal_snd_msg, osal_rcv_msg_tmo, osal_valloc_msg_wait, osal_free_msg,
osal_dynamic_id, osal_snd_sync_msg, osal_snd_sync_direct,
osal_reg_sync_msg_queue_cb, osal_unreg_msg_queue_cb
```
外加（保险起见，其它库也会用）：`osal_msg_size`, `osal_set_msg_pri`, `osal_get_msg_pri`,
`osal_stat_msgq`, `osal_stat_sem`, `osal_sig_sem`, `osal_wai_sem_tmo`,
`osal_lock`, `osal_unlock`, `osal_get_uipc_stat`, `u_osal_init`, `u_osal_exit`,
`u_uipc_init`, `u_uipc_exit`。

### 6.3 伪代码

```c
/* ---- 共享的最小 ABI：块 = 12 字节头 + payload ---- */
#define HDR 12
typedef struct blk { struct blk *next; u8 size_class; u8 pri; u8 pad[6]; } blk_t;

/* 32 字节粒度分配：payload 容量 = class*32 - 12；class 0 → 20 字节 */
static void *valloc(size_t len) {
    if (len > 0x1000) return NULL;                 /* 内核同样上限 */
    size_t need = len + HDR;
    u8 cls = (need <= 20) ? 0 : (u8)((need + 31) / 32);
    blk_t *b = calloc(1, cls ? cls * 32 : 20);
    b->size_class = cls;
    return (u8 *)b + HDR;                          /* 调用者拿到的是 payload 指针 */
}
static size_t msg_size(const void *msg) {          /* 语义与 osal_msg_size 一致 */
    if (!msg) return (size_t)-1024;
    u8 c = ((const u8 *)msg)[-8];
    return c ? (size_t)(c * 32 - 12) : 20;
}
#define BLK(msg) ((blk_t *)((u8 *)(msg) - HDR))

/* ---- 队列：单链 + 优先级有序插入（照抄 osal_snd_msg 行为） ---- */
typedef struct { u32 qid; u32 head, tail; u8 flags; void *cb; } msgq_t;
static msgq_t qs[0x8000];                          /* 按 qid & 0x7FFF 索引 */

int osal_snd_msg(u32 qid, void *msg) {
    if ((i32)qid < 0 || !msg) return -1024;
    msgq_t *q = &qs[qid & 0x7FFF];
    if (q->qid && q->qid != (qid & 0x0FFFFFFF)) return -1023;
    blk_t *b = BLK(msg); b->next = NULL;
    /* 按 b->pri & 0x3F 有序插入 q->head…；此处从简：尾插 + 记日志 */
    ...;
    deliver_or_pump(q);        /* 见下：把请求交给"假副控制器" */
    return 0;
}

/* ---- 一次性回复队列（osal_dynamic_id） ---- */
int osal_dynamic_id(u16 type, u16 max, u32 *out) {
    static u32 next = 0x3C;
    if (type == 0x4A) { *out = 0; return 0; }       /* 释放 */
    *out = 0x610000 | (next++ & 0x7FFF);            /* 造一个 bit15=0 的跨进程 qid */
    return 0;
}

/* ---- 收包 ---- */
int osal_rcv_msg_tmo(u32 qid, void **out, u32 tmo_ms) {
    msgq_t *q = &qs[qid & 0x7FFF];
    if (!q->head) { *out = NULL; return -1022; }    /* 超时 */
    *out = pop(q);
    return 0;
}
```

### 6.4 "假副控制器"要回哪些消息

按 `libsencore` 实际发送的内容，最少要覆盖：

| 触发点 | 请求（payload） | 应答（payload） |
|---|---|---|
| `dmm_allocm(len)` | `+0x00=1`, `+0x04=len`, `+0x16=1` | `+0x02=0`(status), `+0x04=len`(回填), `+0x10=<假地址>` |
| `dmm_free(h)` | `+0x00=4`, `+0x02=h`, `+0x16=2` | `+0x02=0` |
| `tlog_get_version` | `+0x18=0x0603`，len 320 | 版本字符串（放 `+0x18` 之后，长度自定） |
| `tlog_get_serial_code` | `+0x18=0x0701` | 序列号字符串 |
| `tlog_get_dest` / `get_date` | `+0x18=0x0603` / direct 路径 | 对应短应答 |
| `Blog::write` | 13/32/15 字节小报文 | 可只回 status=0 |

应答必须投递到**请求里带的动态 qid**（`sub_12C74` 填的那个字段，推测在 `+0x10`），
否则 `dmm_allocm` 的 `osal_rcv_msg_tmo` 会超时（10 s）。
实现上最省事的做法：在 `osal_snd_msg` 里直接同步解析请求 → 生成应答 → 压入动态 qid 的队列，
再返回 0；这样 `rcv_msg_tmo` 立刻就能取到。

### 6.5 若必须做方案 B（内核/QEMU 侧）

最小要求（全部已确证，可直接照做）：

1. 提供一个 `/dev/uipc`（或让 `osal_uipc.ko` 原样工作）；
2. `open(O_RDWR)` 成功；
3. `ioctl(0x80000010, {0, p16})` 返回 0，并记住当前 pid（后续 opcode 会校验 pid 一致）；
4. `mmap(NULL, 0x100000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)` 必须返回一块
   **1 MiB、进程内可读写**的普通内存；偏移必须落在 `[0, 0x100000)`；
5. `ioctl(0x8000000A)`（valloc）返回的"消息地址"必须是上面这块内的偏移（内核会做
   `vm_start + (handle - BASE)` 变换，桩里可以令 `BASE = vm_start`，则 handle == 用户地址）；
6. 覆盖 opcode 4/5/7/10/11/12 即可让 `libsencore` 的 dmm/tlog 跑通。

---

## 7. 无法确定 / 需要动态验证的部分

| # | 项 | 状态 | 说明 |
|---|---|---|---|
| 1 | `connect` 是否回写 16 字节 | **矛盾** | 内核只有 `copy_from_user`（无 `copy_to_user`），但 `do_init` 把栈上未初始化的 `r7[0..0xC]` 当回执读，且用 `r7[0]` 作 mmap 长度。可能真机上是"读脏栈 + 恰好可用"，也可能我漏看了一次 copy_to_user。**需 gdb/实测确认**（不过内核强制 len==0x100000，所以实际必为 1 MiB）。 |
| 2 | 1 MiB 内部分区表语义 | 推测 | 默认 `{0x100000, 0x40000, 0x8000, 0}` 四个数的含义（总长/三段边界？）未定；`ctx->[0x34]` 存第 4 个字。 |
| 3 | 指针翻译的 `BASE` 具体符号 | 推测 | 重定位落在 `.bss+0x28` 处；同一地址在 `__k_4u_connect` 里当作用户链表头。是结构体同址多字段还是我错配，未定。 |
| 4 | `sub_12C74` 填的确切字段 | 推测 | 只知它写 `msg+0x10` 区域且"看起来"写的是回复 qid；应答回显也读 `+0x10`。 |
| 5 | `msg+0x16` 字段命名 | 推测 | 值 1/2 对应 alloc/free 请求，我暂称"请求种类"，也可能是 `TransType` 的低字节。 |
| 6 | tlog 的 `0x0603`/`0x0701` 位域 | 推测 | 只知是 u16 命令字；高位像 module id、低位像 command id。 |
| 7 | `Blog::write` 三种长度的语义 | 未定 | 0xD / 0x20 / 0xF 三路，报文内容未展开。 |
| 8 | `tlog` / `SubsystemCommunicationCommand` 的 qid 字面量 | 未定 | 从 GOT 全局变量加载，本轮未逐个回溯初值（只确认了 dmm 的 `0x61003C`）。 |
| 9 | `SubsystemCommunicationCommand` 的 `0x140` 报文 | 未定 | 只看到 `valloc(...,0x140)` + `snd_sync_msg`，字段未展开。 |
| 10 | `connect` 里的 `osal_dynamic_id(0x2A,0x3F,...)` 用途 | 推测 | 疑为给每个连接分配一个 id 供内核回调使用。 |
| 11 | 文档 71/75 的 `0x300` 分片 / `FIN_SEND_DATA` 属于哪一层 | **重要** | 本轮确认 libsencore 有 USB 链路；这些字符串更可能属于 **senser 包（USB/串口）**，而不是 uipc。**若要复现字体传输，桩应该做在 USB/tty 那层，而不是 `/dev/uipc`。** |
| 12 | `fcntl(fd, 2, 1)` 语义 | 未定 | `do_init` 里 `r1=2, r2=1`；像 `F_SETFD, FD_CLOEXEC`，未证实。 |
| 13 | `sen.elf` / `ud_send_lsi.elf` | 未分析 | 两个小文件（19 KB / 4.3 KB）可能是副控制器侧或测试工具，值得下一轮看。 |

---

## 8. 关键地址/偏移速查表

### 8.1 `libosal_uipc.so`（VA = 文件偏移）

| VA | 名称 | 备注 |
|---|---|---|
| 0x15f4 | `.plt` 起点 | 88 项，12 B/项 |
| 0x1a84 | `.text` 起点 | |
| 0x1b00 | `u_osal_init` | |
| 0x210c | **`do_init`** | open + connect + mmap（428 B） |
| 0x22e8 | `u_uipc_init` | |
| 0x25b8 | `u_osal_snd_msg` | Thumb，ioctl 4 |
| 0x2604 | `u_osal_snd_sync_msg` | Thumb，ioctl 5 |
| 0x26f4 | `u_osal_rcv_msg_tmo` | Thumb，ioctl 7 |
| 0x2748 | `u_osal_reg_msg_queue_cb` | Thumb，ioctl 8 |
| 0x2870 | `u_osal_valloc_msg_wait` | Thumb，ioctl 10 |
| 0x28c8 | `u_osal_free_msg` | Thumb，ioctl 11 |
| 0x2914 | `u_osal_dynamic_id` | Thumb，ioctl 12 |
| 0x3c34 | `osal_snd_msg` | 双路分发 + 优先级有序插入 |
| 0x3ed8 | `osal_rcv_msg_tmo` | 双路分发 |
| 0x3fec | `osal_valloc_msg_wait` | 双路分发，`len>0x1000` 拒绝 |
| 0x4300 | `osal_reg_msg_queue_cb` | |
| 0x43dc / 0x4408 | `osal_set_msg_pri` / `osal_get_msg_pri` | `msg-7` |
| 0x4b80 | `osal_msg_size` | `msg-8`，class*32-12 |
| 0x4fbc / 0x502c | `osal_lock` / `osal_unlock` | |
| 0xef60 / 0xef80 / 0xefa4 / 0xefb8 | `uipc_opt` / `uconf` / `uipc_stat` / `vpool` | `.bss` 全局 |
| 0x5348 | `"/dev/uipc"` | |
| 0x5354 | `"open /dev/uipc error: "` | |
| 0x536c / 0x5374 | `"ioctl :"` / `"mmap error: "` | |
| 0x5320 | `"[U]**UIPC ERROR** %s: ioctl error %d"` | |
| 0x5534 / 0x551c | `/proc/osal/uipc` / `/tmp/uipc_stat_user.txt` | |

### 8.2 `osal_uipc.ko`（文件偏移 = VA + 0x34）

| VA | 文件偏移 | 名称 | 备注 |
|---|---|---|---|
| 0x2a8 | 0x2dc | `__k_uipc_cdev_mmap` | 强制 len == 0x100000 |
| 0x494 | 0x4c8 | **`__k_4u_connect`** | opcode 16，分区表 + ctx 入链 |
| 0x5a8 | 0x5dc | **`__k_uipc_cdev_ioctl`** | 分发表 + pid 校验 |
| 0x6a4 | 0x6d8 | `__k_4u_dynamic_id` | opcode 12 |
| 0x784 | 0x7b8 | `__k_4u_reg_msg_queue_cb` | opcode 8 |
| 0xb34 | 0xb68 | `__k_uipc_release` | `file->private_data` 在 **file+0xA8** |
| 0xbf8 | 0xc2c | `__k_uipc_open` | |
| **0xe68** | **0xe9c** | 句柄 → 用户 VA | `vm_start + (h - BASE)` |
| 0x10e8 | 0x111c | `__k_4u_valloc_msg_wait` | opcode 10，args 12 B |
| 0x11dc | 0x1210 | `__k_4u_rcv_msg_tmo` | opcode 7 |
| 0x12f8 | 0x132c | `__k_4u_free_msg` | opcode 11 |
| **0x12c0** | **0x12f4** | 用户 VA → 句柄 | 1 MiB 边界校验 |
| 0x1338 | 0x136c | **`__k_4u_snd_msg`** | opcode 4 |
| 0x316c | 0x31a0 | `osal_snd_msg`（内核侧） | |
| 0x40f0 | 0x4124 | `reg_msg_queue_cb` | |
| `.rodata+0x28` | 0x57c8 | **opcode 分发表（17 项）** | op → `__k_4u_*` |
| `.rodata+0x00` | 0x57a0 | `"__k_uipc_cdev_mmap"` 等名字表 | `/proc` 用 |
| `.bss` 0x28/0x2c | — | 用户链表头 / mutex | |
| `.bss` 0xe300 起 | — | `uconf` 等全局 | |

内核侧导出（`__ksymtab`，25 个）：`osal_snd_msg`、`osal_rcv_msg_tmo`、`osal_snd_sync_msg`、
`osal_snd_sync_direct`、`osal_valloc_msg_wait`、`osal_free_msg`、`osal_reg_msg_queue_cb`、
`osal_reg_sync_msg_queue_cb`、`osal_unreg_msg_queue_cb`、`osal_dynamic_id`、`osal_lock/unlock`、
`osal_set/get_msg_pri`、`osal_set_msgq_{log,broadcast}_mode`、`osal_stat_msgq/sem`、
`osal_sig_sem`、`osal_wai_sem_tmo`、`osal_msg_size`、`osal_get_uipc_stat`、
`osal_{get,free}_stack`、`udif_uipc`。
`modinfo`：`author=Sony Corporation`、`license=Proprietary`、`depends=devno`、
`vermagic=3.0.27_nl-rt106+ SMP preempt mod_unload ARMv7`、`"OSAL Version 4.2"`、
`"Compiled at Jul 15 2020 02:41:42"`、源码路径
`<HOME>/git-work/.../Etools-OSAL-UIPC_171H/driver/msgq.c`。

### 8.3 `libsencore.so`（VA = 文件偏移）

| VA | 符号 | 备注 |
|---|---|---|
| 0x132ac | `_Z9dmm_allocmPt` | 最干净的请求/应答样板 |
| 0x13400 | `_Z8dmm_freet` | free 样板 |
| 0x12c74 | `sub_12C74` | 填请求的回复 qid 等 |
| — | `_Z14lsi_trans_initv` | `osal_reg_sync_msg_queue_cb` |
| — | `_Z14lsi_trans_exitv` | `osal_unreg_msg_queue_cb` |
| — | `_ZN29SubsystemCommunicationCommand9DoExecuteEP12SenserPacket` | `0x140` 报文 + `snd_sync_msg` |
| — | `_Z16tlog_get_versionPhi` 等 | 320 B 报文，`+0x18` 命令字 |
| — | `_ZN4Blog5writeEP12LOGREC_PARAM` | 13/32/15 B 报文 |
| 0x15120 | 收包函数（文档 75） | 读 0x200 字节，**属 flash/USB 路径** |
| 0x19BE9 | `"Receive Pkt Err : resCode=0x%x, Adrs=0x%x, DataSize=0x%x"` | |
| 0x19C22 | 同上第二副本 | |
| 0x19C92 / 0x19CDF | `"Trans(to Subsystem) size ..."` | |

---

## 9. 与既有文档的关系（需要更新的结论）

| 文档 | 原结论 | 本轮的修正/补充 |
|---|---|---|
| 71 | "报文里有 `TransType`、`FIN_SEND_DATA`、0x300 分片" | 这些属于 **senser 包（USB/串口）** 层，**不是** uipc 层。 |
| 71 | "实现该通道需逆向 libsencore 消息结构" | 已给出 uipc 层完整结构；senser 包层结构仍待做。 |
| 75 | "追 0xE6CC（open）/0xEE50（读 512）落到哪个硬件通道" | 那是 `SenserIf*` / flash 路径；uipc 侧是 ioctl，**没有 read/write**。 |
| 75 | "QEMU 侧定位该通道寄存器接口" | 若走 uipc，**不需要**寄存器接口；只需用户态符号替换（方案 A）。 |

---

## 10. 下一步建议（按性价比排序）

1. **先做方案 A 的最小桩**，只覆盖 `dmm` 四件事（alloc/free 请求 + 应答），
   用 `LD_PRELOAD` 验证 `libsencore` 的 `dmm_allocm` 不再超时 —— 这一步不需要 QEMU、不需要内核。
2. 用桩把 `tlog_get_*` 也回掉，观察调用序（可作为"初始化进度条"）。
3. 再判断**字体传输到底走哪条链**：在真机/模拟器上 hook `SenserIfSend` 与
   `osal_snd_msg`，看 1.96 MB 字体是通过 `SenserPacket`（USB）还是 OSAL 消息分片传的。
   这是决定"桩做在哪一层"的关键实验，成本很低（只需两组计数）。
4. 若确需方案 B，直接照 §3.6/§3.7 的表实现 6 个 opcode 即可，无需完整 msgq 语义。
5. 补做 `sen.elf`（19 KB）与 `ud_send_lsi.elf`（4.3 KB）的逆向 —— 体量小，
   很可能直接暴露副控制器侧的报文定义。

---

*本报告仅写入 `01-文档/78-uipc协议逆向.md`，未改动工作区其它文件。所有库均从 `nflasha15` 只读提取到临时目录分析。*
