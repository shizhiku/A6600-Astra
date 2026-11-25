# 75 · /system 探测结果 + libsencore 收包路径

本轮为相机只读探测 + 本地库逆向。无设备写入。

## 一、相机 `/system` 探测（只读）

| 路径 | 结果 |
|---|---|
| `/proc/mounts` | 返回 0 字节（该接口对 proc 文件不返回内容） |
| `/proc/self/mountinfo` | 返回 0 字节（同上） |
| `/system`（目录） | `Exception`（目录不可读，接口只能读文件） |
| `/system/version.txt` | `Exception`（不存在） |
| **`/system/sabin/ssboot.bin`** | **OK，11,280 字节** |
| `/system/lib/libMWF.so` | `Exception`（该路径下没有） |
| `/system/lib`（目录） | `Exception`（目录不可读） |

**结论**：`/system` 在真机上是**存在且可读**的分区；cmdline 里的 `cmpr.path=/system/sabin/ssboot.bin` 指向的文件确实存在（11,280 B，应为压缩后的启动镜像）。

这与模拟器中 `/system` 始终挂载失败（`mounting1 /dev/dnflasha3 -> /system as vfat failed. errno(6)`）形成对照：**真机有 `/system`，我们的模拟环境没有**。

## 二、libsencore 收包路径（逆向进展）

### 1. 报文错误字符串的虚拟地址

`.rodata` 段 `sh_addr == sh_offset`，故：

| 字符串 | VA |
|---|---|
| `Receive Pkt Err : resCode=0x%x, Adrs=0x%x, DataSize=0x%x` | `0x19BE9` |
| 同上（第二份副本） | `0x19C22` |
| `Trans(to Subsystem) size ...` | `0x19C92` / `0x19CDF` |
| `FileNotFound` | `0x19ABD` |
| `RECV_OSAL_PACKET` | `0x19AEC` |

### 2. 引用定位方法（踩过的坑）

- ❌ 把字面量当地址直接搜 dword —— 无命中
- ❌ `adr`（`add rX,pc,#imm`）扫描 —— 无命中
- ❌ `movw/movt` 配对 —— 无命中
- ✅ 正确模式：`ldr rX,[pc,#imm]` 取偏移 V，再 `add rX, pc`，地址 = V + (add指令地址 + 4)

例如：字面量 `0x4A61` @ `0x16CC` + `add r0, pc` @ `0x15184` → `0x15184+4+0x4A61 = 0x19BE9` ✓

### 3. 收包函数（`0x15120` 起）

```
015120  push {r4,r5,r6,r7,lr}
015122  sub.w sp, sp, #0x204        ; 512+4 字节栈帧
015128  mov  r4, r0
01512a  strb r6, [r0, #0x10]        ; 清错误标志
015130  movw r1, #0x1002            ; 参数（疑似通道/命令）
015136  blx  0xE6CC                 ; 打开/初始化
015144  mov  r0, r7                 ; 缓冲区
015148  mov.w r2, #0x200            ; ← 读取 512 字节
015160  blx  0xEE50                 ; 读取
015164  cmp.w r0, #0x200            ; 必须刚好读满 512
015168  beq  0x1518E                ; 成功
01516A  movs r6, #1
01516C  strb r6, [r4, #0x10]        ; 置错误标志
015174  ...                         ; 取某 id
015184  add  r0, pc                 ; "Receive Pkt Err ..." 字符串
015188  bl   0x14F98                ; 打印
```

**关键数据点**：

- 单次读取缓冲 **0x200 = 512 字节**
- 读不满 512 即判定收包错误
- 对象偏移：`[r4+0x10]` 错误标志、`[r4+0x1C]` 某状态字节
- 另外此前字符串显示还有 **0x300（768）字节窗口** 的分片校验（`Offset > 300Byte`），应是另一层（共享内存拷贝）的窗口

## 三、下一步

1. 反汇编 `0xE6CC`（打开）与 `0xEE50`（读 512 字节）看它们最终落到哪个硬件通道/系统调用；
2. 追 `0x1002` 这类参数的含义（通道号/命令码）；
3. 在 QEMU 侧定位该通道的寄存器接口，实现“读到固定 512 字节应答”；
4. 之后再攻共享内存侧的 0x300 分片拷贝。

## 四、证据

- 相机探测：`03-证据/相机采集/live-system-20261121/receipt.json`、`system_sabin_ssboot.bin`（11,280 B）
- 脚本：`probe_live_system.py`、`find_sencore_packet_code.py`、`find_sencore_refs3.py`、`map_sencore_strings.py`
- 库：`03-证据/静态分析/libsencore.so`

## 五、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；相机本轮仅只读探测（未修改）。
