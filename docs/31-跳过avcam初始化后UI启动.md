# 31 · 跳过 av-cam 初始化后 UI 栈成功启动

本轮为离线 QEMU 实验。无设备写入。

## 一、诊断镜像：av-cam 入口直接返回

为判断“UI 是否能脱离 av-cam 启动”，生成一个诊断副本 `av-cam-noinit.bin`：把 `entry_pre`（`0x635C6044`）与 `entry_main`（`0x635C6058`）两条 ARM 指令替换为 `bx lr`（`1eff2fe1`）。

- 只改我们喂给模拟器的副本，真机与原始文件未动；
- SHA-256：`e274e882b632b3fa0b2eedcfbf54c8faeec4c774ee5736a43b190453d81451a8`

## 二、结果：原来的空写故障消失

| 项目 | 原始 av-cam | 诊断 noinit |
|---|---|---|
| `Unhandled fault` | 1 | **0** |
| 进入异常监视器 | 是（2.56 s） | 是（**3.22 s**，另一原因） |
| 最后 guest 时间 | 2.565 s | **3.216 s** |

## 三、UI 进程已经跑起来了

新故障点的日志显示：

```
program: im.elf(Appframework) (pid: 228, cpu:0, tid: -1, stackpage: 0x68ec1800)
...
17354000-18c5c000 r-- 0x00000000 image_cmn_169.uxc
18c72000-18f3e000 r-- 0x00000000 image_EVF.uxc
18fa1000-19281000 r-- 0x00000000 image_DSLR_Only_169.uxc
...
address: 00000000, trap_no: 00000006, error_code: 00000000
Illeagle Instruction at 0x04253796
```

即：

1. **`im.elf`（Appframework）进程已创建并运行**；
2. 已加载 UI 资源 `image_cmn_169.uxc`、`image_EVF.uxc`、`image_DSLR_Only_169.uxc`；
3. 随后在 `0x04253796` 触发未定义指令（trap 6）。

这是首次确认**四代 UI 栈可以在本模拟器中运行**，此前一直卡在 av-cam 的等待上。

## 四、非法指令的位置与初步判断

`0x04253796` 落在 `libc-2.11.2.so`（映射区间 `0x0423E000-0x0432B000`）内，偏移 `0x15796`。

解码该偏移：

```
ARM  : 0xbd80  → 解码为数据/无意义
Thumb: 0xbd80  → pop {r7, pc}   ← 合法指令
```

地址为偶数、按 Thumb 解码完全合法，却报未定义指令 → 说明**执行时 CPU 处于 ARM 状态去解释 Thumb 字节**，即发生了**状态不匹配**（函数指针丢失 Thumb 位或调用方式错误）。

由于该故障只在“跳过 av-cam 初始化”的诊断镜像下出现，很可能是**未初始化状态导致的错误跳转**，而非独立的模拟器缺陷。

## 五、结论与意义

1. av-cam 的初始化等待确实是当前唯一挡住 UI 的点；
2. 一旦跳过它，UI 框架与资源加载链路是通的；
3. 但跳过初始化会引入新的错误跳转，因此**不能把 noinit 当成真正的解决方案**。

这为后续提供了两条清晰路线：

- **路线一（正解）**：补齐 av-cam 需要的对端模型（SIO ch0 协议），让初始化正常完成；
- **路线二（权宜）**：在 noinit 基础上继续修 0x04253796 的状态不匹配，把 UI 推到菜单（可先验证 ASTRA 移植，但不是原厂完整启动）。

## 六、证据

- 诊断镜像：`05-原始固件/qemu_in/av-cam-noinit.bin`
- 运行记录：`03-证据/模拟器运行/cmdline-20261120T192924Z-42273/serial.log`
- libc 提取与解码：`03-证据/静态分析/libc-2.11.2.so`，脚本 `decode_libc_fault.py`
- 生成脚本：`make_avcam_noinit.py`

## 七、状态

- 原厂 UI 未启动（但 UI 框架已验证可运行）；
- 最小垫片与 ASTRA UI 未验证；
- 实验固件不可刷；
- 真机未接触。
