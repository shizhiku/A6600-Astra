# 50 · 确认：应用以 SIGABRT 自我终止（不是内核陷阱）

本轮为离线分析与 QEMU 断点实验。无设备写入。

## 一、寄存器现场给出决定性证据

换用相机 libc 后的崩溃现场：

```
r0: 0x00000000   r1: 0x00000172   r2: 0x00000006   r3: 0x00000172
ip: 0x0000010c   sp: 0x12201014   lr: 0x041dbd8f   pc: 0x041cc796
cpsr: 0x20000030  (Thumb: on, Mode: USR)
```

解析：

- `lr = 0x041DBD8F`，libc 基址 `0x041B7000` → 偏移 **`0x24D8F`**；
- 相机 libc 符号表中 **`raise` = `0x24D65`**（大小 124），故 `0x24D8F` **就在 `raise()` 内部**；
- 参数 `r0=0, r1=0x172, r2=6` —— 与 `tgkill(tgid, tid, sig)` 形态一致；
- **`r2 = 6` 即 SIGABRT**。

结论：**应用通过 `raise(SIGABRT)` 自我终止**。Sony 的异常监视器把信号 6 标记为 “Illeagle Instruction”，这个措辞有误导性——它并不是 CPU 未定义指令异常。

## 二、与之前的推断对照

| 之前的推断 | 现在结论 |
|---|---|
| 内核把 syscall 191 判为 bad syscall → SIGILL | **否**（BusyBox 用 191 成功） |
| 用错 libc 导致崩溃 | **否**（换用相机 libc 后同点复现） |
| CPU 处于 ARM 态解释 Thumb 字节 | **否**（内存与文件一致，Thumb 解码合法） |
| 应用主动 `abort()` | **是**（`raise(SIGABRT)` 实证） |

## 三、仍未定位：谁触发了 abort

尝试在 `abort`（相机 libc `0x25AE1`）与 `raise`（`0x24D65`）入口下断，两次运行均超时未命中。原因待查：

- 可能是符号地址与实际入口不符（PLT/别名）；
- 或该函数通过内部跳转进入，未经过符号地址。

## 四、下一步

1. 在 `raise` 内部已知位置 `0x24D8F`（即 `lr` 指向处）**向前找调用者**：把断点设在 `0x24D65`～`0x24D8F` 之间任一确定被执行的地址，读栈回溯。
2. 或者直接在崩溃时刻（`0x041CC796`）读栈，手动回溯到 im.elf 的调用帧。
3. 目标：确定是哪个断言/错误检查触发了 `abort()`，以及它检查的条件。

## 五、本轮其他确认

- 相机 libc 与更新包 libc 在系统调用桩处字节相同（`push {r7,lr}; mov r7,ip; svc #0; pop {r7,pc}`），但整体仅 10/241 块相同，属不同构建；
- 相机 libc 中 `getrlimit = 0x9AD39`、`abort = 0x25AE1`、`raise = 0x24D65`（与更新包偏移不同）。

## 六、证据

- 运行：`03-证据/模拟器运行/cmdline-20261120T203220Z-47366/serial.log`
- 相机 libc：`03-证据/相机采集/live-libc-20261121/system_libc-2.11.2.so`
- 脚本：`observer_initrd_env.py`、`run_live_libc_norand.sh`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；相机本轮未接触。
