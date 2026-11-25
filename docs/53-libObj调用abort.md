# 53 · 用 QEMU 内部钩子定位：libObj.so 调用 abort()

本轮为 QEMU 源码修改、编译与离线运行。无设备写入。

## 一、工具突破：QEMU 内部虚拟地址钩子

gdbstub 的执行断点对用户态地址不可靠（跨进程页表翻译问题）。改为在 QEMU 的 TCG 执行循环里直接比较**虚拟 PC**：

- 在 `accel/tcg/cpu-exec.c` 的 `cpu_loop_exec_tb()` 入口加入 `rea_bp_check()`；
- 由环境变量 `REA_BP_VA` 指定目标虚拟地址；
- 命中时输出 `REA_BP` 行并调用 `cpu_dump_state()` 打印完整寄存器；
- 最多记录 64 次，默认不启用（未设置环境变量时零开销）。

编译通过。

## 二、第一跳：`raise` 的调用者

`REA_BP_VA=0x041dbd65`（相机 libc `raise` 入口）：

```
REA_BP hit=1 va=0x41dbd65 tb_pc=0x41dbd64 size=18
R14=041dcbdf  R13=11979028  R12=042b0298
```

- `R14 = 0x041DCBDF` → libc 偏移 **`0x25BDF`**；
- 相机 libc 中 **`abort` = `0x25AE1`，大小 472**（覆盖 `0x25AE1`–`0x25CB9`）；
- 故 `0x25BDF` **落在 `abort` 内部**。

**证实：`abort()` → `raise(SIGABRT)`。**

## 三、第二跳：`abort` 的调用者

`REA_BP_VA=0x041dcae1`（相机 libc `abort` 入口）：

```
REA_BP hit=1 va=0x41dcae1 tb_pc=0x41dcae0 size=22
R14=05e2491f  R13=113fd140
```

- `R14 = 0x05E2491F`；
- 解析该次运行的内存映射：`0x05E2491F` 属于 **`libObj.so`**，r-x 段 `0x057E3000`–`0x06AE0000`，文件偏移为 0；
- 故偏移 = `0x05E2491F − 0x057E3000` = **`0x64191F`**。

**结论：是 UI 库 `libObj.so` 主动调用了 `abort()`。**

## 四、意义

此前只知道“应用自我终止”，现在把责任精确定位到 **libObj.so**：

- `im.elf` 只是框架进程名，真正的终止者是 UI 库；
- 这很可能是 libObj 内部某个断言/错误检查失败后的主动退出；
- 下一步只需在 `libObj.so` 内定位该调用点，即可知道它检查了什么条件。

## 五、下一步

1. 精确反汇编 libObj 的 `0x64191A` 附近（注意 Thumb `bl` 的返回地址 = 调用点 + 4），确认调用点与前置条件；
2. 查找该调用点附近的字符串引用/断言文本，判断失败原因；
3. 若指向缺失资源或服务，则与 av-cam/系统状态关联；若指向模拟器行为差异，则属环境问题。

## 六、证据

- QEMU 补丁：`02-脚本/patch_qemu_bp_hook2.py`（`accel/tcg/cpu-exec.c`）
- 运行：`03-证据/模拟器运行/cmdline-20261120T204924Z-48634`（raise 命中）
- 运行：`03-证据/模拟器运行/cmdline-20261120T205136Z-48794`（abort 命中）
- libObj 提取：`03-证据/静态分析/libObj.so`（20,889,004 B，来自 `/lib/libObj.so`）

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；相机本轮未接触。
