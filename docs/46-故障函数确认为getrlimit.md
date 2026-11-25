# 46 · 故障函数确认为 getrlimit；BusyBox 对照实验不 conclusive

本轮为离线分析与 QEMU 内 shell 实验。无设备写入。

## 一、故障函数已确认

用 libc 符号表定位偏移 `0x9AC2A`（失败现场）：

```
0x9ac29  size=0x2c  getrlimit
0x9ac55  size=0x2c  setrlimit
0x9ac81  size=0x38  getrlimit64
```

即失败调用来自 **`getrlimit()`**，它内部的 `mov.w ip,#0xBF` 使用系统调用号 **191（`ugetrlimit`）**。

## 二、QEMU 内 shell 对照实验

通过串口向客户机 BusyBox 喂命令：

```
echo SHELLTEST_START      → SHELLTEST_START
ulimit -a
echo getrlimit_rc=$?      → getrlimit_rc=0
ulimit -n 123
echo setrlimit_rc=$?      → setrlimit_rc=0
echo SHELLTEST_END        → SHELLTEST_END
```

结论：**BusyBox 的 `ulimit` 调用成功返回 0**。

## 三、但这个实验不足以证伪

BusyBox 通常是**静态链接**、自带实现，可能走的是系统调用 **76（`getrlimit`）**，而不是 glibc 用的 **191（`ugetrlimit`）**。

两者在 ARM 上并存，内核可能只实现其中一个。因此：

- 本实验只证明了「某个 rlimit 系统调用可用」；
- **没有证明 191 号可用**。

## 四、下一步（可离线完成）

1. 从 initrd 中提取 `/bin/busybox`，反汇编其 `ulimit` 实现，确认它用的是 76 还是 191；
2. 若用的是 76，则实验无效，需要另找动态链接程序测试 191；
3. 若用的是 191，则说明异步：`getrlimit` 在该系统可用，而应用崩溃另有原因（需回到调用栈分析）。

相机仍未上线，真机 libc 比对（`verify_live_libc.py`）继续挂起。

## 五、证据

- 符号定位：`03-证据/静态分析/nflasha7_libc-2.11.2.so`
- shell 实验运行：`03-证据/模拟器运行/shelltest-20261120T202503Z-46799/serial.log`
  - `SHELLTEST_START` 行 7897；`getrlimit_rc=0` 行 12055；`setrlimit_rc=0` 行 15348
- 脚本：`02-脚本/shell_test_getrlimit.sh`、`identify_libc_syscall_fn.py`

## 六、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；真机未接触。
