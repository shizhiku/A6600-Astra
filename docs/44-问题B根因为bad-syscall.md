# 44 · 问题 B 根因：内核把 syscall 191 判为 bad syscall 并投 SIGILL

本轮为离线反汇编与内核字符串分析。无设备写入。

## 一、应用中止点的调用者已定位

在固定基址（`norandmaps`，libc 基址 `0x041B7000`）下断于 SIGILL 地址，取得调用者返回地址 `0x04251C33` → libc 偏移 `0x9AC33`。

反汇编该处（libc）：

```
09ac28  push  {lr}
09ac2a  mov.w ip, #0xbf        ; 系统调用号 0xBF = 191
09ac2e  bl    0x15790          ; 进入 syscall 桩（push {r7,lr}; mov r7,ip; svc #0; pop）
09ac32  cmn.w r0, #0x1000      ; 返回后检查错误码
09ac36  bhi   0x09ac3c         ; 出错 → 设置 errno
```

即：应用调用 **syscall 191**（ARM 上属 rlimit 一族），并在 `svc` 返回后出现 SIGILL。

## 二、内核里找到了对应机制

内核镜像中存在如下字符串：

```
complete system call %08x
<3>Oops - bad syscall.
<6>%s (%d): undefined instruction: pc=%p
```

说明这个内核对自己的系统调用做了**白名单/禁用处理**：遇到不认识或被禁的调用号，会打印 `Oops - bad syscall.` 并按**未定义指令**处理，从而向进程投递 SIGILL。

这与观测完全吻合：

- QEMU `-d int` 记录到大量“用户态未定义指令”异常（305 次）；
- 应用侧没有任何 `ENOSYS` 处理痕迹，而是直接被 SIGILL 终止。

## 三、这解释了此前的所有异常现象

| 现象 | 解释 |
|---|---|
| 内存字节与文件一致、Thumb 解码合法（`pop`）却报未定义 | 异常由内核主动投递，PC 指向 syscall 桩返回处 |
| CPSR 显示 Thumb=on 却是“非法指令” | 同上，与指令解码无关 |
| 无 dlopen/断言/错误文本 | 内核层面直接 SIGILL，glibc 来不及打印 |
| noinit 与 state1 两条路径中止点一致 | 中止点是**固定的一处 syscall 调用**，与 av-cam 状态无关 |

## 四、仍待解释的一点

真机上运行同一内核、同一 libc，理论也会踩到同一 syscall。可能的原因：

1. 真机的执行路径不经过这次调用（某些初始化条件不同）；
2. 该 syscall 在真机上并未被禁用，而是模拟环境的某种状态导致内核走了禁用分支；
3. 我们用的 libc 与真机实际运行的不是同一份（此前已发现 av-cam 存在更新包与真机不同构建的先例）。

第 3 点值得优先排除——与 av-cam 那次一样，可以从真机直接读取 `/lib/libc-2.11.2.so` 做比对。

## 五、下一步

1. **只读采集真机的 `/lib/libc-2.11.2.so`**（与取 av-cam 的方法相同），比对偏移 `0x9AC2A` 处的系统调用号是否一致。若不同，则又是“构建不一致”问题。
2. 若一致，则在 QEMU 中定位内核判定 “bad syscall” 的具体分支，确认是哪个条件触发。
3. 顺带确认该内核的系统调用表中 191 号是否为空。

## 六、证据

- libc 反汇编：`03-证据/静态分析/nflasha7_libc-2.11.2.so` 偏移 `0x9AC00`–`0x9AC60`
- 内核字符串：`/root/qemu_in/nflasha3-Image`
- 扫描脚本：`02-脚本/scan_kernel_syscalls.py`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；真机未接触。
