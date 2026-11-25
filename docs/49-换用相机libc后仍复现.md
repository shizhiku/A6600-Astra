# 49 · 换用相机 libc 后仍复现：问题 B 与构建差异无关

本轮包含本地镜像修改与离线 QEMU 运行。无设备写入。

## 一、把相机 libc 装进模拟器的方法

`nflasha3-initrd` 本身就是**内嵌的 ext2 根文件系统**：

- 超级块位于偏移 1024，块大小 1024，共 2132 块；
- `root=/dev/ram0`，所以根文件系统就是这个镜像。

于是可以原地替换：

1. 定位 `/lib/libc-2.11.2.so` 的 inode（**408**），大小 984,276 B，占用 962 个数据块（含直接块、一级与二级间接块）；
2. 把相机采集到的 libc（984,292 B）写入这 962 块（两者块数相同）；
3. 更新 inode 的文件大小字段为 984,292；
4. 输出新镜像 `nflasha3-initrd-live-libc`（2,184,192 B，与原镜像同大小）。

验证：读回 inode 大小 = 984,292，文件头为 `7f 45 4c 46`（ELF），与源文件一致。

## 二、用相机 libc 启动的结果

组合：`Backup-state1.bin`（绕开 av-cam panic）+ 相机 libc 的 initrd。

| 项目 | 更新包 libc | 相机 libc |
|---|---|---|
| `Unhandled fault` | 0 | 0 |
| 异常监视器 | 是（3.33 s） | 是（3.37 s） |
| 故障地址 | libc + `0x15796` | **仍为 libc + `0x15796`** |
| 进程 | im.elf (pid 368) | im.elf (pid 369) |

## 三、结论：构建差异不是 B 的成因

换用相机 libc 后，故障点**分毫未变**（仍落在 libc 偏移 `0x15796` 的 syscall 桩返回处）。

这否定了“用错 libc 导致 B”的假设。

同时确认两份 libc 在该偏移处的字节**完全相同**：

```
0x15790: 80 b5 67 46 00 df 80 bd   →  push {r7,lr}; mov r7,ip; svc #0; pop {r7,pc}
```

即该桩在两个构建里一模一样，故障不来自桩的实现差异。

## 四、构建差异仍然是真问题（但不解释 B）

此前已确认：相机 libc 与更新包 libc 仅 10/241 个 4 KiB 块相同；av-cam 亦不同。这是**模拟保真度**问题，应继续修正（尤其涉及行为差异时），但它不是当前崩溃的原因。

## 五、下一步

回到 syscall 参数本身：

- 此前寄存器现场显示 `r0 = 0`、`r1 = 0x170`；
- `getrlimit(resource=0, rlim=0x170)` 的 `rlim` 是一个**明显无效的指针**（0x170 = 368，位于低地址）；
- 若内核因此返回 `-EFAULT`，glibc 的 `getrlimit` 会返回 -1，调用方可能据此中止。

因此下一步应确认：这个 `0x170` 是真实的调用参数，还是被信号打断时的无关寄存器值。方法是在 syscall 桩入口（`libc+0x15790`）下断，直接读取 `r0/r1/ip`。

## 六、证据

- 相机 libc：`03-证据/相机采集/live-libc-20261121/system_libc-2.11.2.so`
- 打过补丁的 initrd：`05-原始固件/qemu_in/nflasha3-initrd-live-libc`
- 运行：`03-证据/模拟器运行/cmdline-20261120T202917Z-47159/serial.log`
- 脚本：`patch_initrd_libc.py`、`allow_alt_initrd.py`、`run_live_libc.sh`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；相机本轮仅只读采集。
