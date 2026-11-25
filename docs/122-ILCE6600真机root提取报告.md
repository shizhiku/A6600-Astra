# 122 · ILCE-6600 真机 root 提取报告（首次成功）

> 时间：2026-11-22 06:0x-06:2x。设备：`ILCE-6600`，固件 `1.10`，Product code `0032851225`，序列号 `05674764`，Backup region `CH88301_CN1`。
> 工具：Sony-PMCA-RE（GitHub `ma1co/Sony-PMCA-RE`）+ usbipd-win 5.3.0 + WSL2 Ubuntu。
> **本次只做只读操作，未写入相机任何内容。**

## 一、结论：root 通道已打通，且已实际取到真机文件

| 能力 | 状态 | 证据 |
|---|---|---|
| 进入 PMCA service mode（`054c:0d0e` → `054c:0336`） | ✅ 成功 | `usbipd list` 显示 `054c:0336 Sony USB Device` |
| 通过 Sony senser 认证 | ✅ 成功 | PMCA 输出 `Authenticating` 后进入 `platform shell` |
| 获得 platform shell（root 级命令集） | ✅ 成功 | `help` 列出 `pull/push/shell/bootrom/bk/tweak/info` |
| **获得相机内部 BusyBox root shell** | ✅ **成功** | 输出 `BusyBox v1.29.3 (2018-12-07) built-in shell (ash)`，提示符 `/usr/share/app #` |
| **从真机 pull 出真实文件** | ✅ **成功** | `/usr/lib/libAK8975.so` = **45,428 B**，SHA256 `286e684899ecb2806373129c1bf78a7b9f0cd5c8738f4f36e2c63a6fb3abc05c` |

获得的 root shell 证据（原始串口输出）：

```
>shell
Terminal activated. Press <CTRL+C> to exit.
[ 1777.237706] console [usbgcon-1] enabled
[ 1777.238387] [usbter usbg_sen_ldisc_open][153]exit
BusyBox v1.29.3 (2018-12-07 16:14:33 JST) built-in shell (ash)
Enter 'help' for a list of built-in commands.
ash: can't access tty; job control turned off
/usr/share/app #
```

## 二、关键机制（为什么能拿到 root）

1. **PMCA service mode 本身是高权限模式**：相机切到 `054c:0336` 后，主机可用 Sony senser 协议认证并进入 `serviceshell`；
2. `SenserPlatformBackend` 继承自 `ShellPlatformBackend/FilePlatformBackend/MemoryPlatformBackend/BackupPlatformBackend`，因此具备：
   - `pull/push`（文件读写）
   - `readMemory`（按偏移读内存/存储 → 等价 `dd`）
   - `bootrom`（dump boot rom）
   - `bk r/w/patch`（备份区读写）
3. `shell` 命令通过 `setTerminalEnable` + `transferSenserTerminal` 把相机内部终端桥接到主机 → **直接进入相机 BusyBox ash**；
4. 该 BusyBox shell 运行在相机 root 上下文（可读 `/usr/lib`、可 dump bootrom）。

## 三、踩过的坑（已解决，供复现）

| 问题 | 原因 | 解决 |
|---|---|---|
| `usbipd attach` 报“no WSL 2 distribution running” | WSL 实例空闲会退出 | 保持一个常驻 WSL 会话 |
| 切到 service mode 后 PMCA 报 timeout | 相机重新枚举成新 PID（`0d0e`→`0336`），usbipd 不会自动跟随 | **`usbipd attach --wsl --busid 1-2 --auto-attach`**（官方自动重挂选项），这是关键 |
| `pull /proc/version` 得到 0 字节 | `/proc` 是特殊文件，senser 文件后端读不到 | 改读真实文件（如 `/usr/lib/libAK8975.so`）即成功 |
| `pull /etc/version` 报 `Senser file control error 130` | 该路径在 a6600 上不存在 | 先用 shell 确认路径再 pull |
| 中断 shell 后再次认证报 `Input/Output Error` | 会话被强杀，相机端未复位 | 让相机自然复位（拔插/等待），重新走完整流程 |
| 相机报“请检查所链接设备” | 我此前 `usbipd bind` 后未解绑，设备被 USBIP 驱动占用（`oem215.inf`） | `usbipd unbind --busid 1-2` 归还标准驱动；见文档 121 |

## 四、当前可用的完整复现流程

```powershell
# 1) 保持 WSL 常驻
wsl -d Ubuntu --exec bash -lc "sleep 7200"    # 后台
# 2) 让相机以「大容量储存」模式接上，然后：
usbipd bind --busid 1-2 --force
usbipd attach --wsl --busid 1-2 --auto-attach   # 后台常驻，跟随重新枚举
```

```bash
# 3) 一次性完成：切 service mode -> 认证 -> platform shell
cd /root/astra/Sony-PMCA-RE
sudo PYTHONPATH=/root/astra/Sony-PMCA-RE python3 <仓库脚本>/98_pmca_full_drive.py "pull /usr/lib/xxx /tmp/xxx"

# 4) 需要交互式 root shell 时：
sudo PYTHONPATH=/root/astra/Sony-PMCA-RE python3 <仓库脚本>/98_pmca_terminal.py "cmd1" "cmd2"
```

## 五、下一步（需用户确认后再做）

拿到 root 后可以做的事，按价值/风险排序：

| 选项 | 内容 | 风险 |
|---|---|---|
| **R1 只读 dump** | `pull`/`readMemory` 取 `/usr`、`/etc` 等真实分区做校验，补强 F1/F3 证据；确认 a6600 实际分区布局 | 低（只读） |
| **R2 对比真机与离线镜像** | 用真机 `/usr` 校验我们离线构建的 M1 镜像是否语义一致 | 低（只读） |
| **R3 写入改造镜像** | 需先有可用的 ASTRA 镜像（阶段一 M-E 未达成），且写入 `/usr` 才在已验证恢复范围内 | 中-高 |
| **R4 写 `/etc` 开机钩子** | 持久化 root（A6400 项目做法） | 高（`/etc`=nflasha10，无已验证恢复通道） |

**建议：先做 R1/R2（只读）**，用于验证离线管线；等 M-E 达成后再考虑 R3。

## 六、边界

- 本次仅执行只读命令（`pull`、`shell` 内只读查询），**未写入相机任何分区、未安装开机钩子**；
- 后续任何写入操作仍需用户逐次明确授权，并附镜像 SHA256、目标分区、步骤与失败预案。
