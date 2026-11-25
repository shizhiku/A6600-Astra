# 124 · 第十三轮：真机 root 复用 + Application_Start 阻塞点收窄

## 一、真机只读能力（已确认，全程未写相机）

本轮用 PMCA service mode 通道，对 `ILCE-6600`（FW 1.10）做了**纯只读**采集：

| 项 | 值 |
|---|---|
| 内核 | `Linux 3.0.27_nl-rt106+`，Sony CE Linux 8.2.6.0，编译 `Apr 10 2021` |
| `/usr/lib/libObj.so` | **20,889,004 B**，`r-xr-xr-x`，owner `57285:1000`，`Apr 9 2021` |
| `/usr/lib/appFw.so` | **不存在**（证实路径名与离线推测不同） |
| `/usr` | `ext2 ro`（只读挂载，物理上不可写） |
| `/` | `nflasha7` ext2 ro |

分区表（1 KiB 块）已记录到 `123-ILCE6600真机分区布局.md`，关键点：

- **`nflasha15` = 307200 KiB = 300 MiB**，与 M1 镜像 314,572,800 B **完全一致** → F3 疑点（300 MiB vs sum 的 215,517,184）可以解释为"分区容量 vs ext2 实际使用量"，不矛盾；
- **`/tmp` 与 `/etc` 共用 `nflasha10`**（真机证实 A6400 项目文档的说法）；
- **`nflasha16` = 140 MiB，运行期未挂载**（与 `109` 号报告指出的 ZV-1M2 缺失分区同尺寸，值得后续只读 dump）。

## 二、root 通道工程要点（踩坑总结）

| 现象 | 原因 | 对策 |
|---|---|---|
| `usbipd attach` 报无 WSL2 | WSL 空闲自动退出 | 保持常驻 WSL 会话 |
| PMCA 切 service mode 后 timeout | 相机重枚举 `0d0e`→`0336`，usbipd 不跟随 | **`usbipd attach --wsl --busid 1-2 --auto-attach`** |
| 连续第二次认证 `Input/Output Error` | 上次会话未让相机完全复位 | 每次会话后让相机自然复位再重连 |
| 相机从 USB 消失 | 会话中断后枚举异常 | 拔插 USB 线 |
| `pull /proc/*` 得 0 字节 | `/proc` 是特殊文件，senser 文件后端不支持 | 用 BusyBox shell 内 `cat`（已成功） |

**已确认可用的最可靠调用链**（相机已在 service mode 且 attached 时）：

```
python3 98_cam_bb2.py "cmd1" "cmd2" ...
```
→ platform shell → `shell` → 相机 BusyBox ash → 执行只读命令。

## 三、离线主线：Application_Start 阻塞点收窄

用最小化陷阱（3 个布点）确认了调用顺序：

```
Application_Start (0x54D580)
  └→ 0x54D2B0                      [已命中]
       └→ 0x54F664                 [进入后不再返回]
            ├→ 0x54EF74             [已命中]
            ├→ 0x54833C             [已命中]
            └→ 0x925FB0 ...         [未命中 → 阻塞在此或其后]
```

反汇编 `0x54EF74` 发现关键结构：

```asm
0054ef80  ldr  r0, [r0, #0x10]   ; 取某个管理器对象
0054ef86  ldr  r3, [r0]          ; 取 vtable
0054ef8a  ldr  r3, [r3]          ; vtable[0]
0054ef8c  blx  r3                ; ← 第一个虚函数调用（最可疑的阻塞点）
```

`0x54833C` 本身很短（只调 `0x5482E4` 和 `0x9245CC`）且正常返回，**不是阻塞点**。

结论：阻塞发生在 `0x54EF74` 的那个虚函数调用，或 `0x54EF74` 之后的 `0x925FB0` 系列调用。

## 四、下一轮计划

1. 反汇编 `0x54EF74` 里 `blx r3` 的**实际目标**（运行期打印 r0、vtable 值），确认是哪个类的方法；
2. 反汇编 `0x925FB0` / `0x9256A8` / `0x9246B8`（PLT 桩）解析为具体导入符号；
3. 若阻塞点是 `pthread_cond_wait`/`osal_rcv_msg_tmo` 类，按 `105` 号报告的思路补前置初始化；
4. 继续使用"少量布点 + 命中即撤"的方式，避免像 `deep2`（16 点）那样导致启动崩溃。

## 五、边界

- 真机操作全部为**只读**：`cat /proc/*`、`ls`、`sha256sum`；
- **未写入相机任何文件、未写 `/etc` 钩子、未刷任何镜像**；
- `/usr`、`/` 在相机上本就是 `ro` 挂载；
- 后续任何写入仍需用户逐次明确授权。
