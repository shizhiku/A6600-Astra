# 82 · 结构性发现：UI 是 LIRO 内核态任务，用户态注入不可行

本轮为 QEMU 补丁、交叉编译与运行时探测。无设备写入。

## 一、字体与 eMMC 已解决（回顾）

- 字体：真机 `Backup.bin` 属性 `0x810000` = `"/usr/share/app/fontlist.dat"`；解析器逐条注册、**不检查文件存在**；崩溃真正发生在 `TextRM_loadFont` 内的 `fopen`。把相机 `/tmp/images` 的三个字体放进去后，**用原始未打补丁的 `/usr` 启动也不再崩溃**（客户机时间 65 s，无异常监视器）。
- eMMC：把 initrd 内 `/kmod/emmc.ko` 的调优函数入口改为 `mov r0,#0; bx lr`（文件偏移 `0x4A2C`），连跑 3 次全部正常进 UI。

## 二、本轮否定结论：UI 不是普通用户进程

### 探测方法

交叉编译一个 ARM 预加载探针（`arm-linux-gnueabi-gcc -std=gnu11 -shared -fPIC`），经 `/etc/ld.so.preload` 加载进每个进程，在构造函数里读 `/proc/self/maps`，记录"comm 名 + 是否映射了 libObj.so"，写入 `/dev/console`。

（`/etc` 与 `/tmp` 在本固件是同一个 vfat 分区，所以预加载文件放在 `/tmp` 分区即可生效。）

### 结果

```
INJMAP comm=launch_shell.elf libObj=no
INJMAP comm=bootin.elf       libObj=no
INJMAP comm=im.elf           libObj=no
```

**没有任何用户进程映射 `libObj.so`。**

### 推论

- 之前我们能在 `libObj+0x54ED58`（`TextRM_loadFont`）成功下断，说明该代码确实在执行；
- 但它跑在 **`liro.ko` 加载的内核态任务**里（启动日志中的 `LIRO (liro) rev:4-MUSASHI ... tsk_entry / API support list` 即该任务装载器）；
- 崩溃报告里的 `program: im.elf(Appframework)` 是 **LIRO 任务名**，不是 Linux 进程名；
- `/proc` 里的 `im.elf` 进程只是启动器/壳，不加载 libObj。

**因此 LD_PRELOAD、ptrace、以及任何用户态 dlsym 注入都触不到 UI。**

## 三、这意味着按键注入必须走 LIRO 的 OSAL 队列

按键路径（据 79 号报告）：

```
input.ko（GPIO/ADC/front/vgrip 采集）
   → OSAL 消息（osal_snd_msg / osal_snd_sync_msg）
   → libObj 的 InfraInput（LIRO 任务内）
   → InputService::callback_direct → createEvent → pushFilterEvent
```

`libosal_uipc.so` 是这套 OSAL 队列的**用户态出口**（服务端是 `/kmod/osal_uipc.ko`，1 MiB 共享内存，ioctl `0x80000000|opcode`）。所以理论上可以：

1. 写一个用户态 ARM 小程序，`open("/dev/uipc")` + `ioctl(0x80000010)` connect + `mmap(1 MiB)`；
2. 用 `osal_valloc_msg_wait` / `osal_snd_msg`（可直接链接 `libosal_uipc.so`）构造一条 **`_InfraInputEvent`（24 字节：key_code/sub_key_code/status/ex_info/sub_id/reserved）** 消息；
3. 发给 LIRO 侧的 InfraInput 队列（需要 msg_id/队列号，79 号报告给出 `snd_InfraInputEvent_to_InputServant` 使用 `msg_id 0x014A0429`）。

**但这条路要先解决交叉编译静/动态链接问题**：相机 libc 是 2.11，而我们只有 glibc 2.39 的交叉工具链；直接编译出的可执行文件会要求 `GLIBC_2.34/2.38` 符号（本轮已踩过：`dlsym` → 2.34，`sscanf` → 2.38）。目前可行做法是**只使用 `GLIBC_2.4` 级别的接口**并手工解析 ELF，或直接在 QEMU 侧拦截 OSAL 消息。

## 四、目前状态

| 项 | 状态 |
|---|---|
| 内核 / 用户空间启动 | ✅ |
| 字体（不再崩溃） | ✅ 提供真机 `/tmp/images` 三个文件即可 |
| eMMC 偶然停滞 | ✅ 模块补丁根除 |
| 显示控制器 ch53 640×480 双缓冲 | ✅ |
| GPU 清屏 + 整屏拷贝 | ✅ |
| UI 提交绘制（draw kick） | ❌ 仍只有 19 次自检 + 清屏 |
| 用户态注入 UI | ❌ **结构性不可行（UI 在内核态）** |

## 五、下一步候选

1. **QEMU 侧注入**：在模拟器里直接向 LIRO 的 OSAL 队列投递一条 `_InfraInputEvent`（避开交叉编译与版本问题）——最可控；
2. **用户态 OSAL 发送器**：用 `libosal_uipc.so` 动态链接，只调用其导出函数（老符号），从 shell 里运行；
3. **确认 UI 是否真在等外部状态**：在 LIRO 任务里观察 `InputService::m_pMyInstance` 与 View 激活状态，而不是从 sen 消息猜。

## 六、证据

- 探针源码：`<LEGACY_WORKSPACE>/probe_map.c`
- 运行：`03-证据/模拟器运行/inject-20261121T104935Z-111889`（INJMAP 三行均为 no）
- 无崩溃基线：`03-证据/模拟器运行/realtmp-20261121T101004Z-108371`
- 相关报告：`01-文档/78/79/80/81-*.md`

## 七、状态

原厂 UI：运行中、无崩溃、显示链路正常、无绘制内容；UI 位于 LIRO 内核任务。
ASTRA UI：未开始。
真机未被修改；未做任何刷写。
