# 135 · 第二十二轮：基线恢复 + fbrm 补丁无效（附提问材料）

> 时间：2026-11-22。离线 QEMU。

## 一、上一轮的"环境回归"其实是我自己的失误

之前 6 次失败（对照 2 次 + fbrm2 4 次）全部报：

```
program: im.elf(THREAD_APP) (pid: 359)
address: 08249000, trap_no: 0x0e, error_code: 0x817
page translation fault (0x817) at 0x08249000
```

且 `08249000-0824a000 ---p`（PROT_NONE 匿名映射）。

**根因：这些运行都没有加 `--preload`。**

五代 init 的栈帧约 3.4 MiB，超过 glibc 默认 2 MiB 的 pthread 栈；`THREAD_APP` 栈溢出后撞上 pthread 栈的 **PROT_NONE guard page**（正是 `08249000-0824a000 ---p`），触发 page translation fault。

**加上 `--preload 04-产物/libcrashtrace.so`（含 6 MiB 栈扩容）后，2/2 全部成功**，`bridge7` 完整跑完：

```
bridge7 enter → a5pFw loaded → a5bObj loaded
→ MWF_Init ✓ → infra_input_init ✓ → grm_init(−1) → DDSUserInit ✓ → uxengine_init ✓
→ call appFwBoot entry → appFwBoot entry returned
```

**结论：这不是 QEMU 回归，也不是补丁问题。是实验纪律问题——此后所有运行必须带栈扩容 preload。**

## 二、fbrm 补丁：已按参考语义实现，但无可观测效果

补丁（`a5bObj_fbrm2.img.so`，SHA256 `0b587fab…`）后 12 字节：

```asm
00115618  push {r7, lr}
0011561a  add  r7, sp, #0
0011561c  bl   0x11f766        ← 保留原调用（与参考"先调原函数"一致）
00115620  movs r0, #0          ← 强制返回 0 = 成功
00115622  pop  {r7, pc}
```

对照实验结果（同样带 preload、同样开 `REA_GPE_TRACE`）：

| 指标 | 未打补丁 | 已打补丁 |
|---|---|---|
| `DMPCOUNT draw` | 0 | **0** |
| `list (1800)` | 27 | 27 |
| `ppf (0c18)` | 3 | 3 |
| `psc (001c)` | 3 | 3 |
| `GPETRACE 写操作总数` | 111 | 111 |
| `ch53 base` | 0 | **0** |

**完全一致，补丁没有改变任何 GPU 行为。**

这与参考项目的说明吻合：**只解除这一道完成检查并不保证首帧出现**，因为他们同时还接管了 DMP/Gemini 软件绘制、纹理、Swap、Present、引擎等待。

## 三、当前真实卡点（已收敛为一个明确问题）

五代 `Application_Start` 链能跑到底（`appFwBoot entry returned`），但：

- `GraphicsEngine::drawFramebuffer` 从未被调用（`draw=0`）
- 没有任何 GPU draw kick（`0x202` 寄存器 0 次写入）
- `ch53` 从未编程

也就是说：**五代 UI 的绘制提交根本没被触发**，而不只是被"完成检查"拦住。

## 四、给 GPT 的问题描述（可直接复制）

> **环境**：QEMU 11.1.3，自定义 `sony-a6400` machine，启动 Sony a6600（CXD90045）固件。Guest 是 ARMv7 + Linux 3.0.27，用户态 glibc 2.11.2。
>
> **在做什么**：把一个**五代（ZV-1M2 / ASTRA）**的 `appFw.so` 塞进**四代（a6600）**的 `/usr` 镜像里运行。通过一个 LD_PRELOAD 桥接库，在四代 `im.elf` 进程内 `dlopen` 五代 `a5pFw.so` / `a5bObj.so` / `a5bMWF.so`，依次调用 `MWF_Init`、`infra_input_init`、`grm_init`、`DDSUserInit`、`uxengine_init`，最后调 `appFwBoot::Application_System_Init`（它内部 `dlopen` 五代 appFw、创建 `AppFw` 线程、执行 `Main` → `Application_Start`）。
>
> **已经确认的**：
> - 五代 `Application_Start`（`a5pFw` 偏移 `0x54D580`）确实被执行并返回（用 UDF 陷阱验证）
> - `Application_System_Init` 正常返回，无崩溃
> - 五代 `libObj.so` 里的 `GraphicsEngine::drawFramebuffer`（偏移 `0xE565A`）**从未被调用**
> - GPU 侧 `0x202`（draw kick）寄存器**从未被写入**；`DMPCOUNT draw=0`
> - 显示通道 `ch53` 的 base 一直是 0
> - 我已经把 `GRM_fbrmCheckUpdateFinished`（`libObj` 偏移 `0x115618`）按"先调原函数再强制返回 0（成功）"patch 过，**GPU 行为完全没有变化**
>
> **已知的语义**（已静态核实）：
> - `GRM_fbrmCheckUpdateFinished` 返回 `0` = 成功，`0xFFFFD8F1` = 未完成
> - 它内部调 `0x11F766`，后者返回 `1 - *(fbrm对象 + 0x58)`，且在构造时会把 `+0x58/+0x5C/+0x60` 清零
> - fbrm 单例由 `0x11F6E0` 懒初始化（`__cxa_guard_acquire` + 构造 `0x11F6AC`）
> - `libObj` 里有 `source/GraphicsSystem_gemini.cpp`、`gemini::RenderState`、`gemini-ogl/*` 等字符串，说明绘制走 Gemini（OGL 后端）
>
> **问题**：
> 1. 在"五代 appFw 在四代进程里跑"这种混合环境下，**是什么触发 `drawFramebuffer` 的第一次调用**？是某个定时器/事件循环/还是 `WidgetSystem` 的帧回调？我如何确认这个触发点是否缺失？
> 2. 五代绘制链路要求 GPU/GLES 上下文（Gemini OGL 后端）。四代 `grm_gles.ko`（仅 9,348 字节）+ 四代 `libObj` 的组合，是否可能**根本不提供可用的 GLES 上下文**，导致 draw 永远不发起？如何验证"GLES 上下文是否创建成功"？
> 3. `drawFramebuffer` 到底由谁调用？我能否通过静态调用图从 `drawFramebuffer`（`0xE565A`）反查它的调用者，从而判断是哪个上层环节没走到？
>
> **补充**：我这边 QEMU 的 GPU 模型是自研的（`hw/display/dmp_smaph.c`），只实现了 P3D 寄存器和简单的 draw kick。如果五代走的是 OGL 后端而非 P3D 直通，可能整个绘制路径在我的模型里就没有对应实现。

## 五、边界

- 全程离线 QEMU 分析，**未接触相机、未做任何真机操作**；
- 本次所有对照运行均带栈扩容 preload，结果可复现。
