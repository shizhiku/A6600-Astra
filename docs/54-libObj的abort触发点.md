# 54 · libObj 的 abort 触发点与上下文

本轮为离线反汇编。无设备写入。

## 一、三层调用链已完整还原

RTTI/PLT 桩 → 真正调用点：

```
libObj 0x64795A  →  bl 0x641910（PLT 桩）
0x641910 桩      →  ldr r3,[pc] ; cbz ; blx r3  → abort
abort            →  raise(SIGABRT)  →  tgkill(_,_,6)
```

其中：

| 层 | 证据 |
|---|---|
| `raise` 被 `abort` 调用 | QEMU 钩子命中 `raise` 入口，`LR = libc+0x25BDF`（`abort` 内部） |
| `abort` 被 libObj 调用 | QEMU 钩子命中 `abort` 入口，`LR = 0x05E2491F`（libObj+`0x64191F`） |
| 桩的上层调用者 | QEMU 钩子命中桩入口 `0x05E24912`，`LR = 0x05E2A95F`（libObj+`0x64795F`） |

## 二、PLT 桩的形态（已确认）

```
641912  push {r7, lr}
641914  add  r3, pc
641916  ldr  r3, [r3]      ; 从槽中取函数指针
64191a  cbz  r3, +3
64191c  blx  r3            ; 调用（此处落到 abort）
64191e  pop  {r7, pc}
```

即 `abort` 是通过 **GOT/PLT 槽**间接调用的，属正常的动态链接调用方式，不是异常跳转。

## 三、触发点上下文（关键）

`libObj` 偏移 `0x647926` 起：

```
647926  push {r4,r5,r6,r7,lr}
64792a  sub  sp, #0x1c
647934  ldr  r6, [r3, r2]
647938  blx  0xfe6a4        ; 前置处理（疑似加锁）
64793c  mov  r0, r4
64793e  adds r1, r7, #4
647940  blx  0xff588        ; ← 关键调用，返回错误码
647944  mov  r4, r0
647948  blx  0x10489c       ; 后置处理（疑似解锁）
64794c  cbz  r4, 0x647974   ; 返回 0 → 走正常分支
64794e  ldr  r1, [pc,#0x4c]
647950  mov.w r0, #0x40000000
647956  blx  0x103760       ; 错误上报
64795a  bl   0x641910       ; ← 调用 abort
```

**逻辑非常明确：`0xFF588` 返回非零 → 走错误上报 → 直接 `abort()`。**

## 四、函数身份线索

该函数附近的字面量指向字符串：

```
ContUtil7NetDbIf19destroyContentsListEb
```

这是一段 C++ 修饰名（`ContUtil` / `NetDbIf` / `destroyContentsList`），说明触发 abort 的代码属于 **内容管理 / 网络数据库接口**相关模块。

## 五、下一步

1. 定位 `0xFF588` 是什么函数（libObj 内部偏移，可查动态符号/PLT 表），确认它做什么检查；
2. 确认它返回的错误码含义（当前 `r4 = 返回值`，非零即中止）；
3. 若该检查依赖网络/服务可用性，则与本环境缺少对应服务有关；若依赖资源文件，则检查文件是否齐备。

## 六、证据

- 钩子运行：`cmdline-20261120T204924Z-48634`（raise）、`cmdline-20261120T205136Z-48794`（abort）、`cmdline-20261120T205444Z-49003`（桩）
- 反汇编脚本：`disasm_libobj_abort_site.py`、`disasm_libobj_trigger.py`
- 库文件：`03-证据/静态分析/libObj.so`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；相机本轮未接触。
