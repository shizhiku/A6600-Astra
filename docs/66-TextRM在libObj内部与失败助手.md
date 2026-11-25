# 66 · TextRM_loadFont 就在 libObj 内部，失败来自其首个助手函数

本轮为离线反汇编与一次 QEMU 观测。无设备写入。

## 一、纠正：实现就在 libObj 自身

运行时读取该调用的 GOT 槽内容（`0x06B5CFB4`）：

```
f9 57 24 06 ...  →  0x062457F9
```

减去 libObj 基址 `0x057E3000` 得 `0x6627F9`（Thumb 位），说明调用落到 **libObj 内部**，而不是外部库。

随后在 `.dynsym` 中查到真实定义：

```
TextRM_loadFont   0x54ED59  size 248  (shndx 10 = .text)
TextRM_unloadFont 0x54EF2D  size 64
TextRM_createText 0x550A25  size 556
TextRM_drawText   0x54FCF9  size 812
TextRM_getBounds  0x54F9A1  size 184
```

**因此此前“实现库缺失于 /system”的推测不成立**，实现一直在 libObj 里。

（说明：`st_value` 为奇数表示 Thumb，实际入口是 `0x54ED58`。）

## 二、`TextRM_loadFont` 的逻辑

反汇编（Thumb，入口 `0x54ED58`）：

```
54ed58  push {r4,r5,r6,r7,lr}
54ed5a  sub  sp, #0x1c
54ed5c  ldr  r5,[pc]        ; 取基址
54ed5e  mov  r4, r0          ; r4 = 参数0（字体描述结构，含 "FONT_S_CHINESE"）
54ed62  add  r5, pc
54ed64  mov  r6, r1          ; r6 = 参数1（输出句柄）
54ed66  mov  r0, r5
54ed68  blx  0xfe6a4         ; 加锁
54ed6c  mov  r0, r4
54ed6e  bl   0x54E7A8        ; ← 关键助手：解析/查找字体
54ed72  mov  r4, r0
54ed74  cbz  r0, 0x54EDC2    ; 返回 NULL → 错误分支
...
54edc2  ...                  ; 错误分支：写入错误信息，r0 = 0x81，调用 0x54EB74
54edde  mvn  r5, #0xf        ; 返回 -0x10（即 0xFFFFFFF0）
```

**即：`0x54E7A8` 返回 NULL 时，`TextRM_loadFont` 返回 `-16`（非 0）**，上层 `libObj` 据此判定失败并 `abort()`。

## 三、当前结论

- `abort` 的触发链完整：`TextRM_loadFont`（libObj 内）→ 返回 -16 → 错误上报 → `abort`；
- 失败的直接原因：助手函数 `0x54E7A8` 返回 NULL；
- 该助手负责“按字体描述查找/加载字体”，是下一步的解剖对象。

## 四、下一步

1. 反汇编 `libObj + 0x54E7A8`，确认它在查什么（文件？全局表？副控制器？）；
2. 若它查 `/tmp/images/...` 文件，则结合“字体已放入仍失败”的事实，检查它是否有额外的头部/格式校验；
3. 若它向副控制器请求，则回到通道建模。

## 五、证据

- 运行：`cmdline-20261120T214321Z-53305`（GOT 槽 dump）
- 脚本：`resolve_plt_exact.py`、`resolve_abort_thunk.py`、`check_libobj_deps.py`、`transitive_deps.py`
- 库：`03-证据/静态分析/libObj.so`

## 六、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；本轮无设备操作。
