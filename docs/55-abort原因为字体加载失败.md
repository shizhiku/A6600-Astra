# 55 · 定位到 abort 的直接原因：字体加载失败

本轮为离线反汇编 + QEMU 补丁与重编。无设备写入。

## 一、关键解析：`0xFF588` 是 `TextRM_loadFont`

按 ARM PLT 项的指令序列精确计算其 GOT 地址：

```
0ff588  add  ip, pc, #0x1200000
0ff58c  add  ip, ip, #0x72000
0ff590  ldr  pc, [ip, #0xa24]!
```

计算得 `ip = 0x1371590`，`GOT = ip + 0xa24 = 0x1371FB4`。

在 `.rel.plt` 中精确匹配该 GOT 地址：

```
0x1371fb4 -> TextRM_loadFont
```

**因此 `libObj` 在 `0x647940` 处调用的就是字体加载函数 `TextRM_loadFont`。**

## 二、abort 的完整因果链

```
TextRM_loadFont(...) 返回非 0（失败）
        ↓  (libObj 0x647944: mov r4, r0)
cbz r4, 正常分支       → 失败则继续
        ↓
0x647956  blx 0x103760   错误上报
0x64795a  bl  0x641910   PLT 桩 → abort
        ↓
abort → raise(SIGABRT) → tgkill(_,_,6) → Sony 监视器停机
```

**结论：UI 库因「字体加载失败」而主动中止。**

## 三、工具修正：钩子的链式执行盲区

发现 `REA_BP_VA` 钩子此前有盲区：QEMU 的 TB（翻译块）会**链式跳转**，不经过 `cpu_loop_exec_tb()`，因此热路径上的块不会被检查。

修正：在 `accel/tcg/translate-all.c` 的 `tb_gen_code()` 中，当设置了 `REA_BP_VA` 时给 `s.cflags` 加上 `CF_NO_GOTO_TB | CF_NO_GOTO_PTR`，强制每个 TB 返回执行循环。

已编译通过（注意：新版 QEMU 中该函数参数为 `TCGTBCPUState s`，须写 `s.cflags`）。

## 四、尚未完成

用修正后的钩子在字体加载调用点（`libObj + 0x647940`，运行期 `0x05E2B940`）抓参数，**本次运行 0 命中**，原因待查（可能是该次运行模块基址不同，或调用发生在其它模块/上下文）。

## 五、下一步

1. 核实该次运行的 `libObj.so` 实际基址，确认 `0x05E2B940` 是否为目标地址；
2. 抓 `TextRM_loadFont` 的入参（字体名/资源句柄），确认它在找哪个字体；
3. 检查该字体文件在模拟器文件系统中是否存在（`/usr`、`/system` 或 initrd 内）；
4. 若字体缺失，补齐资源即可让 UI 继续；若字体存在但加载失败，则查加载路径/格式相关依赖。

## 六、证据

- PLT 解析：`02-脚本/resolve_plt_exact.py`（GOT `0x1371fb4` → `TextRM_loadFont`）
- 触发点反汇编：`02-脚本/disasm_libobj_trigger.py`
- QEMU 补丁：`patch_qemu_bp_hook2.py`、`patch_qemu_disable_chaining.py`、`fix_chaining_patch.py`
- 运行：`03-证据/模拟器运行/cmdline-20261120T210058Z-49491`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；相机本轮未接触。
