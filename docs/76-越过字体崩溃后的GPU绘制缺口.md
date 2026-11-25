# 76 · 越过字体崩溃后：UI 运行、显示已编程、GPU 命令未生效

本轮为 QEMU 模型改造与实验。无设备写入。

## 一、诊断补丁：绕过字体 abort

在 `/usr` 镜像副本里把 `libObj::TextRM_loadFont`（偏移 `0x54ED58`）改成 `movs r0,#0; bx lr`：

```
原始字节 f0 b5 87 b0  →  00 20 70 47
```

镜像其余部分字节完全一致（`cmp` 校验：仅 4 字节不同）。

结果：**异常监视器不再出现**（`Entering exception monitor` = 0），系统持续运行到客户机 65 秒。

> 注意：`im.elf` 这行文本只在**崩溃报告**里打印，此前把它当作"UI 是否启动"的指标是误读。

## 二、显示控制器已正常工作

补丁后 `[VPH]` 日志显示：

```
[VPH] ch53 base=0x23a80000 ctrl=0x2 lb=0x500 lines=480 en144=0x230
[VPH] ch53 base=0x23b16000 ctrl=0x2 lb=0x500 lines=480   ← 双缓冲翻转
[VPH] YUV layer still off at vsync 3600
```

即：面板 OSD 通道 ch53 已编程，640×480（`lb=0x500` → 1280 字节/行 ÷ 2 = 640 像素），双缓冲，持续跑到 vsync 3600（约 60 秒）。

## 三、新增能力：帧缓冲导出

在 `hw/misc/cxd90014_vph.c` 中加入 `REA_FB_PATH` / `REA_FB_VSYNC`：在指定 vsync 时把 ch53 扫描缓冲区转成 PPM 落盘。

抓到两个时间点（vsync 600 / 1800）的画面：**640×480，全黑（所有像素为 0）**。

## 四、黑屏原因：GPU 命令提交了但没执行

`hw/display/dmp_smaph.c`（DMP SMAPH-S30 / Sugilite / GPE 模型）已有较完整实现（PSC 填充、PPF 传输、P3D 命令表、软件光栅化与着色器），并已接入 `sony-a6400` 机型。运行日志显示：

```
[DMP] p3d-list addr=0x2053c270 n=4      ← 共 24 次命令表提交
...
```

但**只有 `p3d-list`，没有 `p3d-draw` / `psc-fill` / `ppf-copy`**。

即：驱动确实通过 `/dev/dmpgles2`（客户机内存在，字符设备 248,29）提交了 GPU 命令表，但**绘制 kick 没有发生**，所以帧缓冲始终为空。

`libObj` 的绘制路径（`dmpNative` / `grm::GPEResourceManager` → `GRM_gpermFillrect` / `GRM_gpermRectblit`）最终依赖 GPE 硬件；模型中这条 kick 语义尚未对上 CXD90045。

## 五、结论

- 字体 abort 已被诊断补丁绕过，**UI 主循环与显示输出都在运行**；
- 画面为空是**GPU 绘制未执行**，属硬件模型缺口，不是配置问题；
- 下一步需要让 DMP 模型的命令表解析/kick 与 CXD90045 驱动行为对齐（当前模型移植自 a5000/CXD90014）。

## 六、下一步

1. 在 `dmp_smaph.c` 里 dump 命令表条目（header/value），看驱动写入的寄存器序列；
2. 确认 kick 寄存器（模型按 `+0x202` 处理）在 CXD90045 上是否同址；
3. 若不同，按实际写入地址调整模型，使 `p3d-draw` / `psc-fill` 真正执行；
4. 再次导出帧缓冲，验证是否出现 UI 像素。

## 七、证据

- 补丁脚本：`patch_libobj_nofont.py`、`patch_vph_fbdump.py`、`fix_vph_read_api.py`
- 帧缓冲导出：`03-证据/模拟器运行/fb1.ppm`、`fb2.ppm`（均全黑）、`fb1.png`
- 运行：`03-证据/模拟器运行/nofont-20261121T090001Z-100380`

## 八、状态

原厂 UI：进程运行、显示编程、画面为空（GPU 未执行绘制）。
ASTRA UI：未开始。
实验固件不可刷；真机未被修改。
