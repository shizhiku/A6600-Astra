# 81 · 字体问题与 eMMC 停滞均已解决（都不需要改代码）

本轮为两个并行子任务（uipc 逆向、按键路径、字体链路）与实验验证。无设备写入。

## 一、字体问题已解决：不需要任何代码补丁

### 真相

- 真机 `Backup.bin` 的属性 **`0x00810000`** 存的是字体列表路径：`"/usr/share/app/fontlist.dat"`（64 字节）。
- `TextRM` 的一次性初始化会用该路径 `fopen` 并解析（解析器在 `libObj+0x54E94C`），**逐条注册、不校验文件是否存在**。
- 因此注册一直是正常工作的；崩溃发生在后续 `TextRM_loadFont` 内部真正 `fopen` 字体文件时——**因为 `/tmp/images/` 里没有那三个字体**。

### 验证

按真机 `/tmp/images/` 内容放入三个文件（GB18030 1,958,432 B、Big5 1,150,740 B、Sony_DI_Icons.ttf 545,464 B），使用**原始未打补丁的 `/usr`** 启动：

```
exception monitor: 0      ← 完全没有崩溃
last guest time: 65.7 s
```

**结论：删除此前对 `libObj::TextRM_loadFont` 的"诊断补丁"后依然不崩——字体问题纯属文件缺失。**

## 二、eMMC 调优死循环已解决

`/kmod/emmc.ko`（在 initrd 与 rootfs 中）的 `sdhci_emmc_tuning_request` 入口（文件偏移 `0x4A2C`）改为：

```
0d c0 a0 e1 70 d8 2d e9  →  00 00 a0 e3 1e ff 2f e1   (mov r0,#0 ; bx lr)
```

打补丁的 initrd 连跑 3 次，**全部正常进入 UI**，不再出现 1.9 秒停滞。

## 三、当前唯一剩余阻塞：UI 不提交绘制

即便字体齐备、无崩溃，GPU 侧仍只有：

```
19 × p3d-list   （内容完全相同：写 reg 0x116/0x117/0x044/0x010=0x12345678 的自检序列）
3 × ppf-transfer（整屏拷贝）
2 × psc-fill    （val=0x00000000，清屏为黑）
```

- **没有 draw kick（reg 0x202）**
- 帧缓冲导出（vsync 1500）仍是 640×480 全黑

即：UI 主循环在跑、显示与清屏链路正常，但**不产生任何实际绘制内容**。

## 四、子任务带回的关键信息

### uipc（`01-文档/78-uipc协议逆向.md`）

- `/dev/uipc` 不是私有硬件协议，而是 **OSAL 消息队列的用户态出口**；服务端是 `/kmod/osal_uipc.ko`（38,872 B，符号完整）。
- ioctl ABI 已还原：`cmd = 0x80000000 | opcode`，参数为 8 字节 `{u32 a0; u32 a1}`；`opcode=0x10` 为 connect；共享内存固定 1 MiB。
- `libsencore` 只用 9 个 `osal_*` 用户态符号，**不直接碰 ioctl/mmap** → 可以用同名 `.so` 覆盖这些符号，在纯用户态造应答。

### 按键（`01-文档/79-按键事件路径分析.md`）

- UI 侧存在完整注入链：`InputService::pushFilterEvent`(0x3D1818) / `createEvent`(0x3CFAEA) / `EventManager::push`(0x842A88)，且都是导出符号。
- uipc 记录层**没有"投递按键"命令**（0x0000–0x0009 全是控制类），所以伪造 uipc 报文这条走不通。
- 存在官方测试命令 `INFRA_INPUT_TEST_CMD_CB_SEND_EVENT`（参数为 key_code/sub_key_code/status/ex_info）。
- `infra_tp_key_emulation.txt` 是死代码（文件不存在），可通过重打包 `/usr` 造出来激活；但本轮造出该文件后**未观察到 `[INFRATP]` 日志**，说明未被解析（路径或触发条件还需确认）。

### 字体（`01-文档/80-字体注册链路分析.md`）

- `registerFontFaceFile` 是**未被使用的备用入口**（全库 0 调用者、无指针表引用）。
- 真正的注册入口就是上述列表解析器；路径来自 Backup `0x810000`。
- 只有解析器会给节点写入名字字段，`find_by_name("FONT_S_CHINESE")` 才可能命中。

## 五、下一步

1. 确认 UI 是否在等副控制器"系统就绪"（YUV/模式/电池）才提交首帧；
2. 若确认，做最小 uipc 桩（用户态覆盖 9 个 `osal_*` 符号，按 78 号报告实现应答）；
3. 或先验证按键注入（79 号报告的导出函数链 / 官方测试命令），看菜单能否在不依赖相机的情况下渲染。

## 六、证据

- 运行：`03-证据/模拟器运行/realtmp-20261121T101004Z-108371`（无崩溃，65.7 s）
- 帧缓冲：`03-证据/模拟器运行/fb_orig.ppm`（640×480 全黑）
- 相机采集：`03-证据/相机采集/live-setting-20261121/`（`.hasp` 88 B、`.etools` 4096 B）
- 子任务报告：`01-文档/78/79/80-*.md`

## 七、状态

原厂 UI：**运行中、无崩溃、显示链路正常、无绘制内容**。
ASTRA UI：未开始。
真机未被修改；未做任何刷写。
