# 98 · ASTRA 移植（96 任务书）第 84 轮执行报告

日期：2026-11-22。全部实验在离线镜像副本和隔离 QEMU 覆盖层完成；未连接、未写入真机。基础 emmc、原始固件和既有产物均未被覆盖。

## 一、与任务书 v2 的偏差（已按证据修正）

1. **任务 A 的失败判据错误。** 原脚本把 `mounting1 /dev/dnflasha15 -> /usr as ext2 failed. errno(6)` 当作 `/usr` 挂载失败。实测原厂基线同样打印该行，随后客户机 `/proc/mounts` 明确显示 `/dev/nflasha15 /usr ext2 ro`。该行是压缩设备挂载失败后的预期回退，不是 `/usr` 失败。
2. **实际 SDM 中 `/usr` 分区为 300 MiB**（`0x12c00000`），215,517,184 B 只是 ext2 文件系统长度。原分区内扩文件系统到 300 MiB 不需要改分区表。
3. **五代 `/share` 279.8 MiB 中约 197.6 MiB 是屏幕朗读音频**（10 种语言）。去掉音频后 share 仅 82.1 MiB，主要 ASTRA 视觉资源全部保留。
4. **“全库导出并集只缺 5–6 个符号”不等于实际加载闭包。** 未定义弱符号不需要 stub；同名四/五代库必须择一并隔离。

## 二、已完成的构建（全部有 SHA256 与语义回读）

| 产物 | 大小 | 说明 |
|---|---:|---|
| `astra-m1-verified-visual-300MiB.img` | 314,572,800 | 保留四代 bootstrap；五代库等长私名（libX→a5X）并加显式依赖边；不含朗读音频；全部 555 个库/资源逐字节回读校验通过 |
| `astra-m1-verified-stm.img` | 314,572,800 | 追加真实的五代 root `libSTMcmdexecute.so`（提供 `stm_system`，非伪造） |
| `astra-m1-v-usb-lazy.img` | 314,572,800 | 共享四代 USB/backup 边界（符号层覆盖已证），LAZY|GLOBAL|DEEPBIND 诊断绑定 |
| `astra-m2-768/astra-m2-full-768MiB.img` | 805,306,368 | 全资源（含朗读音频），用于 M2 对比；语义回读 555 项通过 |
| `97_flash_emmc512.img` / `97_flash_emmc768.img` | 2,147,483,648 | 仅 QEMU 的 SDM 迁移副本，未认作可刷镜像 |

M1 验证：`97_verify_layers.py` 输出 `checked=555, mismatches=[]`；早期构建曾因旧 ext2 读取器把稀疏块拼错而让 fsck 通过但内容错误，已改用稀疏感知读取器并加入逐文件 SHA256 回读。

## 三、运行时结果（隔离 QEMU）

### 3.1 挂载与加载

- 原厂与 ASTRA 镜像均实际挂载 `/usr`；ASTRA 停在应用启动层，不是文件系统。
- 四/五代 `libIMDB` 差异：四代 `im.elf` 直接 DT_NEEDED `libIMDB`，但不会加载 `appFw.so`。仅替换文件不等于执行 ASTRA。
- 采用最小路由：保留四代 im/原任务表，仅把 Application 记录路由到五代 `appFwBoot.so`；五代依赖用私名和显式 DT_NEEDED 边隔离。

### 3.2 关键运行时里程碑

1. `appFwBoot.so` 首次加载失败于缺失 `libSTMcmdexecute.so`；补入真实五代 root 库后解决。
2. 强制 NOW 绑定时，`a5bInfraUsbCmn.so` 缺 `PTPT_fin`；改用四代 USB/backup 共享边界并按原生 LAZY 绑定时不再阻塞（共享只证明符号覆盖，不是完整 ABI 保证）。
3. LAZY 运行实际加载 `a5pFw.so` 并进入五代 `THREAD_APP`；崩溃在 2 MB 线程栈底保护页。
4. 静态确认五代初始化函数栈帧 `0x3489CC`（约 3.4 MB）> 2 MB；客户机 libc 默认栈实测 `2097152`。
5. 编写 GLIBC_2.4-only preload，在 `pthread_attr_init` 后把栈提高到 6 MB；`appFwBoot::Application_System_Init` 完整返回，五代 `libObj/appFw` 均加载。
6. 残余崩溃：五代 MWF 的全局单例为空（fault addr 0x8）。原因：保留四代 IMDB 路由跳过了五代 IMDB 自带的 `MWF_Init` 等初始化任务。
7. 在桥接器中先加载五代 `appFw.so` 并调用 `MWF_Init`（返回成功）后，MWF 空指针崩溃消失；应用转入自身的错误断言：`lib::assert::notify_model_system_error(): Assertion 'false' failed`。

### 3.3 当前结论

五代 UI 已能完成库加载、Application 初始化和 MWF 初始化，当前停在**应用主动报告的 model/system error**。这是硬件/模型响应缺失，不再是库缺失或栈溢出。后续应沿 `notify_model_system_error` 的触发条件追所需模型消息，而不是继续补符号。

## 四、任务书 F1–F5（离线）

- **F1 已闭合**：CRC-32/ISO-HDLC；对清单完整镜像 range 计算；8 个原分区全部复算吻合；a6600 原 `/usr`=`520fff36`，修改图=`129576f8`。但 CRC 不一致**不能**表述为写前安全拒绝：原 body 静态链支持写分区后读回校验。
- **F2 未闭合**：FDAT 头 CRC 可复算，但尾部 256 B 是否签名及覆盖范围未知；CRC/AES 重封装不等于签名、版本、型号或硬件接受。
- **F3 已修正**：`/usr` 实际 300 MiB；512 MiB 才需平移 `p16` 以后分区；QEMU 介质足够。原 `us_mkfs.sh` 在 USER/SERVICE 等模式不调用 `edisx.elf`，修改分区配置不足以证明会重写实际分区表。
- **F4/F5 需按改动范围限定**：所有者一手经验表明，固件挂起约 60 秒后看门狗会复位并强制进入 USB 模式，插线后可由主机侧恢复；日志会强制写入 SD 卡。本地固件也确认存在 `arch/arm/mach-cxd900x0/wdt.c`、`/dev/wdt`、`wdt.timeout`/`wdt.mode`、`RT Watchdog Timeout` 等实现痕迹。  
  因此：“绝对无恢复手段”应撤回。但该通道依赖看门狗所在的内核/启动链、USB gadget 和供电完好，只覆盖**仅改 `/usr` 数据分区**的失败；**不能覆盖 kernel/initrd、SDM 分区表或 bootloader 被改坏**。  
  M2 的 SDM 迁移属于后者，风险显著更高；真机侧应只考虑 `/usr`-only 路径。**F2（签名/接受性）仍未闭合，阶段二完成前仍不刷写。**

## 五、产物与复跑入口

- 构建/验证：`02-脚本/97_build_m1.py`、`97_add_stm.py`、`97_variant_image.py`、`97_build_m2_resources.py`、`97_verify_layers.py`、`97_ext2.py`、`97_ext2_verify.py`
- 桥接：`04-产物/97_astra_bridge.c`（v1）、`97_astra_bridge2.c`（含 MWF_Init）
- 栈修复：`04-产物/97_attrstack_preload.c` → `libattrstack97.so`
- 运行：`02-脚本/97_astra_trials.py`
- 证据：`03-证据/ASTRA-97/`（每次运行的 serial/stderr、manifest、语义校验）；`03-证据/静态分析/97_abi/`、`97_flash/`

## 六、下一步（按优先级）

1. **定位 `notify_model_system_error` 的触发条件**：回溯其调用者，确认缺少的是 av-cam/LIRO 状态、UPM、sensor 还是 submicro 消息；这是把界面推到菜单的关键。
2. **用五代 IMDB 任务表补齐初始化顺序**：MWF_Init 已手工补上，其余 `uxengine_init/grm_init/GpeInit/CoreSync` 等应按五代表顺序在 Application 前完成，避免逐个补洞。
3. **清理对四代 IMDB 的依赖**：评估以五代 IMDB 驱动四代 im 的可行性（任务表 228 项、stage 标记差异），或继续单点桥接并记录每项缺失初始化。
4. **阶段二继续离线**：闭合 FDAT 尾部签名覆盖范围、内核分区注册逻辑和恢复通道；未闭合前保持“不可刷”结论。
5. **真机刷写仍禁止**：阶段一、二均未完成，且任何真机写入须单独获得用户明确授权。

## 七、状态

| 目标项 | 状态 |
|---|---|
| ASTRA 库加载 | ✅ 五代 appFwBoot/appFw/libObj/MWF 实际加载 |
| ASTRA Application 初始化 | ✅ `Application_System_Init` 返回 |
| ASTRA 界面渲染 | ❌ 停在应用 model/system error 断言 |
| 原厂菜单 | ✅（已有基线） |
| 可刷入性 | ❌ 接受性/签名未闭合；仅 `/usr` 改动有所有者验证的看门狗恢复通道 |
| 真机写入 | 无 |
