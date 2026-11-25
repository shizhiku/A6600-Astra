# 97_flash · 96任务书F1/F2/F3/F4/F5离线证据审查

审查时间：2026-11-22（Asia/Shanghai）。范围：本工作区原固件、firmware.tar、fdat明文头、分区清单、原包updater及现有打包脚本；按lead补充授权只读分析现有QEMU emmc.img和sdm.bin。未连接、枚举或写入相机，未运行任何探机/部署脚本，未安装插件或更改工具环境。固件ELF仅静态解析；未执行其机器代码。新增文件均为97_flash脚本/报告/证据，原产物未覆盖。

## 结论先行

1. **F1已闭合到“算法、文件覆盖范围、可离线重算”**：CRC-32/ISO-HDLC（IEEE反射多项式0xEDB88320）；对清单指定的完整镜像字节流、长度恰为清单size计算。两轮不同分块尺寸对a6600和ZV-1M2共8个分区全部吻合。a6600原/usr=`520fff36`，现有修改/usr=`129576f8`，均已复现。
2. **任务书153行的数值正确，但“updater会拒绝”必须限定层级和时机**：现有修改tar仍保留原CRC，故与原更新器的分区CRC合同冲突。原包脚本及body代码显示该检查有对`/dev/nflasha15`写后读回的路径，**不能把它当成写前安全拒绝或避免损坏的保障**。没有真机运行证据，不声称具体拒绝响应或发生时点已实测。
3. **F2签名链/覆盖范围尚未闭合**：证明CRC能重算、AES能重新加密、DEND通过，都不证明签名/版本/型号/硬件接受。FDAT尾部256B的身份及验证覆盖范围未确定；现有脚本只沿用旧尾部，没有产生新认证材料。
4. **F3重大修正**：215,517,184B（205.533203125MiB）是ext2镜像长度；原包与实际QEMU SDM声明的`nflasha15`容量均是314,572,800B（300MiB）。在既有300MiB内扩展ext2无需扩SDM分区。要到512MiB才需要将后续分区平移212MiB；2GiB模拟介质足够。
5. **F4/F5：存在设备所有者验证的看门狗恢复通道，但适用范围有限**：固件挂起约60秒后看门狗复位并强制进入USB模式，主机侧可恢复；日志强制写入SD卡。该通道依赖看门狗所在的内核/启动链和 USB gadget 完好，因此只对**仅改 /usr 数据分区**的失败成立；不能覆盖 kernel/initrd、SDM 分区表或 bootloader 损坏。本地固件也确认存在 `arch/arm/mach-cxd900x0/wdt.c`、`/dev/wdt`、`wdt.timeout`/`wdt.mode`、`RT Watchdog Timeout` 等实现痕迹。**接受性与签名（F2）仍未闭合，因此仍不得在阶段二完成前刷写；但“绝对无恢复手段”的表述应撤回。**

## 证据等级与边界

- E1：输入字节、SHA256、可复跑的离线计算/结构观察。
- E2：本机原固件的静态机器码、ELF重定位、原包脚本所支持的控制流；不等于实际分支已运行。
- E3：官方文档、primary项目源码的能力/协议声明；型号适用性和实机运行仍须独立证明。
- U：本次材料不能判定。没有观察到某项，不据此断言不存在。

## 输入身份

完整清单见`../03-证据/静态分析/97_flash/97_flash_input_manifest.json`，最终输入不变性检查、primary来源和全部新增证据SHA256见`../03-证据/静态分析/97_flash/97_flash_final_manifest_v2.json`；实际QEMU盘见`../03-证据/静态分析/97_flash/97_flash_geometry.log`。

| 输入 | 大小B | SHA256 |
|---|---:|---|
| a6600 firmware.tar |315290624|`70ff318d89dda45c14e979a3c8a14b8b20b4bda2b573bc39e35a2701ff20b6b5`|
| a6600 fdat_plain.bin |315434496|`82f97f3bd652cb7d595c8c58ef1d472d7ab2b23eaf201e875dfbb3fb6b340102`|
| a6600 原nflasha15 |215517184|`ed67fdb22a5f3254e761237fc2479d4fcaf4fc6d11c30ab4acb6ab6e7b5767fc`|
| 现有nflasha15_patched.bin |215517184|`17eae802678e5523b6fcbd3ab277aa19eef83065a88bb5f7c29e316446d2afaf`|
| a6600 原part_image.sum |377|`a66d6884ca990e90ee4cc4f487013e5202463ef18cbeeb98956409c803dc3aea`|
| a6600 原partinf.conf |4017|`fc23dc2edb8e378e7985fb5da4d09a0e4c5f2445d679a730fd1d544dde831f78`|
| 原updater.img |143360|`5abbc90976dd9fef6962af743bf414e287def2f039b9fecd4236495a628baa74`|
| 原libupdaterbody.so（从updater.img提取） |106200|`6daad7d8be8807e068563d09436f83b1eadb93a365248c78e6add2f15cfea01d`|
| 原uc_crc32sum.elf（同上） |10076|`8b66eda0597abeae77f10ac6d81b0ae1b5bd3a3c1ccaf82bf803bf8c94f990c3`|
| QEMU emmc.img |2147483648|`8305fdf72050570811c15943a835bee7a0f935f15203e3aaadf14ec290782f01`|
| QEMU sdm.bin |512|`11e7349e6f419882c5d65fd598a9d18f3d4b7ffec1e3373c0208d56baad128c2`|

末轮17项输入复核中，16项固件/打包代码/模拟器输入均保持原SHA256；仅96任务书在并行审查期间由12054B（SHA256 `1a46228a4e1db0cb78a6dacbb6afe284d6dc64b0d5ab2a267bc6a81ca14d001f`）发生变化，本审查未写该文件。首次严格检查如实返回非零并留存`97_flash_final_manifest.json`；v2将该文档漂移与固件不变性分开报告，不掩盖变化。文中“153行”指首次读入任务书的行号。

## F1 · 算法、覆盖range与153行

### 算法和覆盖范围（E1 + E2）

参数：width=32，poly=0x04C11DB7（反射实现0xEDB88320），refin/refout=true，init=0xFFFFFFFF，xorout=0xFFFFFFFF；标准向量`123456789`结果`CBF43926`。Python zlib使用`zlib.crc32(data, 0)`的常规接口。原包`uc_crc32sum.elf`文件offset **5128（0x1408）**处含完整256项IEEE反射CRC表，非仅凭一个校验值猜测算法。

`part_image.sum`为逗号分隔文本；普通文件记录第2字段是8位十六进制CRC，第3字段是十六进制字节长度，第11字段是目标路径。目录项`5,ffffffff,...,dev,`不是一个待校验分区文件。

| 镜像 | 清单size | 覆盖range（半开） | 实际CRC |
|---|---:|---|---|
| a6600 nflasha7 |4921344|`../03-证据/静态分析/97_flash/97_flash_part_image.recomputed.sum`，仅将原记录中的CRC更换为`129576f8`；该清单SHA256=`c9223a78e3711d0d5d9d065155966944b29439d28d3cf396d0925ddeb4c98b69`。**它只是重算能力证据，不是可刷升级包。**

复跑：第一轮1MiB分块；第二轮65521B分块，8/8原分区CRC及size全部匹配。证据：`../03-证据/静态分析/97_flash/97_flash_audit.log`、`../03-证据/静态分析/97_flash/97_flash_crc_verify.log`。

### 原更新器的消费链（E2）

原updater.img解出`../03-证据/静态分析/97_flash/97_flash_updaterimg_config_config.xml`17–19行：`part_image_sum/part_image.sum`触发`us_crc32sum.sh part_image image`。

`../03-证据/静态分析/97_flash/97_flash_updaterimg_bin_us_crc32sum.sh`43–57行：image模式将目标目录设为`/`，命令为`uc_crc32sum.elf -s -c`，清单位置为`$EXTRACT_ROOT/part_image_sum/part_image.sum`。这对应清单内`dev/nflasha15`，不是单纯对tar内文件作发送前检查。脚本29–34行在CRC工具非零返回后转入错误处理。

原body静态流和ELF重定位证据见`../03-证据/静态分析/97_flash/97_flash_updater_flow.disasm.txt`、`../03-证据/静态分析/97_flash/97_flash_updater_vtables.json`、`../03-证据/静态分析/97_flash/97_flash_body_plt_v2.json`：

- `PartitionImageKeyTag::Extract`@0x10b8c，在0x10c00–0x10c0c跳过路径前10字节（`part_image`），构建分区目标路径，0x10c4c调用`BaseNewFirmwareFile::Extract`。
- `NewFirmwareImageFile::extractImageFile`@0x12b70：0x12b94调用`FileHandler::Open`，0x12bfa调用`FileHandler::WriteAll`。这是原包分区写入实现的静态证据，未运行。
- `BaseNewFirmwareFile::Extract`@0x1212c：0x1217c调用XML `IsKey`；0x12188调用文件`extractFile`；之后0x12194才调用`CheckGuardResult`，0x1219e调用XML `Execute`。身份由vtable的重定位项确定。
- tar顺序中`0700_part_image/*`在`0701_part_image_sum/part_image.sum`之前。因此存在“分区内容先被写入，后由sum插件读设备校验”的强静态链。

建议替换153行的表述（本次不改任务书）：**“现有修改镜像CRC32=129576f8，与清单期望520fff36冲突。原更新器含分区CRC检查，预计不能成功完成该更新；该检查可能发生在分区写入后，不能当成写前安全拒绝。重算清单仍不能证明签名、版本、型号或硬件接受。”**

## F2 · 容器完整性、加密与签名分开判断

| 层 | 已证实 | 未证实 |
|---|---|---|
| part_image.sum | ASCII清单内是CRC和长度；可重算 | 清单或所属tar是否受外层签名认证 |
| FDAT明文头 | a6600储存CRC=`91595d86`，恰等于`CRC32(`../02-脚本/build_full_image.py`42–61行只替换nflasha15，其他tar成员原样复制；没有更新part_image.sum。75–76行更新的是fdat头CRC；96–105行从旧DAT取IV和256B尾部并原样拼回；113–114行重算DEND。故不能用“打包成功”推导“认证成功”。

primary证据：[fwtool fdat.py](https://github.com/ma1co/fwtool.py/blob/master/fwtool/sony/fdat.py)，本地留存`../03-证据/静态分析/97_flash/97_flash_primary_fdat.py`。它支持读格式，不代表完整复刻了相机信任链；其CBC encrypt方法直接报不支持，也没有验证尾部256B的实现。本次没有原官方EXE/DAT在限定工作区内可供比对，因此不声称验证了原/改DAT尾部实际相等或官方EXE签名。

## F3 · 分区几何、扩容边界与更新模式

### 实际运行几何（E1）

QEMU emmc.img前64KiB全零，offset510没有MBR `55aa`。不是标准MBR/GPT，**不得直接用parted的假设改表**。

SDM位于磁盘offset **8388608（0x800000）**；前8B=`82461.00`，count30（LE32@8），reserved20B（12:32）全零；从32开始每行16B为`<start,size,type,flag>`，均为LE32。start相对于eMMC用户区域；该QEMU盘在前面额外带8MiB，因此`磁盘offset = 0x800000 + SDM.start`。

| 项 | SDM.start | size | QEMU磁盘start/end |
|---|---:|---:|---|
| nflasha15 |0x2D800000|0x12C00000=300MiB|771751936 / 1086324736|
| nflasha16 |0x40400000|0x08C00000=140MiB|1086324736 / 1233125376|
| 原ext2 |同nflasha15|215517184B=205.533203125MiB|771751936 / 987269120|

当前文件系统尾部距下一分区还有 **99,055,616B=94.466796875MiB**；这是分区内尚未纳入该镜像文件系统的容量，不是分区后空闲。300MiB分区和p16相邻，分区后连续空闲为0。

完整2GiB扫描只发现一个与512B SDM全内容一致的副本@8388608。另有7处`82461.00`字符串，不能误认成冗余分区表。只对这张QEMU输入盘下结论，不声称真实相机无冗余表/硬件隐藏区。

primary [fwtool flash.py](https://github.com/ma1co/fwtool.py/blob/master/fwtool/sony/flash.py)给出SDM头和每行结构，只有magic/version/row/flag解释，无CRC字段。本盘reserved20B全零，**未识别SDM CRC字段**，不声称已证明所有真实硬件校验均不存在。原nflasha7/initrd的emmc.ko同hash=`c05f0a628ee8ceca79e3e47c2e66128153fc094e14ca6f9a9d3ec416aebf167a`，含`82461.00`、`emmc_load_partition_tbl`、`init_fs_part`等原生字符串；原模块初始化注释及反汇编留存。当前证据将注册归属定位到原emmc驱动，完整逐分支硬件校验尚未闭合。

### 512MiB QEMU离线迁移计划（仅模拟器）

新增脚本`../02-脚本/97_flash_m2_plan.py`默认只读；本次仅执行dry-run，**未执行--output构盘**。它锁定已审查输入SHA256，保留SDM header/reserved/type/flag，p15.size改为536870912，p16–p30的start一律加222298112（212MiB），含零长度占位行；原数据尾段在新文件中搬移并逐分区SHA256复核。可选输出只允许新的97_flash命名常规文件，不写输入、不生成可刷DAT、不自动resize ext2。

量化结果见`../03-证据/静态分析/97_flash/97_flash_m2_plan.json`：新p16磁盘start=1308622848；所有分区末尾由1361051648移至1583349760；2GiB剩余564133888B（538MiB），无需扩介质。新增占用区`../03-证据/静态分析/97_flash/97_flash_updaterimg_config_config.xml`20–26行将partinf.conf交给`chknandcapa.elf`，并在partconf.sum后调用`us_mkfs.sh`。

原`../03-证据/静态分析/97_flash/97_flash_updaterimg_bin_us_mkfs.sh`39–49行明确：SERVICE(4)、USER(3)、MINOR(5)、MSCRYPT(6) **不执行edisx.elf**；其他模式才执行`edisx.elf /dev/nflasha $FILE_PARTINF`。故**在普通USER更新包内修改partinf.conf不能推出SDM会被重写**。需要另证更新动作模式、权限、容量、数据迁移和所有依赖方；不能把PRODUCT/LOADER模式名称当成已取得的通道。

## F4/F5 · 恢复路径与写入通道

| 通道 | primary/原包能证明的能力 | 必须具备的启动前提 | 本次恢复结论 |
|---|---|---|---|
| Sony官方USB updater | 正常官方包升级，guard/版本确认、切换updater、传输和完成 | 相机能开机、设置/进入海量存储或已经处于能应答的updater USB状态；供电和原更新器服务链完整 | 只在相应前提仍成立时可讨论重试；无任意损坏救砖证明，亦无同版/降级恢复证明 |
| PMCA firmware协议 | `checkGuard`→query version→switchMode→writeFirmware→complete；有invalid data/model/region/version及供电状态 | 正常扩展命令或updater设备响应；目标firmware handler存活 | 它是协议客户端，不证明绕过认证或坏boot链恢复 |
| PMCA updater shell | 以自定义updater body启动shell，shell后端有文件/进程等接口 | custom updater payload先被接收并执行；模型/架构支持 | 本地pack.py bodyFiles只列至CXD90014，缺CXD90045；本地无ILCE-6600 hdr。不能拿旧型号shell证明a6600通道可用 |
| PMCA service/senser | 认证、文件读写、内存读写、Backup ID读写/保存等命令 | 能从海量存储切service并认证，或已是能应答的service设备；相机相应固件服务必须存活 | generic writeFile/writeMemory不是已证明的a6600原始eMMC重刷器；更不是bootrom rescue |
| 用户态已有root shell | 若OS/驱动/分区仍可用，理论可调用其可写接口 | 所依赖kernel、rootfs、USB/网络和认证仍可启动 | 本次没有调用；不能保证/usr或启动链损坏后还存在该通道 |
| **看门狗→强制USB模式（设备所有者一手运行经验；本轮未离线复测）** | 固件挂起超过约60秒时，看门狗复位并强制进入USB模式；插线后可由主机侧工具恢复；日志会强制写入SD卡，优先级高于系统 | 看门狗所在的内核/启动链、USB gadget 和供电仍完整；SD卡可写 | **对仅修改 /usr 数据分区造成的启动失败，这是可用的恢复通道**；若损坏 kernel/initrd、SDM 分区表或 bootloader，则不能据此保证 |
| bootrom/UART/JTAG/拆焊写存储 | 本次限定材料无已验证a6600完整恢复实现 | 型号特定接入、启动条件、完整设备唯一备份/校准和写入验证 | U，不承诺可救 |
| QEMU副本/覆盖层回退 | 可丢弃新文件，恢复模拟器原始输入 | 宿主原文件完好 | 只恢复模拟器，不是相机恢复路径 |

Sony中国ILCE-6600 v1.10官方说明要求开机、海量存储、足够电量和版本确认，并警告升级中断电可永久损坏；没有承诺任意错误镜像可恢复。已归档`../03-证据/静态分析/97_flash/97_flash_primary_sony_ilce6600_v110.html`，来源：[官方页面](https://service.sony.com.cn/download/firm/00002943.html)。泛型号“更新失败后重试”也不能补足boot链已破坏的恢复前提。

PMCA primary本地源码位置（仅读取，未import或运行）：

- `pmca/commands/usb.py`380–423：guard、模式切换、writeFirmware；656–710：service切换和认证前提。
- `pmca/usb/sony.py`417–581：Updater状态与命令；1016–1045：service file/memory/backup方法。内存写API的存在不表示写入持久分区。
- `updatershell/pack.py`24–31、64–94：支持的body库、模型头/公共payload切分。48B hdr是该旧方案的模型前缀，不可等同新包数字签名。

这些源码的canonical来源为[ma1co/Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE)，不是从第三方教程推导通道。具体本地文件hash见最终manifest。

## 命令与复核

工作目录为本工作区根。下列脚本只做离线读取/提取/计算；证据路径已存在时会拒绝覆盖，复跑需使用新的97_flash证据目录或审查后自行调整输出。不要通过删除原证据来冒充重复运行。

```powershell
python '02-脚本\97_flash_audit.py'
python '02-脚本\97_flash_geometry.py'
python '02-脚本\97_flash_sdm.py'
python '02-脚本\97_flash_extract.py'
python '02-脚本\97_flash_native.py'
python '02-脚本\97_flash_crc_verify.py'
python '02-脚本\97_flash_driver.py'
python '02-脚本\97_flash_plt.py'
python '02-脚本\97_flash_flow.py'
python '02-脚本\97_flash_vtables.py'
python '02-脚本\97_flash_m2_plan.py' --plan-out '03-证据\静态分析\97_flash\97_flash_m2_plan.json'
```

原包提取文件、tar完整成员列表、fdat头hex、分区CRC日志、ELF符号/反汇编、SDM原字节和迁移计划都在`../03-证据/静态分析/97_flash/`。首次PLT映射对ARM旋转立即数处理不完整，已保留为`body_plt.json`用于审计；**有效版本是`body_plt_v2.json`**，flow使用v2。反汇编自动输出中包含函数尾literal pool，解释只引用确切控制流指令和ELF重定位，不把尾部数据误作可执行路径。

### 尚需闭合的离线问题

1. 找到并完整静态证明CXD90045 FDAT尾部256B的生成/验证逻辑及签名覆盖范围，认证失败发生于何阶段。
2. 完整解析a6600实际guard/版本/硬件匹配链，不能从CRC替代。
3. 如继续M2，验证新SDM盘的原内核注册/挂载；该验证仅可支持模拟器几何，不授予刷写结论。
4. 恢复主张应按“改动范围”限定：仅 `/usr` 数据分区的失败，可由所有者验证的看门狗→USB 模式通道恢复（前提是内核/启动链、USB gadget 与供电完整，SD 卡可写）；启动链、SDM 或 bootloader 损坏不在该通道覆盖范围内。任何更广的恢复主张仍须给出型号特定通道、权限、备份范围与成功条件。
