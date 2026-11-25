# 92_menu_map · 原厂 MENU/ENTER 的真实映射与派发

纯静态分析；未启动 QEMU、未改共享源码、镜像或运行配置。时间：2026-11-21。

## 直接结论

**91号问题A的物理键身份前提有误：0x1AC 是 ENTER，不是 MENU。真正 MENU 是 0x1AB。**

| 原厂物理枚举 | physical key_code | InfraInput event_code 基码 | createEvent 释放 | createEvent 首次按下 | createEvent 持续重复 |
|---|---:|---:|---:|---:|---:|
| KEY_TACT_MENU | 0x1AB | 0x15010100 | 0x15010101 | 0x15010102 | 0x15010104 |
| KEY_TACT_ENTER | 0x1AC | 0x15010050 | 0x15010051 | 0x15010052 | 0x15010054 |

ENTER 的最终码成立条件为正常中心键路径、未进入产品包装的备份配置特殊分支，且无其他方向键混合按下。MENU 的原厂包装最终调用 callback_convert，绝不能把基码 0x15010100 当作 createEvent 必定出现的码，也不能给 callback_direct 传 physical 0x1AB。

91所列605次 createEvent 中已有 0x15010052 / 0x15010054：与实际正在注入 ENTER 完全吻合，是静态链条与现有运行观测的强一致性证据；这不证明 MENU 已经送达。应查 0x15010101/102/104。按91列出的全集，它们均未出现。

## 可复核原始数据

机器证据：`03-证据/静态分析/92_menu_map/mapping_evidence.json`。

- libObj.so SHA-256：`ebb6cd0475ebfdb592fb7bdd2a54df8bc694e2e0520733fb84d7dfd31c84038a`
- viewUnified2.so SHA-256：`637457e062375b68d69381bedfb7761ce878c6092489e912da9842696a928e7f`
- viewUnified2.so 直接从原始 nflasha15 ext2 `/lib/viewUnified2.so` 提取，保存在本轮证据目录。
- **注意数据段 VA 与文件偏移不同**：本轮两个 ELF 的相应数据段均 VA=文件偏移+0x8000；代码段此处 VA=文件偏移。

libObj 的原厂键名二元表：

| VA | 文件偏移 | 两个32位字段 |
|---:|---:|---|
| 0x13F0924 | 0x13E8924 | `{0x1AB, 0x01014593}`，字符串 `KEY_TACT_MENU` |
| 0x13F092C | 0x13E892C | `{0x1AC, 0x010145A1}`，字符串 `KEY_TACT_ENTER` |

viewUnified2 的 InfraInputKeyList 三元表每项12字节：

| VA | 文件偏移 | 原始字节 | 解码 |
|---:|---:|---|---|
| 0x9600FC | 0x9580FC | `ab01000000010115feffff7f` | `{0x1AB,0x15010100,0x7FFFFFFE}` |
| 0x95FFA0 | 0x957FA0 | `ac01000050000115feffff7f` | `{0x1AC,0x15010050,0x7FFFFFFE}` |

## list 与 callback 的真正所有者

不是在 libObj 内找到最终产品默认表，而是 libObj 从产品配置对象虚表 +0x44 取得配置数量、+0x48 取得配置表。产品实现是 viewUnified2 导出 `getInputTableSize` (0x2BAB38) / `getConfigInputTable` (0x2BAACC)，后者返回 VA 0x95FA5C。

该源配置表有37项，每项0x14字节：`{list_ptr, callback, count, init_flag, predicate}`。

| 配置项（0起算） | 源配置VA | list VA | count | callback（Thumb函数指针） | init | predicate |
|---|---:|---:|---:|---:|---:|---:|
| 0，含 MENU | 0x95FA5C | 0x96009C | 212 | view+0x2BDBA5 | 0 | NULL |
| 2，含 ENTER | 0x95FA84 | 0x95FF94 | 6 | view+0x2BD9E5 | 0 | NULL |

MENU 在该list的第8项，ENTER在第1项。两个源配置 predicate 都为NULL，所以原厂配置筛选循环默认保留它们；不是因型号 predicate 返回false而排除。

libObj 注册循环 0x3D45F8–0x3D4698：

1. 0x3D4624 调 `InfraInput::SetCallback`；返回值存运行条目+0xC。
2. 成功后，0x3D4644 调 `InfraInput::SetEventKeyList`；返回值存+0xD。
3. 仅在 init_flag 非0时调用 SendEventInitData；两目标条目均为0。

运行表条目0x14字节：`+0 callback_id; +4 list_ptr; +8 count; +C callback_registered byte; +D list_registered byte; +E init_flag byte; +10 callback`。

全局变量均是 libObj VA：

- `[0x13F5CE0]`：筛选后运行表指针；`[0x13F5D20]`：运行表数量。
- `[0x13F5CE8]`：源配置表指针；`[0x13F5DC0]`：源配置数量。
- `[0x13F5E14]`：InfraInput实例指针。

**静态可证明原厂注册意图、默认纳入、真实list/callback；无法仅凭静态宣称本轮注册调用成功。** 要给“本轮已成功注册”盖章，只需主线程读取上述两条运行记录+C/+D；不必再猜物理逻辑映射。

## 状态、边沿、重复与抑制

`0x7FFFFFFE` 是该键表的动态/跟随物理状态模式，不是“只在收到数值0x7FFFFFFE时匹配”，也不是按下状态。libObj `ChangeEventStatus` 0x861578 中，0x8615E8–0x8615F4 将表状态 0x7FFFFFFE / 0x7FFFFFFF 转入动态汇聚分支，扫描同一逻辑基码的物理键、优先级及抑制状态。正常物理 status=1 为按下、0为释放。

- `InputService::changeTactStatus` 0x3CFA20：原始0→分类1，原始1→分类2，0x7FFFFFFF→5，0x7FFFFFFE→6，其余→0。
- MENU view回调 0x2BDBA4 最终 0x2BDE74 调 libObj `callback_convert`，0x3D2FB0→0x3D2EB8。
- 转换器0x3D2F38–0x3D2F5A：分类1→基码+1；分类2且event+0x14==0→基码+2；分类2且repeat非0→基码+4；其他分类不createEvent。
- ENTER view回调0x2BD9E4先更新中心/方向聚合状态，再判断当前合成键与之前键；旧键释放+1、新键按下+2、同键且repeat非0时+4，调用view0x2BCC5C→createEvent。产品Backup ID 0x01070861非0时会改走0x2BCF2C，不能把这一特殊模式忽略。
- ChangeEventStatus 0x861916–0x86195C比较上次缓存的16字节状态并更新，返回changed；MainThread再结合repeat和inhibit决定是否发送。不是“只要持续读到status1就每次发按下”。
- MainThread0x8626CA先匹配physical key，再检查内部项+0x40 disable byte、+0x41 event inhibit byte。0x862740调用ChangeEventStatus；0x862788以后结合changed、repeat、物理inhibit及flags 4控制派发。
- 物理状态表 `[InfraInput+0x24]`，每项0x28；+0x20物理inhibit byte，+0x24 inhibit flags；其中bit0影响动态汇聚候选是否能被选取。
- 事件已注册内部list `[callback_record+0x2C]`，每项0x44；首12字节保留原 `{physical,event_code,status_mode}`，+0x24 config索引，+0x28起缓存物理状态，+0x40/+0x41为前述禁止标志。
- 具体 repeat_time0/repeat_time 来自GETKEYCONFIG运行时配置；本轮未捕获该配置，不能编造MENU重复延时。事件24字节的+0x14是repeat字段，并非ex_info。

## 可直接交给运行主线程的最小断点

所有libObj地址加**本轮实测**load bias；Thumb断点用偶数，函数指针才+1。

1. **libObj+0x8609CC**：最终 `blx r3`，此时r3=真实callback函数指针、r0=cbid、r1=24字节事件。
   - 事件：`+0 logical基码, +4 sub/坐标, +8 status, +C prev_status, +10 ex_info, +14 repeat`。
   - MENU应为基码15010100、回调view_bias+2BDBA5；ENTER为15010050、回调view_bias+2BD9E5。
2. **libObj+0x3D4644**：r0=this、r1=cbid、r2=三元表指针、r3=count；检查返回后+0xD注册成功字节。
3. **libObj+0x3D2F5A**：通用convert即将createEvent，r1=真正最终ID；MENU按下应15010102。
4. **viewUnified2+0x2BCC70**：ENTER聚合路径即将createEvent，r1=最终ID；可解释现有52/54。

若仅作UI进程内原厂回调对照，MENU走 callback_convert / 产品MENU包装，传24字节 `{0x15010100,0,1,0,0,0}`，释放 `{0x15010100,0,0,1,0,0}`；不要向direct回调传physical key。此处只是给主线程准确ABI/字段，不在本轮运行或注入。

## 复现命令及证据文件

`python 02-脚本/92_menu_map.py firmware`：从原始ext2搜索所有/lib ELF的物理1AB/1AC与事件三元组；提取命中的viewUnified2。

`python 02-脚本/92_menu_map.py summary`：生成已核对VA、文件偏移、原始字节、SHA256、注册项的JSON。

`python 02-脚本/92_menu_map.py dis 0x3d2eb8 0xe8`、`vdis 0x2bdba4 0x3a4`、`vdis 0x2bd9e4 0x1c0`：输出精确转换链反汇编，写到本轮证据目录。

证据目录 `03-证据/静态分析/92_menu_map` 内的 `dis_*.txt` 是局部线性反汇编；嵌入literal/jump table可能被显示成无意义指令，只采用报告逐条引用的实际控制流地址，不把literal的伪指令当执行证据。
