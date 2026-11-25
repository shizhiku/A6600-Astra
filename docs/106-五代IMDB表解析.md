# 106 · ZV-1M2 五代固件 IMDB 任务表解析（2026-11-22）

> 范围：只读分析 `05-原始固件/zv1m2_fw` 下的原始 `/usr` 镜像与既有提取件；未运行 QEMU，未修改任何既有镜像/脚本/文档。脚本：`02-脚本/imdb5_decode.py`；证据：`03-证据/静态分析/imdb5/`。

## 1. 结论摘要

1. **数据归属**：任务书说的“文件偏移约 370,524,800（`0x1615C280` 一带）”的 IMDB 模板数据，属于 `/usr` 镜像中的 **`/lib/libIMDB.so`**（ext2 inode 85048，40,596 B，sha256 `9f8bc011ee505d6895c59380e153e8629306f18918340f3992d5c8b6973b8f2d`），与 `05-原始固件/zv1m2_fw/gen5/libIMDB.so` **逐字节相同**。它与 a6600 的 `libIMDB.so`（33,924 B，sha256 `05793f4e8b5b81fbb534953c1164788151d57b13d520158b89a3d1329d59518e`）不是同一文件：a6600 表头 tag=`0x10001`、target 位 8 个、共 198 条记录，与五代表（`0x20000`/9 位/228 条）不同。镜像内偏移不是文件起点：文件从镜像偏移 `0x16158400`（物理块 `0x58561`）开始，模板头在文件内 `0x700c`，字符串区在文件内 `0x3c4d` 起。
2. **表结构**：`imdb_raw` 符号为 132 B 头（`0x20000` + 31 个 target 名槽位），之后是 **228 条 × 44 B** 记录（含一条 `0x28` 终止记录）。44 B 布局为：`type(+0) / flag(+4, stage掩码) / target(+8) / me(+12,u16) / psid(+14,u16) / file(+16) / init(+20) / exit(+24) / sus(+28) / res(+32) / inact(+36) / act(+40)`。
3. **Application 位置**：`Application_System_Init`（file=`appFwBoot.so`，psid=0）在 **index 145**（记录 VA `0x1097c`）。它之前（index < 145）按 im.elf 静态执行模型会执行 **118** 条记录，详见第 5 节顺序清单。Application 记录本身：`/lib/appFwBoot.so` 在镜像中存在，`init_found`=True。
4. **启用判据**：`target` 是“模型/目标特性”掩码，正常 `target=default` 只置 bit0（掩码=1）；`flag` 是执行阶段掩码（1=INFRA0、2=INFRA1、4=INFRA2、0xF=APP线程、0xFF=main 任意）；`type=0x0800000N` 是序号分隔记录（target=0，本身不执行），N=1..9 把表切成 9 段。
5. **提供者分类**：24 条 `psid!=0` 的记录由 `dlopen("/usr/lib/libObj.so")+dlsym` 提供，其中 **23 条 init 入口确实在 `libObj.so` 的 `.dynsym` 中导出**；`core_sync_user_init`（libCoreSync.so，index 45）**不在 libObj 导出中**，是明确缺失实现。其余 `psid==0` 但 `/usr` 镜像里没有对应 `.so` 的记录属于“镜像内缺失”，它们可能位于本次未提供的 `/system`、`/rootfs` 分区，详见第 6 节。
6. **重要反汇编结论**：`im.elf` 解析 `bootin` 传入的字母参数时，`s/u/l/i/a` 会置 boot 位，`g/r` 只被识别但不置位（两代 im.elf 相同）；因此 **B 段（dmm/upm 内核模块）和 C 段（stream/mcmn/ms/mmc/sata/msen/hdmi/cec 内核模块）在本启动路径下不会被 im.elf 执行**。若以 `bootall` 或显式 `boot=g/r` 启动则另论。

## 2. 定位过程（镜像偏移 → 文件）

### 2.1 方法

1. **原始字节搜索**：在 `nflasha15` 上直接搜索 `libInfraInput.so`、`infra_input_init`、`Application_System_Init`、`appFwBoot.so` 等特征串，得到镜像偏移（如 `0x1615c44d`）。
2. **ext2 块反查**：用 `02-脚本/a6600_usr.py` 的 `Ext2` 类遍历镜像，读取每个 inode 的直接/一级/二级块指针，按 `块号 = 镜像偏移 / block_size` 反查所属文件，并换算为文件内偏移：`file_offset = 逻辑块 * block_size + 块内偏移`。
3. **偏移一致性核对**：特征串在镜像中的“文件内偏移”与 `gen5/libIMDB.so` 中位置一致（如 `libInfraInput.so` 均在文件内 `0x3c4d`），并且整文件 SHA-256 相同，从而确认归属。

### 2.2 关键字符串命中

| 字符串 | 镜像偏移 | 所属文件 | 文件内偏移 | 说明 |
|---|---|---|---|---|
| `libInfraInput.so` | `0x1615c44d` | `/lib/libIMDB.so` (文件) | `0x3c4d` | libIMDB 表内字符串 |
| `infra_input_init` | `0x1615c45e` | `/lib/libIMDB.so` (文件) | `0x3c5e` | libIMDB 表内字符串 |
| `infra_input_init` | `0x1625db9a` | `/lib/libObj.so` (文件) | `0x639a` | libObj 静态合并的入口名（导出符号字符串） |
| `libuxengine.so` | `0x1615c6c3` | `/lib/libIMDB.so` (文件) | `0x3ec3` | libIMDB 表内字符串 |
| `uxengine_init` | `0x1615c6d2` | `/lib/libIMDB.so` (文件) | `0x3ed2` | libIMDB 表内字符串 |
| `uxengine_init` | `0x16262725` | `/lib/libObj.so` (文件) | `0xaf25` | libObj 静态合并的入口名（导出符号字符串） |
| `uxengine_init` | `0x16262733` | `/lib/libObj.so` (文件) | `0xaf33` | libObj 静态合并的入口名（导出符号字符串） |
| `uxengine_init` | `0x17bc9870` | `/lib/appFwBoot.so` (文件) | `0x870` | 其他引用 |
| `Application_System_Init` | `0x1615dde9` | `/lib/libIMDB.so` (文件) | `0x55e9` | libIMDB 表内字符串 |
| `Application_System_Init` | `0x17bc968e` | `/lib/appFwBoot.so` (文件) | `0x68e` | 其他引用 |
| `appFwBoot.so` | `0x1615dddc` | `/lib/libIMDB.so` (文件) | `0x55dc` | libIMDB 表内字符串 |
| `appFwBoot.so` | `0x17307e40` | `/lib` (目录项) | `0xe40` | 目录项（文件名，不是文件内容） |
| `appFwBoot.so` | `0x17bc9da5` | `/lib/appFwBoot.so` (文件) | `0xda5` | 其他引用 |
| `libIMDB.so` | `0x652e4d6` | `/bin/im.elf` (文件) | `0x8d6` | im.elf 的 DT_NEEDED 名 |
| `libIMDB.so` | `0x15f3b434` | `/lib` (目录项) | `0x434` | 目录项（文件名，不是文件内容） |
| `libIMDB.so` | `0x161587d9` | `/lib/libIMDB.so` (文件) | `0x3d9` | ELF 元数据（.dynstr 中的 SONAME） |
| `libNVM.so` | `0x1615c1b9` | `/lib/libIMDB.so` (文件) | `0x39b9` | libIMDB 表内字符串 |
| `NVM_Initialize` | `0x1615c1c3` | `/lib/libIMDB.so` (文件) | `0x39c3` | libIMDB 表内字符串 |

### 2.3 文件与块映射

| 项 | 值 |
|---|---|
| 镜像 | `<WORKSPACE>\05-原始固件\zv1m2_fw\extracted\0700_part_image\dev\nflasha15` |
| 镜像大小 / SHA-256 | 530345984 B / `10db74fba126b572071387eecfc2408df8869e7c9e9e8d146528bb104dde408b` |
| ext2 block size / inode size | 1024 / 128 |
| 镜像文件/目录数 | 49986 文件 / 44 目录（`/lib` 下 207 项；全镜像 `.so*` 共 234 个） |
| 目标文件 | `/lib/libIMDB.so`（inode 85048） |
| 文件大小 / SHA-256 | 40596 B / `9f8bc011ee505d6895c59380e153e8629306f18918340f3992d5c8b6973b8f2d` |
| 与 gen5/libIMDB.so 相同 | **是** |
| 文件起点 | 镜像偏移 `0x16158400`，物理块 `0x58561` |
| IMDB 头 / 记录区 | 文件内 `0x700c` / `0x7090` |
| 字符串块 `libInfraInput.so` | 文件内 `0x3c4d` → 逻辑块 15 → 物理块 `0x58571` |
| 任务书偏移 370,524,800 | = `0x1615C280` → 逻辑块 14（物理块 `0x58570`）→ 文件内 `0x3a80`（字符串池内） |

> 说明：文件逻辑块与物理块不是简单连续——`libIMDB.so` 的第 12~15 个逻辑块分别位于物理块 `0x5856e/0x5856f/0x58570/0x58571`，而它们之间还夹着单级间接块 `0x5856d`。因此“镜像偏移 − 文件起点”会多算 `0x400`：任务书的 370,524,800（`0x1615C280`）对应文件内 `0x3a80`，`libInfraInput.so`（`0x1615c44d`）对应文件内 `0x3c4d`，而不是 `0x404d`。这正是必须用 ext2 块表反查、不能只做偏移减法的原因。

## 3. 表结构

### 3.1 头（`imdb_raw`，132 字节）

| 偏移 | 内容 |
|---|---|
| +0 | `0x00020000`（表标识/版本） |
| +4 | 0 |
| +8 … +128 | 31 个 target 名字符串指针槽（本表用到前 9 个） |

target 位（`imdb_raw` 头中取出的顺序，bit0 起）：

| bit | 名字 | 说明 |
|---|---|---|
| 0 | `default` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 1 | `qemu` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 2 | `sim` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 3 | `nfs` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 4 | `set` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 5 | `usbj` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 6 | `resub` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 7 | `adjust` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |
| 8 | `test` | 由 `IMDB_find_target_bit()` 返回 `1<<bit` |

### 3.2 记录（228 × 44 字节）

> 与旧提法对照：`tag` = +0 的 `type`；旧文档里的 `version` 实为 +4 的 `flag`；旧称 `mode` 的 +8 实为 `target` 模型掩码；`me_psid` = +12/+14 的两个 u16；`file_ptr`=+16、`init_ptr`=+20；+24…+40 依次是 exit/sus/res/inact/act 指针。

| 偏移 | 字段 | 类型 | 语义（依据 im.elf/libIMDB.so 反汇编） |
|---|---|---|---|
| +0 | `type` | u32 | 任务类型：0x2000000[1-4]=库/Application，0x1000000[1-2]=insmod，0x40000001=shell，0x00000001=target定义，0x0800000N=序号分隔N，0x28=终止 |
| +4 | `flag` | u32 | 执行阶段掩码：1=INFRA0线程、2=INFRA1线程、4=INFRA2线程、0xF=APP线程、0xFF=main任意 |
| +8 | `target` | u32 | 模型/目标特性掩码；记录执行条件为 `target & 运行期target掩码 != 0` |
| +12 | `me` | u16 | 模块入口 id（`IMDB_find_entry(me, target_mask)` 的键） |
| +14 | `psid` | u16 | 非 0 = 该库已静态合并进 `libObj.so`：库类型改为 `dlopen("/usr/lib/libObj.so")`，Application 类型改为 `dlopen(NULL)` 后 `dlsym(init)` |
| +16 | `file` | char* | 库名/ko 路径/脚本路径；库类型多为 basename（由动态链接器搜索） |
| +20 | `init` | char* | 初始化符号；执行记录时 `dlopen` 后立即 `dlsym(init)` 并调用，参数为 `act` 或 `inact` 字符串（非空时） |
| +24 | `exit` | char* | 退出符号（停机/卸载时用） |
| +28 | `sus` | char* | 挂起符号 |
| +32 | `res` | char* | 恢复符号 |
| +36 | `inact` | char* | inactive/调整模式参数；`im.elf` 在 adjust 标志位置位时传给 init |
| +40 | `act` | char* | active/正常模式参数；未置 adjust 时传给 init |

### 3.3 序号分隔记录（stage 边界）

| type | index | 含义 |
|---|---|---|
| `0x08000001` | 6 | 第 1 段结束/开始标记（target=0，仅作边界） |
| `0x08000002` | 9 | 第 2 段结束/开始标记（target=0，仅作边界） |
| `0x08000003` | 19 | 第 3 段结束/开始标记（target=0，仅作边界） |
| `0x08000004` | 42 | 第 4 段结束/开始标记（target=0，仅作边界） |
| `0x08000005` | 44 | 第 5 段结束/开始标记（target=0，仅作边界） |
| `0x08000006` | 139 | 第 6 段结束/开始标记（target=0，仅作边界） |
| `0x08000007` | 142 | 第 7 段结束/开始标记（target=0，仅作边界） |
| `0x08000008` | 144 | 第 8 段结束/开始标记（target=0，仅作边界） |
| `0x08000009` | 149 | 第 9 段结束/开始标记（target=0，仅作边界） |

## 4. 执行模型（来自 ZV-1M2 `/bin/im.elf` 反汇编）

以下控制流来自从镜像提取的 ZV-1M2 `/bin/im.elf`（23,240 B，sha256 `9d6da003ff1d299dbfaedcd86011e2773e23b076c03bd8bbe51e8309af856db2`，证据副本 `imdb5_im.elf`）与 `/bin/bootin.elf`（15,336 B，sha256 `3eff4684182527fa29253edd2515f5bb6967e182b92e296a1d8f8db44b5961f0`，证据副本 `imdb5_bootin.elf`）的反汇编；并用 a6600 `im.elf` 做同位置交叉核对。

`im.elf` 主流程（函数 `0xa2bc`）按表顺序分阶段执行，核心例程 `0xb9c8(index, end_tag, enabled, stage_mask)`：

1. 从 index 起逐条扫描；遇到 `type == end_tag` 或 `0x28` 停止；
2. 跳过 `target==0` 或 `target & 运行期掩码 == 0` 的记录；
3. 跳过 `flag & stage_mask == 0` 的记录；
4. 其余记录交给 `b8bc` → `b7b8` 按类型分派：insmod / dlopen+dlsym(init) 并立即调用 / Application / shell。

关键函数与字段证据（ZV-1M2 `im.elf`，地址为 VA）：

| 函数/位置 | 证据 |
|---|---|
| `0xb9c8` 执行循环 | `+8` 与 `[0x154d8+0x28]`（运行期 target 掩码）做 `tst`；`+4` 与传入 stage 掩码做 `tst`；`+0xe` 半字经 `0x919c=IMDB_find_entry` 定位；命中后调 `0xb8bc`。 |
| `0xb5c0` 库记录加载 | `ldrh r0,[rec,#0xe]`（psid）：为 0 时 `dlopen(rec+0x10)`，非 0 时 `dlopen("/usr/lib/libObj.so")`；随后 `dlsym(rec+0x14=init)` 并立即调用，参数取 `rec+0x24`(act) 或 `rec+0x28`(inact)。 |
| `0xb4f8` Application 加载 | 与库相同，但 psid 非 0 时改为 `dlopen(NULL)`（从全局符号找入口），即“静态合入 libObj”的 Application 走全局命名空间。 |
| `0xb7b8` 类型分派 | type `0x10000001`→insmod；`0x10000002`→liro 特殊 insmod；`0x2000000[1-3]`→`0xb5c0`；`0x20000004`→`0xb4f8`；`0x40000001`→拼 `"%s %s &"` 通过 OSAL 消息交给 shell 服务；其它 type（含 target 定义 `0x1`、序号分隔 `0x0800000N`）走“成功但无动作”分支。 |
| `0xaf58` target 掩码计算 | `IMDB_find_target_bit(target名)`；找不到或 `target` 为空时掩码=`1`；`default` 时按 `usbj/cho(adjust)` 标志改用 `0x20/0x80`；其它 target 用 `1<<bit`。 |
| `0xb14c` 日志 | 2 字符级别 + 0x94 常量行号，用于确认字符串引用上下文。 |

阶段表（`end_tag` 即序号分隔记录的 type）：

| 段 | 范围 | 门控 boot 位 | 执行者 | stage掩码 | 本启动路径是否执行 |
|---|---|---|---|---|---|
| A 目标定义 | index [0, 6) | 无 | main | 0xff | **是** |
| B 内核模块组1 | index [6, 9) | 0x20000 (g) | main | 0xff | 否 |
| C 内核模块组2 | index [9, 19) | 0x40000 (r) | main | 0xff | 否 |
| D 基础库/全局Infra | index [19, 42) | 0x80000 (u) | main | 0xff | **是** |
| E LIRO | index [42, 44) | 0x100000 (l) | main | 0xff | **是** |
| F Infra并行任务 | index [44, 142) | 0x200000 (i) | infra1/2/4 | 1/2/4（三线程分别） | **是** |
| G BIZ初始化 | index [142, 144) | 0x200000 (i) | main | 0xff | **是** |
| H Application | index [144, 149) | 0x400000 (a) | app | 0xf | **是** |

`bootin.elf`（ZV-1M2 `/bin/bootin.elf`）在 mode3（默认，`/setting/mode/dmode` 首字符 `3`）时把字符串 `"s g r u l i a "` 作为独立参数拼进 `/usr/bin/im.elf debug …` 命令行；`im.elf` 参数解析对 `s/u/l/i/a` 置位（0x10000/0x80000/0x100000/0x200000/0x400000），对 `g/r` 只做识别、不置位（对应分支直接回到参数循环）。因此：

- **B 段（index 6–8：dmm.ko / upm.ko）与 C 段（index 9–18：stream/stream2/mcmn_drv/ms_drv/mmc_drv/sata_drv/msen_drv/hdmi/cec）在正常 mode3 启动中不会被 im.elf 执行**；内核模块加载属于更早的启动档/init 责任。
- D/E/F/G/H 段（基础库、liro.ko、Infra 并行任务、BIZ、Application）会执行。
- 运行期 `target=default`（`im.elf` 未收到 `target=` 时的默认值）→ target 掩码 = **1（bit0）**。

## 5. Application（index 145）之前会执行的初始化任务（按表顺序）

说明：按“全局表顺序”列出；F 段实际由 3 个 INFRA 线程并发执行，每个 INFRA 线程只执行 `flag & 1/2/4` 命中的记录（表中已标 runner），线程内相对顺序即表顺序。`file_in_image` 指该 `.so`/文件是否存在于本次提供的 `/usr` 镜像；`init_symbol_ok` 指该记录的 init 入口能否从期望提供者（动态库或 libObj）解析到。

| # | idx | type | flag/stage | target | me | psid | phase/runner | file | init | 镜像内 | init可解析 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 0 | `0x00000001` target定义 | INFRA0 | 0x00000001（default） | `0x0000` | `0x0000` | A / main | `IMDB:default` | `` | **否** | — |
| 2 | 20 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x003f` | `0x0000` | D / main | `libosal_uipc.so` | `` | 是 | — |
| 3 | 21 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x07fd` | `0x0000` | D / main | `libosal_utm.so` | `` | 是 | — |
| 4 | 22 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x07fe` | `0x0000` | D / main | `libosal_ulogio.so` | `` | 是 | — |
| 5 | 23 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x0282` | `0x0000` | D / main | `libInfraInterchipDatatrans.so` | `interchip_transfer_user_init` | **否** | **否** |
| 6 | 24 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x01e3` | `0x0000` | D / main | `libNVM.so` | `NVM_Initialize` | **否** | **否** |
| 7 | 25 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x003e` | `0x0000` | D / main | `libbackup.so` | `` | 是 | — |
| 8 | 26 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x02dd` | `0x0000` | D / main | `libSaveLoadSettings.so` | `infra_saveLoadSettings_init` | **否** | **否** |
| 9 | 27 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x02cd` | `0x0000` | D / main | `libbkdmn.so` | `BkDmn_init` | **否** | **否** |
| 10 | 28 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x00bd` | `0x0000` | D / main | `libOnDemandLoader.so` | `odl_init` | 是 | 是 |
| 11 | 29 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x0110` | `0x0000` | D / main | `libInfraKikiLogGenerator.so` | `KikiLogGenerator_init` | 是 | 是 |
| 12 | 30 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x0331` | `0x0000` | D / main | `libInfraAccessLog.so` | `AccessLogInfra_init` | 是 | 是 |
| 13 | 31 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x00f7` | `0x0000` | D / main | `libSysDef.so` | `` | 是 | — |
| 14 | 32 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x0097` | `0x0000` | D / main | `libMWF.so` | `MWF_Init` | 是 | 是 |
| 15 | 33 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffffbf（default/qemu/sim/nfs/set/usbj/adjust/test） | `0x0052` | `0x0000` | D / main | `libi2cuipc.so` | `i2cu_user_init` | **否** | **否** |
| 16 | 34 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffffbf（default/qemu/sim/nfs/set/usbj/adjust/test） | `0x0270` | `0x0000` | D / main | `libI2CRight.so` | `i2c_right_init` | **否** | **否** |
| 17 | 35 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffffbf（default/qemu/sim/nfs/set/usbj/adjust/test） | `0x007a` | `0x07fb` | D / main | `libInfraInput.so` | `infra_input_init` | **否** | 是 |
| 18 | 36 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffffbf（default/qemu/sim/nfs/set/usbj/adjust/test） | `0x027a` | `0x0000` | D / main | `libInfraError.so` | `infra_error_init` | **否** | **否** |
| 19 | 37 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x016f` | `0x0000` | D / main | `libJiritsu.so` | `jiritsu_init` | 是 | 是 |
| 20 | 38 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x0266` | `0x0000` | D / main | `libAtn.so` | `Atn_init` | **否** | **否** |
| 21 | 39 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x020f` | `0x0000` | D / main | `libGetLog.so` | `GetLog_init` | 是 | 是 |
| 22 | 40 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x0278` | `0x0000` | D / main | `libread_refresh.so` | `read_refresh_init` | **否** | **否** |
| 23 | 43 | `0x10000002` insmod(liro特殊) | INFRA0 | 0x7fffffff（全比特） | `0x0048` | `0x0000` | E / main | `/usr/kmod/liro.ko` | `` | 是 | — |
| 24 | 45 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x0131` | `0x07fb` | F / infra1/2/4 | `libCoreSync.so` | `core_sync_user_init` | **否** | **否** |
| 25 | 46 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x0080` | `0x07fb` | F / infra1/2/4 | `libgrm.so` | `grm_init` | **否** | 是 |
| 26 | 47 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x0082` | `0x0000` | F / infra1/2/4 | `libgpe.so` | `GpeInit` | **否** | **否** |
| 27 | 48 | `0x20000001` dlopen库(type1) | INFRA0 | 0x7fffffff（全比特） | `0x005c` | `0x07fa` | F / infra1/2/4 | `libDDS.so` | `DDSUserInit` | **否** | 是 |
| 28 | 49 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x007f` | `0x07fb` | F / infra1/2/4 | `libuxengine.so` | `uxengine_init` | **否** | 是 |
| 29 | 50 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x004e` | `0x07fb` | F / infra1/2/4 | `libInfraIndctr.so` | `infra_indctr_init` | **否** | 是 |
| 30 | 51 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x007b` | `0x07fb` | F / infra1/2/4 | `libInfraTp.so` | `infra_tp_init` | **否** | 是 |
| 31 | 52 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x016c` | `0x0000` | F / infra1/2/4 | `libRsrcHotshoe.so` | `rsrc_hotshoe_init` | 是 | 是 |
| 32 | 53 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x007c` | `0x07fb` | F / infra1/2/4 | `libInfraHotshoe.so` | `infra_hotshoe_init` | **否** | 是 |
| 33 | 54 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x007d` | `0x07fb` | F / infra1/2/4 | `libInfraSircs.so` | `infra_sircs_init` | **否** | 是 |
| 34 | 55 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x011b` | `0x07fb` | F / infra1/2/4 | `libInfraDial.so` | `infra_dial_init` | **否** | 是 |
| 35 | 56 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0119` | `0x0000` | F / infra1/2/4 | `libInfraLanc.so` | `infra_lanc_init` | **否** | **否** |
| 36 | 57 | `0x20000001` dlopen库(type1) | INFRA0 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0063` | `0x0000` | F / infra1/2/4 | `libInfraSelector.so` | `Selector_init` | **否** | **否** |
| 37 | 58 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0090` | `0x07fb` | F / infra1/2/4 | `libosal_udate.so` | `udate_init` | **否** | 是 |
| 38 | 59 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0055` | `0x07fb` | F / infra1/2/4 | `libInfraAvbbc.so` | `InfraAvbbc_Init` | **否** | 是 |
| 39 | 60 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00cf` | `0x07fb` | F / infra1/2/4 | `libInfraMediaConfig.so` | `InfraMediaConfig_Init` | **否** | 是 |
| 40 | 61 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00d5` | `0x0000` | F / infra1/2/4 | `libInfraMediaCommon.so` | `mcmn_init` | 是 | 是 |
| 41 | 62 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00c5` | `0x0000` | F / infra1/2/4 | `libInfraFsys.so` | `InfraFsys_Init` | 是 | 是 |
| 42 | 63 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0128` | `0x0000` | F / infra1/2/4 | `CameraOnDemandSaver.so` | `cam_ondemand_saver_init` | 是 | 是 |
| 43 | 64 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x02ef` | `0x0000` | F / infra1/2/4 | `libFsysPosixWrapper.so` | `FsysPosix_Init` | **否** | **否** |
| 44 | 65 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0277` | `0x0000` | F / infra1/2/4 | `libInfraOptionInstall.so` | `infra_option_install_init` | **否** | **否** |
| 45 | 66 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x030a` | `0x0000` | F / infra1/2/4 | `libAiDictionary.so` | `AiDic_init` | **否** | **否** |
| 46 | 67 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x01ae` | `0x0000` | F / infra1/2/4 | `libInfraOptionInstaller.so` | `infra_option_installer_init` | **否** | **否** |
| 47 | 68 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0104` | `0x07fb` | F / infra1/2/4 | `libInfraEyeFiControl.so` | `InfraEyeFiControl_Init` | **否** | 是 |
| 48 | 69 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00b0` | `0x0000` | F / infra1/2/4 | `libInfraMediaMount.so` | `InfraMediaMount_Init` | 是 | 是 |
| 49 | 70 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00af` | `0x0000` | F / infra1/2/4 | `libInfraMediaDetect.so` | `InfraMediaDetect_Init` | 是 | 是 |
| 50 | 71 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00c6` | `0x0000` | F / infra1/2/4 | `libmprdummy.so` | `` | **否** | — |
| 51 | 72 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0195` | `0x0000` | F / infra1/2/4 | `libdiablo.so` | `` | **否** | — |
| 52 | 73 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0127` | `0x0000` | F / infra1/2/4 | `libclema.so` | `` | **否** | — |
| 53 | 74 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x003c` | `0x0000` | F / infra1/2/4 | `libmpr.so` | `` | 是 | — |
| 54 | 75 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00c7` | `0x0000` | F / infra1/2/4 | `libmprctrl.so` | `InfraMprCtrl_Init` | **否** | **否** |
| 55 | 76 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x01c0` | `0x0000` | F / infra1/2/4 | `libMprSeq.so` | `MprSequencerIf_Init` | **否** | **否** |
| 56 | 77 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0276` | `0x0000` | F / infra1/2/4 | `libInfraIPTC.so` | `InfraIPTC_init` | 是 | 是 |
| 57 | 78 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0208` | `0x0000` | F / infra1/2/4 | `libInfraSystemProperty.so` | `InfraSystemProperty_init` | **否** | **否** |
| 58 | 79 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x02ec` | `0x0000` | F / infra1/2/4 | `libInfraCrypt.so` | `iCrypt_init` | 是 | 是 |
| 59 | 80 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x031b` | `0x0000` | F / infra1/2/4 | `libUniqIDGen.so` | `UIDG_init` | 是 | 是 |
| 60 | 81 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x01de` | `0x0000` | F / infra1/2/4 | `libInfraSetupFile.so` | `InfraSetupFile_init` | **否** | **否** |
| 61 | 82 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0209` | `0x0000` | F / infra1/2/4 | `libInfraSystemAdjust.so` | `InfraSystemAdjust_init` | **否** | **否** |
| 62 | 83 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0135` | `0x0000` | F / infra1/2/4 | `libInfraStillPool.so` | `InfraStillPool_Init` | **否** | **否** |
| 63 | 84 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0037` | `0x0000` | F / infra1/2/4 | `libInfraDatabase.so` | `InfraDatabase_Init` | **否** | **否** |
| 64 | 85 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00ae` | `0x0000` | F / infra1/2/4 | `libInfraSalvageStatus.so` | `InfraSalvageStatus_Init` | **否** | **否** |
| 65 | 86 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0038` | `0x0000` | F / infra1/2/4 | `libInfraCacheMgr.so` | `InfraCacheMgr_Init` | **否** | **否** |
| 66 | 87 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffbf（default/qemu/sim/nfs/set/usbj/adjust/test） | `0x01a2` | `0x0000` | F / infra1/2/4 | `libResourceBluetooth.so` | `ResourceBluetooth_init` | 是 | 是 |
| 67 | 88 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffbf（default/qemu/sim/nfs/set/usbj/adjust/test） | `0x0121` | `0x0000` | F / infra1/2/4 | `libUsbBusPower.so` | `UsbBusPower_Init` | 是 | 是 |
| 68 | 89 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x00e7` | `0x0000` | F / infra1/2/4 | `libInfraUsbCmn.so` | `InfraUsbLib_init` | 是 | 是 |
| 69 | 90 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x003d` | `0x07fb` | F / infra1/2/4 | `libsensapi.so` | `senser_init` | **否** | 是 |
| 70 | 91 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00ca` | `0x0000` | F / infra1/2/4 | `libUsbControl.so` | `UsbControl_Init` | 是 | 是 |
| 71 | 92 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0122` | `0x0000` | F / infra1/2/4 | `libBusPower.so` | `BusPower_Init` | 是 | 是 |
| 72 | 93 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00c8` | `0x07fb` | F / infra1/2/4 | `libHotplug.so` | `Hotplug_Init` | **否** | 是 |
| 73 | 94 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x009a` | `0x0000` | F / infra1/2/4 | `libInfraHdmi.so` | `HDMI_init` | 是 | 是 |
| 74 | 95 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x009c` | `0x07fb` | F / infra1/2/4 | `libInfraCec.so` | `CEC_init` | **否** | 是 |
| 75 | 96 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x014d` | `0x0000` | F / infra1/2/4 | `libInfraAirplaneMode.so` | `infra_airplane_mode_init` | 是 | 是 |
| 76 | 97 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0181` | `0x0000` | F / infra1/2/4 | `libInfraNfc.so` | `infra_nfc_init` | **否** | **否** |
| 77 | 98 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x019e` | `0x0000` | F / infra1/2/4 | `libInfraBluetooth.so` | `InfraBluetooth_init` | 是 | 是 |
| 78 | 99 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x004b` | `0x07fb` | F / infra1/2/4 | `libupdater0604.so` | `udtr_senser_init` | **否** | 是 |
| 79 | 100 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x0115` | `0x07fb` | F / infra1/2/4 | `libInfraAdjMedia.so` | `InfraAdjMedia_Init` | **否** | 是 |
| 80 | 101 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x030e` | `0x0000` | F / infra1/2/4 | `libInfraNetRfTest.so` | `InfraNetRfTest_Init` | 是 | 是 |
| 81 | 102 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0294` | `0x0000` | F / infra1/2/4 | `libInfraNetInitializer.so` | `InfraNetInitializer_Init` | 是 | 是 |
| 82 | 103 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00a5` | `0x0000` | F / infra1/2/4 | `libWlanResource.so` | `wlanResource_init` | 是 | 是 |
| 83 | 104 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0157` | `0x0000` | F / infra1/2/4 | `libWlanAdjust.so` | `WlanAdjust_Init` | 是 | 是 |
| 84 | 105 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x01d5` | `0x0000` | F / infra1/2/4 | `libWiredLanResource.so` | `WiredLanResource_Init` | **否** | **否** |
| 85 | 106 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x01d6` | `0x0000` | F / infra1/2/4 | `libWiredLanAdjust.so` | `WiredLanAdjust_Init` | **否** | **否** |
| 86 | 107 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0293` | `0x0000` | F / infra1/2/4 | `libNetServiceEther.so` | `netserviceether_init` | **否** | **否** |
| 87 | 108 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x02ad` | `0x0000` | F / infra1/2/4 | `libInfraNetConnectionManagerEther.so` | `NetConnectionManagerEther_init` | 是 | 是 |
| 88 | 109 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0223` | `0x0000` | F / infra1/2/4 | `libInfraEthernetService.so` | `EthernetService_Init` | **否** | **否** |
| 89 | 110 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x013e` | `0x0000` | F / infra1/2/4 | `libNetService.so` | `netservice_init` | 是 | 是 |
| 90 | 111 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x02ba` | `0x0000` | F / infra1/2/4 | `libInfraIPsec.so` | `InfraIPsec_init` | 是 | 是 |
| 91 | 112 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x012c` | `0x07fb` | F / infra1/2/4 | `libCameraStillDate.so` | `CameraStillDate_init` | **否** | 是 |
| 92 | 113 | `0x20000002` dlopen库(type2) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x012f` | `0x0000` | F / infra1/2/4 | `libdig_level.so` | `dig_level_init` | 是 | 是 |
| 93 | 114 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0147` | `0x0000` | F / infra1/2/4 | `libInfraNetDeviceInfo.so` | `InfraNetDeviceInfo_Init` | 是 | 是 |
| 94 | 115 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffbf（default/qemu/sim/nfs/set/usbj/adjust/test） | `0x0142` | `0x0000` | F / infra1/2/4 | `libWirelessPower.so` | `WirelessPower_Init` | **否** | **否** |
| 95 | 116 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x01db` | `0x0000` | F / infra1/2/4 | `libHandleRsrc.so` | `handle_rsrc_init` | **否** | **否** |
| 96 | 117 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x0108` | `0x0000` | F / infra1/2/4 | `libgps_rsrc.so` | `gps_rsrc_init` | 是 | 是 |
| 97 | 118 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00a1` | `0x07fb` | F / infra1/2/4 | `libgps.so` | `gps_init` | **否** | 是 |
| 98 | 119 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00a2` | `0x07fb` | F / infra1/2/4 | `libcompass.so` | `compass_init` | **否** | 是 |
| 99 | 120 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00a0` | `0x07fb` | F / infra1/2/4 | `libgeo.so` | `geo_init` | **否** | 是 |
| 100 | 123 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x0179` | `0x0000` | F / infra1/2/4 | `libInfraHdmiInput.so` | `HDMI_Input_init` | **否** | **否** |
| 101 | 124 | `0x20000002` dlopen库(type2) | INFRA2 | 0xffffff1f（default/qemu/sim/nfs/set/test） | `0x0210` | `0x0000` | F / infra1/2/4 | `libLccDaemon.so` | `Lcc_Daemon_Init` | **否** | **否** |
| 102 | 125 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x0217` | `0x0000` | F / infra1/2/4 | `libAdjModule.so` | `AdjModule_Init` | **否** | **否** |
| 103 | 126 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x01e0` | `0x0000` | F / infra1/2/4 | `libDpro_EVF.so` | `evf_init` | **否** | **否** |
| 104 | 127 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x0260` | `0x0000` | F / infra1/2/4 | `libInfraUpmPro.so` | `InfraUpmPro_init` | **否** | **否** |
| 105 | 128 | `0x20000002` dlopen库(type2) | INFRA0 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x0238` | `0x0000` | F / infra1/2/4 | `libfan.so` | `fan_infra_init` | **否** | **否** |
| 106 | 129 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x0263` | `0x0000` | F / infra1/2/4 | `libInfraUsb.so` | `InfraUsb_init` | **否** | **否** |
| 107 | 130 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x028e` | `0x0000` | F / infra1/2/4 | `libEMG.so` | `emg_init` | 是 | 是 |
| 108 | 131 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x0286` | `0x0000` | F / infra1/2/4 | `libAdjustUIProxy.so` | `AdjustUIProxy_init` | **否** | **否** |
| 109 | 132 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x02cb` | `0x0000` | F / infra1/2/4 | `libTetheringResource.so` | `TetheringResource_Init` | **否** | **否** |
| 110 | 133 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x02ca` | `0x0000` | F / infra1/2/4 | `libNetServiceTethering.so` | `netservicetethering_init` | **否** | **否** |
| 111 | 134 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x02e0` | `0x0000` | F / infra1/2/4 | `libJiritsuUIView.so` | `JiritsuUIView_init` | **否** | **否** |
| 112 | 135 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x02f3` | `0x0000` | F / infra1/2/4 | `libJiritsuSlave.so` | `JiritsuSlave_init` | **否** | **否** |
| 113 | 136 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x0316` | `0x0000` | F / infra1/2/4 | `BizNetTestTool.so` | `BizNetTestTool_Init` | **否** | **否** |
| 114 | 137 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x0319` | `0x0000` | F / infra1/2/4 | `libInfraMFi.so` | `InfraMFi_init` | 是 | 是 |
| 115 | 138 | `0x20000002` dlopen库(type2) | INFRA2 | 0x7fffffff（全比特） | `0x00a9` | `0x0000` | F / infra1/2/4 | `libInfraHttpClient.so` | `InfraHttpClient_Init` | 是 | 是 |
| 116 | 140 | `0x20000003` dlopen库(type3) | INFRA1 | 0xffffff9f（default/qemu/sim/nfs/set/adjust/test） | `0x00f8` | `0x0000` | F / infra1/2/4 | `libInfraMediaPwrMgr.so` | `InfraMediaPwrMgr_init` | **否** | **否** |
| 117 | 141 | `0x20000003` dlopen库(type3) | INFRA2 | 0xffffffdf（default/qemu/sim/nfs/set/resub/adjust/test） | `0x0102` | `0x07fb` | F / infra1/2/4 | `libInfraCameraBackground.so` | `CameraBackground_init` | **否** | 是 |
| 118 | 143 | `0x20000002` dlopen库(type2) | INFRA0 | 0x7fffffff（全比特） | `0x0258` | `0x0000` | G / main | `libBizInitializer.so` | `BIZ_Init` | **否** | **否** |

> 完整机器可读清单：`03-证据/静态分析/imdb5/imdb5_before_app_tasks.tsv`。

### 5.1 被过滤、不会在 Application 之前执行的记录

index<145 共 145 条，其中会执行 118 条、不执行 27 条。不执行的原因分类：

| 原因 | 记录 |
|---|---|
| target 掩码不匹配（qemu/nfs/set/usbj/resub/test 专用） | idx 1, idx 2, idx 3, idx 4, idx 5, idx 41, idx 121, idx 122 |
| boot 门控 g/r 未置位（B/C 内核模块段） | idx 7, idx 8, idx 10, idx 11, idx 12, idx 13, idx 14, idx 15, idx 16, idx 17, idx 18 |
| 序号分隔记录（target=0，仅作边界） | idx 6, idx 9, idx 19, idx 42, idx 44, idx 139, idx 142, idx 144 |
| 其他 | — |

> 结论：“模型实际启用”的判据就是 `target & 1（default 位）`。被 target 过滤的只有：index 1–5（其它 target 的定义记录）、41（libTestDriver，test 专用）、121/122（USB充电/USB WoLE，usbj 专用）。kernel module 组（7/8、10–18）不是 target 过滤，而是 boot=g/r 位在本启动路径下不置位。

## 6. 镜像存在性与“只存在于 libObj 导出里”的入口

### 6.1 分类统计

| 类别 | 数量 | 说明 |
|---|---|---|
| 缺失(psid=0 且镜像无此文件) | 98 | |
| 动态库(镜像内) | 69 | |
| libObj静态合并(psid!=0) | 24 | |

- 库类型记录总数：191；`psid!=0`（libObj 静态合并）：24。
- Application 之前执行的库类型记录中，镜像内存在动态库 42 条，libObj 静态合并 24 条，缺失 50 条。

### 6.2 只存在于 `libObj.so` 导出中的入口（psid!=0，共 24 条）

| idx | psid | 记录中的库 | init | libObj 导出? |
|---|---|---|---|---|
| 35 | `0x07fb` | `libInfraInput.so` | `infra_input_init` | 是 |
| 45 | `0x07fb` | `libCoreSync.so` | `core_sync_user_init` | **否（缺失实现）** |
| 46 | `0x07fb` | `libgrm.so` | `grm_init` | 是 |
| 48 | `0x07fa` | `libDDS.so` | `DDSUserInit` | 是 |
| 49 | `0x07fb` | `libuxengine.so` | `uxengine_init` | 是 |
| 50 | `0x07fb` | `libInfraIndctr.so` | `infra_indctr_init` | 是 |
| 51 | `0x07fb` | `libInfraTp.so` | `infra_tp_init` | 是 |
| 53 | `0x07fb` | `libInfraHotshoe.so` | `infra_hotshoe_init` | 是 |
| 54 | `0x07fb` | `libInfraSircs.so` | `infra_sircs_init` | 是 |
| 55 | `0x07fb` | `libInfraDial.so` | `infra_dial_init` | 是 |
| 58 | `0x07fb` | `libosal_udate.so` | `udate_init` | 是 |
| 59 | `0x07fb` | `libInfraAvbbc.so` | `InfraAvbbc_Init` | 是 |
| 60 | `0x07fb` | `libInfraMediaConfig.so` | `InfraMediaConfig_Init` | 是 |
| 68 | `0x07fb` | `libInfraEyeFiControl.so` | `InfraEyeFiControl_Init` | 是 |
| 90 | `0x07fb` | `libsensapi.so` | `senser_init` | 是 |
| 93 | `0x07fb` | `libHotplug.so` | `Hotplug_Init` | 是 |
| 95 | `0x07fb` | `libInfraCec.so` | `CEC_init` | 是 |
| 99 | `0x07fb` | `libupdater0604.so` | `udtr_senser_init` | 是 |
| 100 | `0x07fb` | `libInfraAdjMedia.so` | `InfraAdjMedia_Init` | 是 |
| 112 | `0x07fb` | `libCameraStillDate.so` | `CameraStillDate_init` | 是 |
| 118 | `0x07fb` | `libgps.so` | `gps_init` | 是 |
| 119 | `0x07fb` | `libcompass.so` | `compass_init` | 是 |
| 120 | `0x07fb` | `libgeo.so` | `geo_init` | 是 |
| 141 | `0x07fb` | `libInfraCameraBackground.so` | `CameraBackground_init` | 是 |

示例（与任务书一致）：`libInfraInput.so` 不在 `/usr` 镜像中，但 `infra_input_init` 由 `libObj.so` 导出；`libgrm.so/grm_init`、`libuxengine.so/uxengine_init`、`libDDS.so/DDSUserInit`、`libCoreSync.so/core_sync_user_init` 均为“静态合并”记录。24 条静态合并记录中，**23 条 init 入口可在 libObj 的 `.dynsym` 中解析，1 条（`core_sync_user_init`）缺失**。

### 6.3 缺失实现清单（Application 之前会执行、但当前提供的镜像内无实现）

| idx | type | stage | psid | file | init | 缺失类型 |
|---|---|---|---|---|---|---|
| 23 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libInfraInterchipDatatrans.so` | `interchip_transfer_user_init` | 库文件缺失 |
| 24 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libNVM.so` | `NVM_Initialize` | 库文件缺失 |
| 26 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libSaveLoadSettings.so` | `infra_saveLoadSettings_init` | 库文件缺失 |
| 27 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libbkdmn.so` | `BkDmn_init` | 库文件缺失 |
| 33 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libi2cuipc.so` | `i2cu_user_init` | 库文件缺失 |
| 34 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libI2CRight.so` | `i2c_right_init` | 库文件缺失 |
| 36 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libInfraError.so` | `infra_error_init` | 库文件缺失 |
| 38 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libAtn.so` | `Atn_init` | 库文件缺失 |
| 40 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libread_refresh.so` | `read_refresh_init` | 库文件缺失 |
| 45 | `0x20000001` dlopen库(type1) | INFRA0 | `0x07fb` | `libCoreSync.so` | `core_sync_user_init` | libObj未导出该入口 |
| 47 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libgpe.so` | `GpeInit` | 库文件缺失 |
| 56 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libInfraLanc.so` | `infra_lanc_init` | 库文件缺失 |
| 57 | `0x20000001` dlopen库(type1) | INFRA0 | `0x0000` | `libInfraSelector.so` | `Selector_init` | 库文件缺失 |
| 64 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libFsysPosixWrapper.so` | `FsysPosix_Init` | 库文件缺失 |
| 65 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libInfraOptionInstall.so` | `infra_option_install_init` | 库文件缺失 |
| 66 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libAiDictionary.so` | `AiDic_init` | 库文件缺失 |
| 67 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libInfraOptionInstaller.so` | `infra_option_installer_init` | 库文件缺失 |
| 71 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libmprdummy.so` | `` | 库文件缺失 |
| 72 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libdiablo.so` | `` | 库文件缺失 |
| 73 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libclema.so` | `` | 库文件缺失 |
| 75 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libmprctrl.so` | `InfraMprCtrl_Init` | 库文件缺失 |
| 76 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libMprSeq.so` | `MprSequencerIf_Init` | 库文件缺失 |
| 78 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libInfraSystemProperty.so` | `InfraSystemProperty_init` | 库文件缺失 |
| 81 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libInfraSetupFile.so` | `InfraSetupFile_init` | 库文件缺失 |
| 82 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libInfraSystemAdjust.so` | `InfraSystemAdjust_init` | 库文件缺失 |
| 83 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libInfraStillPool.so` | `InfraStillPool_Init` | 库文件缺失 |
| 84 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libInfraDatabase.so` | `InfraDatabase_Init` | 库文件缺失 |
| 85 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libInfraSalvageStatus.so` | `InfraSalvageStatus_Init` | 库文件缺失 |
| 86 | `0x20000002` dlopen库(type2) | INFRA1 | `0x0000` | `libInfraCacheMgr.so` | `InfraCacheMgr_Init` | 库文件缺失 |
| 97 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libInfraNfc.so` | `infra_nfc_init` | 库文件缺失 |
| 105 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libWiredLanResource.so` | `WiredLanResource_Init` | 库文件缺失 |
| 106 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libWiredLanAdjust.so` | `WiredLanAdjust_Init` | 库文件缺失 |
| 107 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libNetServiceEther.so` | `netserviceether_init` | 库文件缺失 |
| 109 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libInfraEthernetService.so` | `EthernetService_Init` | 库文件缺失 |
| 115 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libWirelessPower.so` | `WirelessPower_Init` | 库文件缺失 |
| 116 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libHandleRsrc.so` | `handle_rsrc_init` | 库文件缺失 |
| 123 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libInfraHdmiInput.so` | `HDMI_Input_init` | 库文件缺失 |
| 124 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libLccDaemon.so` | `Lcc_Daemon_Init` | 库文件缺失 |
| 125 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libAdjModule.so` | `AdjModule_Init` | 库文件缺失 |
| 126 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libDpro_EVF.so` | `evf_init` | 库文件缺失 |
| 127 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libInfraUpmPro.so` | `InfraUpmPro_init` | 库文件缺失 |
| 128 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libfan.so` | `fan_infra_init` | 库文件缺失 |
| 129 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libInfraUsb.so` | `InfraUsb_init` | 库文件缺失 |
| 131 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libAdjustUIProxy.so` | `AdjustUIProxy_init` | 库文件缺失 |
| 132 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libTetheringResource.so` | `TetheringResource_Init` | 库文件缺失 |
| 133 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libNetServiceTethering.so` | `netservicetethering_init` | 库文件缺失 |
| 134 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libJiritsuUIView.so` | `JiritsuUIView_init` | 库文件缺失 |
| 135 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `libJiritsuSlave.so` | `JiritsuSlave_init` | 库文件缺失 |
| 136 | `0x20000002` dlopen库(type2) | INFRA2 | `0x0000` | `BizNetTestTool.so` | `BizNetTestTool_Init` | 库文件缺失 |
| 140 | `0x20000003` dlopen库(type3) | INFRA1 | `0x0000` | `libInfraMediaPwrMgr.so` | `InfraMediaPwrMgr_init` | 库文件缺失 |
| 143 | `0x20000002` dlopen库(type2) | INFRA0 | `0x0000` | `libBizInitializer.so` | `BIZ_Init` | 库文件缺失 |

> 全表缺失清单位于 `03-证据/静态分析/imdb5/imdb5_missing.tsv`（共 99 条，其中 before-app 51 条）。`psid=0` 且镜像无文件的条目，可能位于本次未提供/未提取的 `/system`、`/rootfs` 分区，因此报告只声称“在本次提供的 `/usr` 镜像中缺失”，不声称相机运行期一定缺少该库。

## 7. 复现与产物

```
python 02-脚本/imdb5_decode.py
```

| 产物 | 内容 |
|---|---|
| `imdb5_locate.json` | 镜像/文件定位证据：字符串命中、块映射、文件 SHA |
| `imdb5_header.json` | imdb_raw 头（tag、31 个 target 名槽位） |
| `imdb5_records.tsv` | 全部 228 条记录：字段、执行阶段、提供者、执行判定 |
| `imdb5_before_app_tasks.tsv` | Application 之前会执行的任务顺序清单 |
| `imdb5_providers.json` | 逐条记录的镜像存在性/提供者/符号可解析性 |
| `imdb5_execution.json` | im.elf 静态执行模型与逐条执行判定/跳过原因 |
| `imdb5_missing.tsv` | 缺失实现清单（全表 + before-app 标记） |
| `imdb5_summary.json` | 汇总统计/哈希（本报告数据源） |
| `imdb5_libIMDB.so / imdb5_libObj.so / imdb5_im.elf / imdb5_bootin.elf / imdb5_appFwBoot.so` | 从镜像只读提取的关键件副本（SHA 见 imdb5_copies.json） |
| `imdb5_decode.log` | 脚本运行日志 |

## 8. 限制与未决

1. 本次提供的镜像集只有 `nflasha15`（/usr）与 `nflasha7`（raw，非文件系统）；`/system`、`/rootfs` 等分区不在包内，因此 `psid=0` 但 `/usr` 无文件的 98 条库记录（其中 Application 前会执行 50 条）不能断言“相机运行期缺失”。
2. “Application 之前执行”是依据 `im.elf` 静态控制流 + `bootin.elf` mode3 参数拼接的静态推演；没有真机 `strace`/QEMU 运行验证。若启动参数为 `bootall` 或显式 `boot=g/boot=r`，B/C 段会额外执行。
3. `libObj.so` 导出符号统计基于 `.dynsym`；不排除运行期由其它已全局加载库补足个别入口的可能，但已对镜像内 199 个 `.so` 的 `.dynsym` 做交叉检查，未发现可补足者。
4. 记录中的 `me`/`psid` 字段命名沿用 im.elf 调试打印（`.me=0x%04x .psid=0x%04x`）；`psid!=0` 的判定来自 `im.elf` 加载分支（`[rec+0xe]` 非 0 时库类型走 `/usr/lib/libObj.so`、Application 类型走 `dlopen(NULL)`）。

