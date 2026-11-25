# 97_abi · ASTRA 独立 ABI / 加载链审查

审查日期：2026-11-22（本地 UTC+8）。范围：95、96任务书、全部 `astra_*` 脚本、两机原始 ext2 `/usr`、a6600 rootfs、Windows 可读的 WSL `/root/astra/stage`。本审查没有运行 QEMU、没有访问真机、没有修改原库、现有镜像或启动脚本。只在 `97_abi` 证据目录生成提取件与一个新 IMDB 实验变体。下述运行建议交由主线程执行。

## 1. 对主线方案的结论

1. **95 的“全部导出并集”不能证明 ABI 闭包通过。** 它同时合并了四代、五代同名库，且纳入所有未加载、未部署的库。`astra_plan_lite.py` 反而按“同名存在就复用四代”，`astra_stage_libs.py` 只携带少数五代库。三者的假设不一致。
2. **直接替换五代 libIMDB 不等于执行 ASTRA。** IMDB 是任务数据库；四代 `im.elf` 首先通过 DT_NEEDED 加载它，然后解释数据库，按记录类型选择 `dlopen(NULL)`、固定 `/usr/lib/libObj.so` 或数据库库名。五代数据库改了大量硬件任务与阶段标记。
3. **不能全局替换 libObj/libmpr 后仍期待原启动链不变。** 四代 libObj 是合并了多项底层初始化入口的包；五代 libObj 不是等价替代。旧任务表至少有六个原来能解析的前置 init 在新 libObj 中消失。
4. **最小路由修改是保留四代 im/IMDB/bootstrap，只改 Application 一条。** 已生成独立 IMDB 副本，等长名字 `astra.so`，指向专用桥或原始五代 appFwBoot 的别名。它只改路由，不声称实现了 ABI 隔离。
5. **有意义的同进程五代加载需要确定的提供者闭包。** 五代私有文件名/SONAME 与四代区分，再显式建立 `appFwBoot/appFw → 五代 libObj/libmpr/其它必需库` 依赖边。仅改文件名、设置 LD_LIBRARY_PATH、或 RTLD_DEEPBIND，不能证明同名 C++ 符号绑定到五代。
6. **补齐五代root的真实STM库后，剩六个强未定义符号。** 未带五代root时为七个；`stm_system`已有原始实现，不应写shim。其余六个精确参数身份已恢复；多数返回类型、结构布局、操作语义尚无充分证据。未写任何未知函数 return0 shim。

## 2. 输入身份和复跑

原始镜像 SHA-256：

| 输入 | SHA-256 |
|---|---|
| a6600 nflasha15 | `ed67fdb22a5f3254e761237fc2479d4fcaf4fc6d11c30ab4acb6ab6e7b5767fc` |
| ZV-1M2 nflasha15 | `10db74fba126b572071387eecfc2408df8869e7c9e9e8d146528bb104dde408b` |
| a6600 nflasha7 | `6bc8802e44686f4d8bf9158e7a8fa496a019a57c281564204bf714d5bb55ced9` |

`03-证据/静态分析/97_abi/inputs.json` 保存完整路径。每个 ELF 的实际字节 SHA、SONAME、DT_NEEDED、动态符号 bind/type/visibility/value 都在 `inventory.json`。stage 是审查开始时的可读快照；主线程后续构建不在这些静态数值内。

复跑命令（Windows Python，pyelftools/capstone）：

```powershell
python 02-脚本/97_abi_audit.py
python 02-脚本/97_abi_entries.py
python 02-脚本/97_abi_startup.py
python 02-脚本/97_abi_scope.py
python 02-脚本/97_abi_calls.py
python 02-脚本/97_abi_patch_imdb.py
```

反汇编证据由 WSL 的 `arm-linux-gnueabi-objdump -d -M force-thumb <证据目录ELF>` 生成。目标代码没有被执行。静态结果以字节身份确定性复核，不把它冒称96任务书要求的两次运行时复现。

## 3. 并集算法掩盖了什么

原脚本 `astra_symbol_diff.py` 的 `combined = all_provided | zv_exports | root_exports` 完全不检查：

- 哪个同名 SONAME / 文件会被动态加载器实际选择；
- 未定义项是强符号还是弱符号；
- 该提供者是否在 DT_NEEDED 闭包或已加载的全局作用域内；
- C++ 类型布局、对象所有权、TLS、异常、单例状态；
- 符号版本与装载顺序。

两代 `/usr` 共有 **153 个同路径而字节不同的 ELF**。`collisions.json` 对每项列出 SHA 和两边独有导出；这是同路径冲突清单，不能把153直接理解为153个必然出错的 SONAME。

即使把“a6600 文件被 stage 同路径覆盖后，全部仍可用库”的导出再做最乐观合并，五代目标库仍有：

| 五代消费者 | 全部实际可用 mixed 库并集仍缺强符号 | 完整五代库并集仍缺强符号 |
|---|---:|---:|
| appFw.so | 29 | 2 |
| libObj.so | 11 | 2 |
| libmpr.so | 13 | 3 |
| appFwBoot.so | 0 | 0 |
| libIMDB.so | 0 | 0 |

29+11+13 = **53 个消费者-符号引用项**。其中 **46 项**由未携带的五代库导出，被95的跨代并集掩盖。它们不是可据此直接写 shim 的46个新函数。`hidden_by_union.json` 逐项给出消费者、名字和五代实际提供者；`scope_bounds.json` 保存各组全清单。

更严格地只取 `im.elf + appFw + Obj + mpr` 种子与 DT_NEEDED 闭包，mixed 场景选中44个不同字节 ELF，出现81个强未解析引用项。这里包含其它被混代破坏的消费者（例如四代 libmprctrl 的16项），**不是运行时最终错误数**；原程序还依赖 IMDB 按序 dlopen 的全局提供者。完整五代目标闭包也存在未显式声明的全局依赖，不能用151项结果反称五代原厂也不能运行。

## 4. im.elf 真正加载哪一个库

### 4.1 DT_NEEDED 与数据库解释是两层

四代 im SHA：`ab7eed01e7ac204f555298bdfd13c0ffa89b34d1f1cd399bd74ad734ede8d93e`。

其 DT_NEEDED 包含 `libIMDB.so`、jemalloc、OSAL、backup、标准库；**没有 appFw.so / appFwBoot.so / libObj.so**。所以 LD_TRACE_LOADED_OBJECTS 只能确认这层，不会执行 IMDB 的后续 dlopen，也不会证明 ASTRA 入口执行。

五代 im 新增 `libSTMcmdexecute.so`、`libssl.so.3`、`libcrypto.so.3` 等 DT_NEEDED。直接换五代 im/bootin 不是最小变更；当前 stage 无这些新增依赖的完整承诺。

### 4.2 四代 im 的真实分派规则

在 `a6_im_thumb.txt`：

- `0xb40c–0xb416`：类型 `0x20000001/02/03` 调用 `0xb200`；
- `0xb41c–0xb422`：类型 `0x20000004` 调用 `0xb14c`；
- 两类都读取记录 `+14` 的16位值。

| 类型 | +14 为0 | +14 非0 |
|---|---|---|
| 0x20000001/02/03 | dlopen(record+16库名) | dlopen(`/usr/lib/libObj.so`) |
| 0x20000004 Application | dlopen(record+16库名) | dlopen(NULL)，从全局对象找入口 |

固定 `/usr/lib/libObj.so` 字符串在 im VA `0xc332`。`+20` 指向入口名，交 dlsym。

不能把 Application 也误写成固定 dlopen(libObj)：它实际走 dlopen(NULL)，通常再由已全局加载的 libObj 提供该符号。区分这两条分支是本审查的关键。

### 4.3 两代 Application 记录

记录固定 **44字节**。IMDB_get_entries 返回 `imdb_raw+132`；IMDB_find_entry 按44步进；类型40为终止项。两代 API 形状相同，内容不同。

| 字段 | 四代第123条 | 五代第145条 |
|---|---|---|
| 记录 VA | 0xf0f8 | 0x1097c |
| type | 0x20000004 | 0x20000004 |
| target mask | 0xffffff9f | 0xffffff9f |
| word+12 | 0x07fb0083 | 0x00000083 |
| +14半字 | 0x07fb | 0 |
| +16库名 | appFw.so | appFwBoot.so |
| +20入口 | Application_System_Init | Application_System_Init |
| +36/+40 | AdjChkConfig.so / AppConfig.so | 同左 |

原表有198条（含终止），五代表有228条。五代新增硬件/网络任务，还将后段阶段项6/7/8改为带 `0x08000000` 的阶段编号并新增阶段；本审查没有证明旧 im 对全部新标记语义等价。因此整表替换不是保守入口实验。

四代 Application 之前，至少六条原本由旧 libObj 提供的 init 在五代 libObj 不再导出：`infra_lanc_init`、`Selector_init`、`InfraStillPool_Init`、`InfraDatabase_Init`、`InfraSalvageStatus_Init`、`InfraMediaPwrMgr_init`。这些条目仍有 target 条件；它们是明确的替换风险，不能据静态表直接断言本次运行必达。

### 4.4 init / shell 不是 IMDB 解释器

提取的四代 init 含 `/usr/bin/bootin.elf` 与 `/usr/bin/launch_shell.elf` 路径。launch_shell 没有 IMDB 导入，只含 shell/reopen/execv 等逻辑及 `/bin/ash --login`。bootin 则包含 `im.elf`、`target=qemu`、`lazy-global`、`LD_PRELOAD`、`Bb fork_imelf()`/`Bb system()`等启动证据。没有 im 进程时，应按 init→bootin→system(im)分别定位；不可只凭该现象推断“libIMDB解析失败”。

## 5. ASTRA 原生入口契约

五代 appFwBoot SHA：`187b335c5d59ebb581ef24eee2b8a92bdfce1af61ce7298e8466e645a6cdbe5e`。

`Application_System_Init` 在 VA `0x1270`（Thumb symbol值0x1271），284字节。

四代 im 的 type4 入口调用在 `0xb1c4/0xb1c8` 按模式选择记录+36或+40作为 r0，在 `0xb1d0` 调入口，返回值不作业务判断。appFwBoot 保存 r0，再把它作为字符串与 `AppConfig.so` 比较。因此最窄调用声明可写：

```c
typedef void (*application_system_init_fn)(const char *config_so);
```

这里 `void` 表示调用方忽略返回值的安全调用形状，不能用它断言源代码的实际返回声明。

boot入口逻辑：

1. config==NULL 或等于 `AppConfig.so`：dlopen(`appFw.so`,0x101)，dlsym(`Application_Start`)；
2. 其它配置：dlopen(`AdjChkConfig.so`,0x101)，dlsym(`_ZN13app_adjchk_ui9main_loopEv`)；
3. 创建 OSAL 等待线程，线程函数 `_Z4MainPv` 接收上述函数指针；
4. Main 调 `uxengine_init2`、arena初始化、设置 `/usr/share/app/`、区域检查资源、加载 `global.xdb`、字体命名空间，最后调用应用函数。

appFw 的 `Application_Start` 是真实公开导出，VA `0x54d580`（Thumb symbol值0x54d581），72字节；进入立即重写 r0，未读取外部传参。boot::Main 也是按不传业务参数的函数调用。可用调用形状为 `void (*)(void)`，但不应绕过 boot 的 UX 初始化直接调用它来冒充完整原生入口。

boot的非root强导入由五代 libObj（20项 UX/Libra/stella）以及 OSAL（5项）提供；它自己的 DT_NEEDED 却只有标准库。appFw同样没有显式 DT_NEEDED libObj/libmpr。**这说明它们原本依赖 IMDB 建立的全局加载顺序。**

五个OSAL符号在两代均存在：`osal_set_cpu`、`osal_create_waitable_thread`（libosal_utm），`osal_valloc_msg_wait`、`osal_snd_sync_msg`、`osal_free_msg`（libosal_uipc）。首轮桥可优先共享四代OSAL；符号存在不证明内部结构/回调/TLS语义已兼容。

## 6. 已生成的最小 IMDB 路由实验件

产物：`03-证据/静态分析/97_abi/97_abi_libIMDB_appboot.so`。

- 输入旧libIMDB SHA：`05793f4e8b5b81fbb534953c1164788151d57b13d520158b89a3d1329d59518e`；
- 输出 SHA：`e503cb7061b06e5abed7d7abd093b4b7b0bf21d1b93fb4e2818247599e4371b5`；
- 文件长度、ELF头/段/节、所有REL重定位不变；
- 四代 Application 第123条 fileoff `0x70f8`；`+14` 即 `0x7106` 从 `fb07` 改为 `0000`；
- 名字指针原值0x496f不变，在 fileoff `0x496f` 将8字节 `appFw.so` 等长改为 `astra.so`；
- 只有六个实际字节发生变化，其它记录全部字节相同。

加载要求：将专用桥或原始五代 appFwBoot 另存为 guest `/usr/lib/astra.so`。若采用后者，别名文件的 SONAME 仍是 appFwBoot.so，这不是错误，但它仍缺乏私有依赖闭包保证。**不要把12字节 appFwBoot.so 直接覆盖原8字节字符串；那会破坏后邻字符串。**

本件未写入任何镜像。完整断言与差异清单在 `97_abi_imdb_patch.json`；生成器 `97_abi_patch_imdb.py` 先断言输入SHA、记录类型/ID/指针，再写新文件。

## 7. 最小隔离加载方案与主线程提案复核

建议采用两层、一次只证明一个层次：

### 第一层：保持bootstrap，用单条Application桥证明调用到达

保留原 im、bootin、旧 IMDB（仅上述单条patch）、四代 libObj/libmpr/OSAL/硬件链。`astra.so` 应记录收到的 config 与 dlerror，并在失败时明确返回/报告失败；不得伪造未知真实函数的成功。此步即能区分“Application根本没走到”“dlopen失败”“已进入五代boot”。

### 第二层：给五代建立实际私有闭包

主线程提出的等长私有文件名/SONAME（如 `libObj.so→a5bObj.so`）可避免加载器按旧同名映射复用四代文件，值得作为可控实验。但它还必须满足：

- 每条五代 Sony DT_NEEDED 都选定唯一代际；不要把所有同名索尼库当作可复用；
- appFwBoot 与 appFw 对五代 Obj/mpr 的关系是显式依赖或等效的闭包，不是“曾dlopen过就算依赖”；
- 单独先 RTLD_GLOBAL 加载 a5Obj，不能保证后续重定位优先于更早全局四代 ux/libra 符号；
- RTLD_DEEPBIND只改变当前查找范围内优先级，不替你添加缺失的依赖边，也不是独立链接命名空间；
- boot内部嵌套 dlopen(appFw)会再建立查找组，必须独立检查其提供者；
- 同进程共享一套 root libc/libstdc++/libgcc/OSAL，明确五代对象与旧bootstrap边界；不要未经核验创建第二套pthread/OSAL单例。

如需强隔离，应另评估新链接命名空间或独立进程及IPC边界；它们会引入第二套libc/TLS/状态或无法继承IMDB初始化的实际问题，本审查不把它们包装成“一行dlmopen即可”。对当前最小运行实验，私有SONAME+显式依赖边+提供者核验比全量替换更可诊断。

加载验证阶段应选择 RTLD_NOW。boot原始 `0x101` 为 LAZY|GLOBAL；加DEEPBIND变 `0x109` 仍LAZY；若要 NOW|GLOBAL|DEEPBIND 是 `0x10a`。LAZY的dlopen成功不能证明全部强函数符号已消除。

## 8. 六个真实强缺口与一个已找到原库的符号

下表最初七项是在“完整五代/usr库+四代root标准库”的可见导出并集中仍缺的符号。后续补扫五代root后，`stm_system`由原始 `libSTMcmdexecute.so`提供，真正剩六项。不把库中未定义弱 `_Jv_RegisterClasses` / `__gmon_start__` 计入。弱符号正常可以未定义为0，不必先做两份空stub。

| 消费者 | 精确身份/参数 | 不能凭空假设的部分 |
|---|---|---|
| libObj | C符号 `arch_phys_to_cache` | C名不编码参数/返回；不可直接假定恒等映射或返回0 |
| libObj | C符号 `stm_system`（已找到原库） | 真实root库导出VA0x829、164字节；调用点传r0程序路径/r1 argv/r2参数数量/r3选项，并消费wait状态，不能换成libc单参数system |
| appFw | `infra_wrapper_imaging::detail::set_user_matrix(const set_user_matrix_in_t&, set_user_matrix_out_t&)` | 返回类型不在普通C++函数mangle里；in/out结构布局和输出语义未证 |
| appFw | `infra_wrapper_bb::detail::adf_ext_type(const adf_ext_type_in_t&, adf_ext_type_out_t&)` | 同上，不能用空输出/返回0假装成功 |
| libmpr | `GpsMgr::SetAllInvalidDefStrGpsInfo(DefStruct::GpsInfo*)` | 返回类型、是否静态成员、GpsInfo实际大小/无效哨兵值未证 |
| libmpr | `std::basic_regex<char,std::regex_traits<char>>::_M_compile()` | this对象/旧STL布局和异常语义未证；不能把无操作当作编译成功 |
| libmpr | 返回bool的 `std::regex_search<...>(normal_iterator<const char*,std::string>,同型迭代器,match_results<...>&,basic_regex<char,...> const&,std::bitset<11>)` | 这是带旧bitset参数的具体模板ABI；不能拿现代不同签名的regex_search或POSIX regexec直接顶替 |

精确 mangled 字节名字在 `union_missing.json`；完整 demangle 在 `true_missing_demangled.json`；静态调用附近指令在 `true_missing_calls.json`。后者使用实际 ARM PLT 指令计算 GOT 地址再关联 REL，**没有假设REL顺序等于PLT顺序**，并处理Thumb interworking veneer和ARM PIC长跳板。最终六个剩余符号都有原始调用点证据（wrapper需经长跳板）：adf_ext_type为0x2b1575a→0x2ba1568→PLT0x52a914，set_user_matrix为0x2b19ea4→0x2ba0f7c→PLT0x52932c。两个外层封装保存并转交r0/r1，前后trace组/号分别(0,0x58)/(0xa,0x122)，丢弃目标返回值；这不能替代out结构的正确写入语义。

此外，“无GLIBC_2.4以上版本需求”只消除一类版本标签门槛，不证明libstdc++、内核接口或Sony ABI等价。依赖齐全也必须指实际部署闭包齐全，而不是原固件某处存在。

## 9. 五代root非/usr依赖补查

主线程在真实桥路径中报告 `libSTMcmdexecute.so` 缺失后，本审查补扫五代 nflasha7。根镜像SHA `9abb66b5436c3147b10a7f4a770897f0ddfc54f45f4820128851f7a315c427d1`。

以 appFw/Obj/mpr/Boot/AdjChk 为种子，选择五代usr、复用a6600已有root标准路径，再查五代root，**唯一新增root库是 `/lib/libSTMcmdexecute.so`**：4688字节，SHA `aabdecd5a624e8397ef78cd5cb4c0b4d58ad71d72b86b9f307e01488751cfb9a`，仅依赖pthread/stdc++/m/dl/gcc_s/c/rt。版本要求仅 `GLIBC_2.4`、`GCC_3.5`，没有新增递归库。已提取为证据 `zvroot_libSTMcmdexecute.so`。ssl3/crypto3不是这组ASTRA种子的额外需求；它们属于换用五代im时才需要另解的路径。

该库真实导出 `stm_system`（Thumb VA0x829、164字节）、stm_popen、stm_pclose。libObj七个调用点使用路径/argv/参数数目/选项并检查wait状态；原库使用fork/execve/waitpid/pipe等。携带这个真实实现优于任何凭名字写出的system转发shim。证据：`gen5root_required.json`、`gen5root_export_witnesses.json`、`zvroot_stm_thumb.txt`。

## 10. 最小共享旧USB/网络边界

针对主线程随后报告的 `a5bInfraUsbCmn.so: PTPT_fin`，静态逐边核对：

- 五代 UsbCmn 的 PTPT_init/PTPT_fin 并非其DT_NEEDED中提供；五代实际提供者是 libInfraPtpControl；
- 五代 PtpControl 却再依赖10个 PTPT_*_ip，它们不在五代用户态动态导出中，而四代PtpControl内部自带这些实现；
- 因此加五代PtpControl只是把缺口向后推。若ASTRA验证不需要替换USB服务，应优先共享旧USB边界。

符号层已证覆盖：新Obj使用UsbControl的25项强符号，旧库全有；新UsbControl使用UsbCmn的2项、sencore使用UsbCmn的3项，旧库也全有；新Obj/appFw使用backup分别11/14项，旧库全有。最小候选共享组是旧 UsbControl、UsbCmn、backup，并在NOW闭包需要时带入**真实旧PtpControl及其旧ptp/MWF/OSAL链**。PTP/USB有回边，应同组建立依赖；不要一边NOW单独加载而缺另一个方向的符号。

共享意味着将私有五代消费者的这些DT_NEEDED边指回原名旧实例；不应再复制旧文件成a5私名，制造第二套USB/backup单例。`boundary_coverage.json` 给出每个使用符号、旧/新定义大小、类型、SHA。C名字不编码完整签名；同名C++参数mangle也不等于对象布局相同，故此处只证明符号层覆盖，不是行为ABI担保。

已证明不能简单退回旧库的直接边：

| 五代消费者→服务 | 旧库缺失 |
|---|---|
| Obj→InfraMediaCommon | mcmn_addr_clr/set、mcmn_drv_getpartinfo/getrealname/registcallback/unregistcallback、mcmn_misc_getrandom |
| Obj→util_date | date_time_add_subseconds |
| appFw→NetCommon | NetCommonLibrary_::NetServiceWrapperForApConnection::InitCmd(unsigned int) |
| appFw→GOConnectionManager | GetMacAddress(char*,unsigned int)、GetBSSID() |

原生Boot本就是LAZY；保留LAZY+DEEPBIND、无假实现地观察实际首次调用，是有意义的路径诊断，但**不能将其记作全符号闭包或ABI已通过**。这与用NOW一次列出所有冷功能缺口是两个不同实验。

## 11. 六个剩余名字的全镜像检索与内核映射语义

另扫五代usr的49921个普通文件、root的136个普通文件（含bin/sbin、kmod/LIRO），同时检查dynsym和symtab，六个名字没有可见ELF定义。五代im也没有提供这些动态导出；原固件现有libstdc++也不导出那两个具体regex实例，不能仅换入它便视为已解决。

nflasha3尚未在原提取目录展开，因此从原firmware.tar只读解析FAT12，不改原目录。该系统镜像SHA `a9f44334b61fba73ce39f5fc24e3e022430b0d44910bcdf2d5c4d3cf4ea0e332`；其中AV-CAM.BIN 17195164字节，SHA `3a1aeecbbe9f7a3e30f808f804f00dac920a16bf1a2e93ae036a087d8262c279`，未发现六个名字的明文。名字未出现不能排除无符号/编号化功能实现。

VMLINUX.BIN（SHA `fc6009d3a77057a56abf543c6882f905c447c5b7075d7b70ac55b533e57bad94`）则确有 arch_phys_to_cache 导出。内核映射base为0x60108000：导出记录file0x32b588含 `{0x6011f21c,0x6043ae25}`，后者映射到file0x332e25的精确名字；函数file0x1721c。独立的错误格式/函数名literal也按此base正确映射，非凭邻近名字猜函数。

原始ARM实现的条件：

- pa==0受运行时BSS字0x604b3540控制，可直接返回0；
- 其它或未提前返回的pa，若 unsigned pa<0x40000000，返回 pa+0x60000000；
- 否则若0x80000000≤pa<0x90000000，返回 pa+0x20000000；
- 其它地址打印 `ERROR:%s:pa=0x%08lx`，按运行时BSS字0x604b3544选择诊断/panic，非panic分支返回0。

边界表原值在0x60495c20：40000000、90000000、a0000000、b0000000、ffffffff。调用/实现都支持单个32位地址参数→r0地址返回；printf的%lx支持ARM32 unsigned long解释，但源级类型仍为推断。

**这是真实内核缓存别名算法，不是用户态地址映射许可。** 不能将它做成恒等映射，也不能因为数值规则已知就假设用户进程能解引用0x60000000/0xa0000000区域；用户态是否应走DMM mmap/ioctl仍待证。未输出该函数的shim。完整可复跑证据在 `archphys_kernel_evidence.json`、`archphys_kernel_disasm.txt`，生成器 `97_abi_archphys.py`。

## 12. 主线程下一轮最有区分力的证据

1. 记录 im 的启动命令和退出码，再把 LD_TRACE 与实际执行分开。
2. 在唯一Application桥记录 config、dlopen绝对目标、flags、dlerror；既检查到达又检查加载。
3. 在五代boot `Application_System_Init` 与 appFw `Application_Start` 两个地址分别观察到达，不以maps中出现库替代入口到达。
4. 核对每个五代UX/Libra导入实际绑定的提供者文件/代际；必须能反证它不是旧libObj。
5. 真缺口按完整mangle逐项记录；没有语义与原型证据就保留明确失败，不扩散return0 shim。

所有建议均由主线程在隔离QEMU覆盖层执行。本分支没有做运行期成功声明。
