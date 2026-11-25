# 92：MENU / ENTER View 消费与 NTSC 提示（独立只读静态分析）

未启动 QEMU，未修改任何既有源文件；仅新建 92_menu_consumer 前缀分析文件并从原始 ext2 提取配置 ELF。

## 可直接用于主线程验证的结论

- 输入逻辑基码：MENU `0x15010100`，ENTER `0x15010050`（物理映射由另一分析者确认，本报告不重复）。
- `InputService::callback_convert(int, _InfraInputEvent*)` 是最小完整 native 输入入口，函数指针为 `libObj load_bias + 0x3d2fb1`；它转入 `0x3d2eb8`。参数 `r0=0`（callback id），`r1` 指向至少 24 字节 `{uint32 event_code, reserved, status, data, value, repeat}`。对 ENTER / MENU，使用 `{base_event,0,1,0,0,0}` 按下，再 `{base_event,0,0,0,0,0}` 释放。
- `changeTactStatus` @libObj `0x3cfa20`：raw 0→1，raw 1→2，raw `0x7fffffff`→5，raw `0x7ffffffe`→6。`callback_convert` @`0x3d2f38..52`：转换结果1→base+1，结果2且+0x14=0→base+2，结果2且+0x14!=0→base+4。因此上述完整边沿产生 ENTER `...51/...52`、MENU `...101/...102`。不要把带边沿的 functional event 再作为 base 重复转换。
- 此入口自行创建 native Event(dest=4)、附 Int 参数32（来自输入+0x10），调用 `pushFilterEvent`。普通 pthread 调用；不要从 SIGALRM 等异步信号处理器调用。
- 另一完整入口 `callback_direct` 为 `libObj+0x3d2ea7`；同样传24字节结构，但它保持 event_code 原样，附参数27=输入+8、28=输入+0xc、32=输入+0x10（均原厂整数参数对象），再 pushFilterEvent。它不是 callback_convert 的等价边沿编码接口，不建议把 direct / convert 契约混用。
- 主线程已另行报告：普通 pthread 先 ENTER 后 MENU，经 callback_convert 已实际打开原厂中文设置菜单；此处只记录为主线程动态验证，不冒称本分析者运行。

## NTSC 提示确切消费者

`viewUnified2.so` RTTI `N11DefRootView17ActionNtscCautionE` 字符串文件/VA `0x683001`；typeinfo VA `0x8e9408`，vtable execute `0x2aee8d`。

`ActionNtscCaution` 指令 `0x2aee8c..2aeef6` 读取 backup `0x01070148` 和 `0x010704fd`，条件满足时调用根 View 的 setCautionTrigger：NTSC 对应 trigger `0x089e`，另一制式条件对应 `0x0e87`。这不是 `ViewNtscPalSEL_D`（那是设置里的制式选择确认页）。实际提示消费者为 `ViewCaution`，工厂 `ViewCautionToInstance=0x664f2b`，分配0x16c字节对象。

从原始 a6600 nflasha15 提取：

- `/lib/CautionRsrcConfig.so`，本地 `92_menu_consumer_CautionRsrcConfig.so`。
- subtype `5WAY_M_R` 的 `m_caution2RsrcIdTbl` VA `0x75b0`，12字节/项，`[0x89e]` VA/file `0xdd18` = `{0x000e0040,0,9}`。
- `m_rsrcTriggerTbl_5WAY_M_R` VA `0x1e010`，28字节/项；资源 `[0x40]` VA `0x1e710`、文件 `0x16710` = `{0x5e38,0,0,0,1,0,0}`。offset +0x10 的呈现/交互类型为1。
- 注意该 ELF 第二LOAD的 VA 比文件偏移大0x8000，不能把上述VA直接当文件偏移；这已在最终记录中校正。

`ViewCaution` 类型1路径：

1. `0x666b2e..0x666bee` 检查当前 caution resource 的 byte+0x10 ==1；`0x666c20` 包装为 checker12。
2. `ViewCaution` transition dispatcher `0x666da4`，初始状态0的 `0x666e16..24` 调 checker12，置 state=3。
3. 状态→trigger函数数组 VA `0x94998c`、文件 `0x94198c`；state3=`0x663a71`。`0x6645a4` 按当前state索引该表并调用 `View::requestTriggerTable`。
4. 状态3 trigger `0x663a70`：ENTER functional press `0x15010052` 在 `0x663a8c..90` 比较命中，跳 `0x663b66` 返回 local event3；ENTER release `0x15010051` 返回 `0x11012004`。
5. 状态3 transition `0x6671dc`，`0x6671f8..1fc` 比较 local event3，跳 `0x66732e` 写 action10。
6. action dispatcher `0x6667c6` 的 action10 TBH 目标=`0x666874`，跳 `0x665c20`。`0x665c20..36` 调 `SvcCautionIF::GetHitCaution(1)`，再以 `{this,current_id,false}` 调 setCautionTrigger，清除当前提示。

所以：NTSC提示确实有明确的 ENTER 按下确认路径；MENU不是这个提示的确认键。MENU在提示状态3经默认trigger链，不产生local event3，因此不能代替ENTER清提示。不要从“MENU未打开菜单”反推物理键或驱动未发送。屏蔽/透传的完整默认策略依赖通用trigger链，本报告不把所有MENU分支都粗称为同一返回值。

## 最小完整调用契约

```c
#include <stdint.h>
typedef struct { uint32_t code, reserved, status, data, value, repeat; } InfraEvent;
typedef void (*cb_t)(int, InfraEvent *);
// 使用dlsym("_ZN12InputService16callback_convertEiP16_InfraInputEvent")，或已确认load_bias+0x3d2fb1。
// 仅普通线程，在libObj及InputService完成初始化后调用；不是signal handler。
static void edge(cb_t cb, uint32_t base, uint32_t raw) {
    InfraEvent ev = {base, 0, raw, 0, 0, 0};
    cb(0, &ev); // 同步复制/转换输入，不保留栈上的ev指针。
}
// edge(cb,0x15010050,1); delay; edge(cb,0x15010050,0);
// 等待提示完成关闭后，再MENU完整按下/释放。
// edge(cb,0x15010100,1); delay; edge(cb,0x15010100,0);
```

初始化至少检查导出单例 `_ZN12InputService13m_pMyInstanceE` 指向非NULL（该符号存储槽在libObj VA `0x13f5e6c`）；非NULL只是必要条件，UI/当前View ready仍需主线程自己的状态判据。所有函数指针Thumb +1；断点PC用偶数地址。不得复用旧运行的绝对映射基址。

## 如需直接原厂队列注入

优先以上callback_convert，它已完成准确的边沿编码、Event创建、参数构造和原厂过滤。

- `InputService::createEvent(unsigned long,unsigned char)` @libObj指令 `0x3cfaea`，成员调用 `r0=self,r1=eventId,r2=4`，返回 native `Event*`，对象16字节。它只创建Event，不自动附输入状态参数，也不自动push。
- `InputService::pushFilterEvent(Event*)` @`0x3d1818`，成员调用 `r0=*m_pMyInstance,r1=Event*`。锁原厂InputService filter，过滤并交服务批队列；Event所有权转交，不得栈分配或自行释放已push对象。
- direct路径的最小完整参数：Int parameter27=raw status，28=data，32=value；原厂分配20字节整数参数对象，ctor `0x3457a4`（函数指针+1），以 `Event::addParameter(unsigned long,ParamBase*)` 加入。
- convert路径的最小完整参数：eventId已按raw0/1转换为base+1/base+2；Int parameter32=value即可。更稳妥仍是调用callback_convert，不手造C++对象。
- 原厂最终通用队列另有导出 `EventManager::push(Event*,bool)` @libObj `0x842a89`，但需要真实EventManager对象且会绕过InputService过滤。此处不建议从未知this或假造对象直接调用。

## 已落盘复核证据

- `92_menu_consumer_trigger_paths.txt`：只对纯trigger比较代码做静态常量传播，明确记录 ENTER51→11012004、ENTER52→3；不是运行固件。
- `92_menu_consumer_tools.py` / `92_menu_consumer_dis.py`：定点Capstone反汇编，可重生上述指令。
- `92_menu_consumer_scan.txt`：字符串/常量初筛。

限制：纯静态不能保证任意时机调用callback时UI已就绪；主线程已有普通pthread实测应优先采用。未追物理映射或driver sender。
