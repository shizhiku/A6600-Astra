# 18 · liro.ko 线程结构分析（进行中）

本轮只分析本地 `03-证据/静态分析/liro-fault-static/liro.ko`，未访问相机、未运行固件。

## 已确认

### 1. liro.ko 的代码是 ARM 模式，不是 Thumb

初次用 Thumb 反汇编得到的全是乱码；按 ARM 模式重新反汇编后指令连贯（`stmdb sp!,{...}`、`bl`、`ldr rX,[pc,#imm]` 等）。

这一点很重要：此前对 av-cam（Thumb）与 liro（ARM）必须分别处理，混用会导致错误结论。

### 2. 模块内有两处内核线程创建

两处都调用 `kthread_create_on_node`：

| 位置 | 线程函数 | 线程名格式串 |
|---|---|---|
| `.text+0x3E4` | `thread_resume` | `liro-RESUME` |
| `.text+0x5AC` | `thread_resume` | `liro-RESUME` |

即这两处创建的是 **挂起/恢复相关线程**，不是崩溃所在的 `liro-kliro_66`。

### 3. `kliro_%d` 字符串确实存在，但加载点未定位

- 字符串位于 `.rodata.str1.1+0x6A8`。
- 引用该节的重定位中，只有一处就地加数等于 `0x6A8`：`.text+0x23C4`。
- 但 `0x23C4` 处在**字面量池**里（相邻池项为 `0x780`、`0`），不是指令。

尝试过：
- ARM 模式全字节 `ldr rX,[pc,#imm]` 扫描（含跳过数据区与不跳过两种）；
- Thumb 模式同样扫描。

**都没有找到**计算目标为 `0x23C4`/`0x23C0` 的加载指令。说明加载方式不是简单的 PC 相对字面量加载，可能经过 `add rX, pc, #imm` 再解引用、或经 `R_ARM_REL32` 等重定位间接寻址。

## 尚未确定

- 创建 `liro-kliro_<n>` 线程的代码位置与其线程函数。
- `kliro` 线程的职责（它为什么会在启动早期就跑到那段“等待 → 30 次重试 → 报错”的路径）。
- 运行时观测到的线程名是 `liro-kliro_66`，说明存在按索引编号的 kliro 线程集合；索引 66 的含义未知。

## 下一步

1. 用重定位驱动的方式定位 `0x23C4` 的加载点：解析所有 `R_ARM_REL32` / `R_ARM_ABS32` 重定位，找出指向该池项或跨节引用的代码。
2. 若仍不成功，改从运行时入手：在模拟器中对 `kthread_create_on_node` 的调用点设断点，捕获实际传入的名字指针与线程函数地址，直接得到 kliro 线程的真实函数体。
3. 拿到线程函数后，再回溯它调用的 av-cam 入口与等待逻辑。

## 记录

- `03-证据/静态分析/liro-fault-static/liro-thread-name-refs.json`：字符串与重定位定位结果
- 脚本：`02-脚本/find_liro_thread_creator.py`、`find_liro_thread_ref2.py`、`resolve_liro_thread_names.py`

当前结论不变：原厂 UI 未启动，最小垫片与 ASTRA UI 未验证，实验固件不可刷。
