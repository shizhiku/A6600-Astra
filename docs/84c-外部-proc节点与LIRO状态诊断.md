# 84 · proc 节点真实注册与 LIRO/OSAL 状态诊断

范围：只读分析 `input.ko`、`liro.ko`、`osal_uipc.ko`，并与 `procinput-20261121T113737Z-116283`、`probe84-20261121T115805Z-118001` 运行日志交叉核对。不重复 evdev、LD_PRELOAD 过早采样等已排除路径。

## 1. `input.ko` 的真实 proc 节点

**真实路径是 `/proc/udm/input`，不是 `/proc/input`。** 运行日志列出了 `/proc/udm/input`，且 `echo get/table > /proc/udm/input` 后读取成功。

静态调用链：

- `init_module`（`.init.text+0xC20`）调用 `udif_driver_register(&udif_input, 1)`；实参 `r0` 指向 `.data+0x2C` 的 `udif_input` 驱动描述符，`r1=1`。
- UDIF 匹配并调用 `kbd_probe`（`.text+0x40C0`）。
- `kbd_probe+0x24`（指令地址 `.text+0x40E8`）调用 `udif_create_proc(.data+0x18)`。
- `.data+0x18` 描述符的重定位为：名称 `.rodata.str1.1+0x237 = "input"`，读回调 `kbd_read_proc`（`.text+0x123C`），写回调 `kbd_write_proc`（`.text+0x1A4`），私有数据 `.bss+0x5C`。
- 父目录 `/proc/udm` 由 Sony UDIF 框架提供，因此描述符中的相对名 `input` 落地为 `/proc/udm/input`。

创建条件：模块完成 `udif_driver_register`，且 UDIF 设备匹配后进入 `kbd_probe`。`kbd_probe` 对 `udif_create_proc` 的调用是无条件的；只有注册结果的错误处理在调用之后。

### `Input_debug` / `key_tbl` 是否控制创建

不控制。

- `Input_debug` 的参数存储是 `.bss+0x0`。`kbd_probe` 只在 `udif_create_proc` 返回异常后读取它，决定是否 `printk`；它不包围、不跳过创建调用。
- `key_tbl` 的参数存储是 `.bss+0x10`。它参与 `kbd_init` 的键表/Backup 初始化选择，但 `kbd_probe` 的 proc 注册路径不引用 `.bss+0x10`。
- 因此设置或不设置 `Input_debug`、`key_tbl` 都不会决定 `/proc/udm/input` 是否出现；真正门槛是 UDIF 驱动注册与 probe 是否发生。

写入选择读取页：`table=0`、`get=1`、`adc=2`、`front=3`、`gpio=4`、`vgrip=5`；另有 `multi_selector_soft` 切换命令。运行日志已验证 `get` 和 `table`。

## 2. `/proc/liro`

注册链：

- `liro_proc_init` 调用 `proc_mkdir("liro", NULL)`，结果保存到 `liro_proc_dir`（`.bss+0x130`）。
- `liro_init+0xD8` 以 `r0="susres"` 调用 `liro_create_entry`。
- `liro_create_entry("susres")` 实际调用 `create_proc_entry("susres", 0444, liro_proc_dir)`；`r1=0x124` 即八进制 `0444`。
- 返回后 `liro_init` 把 `.data+0x4` 的 file-operations 指针写入 proc entry；该表的读处理重定位到 `proc_suspend`（`.text+0x524`）。

结论：`/proc/liro/susres` 是 suspend/resume 控制动作入口，不是 LIRO task/queue 状态页。`proc_suspend` 会调用 `pm_get_state`、恢复回调、创建 `liro-RESUME` 线程并等待完成；没有 task/queue dump 格式。运行日志中 `cat /proc/liro/susres` 返回 `Input/output error`，与“不可作为状态读取页”一致。

## 3. `/proc/osal`

`osal_uipc.ko` 的注册实参：

- `k_osal_init`：`proc_mkdir("osal", NULL)`；随后 `create_proc_entry("minfo", 0400, osal_dir)`，读回调 `__k_minfo_proc_read`。
- `k_uipc_init`：`create_proc_entry("uipc", 0600, osal_dir)`；read/write 分别为 `__k_uipc_proc_read`、`__k_uipc_proc_write`。
- `/proc/osal/ulogio` 在运行时存在，但不由本次要求的三个模块注册，不能用 `osal_uipc.ko` 的代码把它认定为 task/queue 状态源。

节点能力：

- `minfo`：只调用 `vpool_dump`，实测输出类似 `(21688) 68900000 131072`；是内存池信息，不显示 task、msgq 或 blocking。
- `uipc` 第 0 页：OSAL 版本、proxy/log 配置、全局资源计数、fblock/vblock、dynamic IDs。实测有 `msgqs=792`、`sems=161` 等，但这是总量，不是某个 LIRO task 的阻塞位置。
- `uipc` 第 1 页：静态分支直接调用 `msgq_dump`，表头为 `ID(Hex) M C S B L A F W`，可显示全局 OSAL msgq 的状态位，并在特定队列后附加 `%04lx %lx` 两个字段。
- `uipc` 第 2 页：直接调用 `bsem_dump`，表头为 `ID(Hex) L W O`，可显示二值信号量的 lock/wait/owner 类字段。
- 第 3 页是已连接 UIPC 进程的采集页，输出 `====Process %d====`，忙时显示 `busy...escaped`；它不是 LIRO ITRON task 表，也不等同 Linux `wchan`。
- `uipc` 写命令只有 `debug`、`log`、`qlog` 三类，修改日志开关；只读诊断不要写这些命令。

所以：**Sony 节点中，只有 `/proc/osal/uipc` 的 msgq/bsem 分页能直接提供 queue/等待相关状态；没有一个已确认 Sony 节点能完整显示 LIRO task 的 Linux 阻塞栈。** 真正的线程阻塞点应读标准 `/proc/<pid>/task/<tid>/{status,wchan,stack}`。新日志已确认晚期 `im.elf` PID 144 映射 `libObj.so`，并看到 `THREAD_INFRA0` tid 318 的 `wchan=sugilite_ioctl`；因此此前“UI 是 LIRO 内核任务”的结论应废弃，不能再用它解释 proc 结果。

## 4. 客户机只读命令

```sh
# 节点与权限
ls -l /proc/udm/input /proc/liro /proc/osal

# input 当前事件、完整键表及各输入源状态
printf 'get\n'   > /proc/udm/input; cat /proc/udm/input
printf 'table\n' > /proc/udm/input; cat /proc/udm/input
printf 'adc\n'   > /proc/udm/input; cat /proc/udm/input
printf 'front\n' > /proc/udm/input; cat /proc/udm/input
printf 'gpio\n'  > /proc/udm/input; cat /proc/udm/input
printf 'vgrip\n' > /proc/udm/input; cat /proc/udm/input

# OSAL 总览与内存池
cat /proc/osal/minfo
cat /proc/osal/uipc

# 定位晚期真正映射 libObj.so 的进程
for p in /proc/[0-9]*; do
  grep -q 'libObj.so' "$p/maps" 2>/dev/null && echo "$p $(cat "$p/comm")"
done

# 对选定 PID（当前日志为 144）读取每个线程的真实阻塞位置
P=144
for t in /proc/$P/task/*; do
  echo "=== $t ==="
  cat "$t/comm" "$t/status" "$t/wchan" 2>/dev/null
  cat "$t/stack" 2>/dev/null
done
```

内部第 1/2 页的可靠用户态选择方式尚未运行验证，不能把普通 `dd skip=1/2` 等同于指定 proc 回调页：`dd` 可能只是从读出的文本中丢弃字节。当前只确认普通 `cat` 的总览输出；定向 msgq/bsem 页需要进一步核对回调的 offset/start 约定，再用匹配的 seek/pread 小工具验证。不要为切页随意写 `debug/log/qlog`，它们是日志控制命令。

## 5. ADC `port f` 映射修正

`/proc/udm/input table` 中 `port:f-0` 的 `f` 是十六进制全局 ADC 通道 `0x0f`，即 `ADC unit 1 + local channel 3`，不是传给单个 ADC 设备的 local channel 15。

QEMU 的 `cxd90014_adc_set(dev, ch, level)` 只接受 `0 <= ch < 12`；传 `15` 会被静默忽略。现有 a6400 板模型的 `sony_a6400_rear_adc` 是第二个 ADC 单元，故 a6600 的 `port f` 应在该设备上写 **local `ch3`**。本次 a6600 表中 `port f-0, 0..0x5b` 对应键码 `0x1ac`（当前命名结论为 MENU），所以测试值可用 `ch3, level 45`，并立即用 `echo adc/get > /proc/udm/input; cat ...` 验证驱动实际读值和键事件。

不要照搬 a6400 的应用映射：a6400 证据把其 MENU 放在 submicro CAkey bit 2，而 a6600 当前运行表把键码 `0x1ac` 放在 ADC 全局 `0x0f`。硬件通道映射相同不代表两机型的按键分配相同。

## 6. 证据文件

- `03-证据/静态分析/84_proc_static.txt`：重定位感知的函数、字符串和注册调用实参。
- `02-脚本/84_proc_static.py`：只读生成脚本。
- `03-证据/模拟器运行/procinput-20261121T113737Z-116283/serial.log`：真实目录名。
- `03-证据/模拟器运行/probe84-20261121T115805Z-118001/serial.log`：节点读取、input table、OSAL 总览及线程 wchan。
