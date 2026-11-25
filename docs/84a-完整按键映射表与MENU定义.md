# 84 · 找到完整按键映射表与 MENU 定义；ADC 注入可达驱动但不产生按键事件

> ⚠️ **本文中 `MENU = 0x1AC` 有误**：`0x1AC` 实际是 **ENTER**，**MENU 是 `0x1AB`**。
> 键表行结构是 `{code, name_pointer}`，此前读偏了一列。
> 正确映射与最终结论见 `94-原厂菜单已打通.md`。以下保留原始记录供追溯。

本轮为 QEMU 模型调试与客户机内实时探测。无设备写入。

## 一、找到输入驱动的调试接口

`input.ko` 通过 `udm` 框架暴露 `/proc/udm/input`，支持：

```
table | get | adc | front | gpio | vgrip | multi_selector_soft
```

实测各模式输出：

- `front`：打印 `*** Front UIPC data ***`、`FR_INPUT_MSG size:24` 原始字节、`PwrKey1..5` 状态；
- `adc`：打印 `*** ADC UIPC data ***`，Ch0/Ch1 各 12 个端口的电平；
- `get`：打印 `*** Getkey ***`、`keycode / subcode / value / ext`；
- `table`：**打印完整的 ADC / GPIO / FRONT / VGRIP 按键映射表**。

## 二、完整按键映射表（关键数据）

```
*** ADC KeyConfig ***
ID: 0-1  port: c-0    0/ 5b  H2 key: 1f8-1        ← PLAY
ID: 0-1  port: c-0   5c/111 H2 key: 7095-1
ID: 0-1  port: c-0  112/1b7 H2 key: 1f0-1
ID: 0-1  port: c-0  1b8/257 H2 key: 70ec-1
ID: 0-1  port: d-0    0/ 5b H2 key: 70e7-1
ID: 0-1  port: d-0   5c/111 H2 key: 70e7-1
ID: 0-1  port: d-0  1b8/257 H2 key:   66-1
ID: 0-1  port: f-0    0/ 5b H2 key:  1ac-1        ← ★ MENU (KEY_TACT_MENU)
ID: 0-1  port: f-0   5c/111 H2 key:    3-1
ID: 0-1  port: f-0  112/1b7 H2 key:   15-1
ID: 0-1  port: f-0  1b8/257 H2 key:   30-1
ID: 0-1  port: f-0  258/304 H2 key:  1af-1
ID: 0-1  port:10-0 .. 11-0  H4 key:7025-x  adc ref:0115   ← 多向选择器

*** GPIO KeyConfig ***
ID: 0-2  port: 0-3 / 0-4 / 0-7 / 0-11 / 1-1 / 5-4 / 9-16
         → key 70fd / 70fe / 70dc / 70c6 / 70ef / 4b,4c / 4d,47

*** FRONT(CA) KeyConfig ***
ID: 0-4  port:6000-0/1/2/5/9 → key 2 / 1f7 / 1ab / 70d5 / 7094

*** VGRIP KeyConfig *** （空）
```

**结论：MENU = keycode `0x1AC`，ADC 端口 `0xF`，有效电平区间 `0x000–0x05B`（0–91）。**

## 三、ADC 注入可达驱动，但不产生按键事件

在 `rear_adc`（ADC 单元 1）通道 3 注入电平 0x20 并保持，读取 `adc` 模式：

```
Ch1:Port 3 0020      ← 注入值确实到达驱动
其余端口 03FF（空闲）
```

即 **注入链路是通的**。但同一时刻 `get` 模式仍然输出：

```
*** Getkey 0x0 ***
keycode:0x0
```

逐通道扫描（ch0–ch7，每通道 5 秒）后轮询 `get`，**全部为 0x0**。

同时用断点确认按键扫描函数 `kbd_timer_hndlr`（模块基址 `0x5f07c000` + `0x21e4`）**确实在持续运行**（多次命中）。

## 四、现在的矛盾点

- 驱动能读到我们注入的 ADC 值（`Ch1:Port3 0020`）；
- 驱动扫描线程在跑；
- 但按 key table 的映射（port 0xF → 0x1AC）本应产生 MENU 事件，实际没有。

可能原因（待验证）：

1. key table 的 `port` 编号并非"单元*12+通道"，`0xF` 可能指向另一个 ADC 单元/端口（Ch0 全 `FFFF`，说明该单元数据来源不同）；
2. 按键事件需要一次"变化沿"或某个 UIPC 请求/应答周期才会被采样；
3. `get` 模式显示的是"最近一次上报的按键"，事件可能已被上层消费。

## 五、下一步

1. 扩大 ADC 模型到 20+ 通道，测试单元 0 的 port 0xC–0x11；
2. 在 `kbd_timer_hndlr` 内部对 ADC 读取处下断点，直接观察它读到的值与比较过程；
3. 若确认事件已产生但被消费，则改为观察 GPU/UI 是否响应（而不是读 `get`）。

## 六、证据

- 运行：`03-证据/模拟器运行/procinput-20261121T120137Z-118343`（Ch1:Port3=0020）
- 按键表：`procinput-20261121T114856Z-116993`
- 扫描断点：`procinput-20261121T121216Z-119133`（REA_BP 多次命中）
- QEMU 补丁：`patch_adc_inject.py`、`patch_adc_hold.py`、`fix_adc_hold_env.py`

## 七、状态

原厂 UI：运行、无崩溃、显示链路正常、仍无绘制。
按键：MENU 定义已知、注入可达驱动、但未产生按键事件。
ASTRA UI：未开始。
真机未被修改。
