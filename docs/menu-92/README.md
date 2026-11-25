# 92 · 原厂菜单已打通：91号问题的修复与运行验证

本轮只操作离线固件副本与隔离QEMU覆盖层，未连接或修改相机。原始/usr、QEMU硬件行为、字体与eMMC既有补丁均未为菜单实验改写。

## 结果

已经实际打开a6600简体中文原厂菜单：**设置4，4/7**，菜单包括USB连接、USB LUN设定、USB电源供给、语言等。

- 普通pthread调用原厂输入转换器：已复跑两次，均在vsync1800捕获同一菜单帧。
- 不使用任何预加载库的硬件输入路径：独立复跑两次，均在vsync1800与2400捕获同一菜单帧。
- 菜单图像的PPM SHA-256：`261759d395c6a58884154fed1c0b4d8c45879314fa06af650be35fac96ffb87d`。
- PNG由原始PPM转换，640×480；图像代理已实际查看，明确识别为原厂中文菜单，而非按文件名推测。

主证据：`03-证据/模拟器运行/run-20261121T152425Z-native-1/fb.1.png`；硬件路径：`run-20261121T153129Z-front-1/fb.1.png`。

## 根因一：物理键名表被读偏了一列

此前由我给出的 `MENU=0x1AC` 有误。表的行结构是 `{code, name_pointer}`，不是 `{name_pointer, following_code}`。该错误使后续把ENTER实验当作MENU实验，必须更正。

| 原厂物理键 | 正确physical code | InfraInput逻辑基码 | createEvent按下 | 释放 | 重复 |
|---|---:|---:|---:|---:|---:|
| MENU | 0x1AB | 0x15010100 | 0x15010102 | 0x15010101 | 0x15010104 |
| ENTER/中心确认 | 0x1AC | 0x15010050 | 0x15010052 | 0x15010051 | 0x15010054 |

原始libObj文件偏移：

- `0x13E8924={0x1AB,0x01014593}` → `KEY_TACT_MENU`；VA为0x13F0924。
- `0x13E892C={0x1AC,0x010145A1}` → `KEY_TACT_ENTER`；VA为0x13F092C。

产品默认表在viewUnified2，而非libObj：

- MENU：文件0x9580FC、VA0x9600FC，原始12字节 `ab01000000010115feffff7f`。
- ENTER：文件0x957FA0、VA0x95FFA0，原始12字节 `ac01000050000115feffff7f`。

所以旧605次命中中0x15010054×579和0x15010052，已经与ENTER的按下/重复链相符；它们不是无关事件，也不能据“不等于1AC”判为驱动丢键。

详见 `92_menu_map-真实MENU与ENTER映射.md` 及其mapping_evidence.json，包含ELF哈希、VA/文件偏移和注册结构。

## 根因二：NTSC提示需要ENTER确认

“运行于NTSC。”由ViewCaution消费。静态路径已追到：

```text
ActionNtscCaution → caution trigger 0x089E
→ 资源类型1 → ViewCaution state3
→ 接收ENTER功能按下0x15010052
→ local event3 → action10 → 清除当前caution trigger
```

MENU不产生这条确认分支，不能替代ENTER清除此提示。因此应先按ENTER并释放，等待提示退出，再按MENU并释放。运行验证与此静态路径一致。

详见 `03-证据/静态分析/92_menu_consumer_report.md`。不要将它与设置页面 `ViewNtscPalSEL_D` 混为一谈。

## 解法一：纯硬件注入，推荐复现

不需要LD_PRELOAD，不改UI代码，不伪造sen READY消息。

保持当前已验证的机器属性：

```text
sony-a6400,rear-controls=on,submicro-frames=<已采集回放文件>
```

使用现有模型注入器：

```text
REA_ADC_SEQ=3:32
REA_ADC_T0=12000
# 不设置REA_ADC_HOLD：在第二ADC单元local ch3短按ENTER，随后释放。

REA_FRONT_BTN=4,0,0,4
REA_FRONT_T0=25000
# 前面板bit2是真MENU；25秒时按一次，40秒时再按一次。
```

时间单位是客户机虚拟毫秒，不是宿主墙钟。每个front槽5秒，前1.5秒按下，其余时间释放。该序列先确认NTSC，再打开菜单，稍后再关闭。

`92_experiments.py run front` 已固定该配置，并使用无preload的字体tmp镜像。

第一轮硬件结果：

| vsync | 抓帧后客户机uptime | ch53 base | 内容 |
|---:|---:|---|---|
| 1200 | 20.12 s | 0x23A80000 | NO CARD拍摄OSD |
| 1800 | 30.02 s | 0x23B16000 | 设置4 / 4/7菜单 |
| 2400 | 40.05 s | 0x23B16000 | 同一菜单 |
| 3000 | 50.28 s | 0x23B16000 | 黑帧 |
| 3600 | 60.50 s | 0x23B16000 | 黑帧 |
| 4200 | 未取得 | 0x23A80000 | NO CARD拍摄OSD |

上述uptime是抓帧后通过串口查询的相邻采样，不冒充像素捕获瞬间的精确时间。黑帧尚有缓冲/过渡问题，不能据此声称已修好全部显示时序。

## 解法二：普通线程调用原厂callback_convert

已编译并运行验证：`04-产物/92_native_menu_probe.c`、`libnative_menu92.so`。

- 不使用SIGALRM。
- 显式链接旧 `pthread_create@GLIBC_2.4` / `pthread_detach@GLIBC_2.4`。
- 构造函数只在im.elf中创建worker；worker等待libObj和InputService初始化，动态读取当轮load bias。
- 调用原厂 `callback_convert`，不手工创建缺参数的Event。

最小ABI：

```c
// 指令偏移0x3D2FB0；Thumb函数指针为load_bias+0x3D2FB1
struct InputEvent24 {
    uint32_t logical_base, sub, status, prev_status, ex_info, repeat_count;
};
// 按下MENU：{0x15010100,0,1,0,0,0}
// 释放MENU：{0x15010100,0,0,1,0,0}
callback_convert(0, &event);
```

ENTER用0x15010050。转换器根据status/repeat生成最终边沿ID，再走原厂Event与pushFilterEvent，不应向callback_direct直接传物理码1AB/1AC。

当前探针的顺序为：初始化就绪后等待12秒→ENTER按下/释放→等待10秒→MENU按下/释放→等待12秒→MENU按下/释放。两次独立运行均抓到相同菜单，之后可回到拍摄OSD。

## B · 驱动并非已证实丢键

真实driver发送合同已定位：

```text
input.ko .text+0xC40:
r0 = qid 0x007A0020
r1 → 16字节 {physical_key, 0, value/status, aux}
消息前4字节 = 0x00410025
.text+0xC44返回r0=0表示发送成功
```

MENU走front6000 bit2路径，经去抖、pending后进入该包装器；不是ADC1AC路径。去抖、订阅、inhibit及所有回调共用的入口详见 `92_menu_send_B静态结论.md`。

本轮纯硬件序列已能端到端打开菜单，因此不再需要以“驱动不发MENU”作为已定位故障继续补协议。

观测限制：尝试的最终callback地址位于一个TB内部，现有REA_BP在TB入口采样，r1当时尚未建立；该条记录不能用于声称完整抓到了callback payload，也不能把匹配数0当作回调未发生。硬件路径的闭环以输入序列、匹配对照和真实菜单帧为依据。

## C · 空DSO与旧注入器对照

所有正式对照固定：相同QEMU二进制、kernel、initrd、原厂/usr、Backup、setting、字体、rear-controls与submicro回放；只改变tmp分区中的preload库。各输入SHA-256保存在run.json的input_manifest中。

- 无preload：已捕获正常NTSC提示。
- 完全空DSO：已捕获与无preload相同的NTSC提示，像素/文件哈希一致。
- 旧SIGALRM v7：在匹配配置下也停在NTSC提示，未重现此前黑屏；它仍发错误的0x1AC逻辑Event，不能打开菜单。
- 正确普通线程注入：能确认提示并打开菜单。

不能因此说SIGALRM任意调用UI安全，也不能说任何DSO都无影响；能否定的是“多加载一个DSO必然使该基线不能渲染”的过强判断。

另保留两个早期诊断样本：未启用rear-controls与回放时，无preload和空DSO都黑。它们不纳入正式C0/C1比较；这说明机器属性/回放配置必须与preload一起纳入实验记录，不能把不同启动配置的黑帧归因于DSO。

正式匹配配置下，最终对照如下：

| 条件 | 独立运行次数 | 结果 |
|---|---:|---|
| 无预加载 | 2 | 两次各6帧均为同一NTSC提示 |
| 空DSO | 2 | 两次各6帧均与基线NTSC图像哈希一致 |
| 旧SIGALRM v7 | 2 | 两次各6帧仍为NTSC提示，未打开菜单、未复现黑屏 |
| 正确普通线程注入 | 2 | 两次均在vsync1800捕获相同原厂菜单 |
| 无预加载，纯ADC+front输入 | 2 | 两次均在vsync1800、2400捕获相同原厂菜单 |

两次硬件运行：`run-20261121T153129Z-front-1`、`run-20261121T153655Z-front-2`；两次线程运行：`run-20261121T152425Z-native-1`、`run-20261121T153018Z-native-2`。

最终样本数量、每帧分类、哈希、buffer与相邻uptime统一见 `03-证据/静态分析/92_results.json`。

## D · 可比性与未完成边界

已做到：冻结输入哈希、每次独立qcow2子覆盖层、6个固定vsync多帧捕获、记录输出缓冲、PPM哈希和可取得的抓帧后uptime、区分机器属性不同的样本。

未宣称做到：根治所有偶发黑帧；每一采样时刻都显示稳定菜单；捕获瞬间的精确QEMU虚拟ns。当前QMP不支持所尝试的 `info clocks`，错误原样归档；没有用墙钟替代虚拟时钟。

E（ASTRA移植）本轮未启动；原厂菜单前置条件已经达到。

## 可复现入口

在WSL中：

```bash
# 本轮冻结输入已在${RUN}/inputs-v2，prepare会拒绝覆盖。
python3 <WORKSPACE>/02-脚本/92_experiments.py run front --rep 3 --wall 320

# 可选：已编译普通线程注入器，使用本轮native-v1冻结库
python3 <WORKSPACE>/02-脚本/92_experiments.py run native --rep 3 --wall 320
```

初次准备可执行同脚本 `prepare`；该命令只写新的实验目录并拒绝覆盖既有冻结输入。分析与PNG转换使用 `92_analyze_results.py`，需要Pillow（本轮用DSH自带Python）。最终交付复制到用户指定的 `6600 2` 目录。
