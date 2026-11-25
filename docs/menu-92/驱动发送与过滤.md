# 92_menu_send · 问题B：驱动到InfraInput静态结论

日期：2026-11-21。只做静态读取与新增证据；未修改共享QEMU源码、未启动QEMU。

## 先纠正键身份

主线程与menu-map交叉核验：`0x1AB=KEY_TACT_MENU`，`0x1AC=KEY_TACT_ENTER`。真正MENU来自front type `0x6000`的bit2；ADC15读到`1AC/value1`不证明MENU发生，更不证明消息发出。

## 1. 实际osal_snd_msg调用点

input.ko SHA256：`71cbca3d5a1bb2c2f35b4ba1ca296f717cbc4eb63a78b900b30d1a87df48cc32`。

使用GNU objdump重新完整导出并保留R_ARM_CALL重定位，确认`.text`只有两处`osal_snd_msg`：

|用途|.text偏移|按模块基址5F07C000计算的VA|参数|
|---|---:|---:|---|
|真实物理键上报|0xC40|0x5F07CC40|r0=0x007A0020；r1=16字节payload指针|
|物理键上报返回|0xC44|0x5F07CC44|r0=结果，0成功；失败路径释放消息|
|日志/镜像路径|0xAE0|0x5F07CAE0|r0=0x008F013A；r1是另一种带头记录|
|键包装器入口|0xBA0|0x5F07CBA0|r0=配置类别/来源，r1=物理key，r2=value，r3=附加值|

**不要把AE0镜像发送作为键投递证据，也不要因timer函数内没有osal_snd_msg重定位就断言没发送。** timer通过内部BA0包装器发送。

真实C40前的16字节payload：

```c
struct InputDriverEvent {
    uint32_t key_code; // +0 = 包装器入参r1；MENU应1AB
    uint32_t zero;     // +4 = 0
    uint32_t value;    // +8 = 包装器入参r2
    uint32_t aux;      // +C = 包装器入参r3
};
// *(uint32_t *)(payload - 4) = 0x00410025
// osal_snd_msg(0x007A0020, payload)
```

证据：`03-证据/静态分析/input_uipc/92_menu_send_input_full.dis.txt`，BA0–D0C；875–885行构造payload并真实发送，932–939行常量。AE0镜像路径见784–789行。

## 2. 真正MENU的front扫描、极性、去抖与边沿

已有timer证据：`03-证据/静态分析/input_uipc/kbd_timer_hndlr.dis.txt`。

- `+2B18..2B58`：申请24字节消息，qid=`0x00280132`，经内部`+BC`同步查询front状态；查询失败整组跳过。
- `+2B6C..2B98`：每配置64字节；仅`config[+1C]==u8(timer_arg)`的扫描周期组被处理；`r6=config`，`r4=16B状态项`。
- `config[+8]==0x6000`选返回消息的`+8`这个u32，`config[+C]`为位号；MENU应bit2。
- `+2DAC`从这个u32提取bit；`+2E5C`先转为`(raw_bit==0)`，再与`u32(config+0x10)`比。因此**QEMU OR BIT2是否是按下取决于配置极性**，应读取配置而不能凭raw猜。
- 标准非聚合类型的signed counter在`state+0xC`：有效时负数→+1，否则++至100；无效时正数→-1，否则--至-100。每次只在counter等于`+s8(config+0x20)`或其负值时生成按下/释放状态。
- `config+0x2F`经`1-x`和无符号截断变成pending资格，非0会令pending为0。类型2仅保留按下，释放分支跳过。类型4按group状态聚合，不能套成普通单键。
- `+2F8C`只在`state+0xE`(pending)非0时继续；`+2FA4`调用BA0：`r0=config[+4]`，`r1=config[+24]`，`r2=state[0]`，`r3=state[4]`。随后pending清零，`state+0xD`序列字节递增且避开0。

推荐主线程断点（ARM地址均为偶数，不加Thumb位）：

|VA|用途|需要读取|
|---:|---|---|
|5F07EDAC|front bit提取|r1=front组u32；r0=位号；r6=config|
|5F07EE5C|极性/原始值|r3=raw bit；r6=config64B；r4=state16B|
|5F07EEBC|去抖判定入口|config+20阈值；state+C counter；config+2F资格|
|5F07EF8C|是否有pending|state+E，r6=config|
|5F07EFA4|真正front发送前|r0-r3=来源、物理key、value、aux|
|5F07CC40|实际OSAL调用|r0=qid；r1=payload16B；payload-4为source|
|5F07CC44|OSAL发送结果|r0==0成功|

一次在`5F07EE5C`以MEMREG=6读64字节，即可验证MENU的`+8=6000,+C=2,+10=极性,+1C=扫描周期ms,+20=阈值,+24=1AB,+2F=资格`。保持有效时间至少`阈值×扫描周期`并完成一次释放；仅在±阈值相等时上报，持续按住不会每轮重报。

## 3. InfraInput接收、订阅与抑制

libObj偏移均用偶数Thumb指令地址；下表绝对VA按本轮陈述中的load bias `0x057E3000`计算，运行时仍应核对。

### 接收层

- RecvThread实际接收qid=`0x007A0020`：off`862D94`调用`osal_rcv_msg_tmo`；off`862E3E`开始`ldm r8,{r0-r3}`读取driver16B。
- off`862F86`用driver payload[0]查物理key索引；负索引丢弃。这里是物理配置索引，不等价于客户端未订阅。
- off`862FFA`检查`instance+0x44`，非0直接丢弃这次分发。
- `instance+0x24`指向40字节/key cache；cache+0x20是`GetKeyInh`返回字节，cache+0x24是附加inhibit flags。`SetKeyInh(this,key,bool)`在off`8613FC`；off`861492`实际存入cache+20并清cache+24。
- off`863096`把每键inhibit映射到扩展消息flags bit1，把`instance+0x20`映射到flags bit3；不是所有inhibit都在RecvThread直接丢包，后级会决定是否派发。
- off`86313C`经内部消息发送器发24字节到qid=`0x007A804C`。

### 订阅/EventThread层

- `instance+0x9C`是客户端链表；每客户端+0x2C指向68字节订阅条目数组，+0x28为条目数。
- off`8626CA..8626DA`逐条比对订阅entry[0]与收到的物理key；不匹配跳过。
- off`8626DE`读entry+0x40，非0跳过；off`8626E8`读entry+0x41，非0进入额外禁用分支。
- off`8627C0/27E8/27FE/2812`将每键inhibit及inhibit flags与订阅配置联合判定；off`8629E2`最终检查r6（允许发送），0不发。
- off`862A10`发送转换后的24字节`InfraInputEvent`到客户端qid。
- 客户端回调线程off`860B64`再次检查`instance+0x20`，非0不调用callback。
- 所有输入callback最终共用off`8609CC`的`blx r3`：`r3=实际callback函数指针，r0=callback_id，r1=24B事件指针`。比单独测direct更可靠，能覆盖convert/panel等。

24B客户端事件不能按driver16B解释：`+0=映射后的event_code`（helper861578从订阅entry+4取），`+4/+6=driver payload[1]拆出的s16`（当前驱动为0），`+8=value/status`，`+10hex=aux`，`+14hex=计数`。物理key要在driver/RecvThread处观察，或通过订阅表反查。

|libObj偏移|当前VA|用途|
|---:|---:|---|
|862E3E|06045E3E|收driver16B；MEMREG=8|
|862F8A|06045F8A|物理key查找后的r0索引|
|862FFA|06045FFA|instance+44丢弃开关；instance=r5|
|8613FC|060443FC|SetKeyInh入口r0=this,r1=key,r2=bool|
|86309E|0604609E|r4=每键inhibit，r3=全局instance+20|
|86313C|0604613C|向qid7A804C发24B扩展消息；r2=消息|
|8626CA|060456CA|订阅物理key匹配|
|8629E2|060459E2|最终r6允许发送开关|
|860B64|06043B64|回调前全局inhibit检查|
|8609CC|060439CC|统一callback调用；MEMREG=1，记录r3|

相关新证据：`92_menu_send_infra.dis.txt`（85D000–862500），`92_menu_send_infra_threads.dis.txt`（8623A0–864D00），均在`03-证据/静态分析/input_uipc/`。

## 4. 当前QEMU注入实现与可立即实施的修复

只读检查`\\wsl.localhost\Ubuntu\root\qemu-11.1.3\hw\arm\sony_a6400.c`：

- 950–986行：`REA_FRONT_BTN`逗号分隔列表，每个候选占5秒；前1500ms置位，后3500ms释放；`REA_FRONT_T0`是客户机虚拟毫秒，默认20000。
- 880–889行：submicro tick中更新注入状态；不是宿主时间。
- 1742–1753行：仅`sony_a6400_rear_controls && out[0]==0x20 && front_pressed`时注入；低字节只允许BIT1/BIT2，`out[28]|=bits`，并重算CRC16；释放靠重新复制原始frames。

**立即修复方向**：将按错键的ADC1AC/level1实验改为`REA_FRONT_BTN=0x4,0x4,0x4`，确保机型配置开启rear-controls；t0放在UI已稳定后的客户机时间。先以配置dump证实极性，再解释OR操作是否正确。列表重复同一4可在每5秒槽重复一次完整按下/释放，避免仅在启动期发一次被inhibit吞掉。

若raw按下→pending无变化，读取阈值和scan周期，只有当1500ms短于阈值×周期时才调整注入保持时长；若config+10说明active-low则要在slot-A帧按下时清BIT2、释放恢复原值（保留CRC重算）。这些改变应由主线程统一修改共享QEMU。

最小因果判定：`5F07CC40(payload key1AB)`→`5F07CC44(result0)`→`06045E3E(key1AB)`→`060439CC(event_code及callback)`→`createEvent`。如果链到统一callback仍没有createEvent，才进一步看InputService过滤/UI消费；不要把仅proc getkey或AE0命中算作成功发送。

## 边界

静态分析证明代码路径、参数与可见过滤条件；未声称本轮动态发送已发生。MENU配置实际极性/阈值、当轮模块/库基址、订阅表的实时内容仍需要主线程本次QEMU读取，以上断点已给出取得它们的明确位置。
