# 32 · 卡死根因：屏幕朗读子系统缺少资源导致内存分配死循环

> 时间：2026-11-25
> 现象：在菜单里操作一段时间（尤其切换语言后）UI 停止响应，按键触摸全部无效

---

## 一、结论

**不是死锁，是屏幕朗读（screen reader）子系统在反复申请内存失败，最终拖死整个 UI。**

---

## 二、证据链

### 1. 卡死前日志呈固定循环（每 6 秒一轮）

```
APPFW_SEQ: adf_sys_set_text_speech_output   out:0x1
APPFW_SEQ: dmm alloc_core ERROR!(ret_code = 0xFFFFFFFD(-3))
APPFW_SEQ: dmm_free handle[0xffff]
APPFW_SEQ: adf_sys_set_text_speech_volume   vol:0x10
（重复 → 画面停止更新）
```

`dmm alloc_core` 是动态内存分配，返回 `-3`（失败），随后拿 `0xffff` 无效句柄去 `free`。

### 2. 线程转储显示没有任何线程死锁

```
tid=144  S  osal_rcv_msg_tmo      ← UI 主线程，正常等消息
tid=145  S  __k_4u_wait_cb
tid=148  S  poll_schedule_timeout
tid=301  S  futex_wait_queue_me
tid=372  R  wchan=0               ← 渲染泵线程正常
```

**全部是正常的等待状态**，没有 `D`（不可中断）状态，没有互相持锁。

### 3. 缺的是 `/share/screenreader`

| 镜像 | `/share` 内容 |
|---|---|
| ZV-1M2 原厂 `/usr` | **`screenreader` 226 MB**（10 种语言，49,124 个 `.bin`）+ `app` 83 MB |
| 我们的 300 MiB 镜像 | 只有 `app` 84 MB，**没有 screenreader** |
| a6600 原厂 `/usr` | 也没有 screenreader（这是五代新增特性） |

每种语言目录 20~26 MB：

```
italian 26M  spanish 25M  portuguese 25M  german 24M
traditionalchinese 23M  simplifiedchinese 23M  japanese 23M
french 21M  korean 20M  english 20M
```

---

## 三、尝试过的修复

### 修复：给镜像加一个空的 `/share/screenreader/simplifiedchinese/` 目录

（镜像 `a6600_v44_srx.img`，仅新增一个空目录与一个 0 字节 `.keep` 文件）

| 指标 | 修复前 | 修复后 |
|---|---|---|
| 菜单静置 | **154 秒后开始 dmm 错误刷屏** | **240 秒内 dmm 错误 0 次** |
| 绘制 | 报错后很快停止 | 持续增长 `#4200 → #7600` |
| 切换语言后 | drawfb 冻结在 #5800 | 涨到 #7800，再约 60 秒后停止 |

**结论：空目录足以消除"正常使用（不切语言）"时的死循环，但无法覆盖切换语言。**

原因：切换语言会让朗读引擎重新加载该语言的数据，再次走到同样的失败路径。

### 仍存在的问题

即使 `dmm` 错误为 0、画面持续刷新，**部分输入动作仍不生效**：

- 点「关闭」按钮只产生高亮（png 34694 ↔ 34479），不发生屏幕切换
- 点左栏图标、菜单项无任何变化
- `open screen` 计数不再增长

也就是说：**绘制活着，事件处理不一定活着。** 这与 dmm 循环是两个问题（后者已缓解），需要单独定位。

---

## 四、为什么不能直接把资源放进去

`/usr` 分区固定 **300 MiB**，当前镜像已用 292,956 KiB，**仅剩 14,244 KiB（约 14 MB）**。

单个语言的朗读数据就要 **23 MB**，装不下；全部 226 MB 更不可能。

---

## 五、可行的修复方向

| 方向 | 说明 | 难度 |
|---|---|---|
| **A. 关闭朗读功能** | 最理想。但前台菜单里**没有这个开关**（Setup 11 项全查过：Area/Date、Reset、Operation Customize、Touch Operation、Monitor、Display Option、Power Setting、Sound Option、USB、External Output、Setup Option），Sound Option 里只有音量与提示音 | 需要找内部开关/模型字段 |
| **B. 只放一种语言** | 需要腾出 23 MB。当前只剩 14 MB，还要再挤 9 MB（例如删掉其他 9 种语言的字符串资源，约 2 MB，仍不够） | 中 |
| **C. 让加载失败后不再重试** | 在垫片里 hook 失败路径，把 `dmm alloc_core` 的错误吞掉并标记"已禁用" | 需要定位函数（二进制已 strip） |
| **D. 扩大分区（仅 QEMU）** | 真实机是 300 MiB 改不了；但可在模拟器用大镜像**验证因果**，确认后再谈真机取舍 | 低（验证用） |

---

## 六、对交付的影响

- 当前发布镜像在**常规浏览菜单时是稳定的**（dmm 错误只在特定操作后出现）
- **切换语言会触发卡死**——这是已知缺陷
- 真机上是否同样发作**未知**（真机的 `/usr` 同样没有 screenreader，但真机有完整 `/system` 等分区，可能有资源来自别处）

---

## 七、下一步

1. 用大镜像（QEMU-only）验证"放入 screenreader 资源即不再卡死"这一因果
2. 若成立，再决定真机方案：腾空间放一种语言，或找到关闭朗读的开关
3. 短期规避：**刷入后不要切换语言**
