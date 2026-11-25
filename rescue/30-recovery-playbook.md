# 30 · 救砖手册（刷写失败怎么恢复）

> 前提：**到目前为止相机从未被写入**，本文是为将来刷写准备的后路。
> 最要紧的一条：**刷写前必须先把两个分区备份出来并拷离相机**。

---

## 一、先分清三种"砖"

| 现象 | 严重程度 | 通常是哪一步出错 |
|---|---|---|
| **A. 完全不开机**（无画面、无灯、无声音） | 最重 | WBI 未清 / 写错分区 |
| **B. 能上电但黑屏、无 UI** | 中 | `/usr` 写入不完整，或 `/etc` 的 preload 指向坏库 |
| **C. 能开机但菜单异常 / 卡死** | 最轻 | 五代资源或垫片问题，原厂系统本身完好 |

---

## 二、恢复顺序（从最轻的手段开始，不要跳步）

### 第 1 步：清 WBI 前 512 字节

**为什么先做这个**：用户实测结论——不清则不开机。这是最常见的"假砖"。

```sh
# 在相机上（root）
dd if=/dev/zero of=/dev/nflasha<WBI> bs=512 count=1 conv=fsync
sync
```

> ⚠️ `<WBI>` 的确切编号**必须在刷写前用 `probe_camera_ro.sh` 确认**。
> 清错分区后果不可控。

**判据**：重启后能进原厂界面 → 已恢复，结束。

---

### 第 2 步：只恢复 `/etc`（12 MiB）—— 最有效的一招

**这是本方案最关键的设计**：注入是靠 `/etc/ld.so.preload` 触发的。
只要把 `/etc` 恢复成原厂（空分区），**preload 就消失，系统立刻回到原厂启动路径**，
完全不需要等 300 MiB 的 `/usr` 写完。

```sh
dd if=/tmp/backup_etc.bin of=/dev/nflasha10 bs=512 count=24576 conv=fsync
sync
dd if=/dev/zero of=/dev/nflasha<WBI> bs=512 count=1 conv=fsync
sync
```

**判据**：重启后能进原厂界面 → 已恢复。
此时 `/usr` 里虽然还有五代库和垫片，但**没有 preload 就不会被加载**，等价于原厂。

> 也可以只做更轻的一步：把 `/etc/ld.so.preload` 清空（若能单独访问该文件）。

---

### 第 3 步：恢复 `/usr`（300 MiB）

```sh
dd if=/tmp/backup_usr.bin of=/dev/nflasha15 bs=512 count=614400 conv=fsync
sync
dd if=/dev/zero of=/dev/nflasha<WBI> bs=512 count=1 conv=fsync
sync
```

**判据**：重启后能进原厂界面且菜单正常 → 完全回滚。

---

### 第 4 步：串口刷机（最后手段）

前面三步都失败、机器完全无响应时：

- 从 **multi 接口引出串口**（用户提供的途径）
- 通过串口进入 bootloader，重新写入分区

这一步需要额外的硬件（USB-TTL）和 bootloader 协议支持，**本工程未验证过**。

---

## 三、为什么"第 2 步"能救大多数情况

我们的改动分布：

```
/usr  (nflasha15)  ── 五代库、资源、垫片 appFwBoot.so
/etc  (nflasha10)  ── ld.so.preload    ← 唯一的"开关"
```

`/etc` 里只有一个 22 字节的文件（`/usr/lib/appFwBoot.so`）。
**没有它，`/usr` 里那些五代库永远不会被加载。**

所以：
- `/usr` 写坏了但 `/etc` 是原厂 → 系统正常按原厂启动（只是多了些没用的文件）
- `/etc` 写坏了但 `/usr` 是原厂 → preload 指向不存在的库 → **可能开不了机（R1 风险）**

**⇒ 这就是刷写顺序必须"先 /usr 后 /etc"的原因。**

---

## 四、刷写前的必备清单

- [ ] `dd` 备份 `/dev/nflasha15`（614,400 扇区）与 `/dev/nflasha10`（24,576 扇区）
- [ ] 备份**拷出相机**，记 SHA-256，至少存两份
- [ ] 已跑 `probe_camera_ro.sh`，确认两个分区 size 与 **WBI 节点名**
- [ ] 确认 `/etc/ld.so.preload` 当前不存在（原厂状态）
- [ ] 接受刷写过程**不能断电**

---

## 五、当前的验证状态

| 项 | 状态 |
|---|---|
| 原厂备份镜像已抽出并校验 | ✅ `stock_usr.img` / `stock_etc.img`，`e2fsck` clean |
| 原厂镜像可启动 | ✅ QEMU 演练通过（5 帧、134 色完整界面） |
| 恢复脚本 | ✅ `scripts/flash_astra.sh` 内含备份与恢复路径 |
| 真机备份 | ⬜ 需相机 |
| WBI 节点名 | ⬜ 需相机确认 |
| 真机演练 | ⬜ 未做 |

---

## 六、一句话总结

**先清 WBI，再恢复 `/etc`。** 这两步能解决绝大多数情况，
而且每一步都只需要写 12 MiB 甚至 512 字节，不需要动 300 MiB 的 `/usr`。
