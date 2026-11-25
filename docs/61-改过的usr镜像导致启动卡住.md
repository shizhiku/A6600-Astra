# 61 · 改过的 /usr 镜像导致启动卡住（需换方案）

本轮为镜像重建、只读挂载验证与一次运行。无设备写入。

## 一、镜像重建与验证（本次做对了）

按上一轮结论，去掉 `e2fsck -fy`，流程改为：

1. 复制原始 `nflasha15` → `nflasha15-font2`（215,517,184 B）；
2. `debugfs` 写入字体（inode 42788，Size 1,958,432，Blockcount 3844）；
3. `debugfs` 替换 `/share/app/fontlist.dat`（363 字节，路径已改为 `/usr/share/app/...`）；
4. **只读校验** `e2fsck -fn`：通过（845/52624 文件，202865/210464 块）；
5. **只读挂载测试**：`mount -o loop,ro` **成功**，目录内容正确。

镜像本身在宿主机是完全可用的。

## 二、但用该镜像启动：UI 不启动

| 运行 | initrd | `/usr` | 结果 |
|---|---|---|---|
| `cmdline-20261120T203220Z-47366` | 相机 libc | **原始** | UI 启动，3.3 s 触发 abort |
| `cmdline-20261120T211851Z-51288` | 相机 libc | **改过（含字体）** | **卡住**：无 `im.elf`/`VPH`/`uxc`，客户机时间 35.5 s |
| `cmdline-20261120T211536Z-50849` | 同上 | 同上（不同副本） | 同上 |

## 三、排除的判别点

`/usr` 挂载失败信息在**早期能正常启动 UI 的运行里同样存在**：

```
init mount_partition:(1097): mounting1 /dev/dnflasha15 -> /usr as ext2 failed. errno(6)
main: mounting /usr as ext2 failed(-1), trying no-compress
```

因此 `/usr` 的这条失败日志**不是**本次卡住的原因；差异只在于 `/usr` 镜像内容。

## 四、当前判断

- 镜像在宿主机可挂载、文件系统一致；
- 但在模拟内核下，使用该镜像会导致启动阶段停滞（eMMC 调优反复重试，UI 未起）；
- 可能原因：
  1. 新 inode（42788）位于文件系统后部，触发内核或模拟块设备的边界问题；
  2. `debugfs` 写入的目录项/inode 属性（Mode 0777）与内核预期不符；
  3. 镜像通过 `qemu-io` 写入 overlay 时，稀疏/分配差异导致分区内容异常。

## 五、下一步建议（换方案，减少对 /usr 的改动）

### 方案 1：改回 initrd 根文件系统

字体期望路径就是 `/tmp/images/...`。把 initrd 的 ext2 扩容（`resize2fs`），在其中创建 `/tmp/images/` 并放入字体，完全不碰 `/usr`。

风险：启动脚本可能把 tmpfs 挂到 `/tmp`，覆盖该目录。需先确认。

### 方案 2：保留改过的 /usr，但先定位卡住原因

- 用 `debugfs` 把字体写到**靠前的空闲 inode**（先删除一个无用大文件腾出前部空间）；
- 或改用 `e2cp`/`e2tools` 等工具写入；
- 或改用「原地替换一个已有文件」的做法（例如把字体写到 `/share/app/Sony_DI_Icons.ttf` 的位置不现实，但可考虑把某个非必需的大文件替换为字体）。

### 方案 3：先做最小验证

只改 `fontlist.dat`（不新增字体文件），把 `FONT_S_CHINESE` 指向一个**已存在**的字体（如韩文 `.ltt`），验证「改配置是否会影响启动」。若连这个都卡住，则问题在「改 /usr」本身，而不在字体写入。

**建议优先执行方案 3**，成本最低、判别力最强。

## 六、证据

- 新镜像：`05-原始固件/qemu_in/nflasha15-font2`
- 校验：`e2fsck -fn` 通过；`mount -o loop,ro` 成功
- 运行：`cmdline-20261120T211851Z-51288`、`cmdline-20261120T211536Z-50849`
- 对照：`cmdline-20261120T203220Z-47366`
- 脚本：`rebuild_usr_font.sh`、`run_with_font2.sh`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；本轮无设备操作。
