# 60 · 字体已注入但 /usr 挂载失败（上一步的“不再崩溃”是假象）

本轮为本地镜像修改与一次运行。无设备写入。

## 一、已完成

1. 从相机采集到中文字体：`/tmp/images/MYingHeiC-GB18030-SJ_wIcon.ltt`，1,958,432 字节；
2. 复制 `/usr` 镜像（215,517,184 B）为 `05-原始固件/qemu_in/nflasha15-font`；
3. 用 `debugfs` 写入字体到 `/share/app/MYingHeiC-GB18030-SJ_wIcon.ltt`，并把
   `/share/app/fontlist.dat` 中 `FONT_S_CHINESE` 的路径由 `/tmp/images/...` 改为 `/usr/share/app/...`；
4. 验证：`debugfs stat` 显示该文件 3844 块（≈1.96 MB），`cat fontlist.dat` 显示路径已改。

## 二、运行结果（必须如实记录）

用修改后的 `/usr` 启动：

| 指标 | 结果 |
|---|---|
| `Unhandled fault` | 0 |
| 异常监视器 | **0** |
| 最后客户机时间 | **35.57 s** |

初看像是突破，但检查日志后发现关键问题：

```
init mount_partition:(1097): mounting1 /dev/dnflasha15 -> /usr as ext2 failed.  errno(6)
main: mounting /usr as ext2 failed(-1), trying no-compress
```

- 日志中 **`im.elf`、`VPH`、`uxc` 出现次数均为 0**；
- 即 **UI 进程根本没有启动**。

**结论：这次“不崩溃”是因为 `/usr` 没挂上、UI 没跑起来，而不是字体起了作用。上一段的推断必须撤回。**

## 三、`/usr` 挂载失败的可能原因

修改流程中在 `debugfs` 写入后执行了 `e2fsck -fy`，可能造成：

1. 文件系统特性/状态字段被改动，内核（3.0.27）拒绝挂载；
2. 或 `debugfs write` 后元数据未被内核接受，`e2fsck` 的“修复”进一步改变了布局。

需重新制作：**不做 `e2fsck`**，并在宿主机用只读挂载验证镜像可挂载后再启动。

## 四、下一步

1. 重新复制原始 `/usr` 镜像；
2. 仅用 `debugfs` 写入字体与 `fontlist.dat`（不跑 `e2fsck`）；
3. 在 WSL 中 `mount -o loop,ro` 验证可挂载且文件存在；
4. 通过后再启动，观察 `/usr` 是否挂载成功、UI 是否启动、abort 是否消失。

## 五、证据

- 修改镜像：`05-原始固件/qemu_in/nflasha15-font`（sha256 前缀 `97074296f2d65316…`）
- 运行：`03-证据/模拟器运行/cmdline-20261120T211536Z-50849/serial.log`
  - 挂载失败行：`mounting1 /dev/dnflasha15 -> /usr as ext2 failed`
- 采集字体：`03-证据/相机采集/live-fonts-20261121/`

## 六、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；本轮无设备操作。
