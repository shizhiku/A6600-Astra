# 63 · 字体已放进 /tmp/images 仍 abort；/usr 卡顿的真因是改 fontlist

本轮为镜像构建与两次运行。无设备写入。

## 一、修正上一轮的结论

上一轮认为“任何改动 `/usr` 都会卡住”。本轮做了「只读写挂载、不改任何文件」的对照：

| 镜像 | 改动 | 结果 |
|---|---|---|
| `nflasha15-copy` | 无 | UI 启动（abort，`monitor: 1`） |
| `nflasha15-touch` | **仅超级块更新**（挂载 rw 后立即卸载，未改文件） | **UI 启动**（`monitor: 1`） |
| `nflasha15-listonly` | 改 `fontlist.dat` | 卡住（无 `im.elf`） |
| `nflasha15-font3` | 加字体 + 改 `fontlist.dat` | 卡住（无 `im.elf`） |

**结论修正：不是“任何改动”都卡，而是“改动 `fontlist.dat`”会卡。** 超级块更新时间戳不影响启动。

推测：`fontlist.dat` 被改后，字体获取路径进入异常分支并阻塞（`libsencore` 可能按自己的内部表匹配路径，改表反而导致等待）。

## 二、新方案：不动 fontlist.dat，把字体放进 `/tmp/images/`

`fontlist.dat` 与 `/usr` 均保持原样，只在根文件系统里放字体：

1. 复制 `nflasha3-initrd`（ext2 根文件系统，2.18 MB）；
2. 尝试扩到 24 MB → **QEMU 直接退出**（exit 1）：内核命令行限定 `initrd=0x700000,8M`，**上限 8 MB**；
3. 改为扩到 **6 MB**，`resize2fs` 成功；
4. rw 挂载，`mkdir -p /tmp/images`，放入字体（1,958,432 B），剩余 2.2 MB；
5. 只读校验通过。

## 三、运行结果：UI 起来了，但 abort 依旧

| 项目 | 结果 |
|---|---|
| `Unhandled fault` | 0 |
| 异常监视器 | **1** |
| `im.elf` 出现次数 | 4（UI 进程确实启动） |
| `uxc` 出现次数 | 7（UI 资源已加载） |
| 故障地址 | **仍为 libc + `0x15796`**（与之前完全一致） |

即：**字体放进 `/tmp/images/` 后，abort 的位置没有任何变化。**

## 四、可能的解释

1. `/tmp/images` 下的文件虽然存在，但 `TextRM_loadFont` 并不直接读文件，而是**向副控制器请求**（`libsencore` 负责传输），
   因此“文件存在”并不足以满足它；
2. 或加载器校验字体头/版本，发现与预期不符；
3. 或某处仍按 `fontlist.dat` 的路径查表，而表里是 `/tmp/images/...`，与实际文件虽匹配但其它前置校验失败。

## 五、下一步

1. 在 `TextRM_loadFont` 内部（而非其 PLT 桩）下断，读取返回路径与错误码，确认失败发生在“取数据”还是“解析数据”；
2. 若确认是“向副控制器取数据”，则回到**建模副控制器文件传输**这一根本方案；
3. 或用 hook 在 `open`/`read` 相关系统调用上观察是否真的打开了 `/tmp/images/...`。

## 六、证据

- 镜像：`05-原始固件/qemu_in/initrd-font6`（6 MB，含字体）、`nflasha15-touch`
- 运行：
  - `cmdline-20261120T213359Z-52554`（touch 镜像，UI 启动）
  - `cmdline-20261120T213702Z-52908`（initrd-font6，UI 启动但同点 abort）
  - `cmdline-20261120T213628Z-52786`（24 MB initrd，QEMU 立即退出）
- 脚本：`make_initrd_font6.sh`、`make_touch_image.sh`

## 七、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；本轮无设备操作。
