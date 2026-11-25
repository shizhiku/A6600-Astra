# a6600 预加载探针包（astra_probe.so）

**状态：已编译，未安装。没有向相机写入任何东西。**

用来说明「a6600 能不能跑自定义代码」这条链路的最小可验证工件。

## 1. 它是什么

- 目标：`arm-linux-gnueabihf` / Cortex-A5 / ARMv7 软 fp，`e_flags = 0x05000002`（与机身自带 `/usr/tool/LeakTracer.so` 完全一致）
- 5,232 字节，**无 libc 依赖、无 `DT_NEEDED`、无未定义符号**（纯 ARM EABI 系统调用：open/write/close/getpid）
- 构造器（`DT_INIT_ARRAY`）只做一件事：向
  - `/setting/mode/astra_probe.log`
  - `/tmp/astra_probe.log`
  追加一行 `ASTRA_PROBE_OK pid=<pid>`

**不改内存、不打补丁、不装钩子。** 只是证明 preload 真的生效了。

## 2. a6600 的 preload 机制（机身自带，非本项目发明）

`/usr/bin/bootin.elf` 读 `/setting/mode/dmode` 与 `/setting/mode/preload`，把后者拼成
`LD_PRELOAD="<路径>" im.elf …` 再 `system()` 拉起主程序。

`/usr/bin/change_mode.sh` 是索尼自带的开关：

```sh
change_mode.sh p /setting/mode/astra_probe.so   # dmode=3p, preload=<path>
change_mode.sh 3                                # 恢复默认（清空 preload）
```

可用模式（原厂脚本原文）：`0..6` 正常启动档位、`7` LeakTracer、`8` wcheck、`9` KMC ICE、
`a` target gdb、`b` gdbserver、`d` DUMA、`e` eFence、`f` jemalloc、`10` mcheckb、`p` 自定义 preload。

## 3. 安装（**必须等写通道确认后再做**）

前置：能把文件写进 `/setting`（vfat，nflasha2 @0x00800000，20MB）。目前三条候选通道都还没验证：

1. PMCA `serviceshell`（A6400 同 SoC 可行，a6600 未验证）
2. UART 串口 root shell（anlock6600 称 init 每次启动都开，但 a6600 主板的测试点未定位）
3. 官方升级包 `0800_appli/setting/*` 覆盖（拷贝步骤未识别）

写入步骤（有通道后）：

```
cp astra_probe.so /setting/mode/
change_mode.sh p /setting/mode/astra_probe.so
# 断电，取电池 10 秒，冷启动
cat /setting/mode/astra_probe.log     # 应看到 ASTRA_PROBE_OK pid=...
```

## 4. 撤销

```
change_mode.sh 3            # 清空 preload，恢复原厂启动链
rm -f /setting/mode/astra_probe.so
```

## 5. 风险（真实存在，别忽略）

- **preload 库在 `im.elf` 启动阶段加载**：如果它崩溃，`im.elf` 起不来，**相机 UI 会一直黑屏/卡住，且无法从相机界面恢复**——只能靠 USB/串口把文件删掉。
  （anlock6600 文档 §7.4 原话：“Recoverable from the serial shell (delete the file) but **not** from the camera UI”。）
- 所以**在拿到可靠的写/删通道之前，不要装**。
- 这个探针本身没有副作用，但“能装”和“能删”必须成对具备。

## 6. 构建

```sh
python -m ziglang cc -target arm-linux-gnueabihf -O2 -fPIC -shared -nostdlib \
  -Wl,-soname,astra_probe.so -o astra_probe.so probe.c
# e_flags 0x05000400 -> 0x05000002（对齐机身 LeakTracer.so）
```

## 7. 校验值

| 文件 | 大小 | SHA-256 |
|---|---|---|
| `astra_probe.so` | 5,232 B | `40a897b40b7d01e8469526c4accf9d06de5f7f413e10b5dd2f07b4fb4bbde6ac` |
| `probe.c` | — | 见仓库 |
