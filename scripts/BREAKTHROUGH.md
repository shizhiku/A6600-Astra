# a6600 突破记录：USB 服务通道 + 写权限已确认

时间：2026-11-20 20:26（Asia/Shanghai）
状态：**只读探测完成，未修改相机任何持久内容**（唯一的写操作是创建并立即删除一个 1 字节测试文件）

## 一、达成的事

通过 USB（WSL2 + usbipd + PMCA Senser），在 **未拆机、未刷机、未改任何分区** 的前提下，
拿到了 a6600 的 **root shell**（`/usr/share/app #`，uid=0）。

流程回顾：
1. 相机 → `054C:0D0E`（大容量储存）
2. PMCA 认证 → 相机切服务模式 → `054C:0336`
3. usbipd 把 `0336` 透传进 WSL → PMCA 认证 → ash shell

## 二、相机内部实况（实测）

| 项 | 值 |
|---|---|
| 内核 | `3.0.27_nl-rt106+` SMP PREEMPT RT，Sony CE Linux 8.2.6.0，2021-04-10 编译 |
| CPU | ARMv7 Cortex-A5（`0xc05`）×4，**无 NEON**，`Hardware: ARM-CXD900X0` |
| 内存 | 1 GB + 256 MB（`mem=1G@0 mem=256M@0x80000000@1`） |
| 分区 | nflasha1..18/B0/B1，与 `partinf.conf` 完全一致 |
| `/usr` | `/dev/nflasha15` **ro** ext2 |
| `/setting` | `/dev/nflasha2` **rw** vfat |
| `/tmp` + `/etc` | **同一个** `/dev/nflasha10`（rw vfat，双挂载，A6400 也这样） |
| `/system` | nflasha3 rw vfat |
| busybox | v1.29.3（2018-12-07），**没有** `id`/`df`/`awk`/`head`/`tail`/`ps` |
| `/setting/mode/` | 存在，**权限 0777，空的**（无 dmode / 无 preload） |
| `/usr/bin/` | `bootin.elf` 13,068 B、`change_mode.sh` 4,022 B（属主 57285:1000） |
| `/usr/tool/` | `LeakTracer.so`、`libefence.so`、`libjemalloc_tsh.so.1`、`libmcheckb.so`、`LeakCheck` |
| `/system/sabin/` | `ssboot.bin`、`ssboot_any.bin`、`idt_cam.bin`、`sa_dfdet.bin` |
| 服务库 | `libJiritsu.so`、`libInfraMscServer.so`、`libptp.so` 全部在位 |

**写权限实测**：`touch /setting/mode/.dsh_rw_test` → 成功 → `rm` → `RW_TEST_OK`。

## 三、下一步（L1）设计

a6600 的 `bootin.elf` 会读 `/setting/mode/{dmode,preload}`，拼成
`LD_PRELOAD="<preload>" im.elf …`。

**两轮验证，把风险压到最低：**

### 第 1 轮（零代码，验证配置链路）
```sh
change_mode.sh p /setting/mode/does-not-exist.so
```
`ld.so` 对不存在的 preload **只会告警并忽略**，im.elf 照常启动。
→ 冷启动后若相机正常进 UI，说明 `dmode` 解析 + preload 拼接链路在 a6600 上成立且安全。

### 第 2 轮（我们的 5 KB 探针）
```sh
cp astra_probe.so /setting/mode/
change_mode.sh p /setting/mode/astra_probe.so
```
→ 冷启动后检查 `/setting/mode/astra_probe.log` 是否有 `ASTRA_PROBE_OK pid=…`。

## 四、回滚

```sh
change_mode.sh 3          # 清 preload，恢复原厂启动链
rm -f /setting/mode/astra_probe.so
```

## 五、已知风险（唯一真实风险点）

若 preload 的 `.so` 让 `im.elf` 起不来，**相机 UI 不启动，USB 服务模式可能也不再出现**
（USB gadget 由 im.elf 的 `libInfraMscServer` 建立）。那时只能靠 UART 串口 shell 删文件，
而 **a6600 的 UART 测试点尚未定位**（anlock6600 也只写到"未知"）。

缓解：
- 我们的 `.so` 无 `DT_NEEDED`、无未定义符号、`e_flags=0x05000002`（与机身 `LeakTracer.so` 一致），
  构造器只做 open/write/close，失败即静默返回 —— 加载层面几乎不可能失败。
- 先跑第 1 轮（不存在的文件）确认链路，再上真库。

## 六、环境（本机）

- WSL2 Ubuntu（Python 3.14），`python3-usb`、`python3-pycryptodome`（提供 `Cryptodome`）
- PMCA：`/root/a6600/pmca-vendor`（来自 ZV-E10 仓库 vendored 副本）
- 探针：`/root/a6600/probe/probe_readonly.py`、`probe_writetest.py`
- 日志：`probe-out.txt`、`probe-out2.txt`（已回拷到 Windows 工作区）

### 每轮探测的命令模板
```powershell
# 1) 相机插好（054C:0D0E）后
usbipd bind --busid 1-1 --force
usbipd attach --wsl Ubuntu --auto-attach --busid 1-1   # 后台常驻
# 2) 跑脚本（会自动切 0336；若超时，等 3 秒再跑一次即可）
wsl -d Ubuntu -u root -- bash -lc "cd /root/a6600/probe && python3 probe_readonly.py --pmca-dir /root/a6600/pmca-vendor"
```
