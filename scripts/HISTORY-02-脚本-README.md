# a6600 只读服务通道探针（L0.5）

**这一步只做一件事：确认你的 a6600 有没有和 A6400 一样的 USB 服务通道。**
探针只发读取命令（`cat` / `ls` / `ps` / `df`），不写文件、不删文件、不 mount、不重启。

唯一的“状态变化”是进入/退出 Sony 服务模式（USB `054C:xxxx` → `054C:0336`），
这和 A6400 Extra-Menu 的部署流程是同一个动作，只是我们不写任何东西。

---

## 为什么必须用 WSL2（而不是 Windows 直连）

Senser 通道走的是 USB 厂商自定义命令，Windows 自带的 MSC 驱动不转发这类命令，
所以要么把相机接口绑给 libusb（Zadig，Windows 11 上经常被内核隔离/驱动签名搞坏），
要么把 USB 透传进 WSL2（不改 Windows 任何驱动）。A6400 项目也是这么建议的。

---

## 步骤

### 0. 检查（30 秒，不改任何东西）

管理员 PowerShell：

```powershell
wsl --status
winget --version
```

`wsl --status` 报「未安装」是正常的，继续。

### 1. 装 WSL2 + Ubuntu（约 10–20 分钟，可能重启一次）

管理员 PowerShell：

```powershell
wsl --install -d Ubuntu
```

装完按提示设一个 Linux 用户名/密码，然后：

```powershell
wsl -l -v
```

确认 `VERSION` 是 **2**（不是 1）。如果是 1：`wsl --set-version Ubuntu 2`。

### 2. 装 usbipd-win（1 分钟）

管理员 PowerShell：

```powershell
winget install --exact dorssel.usbipd-win
```

装完**关掉这个窗口再开一个新的**（刷新 PATH）。

### 3. 在 Ubuntu 里装依赖（1 分钟）

```bash
sudo apt update
sudo apt install -y python3-usb libusb-1.0-0 usbutils
```

### 4. 相机设置（重要）

- 电量 > 50%，装好 SD 卡（不用管卡里有什么，探针不碰它）
- `MENU → 设置 → USB → USB 连线` = **大容量储存（Mass Storage）**
- `USB LUN 设定` = **多重**
- 用**能传数据**的线（只能充电的线不行）

### 5. 把相机挂进 WSL（每次探测都要做）

相机插上后，**管理员 PowerShell**：

```powershell
usbipd list
```

找到那行 `054c:` 开头的（BUSID 形如 `2-3`），然后：

```powershell
usbipd bind --busid 2-3
usbipd attach --wsl --auto-attach --busid 2-3
```

> **这个 PowerShell 窗口不要关**。后面相机会重枚举成 `054c:0336`，
> `--auto-attach` 才会把它自动接回 WSL。

在 Ubuntu 里验证：

```bash
lsusb | grep -i 054c
```

能看到 `054c:` 就对了。

### 6. 跑探针

Ubuntu 里：

```bash
cd <LEGACY_WORKSPACE>/a6600_probe

sudo python3 probe_readonly.py \
  --pmca-dir <LEGACY_WORKSPACE>/repo/tools/flash/camtool/vendor
```

预期：先打印 `Using drivers ...`，然后逐条 `[label] rc=0`，最后打印整份报告。

**相机屏幕可能变黑、按键无反应——这是正常现象**，探针结束会退出服务模式。

### 7. 把结果发回来

报告会存成 `a6600-probe-<时间>.txt`。把里面的内容贴回来（**注意**：里面会有序列号/固件版本，介意的话先自己删掉再发）。

---

## 中途停下来的条件

| 现象 | 怎么办 |
|---|---|
| `usbipd attach` 报错 / `lsusb` 看不到 054c | 停。换线/换口，重跑第 5 步；仍不行就告诉我 |
| 探针打印 `[X] 连接失败` | 停。把整段输出发我 |
| 卡在服务模式超过 60 秒没输出 | `Ctrl+C`，拔线，**取电池 10 秒**装回再开机 |
| 相机拔电池后不开机 / 红灯不亮 | 立刻停手，告诉我（这种情况极罕见，但必须说清） |

**不要**在探针跑的过程中拔线、关机、按相机按键。

---

## 备选：不走 WSL（不推荐）

如果你坚持不装 WSL，可以试 Windows 直连：

1. 装 [Zadig](https://zadig.akeo.ie/)，给相机的 `054c:` 设备装 **libusb-win32**（不是 WinUSB）
2. 相机重枚举成 `054c:0336` 后再开一次 Zadig，给它也装 libusb-win32
3. 在 Windows 直接跑 `python a6600_probe\probe_readonly.py --pmca-dir repo\tools\flash\camtool\vendor`

失败率明显更高（Win11 内核隔离 / 驱动签名），装坏了要手动去设备管理器卸载驱动。

---

## 这一步能证明什么

- `/proc/mounts` 里 `/setting` 是 `rw` 还是 `ro` → **能不能写**
- `/setting/mode/` 是否存在、`dmode`/`preload` 当前内容 → **preload 槽位状态**
- `/usr/bin/change_mode.sh` 在不在 → **切换工具在不在**
- `/usr/lib/libJiritsu.so`、`libInfraMscServer.so` 在不在 → **服务栈是否与 A6400 同构**

如果这一步通了，下一步（L1）才是往 `/setting` 放那个 5 KB 的探针 `.so`。
那一步仍然是**可撤销**的（`change_mode.sh 3` 即恢复原厂启动链）。
