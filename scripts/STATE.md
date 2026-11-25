# a6600 探针 — 断点续做状态（重启前存档）

时间：2026-11-20 19:5x（Asia/Shanghai）

## 已完成

| 项 | 状态 |
|---|---|
| 相机已连接 | ✅ `USB\VID_054C&PID_0D0E\CFD19056970C`（USB 大容量存储设备） |
| Windows 直连 libusb | ❌ 只能枚举，打开报 `NotImplementedError`（设备绑定在 MSC 驱动上） |
| WSL 功能 | ✅ `VirtualMachinePlatform` / `Microsoft-Windows-Subsystem-Linux` 已启用，**等待重启** |
| usbipd-win | ✅ 已装 v5.3.0（PATH 需新开窗口） |
| 探针脚本 | ✅ `a6600_probe/probe_readonly.py`（只读，17 条命令，带禁止词过滤） |
| PMCA 依赖 | ✅ vendored 副本 `repo/tools/flash/camtool/vendor` + `a6600_probe/config.py` 桩；import 已验证 |
| 固件解包 | ✅ `a6600_fw/`（1.10，nflasha15=/usr 802 文件，libObj.so 哈希与 anlock6600 一致） |

## 重启后要做的（按顺序）

```powershell
# 1) 管理员 PowerShell：装发行版（不自动启动）
wsl --install -d Ubuntu --no-launch
wsl --set-default-version 2
wsl -l -v
```

```powershell
# 2) 用 root 直接跑（--no-launch 不会让你设用户）
wsl -d Ubuntu -u root -- bash -lc "apt update && apt install -y python3-usb libusb-1.0-0 usbutils"
```

```bash
# 3) Ubuntu 里（root 或普通用户）
mkdir -p ~/a6600 && cp -r "<LEGACY_WORKSPACE>/a6600_probe" ~/ && cp -r "<LEGACY_WORKSPACE>/repo/tools/flash/camtool/vendor" ~/pmca-vendor
```

```powershell
# 4) 管理员 PowerShell（保持打开）
usbipd list
usbipd bind --busid <BUSID>
usbipd attach --wsl --auto-attach --busid <BUSID>
```

```bash
# 5) Ubuntu
cd ~/a6600_probe && sudo python3 probe_readonly.py --pmca-dir ~/pmca-vendor
```

## 停止条件（不变）

- `lsusb | grep -i 054c` 无输出 → 重新 attach
- 探针卡 60s → Ctrl+C、拔线、取电池 10 秒
- 相机不开机/红灯不亮 → 立刻报

## 关键路径

- 探针：`<LEGACY_WORKSPACE>\a6600_probe\`
- PMCA：`...\repo\tools\flash\camtool\vendor\`
- 固件产物：`...\a6600_fw\`
- 说明：`a6600_probe\README.md`
