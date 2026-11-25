#!/usr/bin/env python3
"""a6600 只读服务通道探针（Senser shell）。

对相机**只执行读取命令**：不写文件、不删文件、不 mount、不重启。
唯一会改变状态的动作是进入 Sony 服务模式（USB 054C:xxxx -> 054C:0336），
这与 A6400 Extra-Menu 的部署流程是同一个动作；探针结束会退出该模式。

用法（WSL2 / Linux）：
  sudo python3 probe_readonly.py \
      --pmca-dir <HOME>/.../repo/tools/flash/camtool/vendor

输出：屏幕上 + a6600-probe-<时间>.txt
"""
import argparse
import re
import sys
import time
from datetime import datetime
from pathlib import Path

# 只读命令白名单：label, shell command
COMMANDS = [
    ("identity",      'id; uname -a'),
    ("kernel",        'cat /proc/version'),
    ("cpuinfo",       'cat /proc/cpuinfo'),
    ("cmdline",       'cat /proc/cmdline'),
    ("partitions",    'cat /proc/partitions'),
    ("mounts",        'cat /proc/mounts'),
    ("setting-top",   'ls -la /setting 2>&1'),
    ("setting-mode",  'ls -la /setting/mode 2>&1'),
    ("dmode",         'cat /setting/mode/dmode 2>&1'),
    ("preload",       'cat /setting/mode/preload 2>&1'),
    ("change-mode",   'ls -l /usr/bin/change_mode.sh /usr/bin/bootin.elf 2>&1'),
    ("service-libs",  'ls -l /usr/lib/libJiritsu.so /usr/lib/libInfraMscServer.so /usr/lib/libptp.so 2>&1'),
    ("df",            'df -h /setting /usr /tmp 2>&1 || /bin/busybox df -h 2>&1'),
    ("rw-check",      "awk '$2==\"/setting\"||$2==\"/usr\"||$2==\"/tmp\"{print $2,$4}' /proc/mounts"),
    ("tmp-bt",        'ls -la /tmp_bt 2>&1 | head -20'),
    ("usb-state",     'cat /sys/class/udc/*/state 2>&1'),
    ("processes",     'ps 2>&1 | head -30'),
]

# 防御：任何包含这些词的命令一律拒绝执行（即使被误改）
DENY = re.compile(r"\b(rm|mv|cp|dd|mkfs|mount|umount|reboot|poweroff|kill|chmod|chown|echo.*>)\b")


def run_cmd(cam, cmd, timeout=15.0):
    """发送一条命令并等待 __PMCA_RC 标记（与 A6400 部署器同一套机制）。"""
    dev = cam.dev
    pat = re.compile(rb"__PMCA_RC:(\d+)__")
    out = bytearray()
    rc = None

    try:
        dev.writeTerminal(b"\x03\n")
        time.sleep(0.15)
        dev.readTerminal()
    except Exception:
        pass

    dev.writeTerminal(f"{cmd}; printf '\\n__PMCA_RC:%s__\\n' $?\n".encode())
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            chunk = dev.readTerminal()
        except Exception:
            break
        if chunk:
            out.extend(chunk)
            m = pat.search(out)
            if m:
                rc = int(m.group(1))
                time.sleep(0.05)
                try:
                    more = dev.readTerminal()
                    if more:
                        out.extend(more)
                except Exception:
                    pass
                break
        else:
            time.sleep(0.01)
    text = bytes(out).decode("latin1", errors="replace")
    text = re.sub(r"__PMCA_RC:\d+__", "", text).strip()
    return text, rc


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pmca-dir", required=True, help="PMCA 源码目录（含 pmca/ 包）")
    ap.add_argument("--out", default="", help="报告输出路径")
    args = ap.parse_args()

    sys.path.insert(0, str(Path(args.pmca_dir).resolve()))
    sys.path.insert(0, str(Path(__file__).resolve().parent))  # config.py
    from pmca.commands.usb import senserShellCommand

    report = []
    seen = {"ok": False}

    def callback(cam):
        cam.setTerminalEnable(True)
        time.sleep(0.6)
        try:
            cam.dev.readTerminal()
        except Exception:
            pass
        try:
            for label, cmd in COMMANDS:
                if DENY.search(cmd):
                    report.append(f"=== {label} ===\n[SKIPPED: 命中禁止词] {cmd}\n")
                    continue
                out, rc = run_cmd(cam, cmd)
                report.append(f"=== {label} (rc={rc}) ===\n{out}\n")
                print(f"[{label}] rc={rc}", flush=True)
            seen["ok"] = True
        finally:
            try:
                cam.setTerminalEnable(False)
            except Exception:
                pass

    print("== a6600 只读探针：正在寻找相机并进入服务模式 ==", flush=True)
    print("   （相机屏幕可能变黑，这是正常现象；期间不要拔线）", flush=True)
    try:
        senserShellCommand(driverName="libusb", complete=callback)
    except Exception as exc:
        print(f"\n[X] 连接失败: {type(exc).__name__}: {exc}", flush=True)
        print("    常见原因：相机不在『大容量储存』、线不支持数据、usbipd 没 attach、", flush=True)
        print("    或 PMCA 找不到 054C 设备。把这段输出原样发回来即可。", flush=True)
        raise SystemExit(1)

    text = "\n".join(report)
    out = Path(args.out) if args.out else Path(
        f"a6600-probe-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt")
    out.write_text(text, encoding="utf-8")
    print("\n" + text, flush=True)
    print(f"\n[+] 已保存: {out}", flush=True)
    if not seen["ok"]:
        print("[!] 没有执行完命令集，通道可能不稳定", flush=True)


if __name__ == "__main__":
    main()
