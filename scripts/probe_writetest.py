#!/usr/bin/env python3
"""Second-stage probe: confirm /setting is writable (1-byte file, created and removed)."""
import re
import sys
import time
from pathlib import Path

COMMANDS = [
    ("tool-dir",     'ls -l /usr/tool 2>&1'),
    ("sabin",        'ls -l /system/sabin 2>&1'),
    ("busybox",      'busybox 2>&1 | tail -5'),
    ("rw-test",      'touch /setting/mode/.dsh_rw_test && ls -l /setting/mode && rm -f /setting/mode/.dsh_rw_test && echo RW_TEST_OK'),
    ("setting-after",'ls -la /setting/mode 2>&1'),
    ("free",         'cat /proc/mounts | grep setting'),
    ("sd",           'cat /proc/partitions | grep mmca'),
]


def run_cmd(cam, cmd, timeout=15.0):
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
    return re.sub(r"__PMCA_RC:\d+__", "", text).strip(), rc


def main():
    sys.path.insert(0, "/root/a6600/pmca-vendor")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from pmca.commands.usb import senserShellCommand

    report = []

    def cb(cam):
        cam.setTerminalEnable(True)
        time.sleep(0.6)
        try:
            cam.dev.readTerminal()
        except Exception:
            pass
        try:
            for label, cmd in COMMANDS:
                out, rc = run_cmd(cam, cmd)
                report.append(f"=== {label} (rc={rc}) ===\n{out}\n")
                print(f"[{label}] rc={rc}", flush=True)
        finally:
            try:
                cam.setTerminalEnable(False)
            except Exception:
                pass

    print("== 第二阶段：写权限验证（只建/删一个 1 字节文件）==", flush=True)
    senserShellCommand(driverName="libusb", complete=cb)
    text = "\n".join(report)
    Path("a6600-write-test.txt").write_text(text, encoding="utf-8")
    print("\n" + text, flush=True)


if __name__ == "__main__":
    main()
