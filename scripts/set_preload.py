#!/usr/bin/env python3
"""Write /setting/mode/{dmode,preload} via Sony's own change_mode.sh (no custom code)."""
import re
import sys
import time
from pathlib import Path

PRELOAD = sys.argv[1] if len(sys.argv) > 1 else "/setting/mode/does-not-exist.so"

COMMANDS = [
    ("change",  f'/usr/bin/change_mode.sh p {PRELOAD} 2>&1'),
    ("dmode",   'cat /setting/mode/dmode 2>&1; echo'),
    ("preload", 'cat /setting/mode/preload 2>&1; echo'),
    ("sync",    'sync; echo SYNC_OK'),
    ("listing", 'ls -la /setting/mode 2>&1'),
]


def run_cmd(cam, cmd, timeout=20.0):
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

    print(f"== 写入 preload 配置: {PRELOAD} ==", flush=True)
    senserShellCommand(driverName="libusb", complete=cb)
    text = "\n".join(report)
    Path("a6600-setcfg.txt").write_text(text, encoding="utf-8")
    print("\n" + text, flush=True)


if __name__ == "__main__":
    main()
