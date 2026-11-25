#!/usr/bin/env python3
"""Upload astra_probe.so to /setting/mode and point the preload at it (cycle 2)."""
import hashlib
import re
import sys
import time
from pathlib import Path

LOCAL_SO = Path("/root/a6600/astra_probe.so")
CAM_SO = "/setting/mode/astra_probe.so"
EXPECT_SHA = "40a897b40b7d01e8469526c4accf9d06de5f7f413e10b5dd2f07b4fb4bbde6ac"


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
    return re.sub(r"__PMCA_RC:\d+__", "", bytes(out).decode("latin1", "replace")).strip(), rc


def main():
    data = LOCAL_SO.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    print(f"local {LOCAL_SO} {len(data)} B sha256={sha}", flush=True)
    assert sha == EXPECT_SHA, "本地文件哈希不符"

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
            print("uploading...", flush=True)
            cam.writeFile(CAM_SO, data)

            checks = [
                ("ls",        f'ls -l {CAM_SO} 2>&1'),
                ("sha",       f'sha256sum {CAM_SO} 2>&1 || md5sum {CAM_SO} 2>&1'),
                ("loader",    'ls -l /lib/ld-* 2>&1'),
                ("ldlist",    f'/lib/ld-2.11.2.so --list {CAM_SO} 2>&1'),
                ("setcfg",    f'/usr/bin/change_mode.sh p {CAM_SO} 2>&1'),
                ("dmode",     'cat /setting/mode/dmode 2>&1; echo'),
                ("preload",   'cat /setting/mode/preload 2>&1; echo'),
                ("sync",      'sync; echo SYNC_OK'),
            ]
            for label, cmd in checks:
                out, rc = run_cmd(cam, cmd)
                report.append(f"=== {label} (rc={rc}) ===\n{out}\n")
                print(f"[{label}] rc={rc}", flush=True)
        finally:
            try:
                cam.setTerminalEnable(False)
            except Exception:
                pass

    senserShellCommand(driverName="libusb", complete=cb)
    text = "\n".join(report)
    Path("a6600-deploy.txt").write_text(text, encoding="utf-8")
    print("\n" + text, flush=True)


if __name__ == "__main__":
    main()
