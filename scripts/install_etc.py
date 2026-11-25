#!/usr/bin/env python3
"""Install the probe into /etc and set /etc/ld.so.preload -- via file control only (no shell)."""
import hashlib
import sys
from pathlib import Path

SO = Path("/root/a6600/astra_probe.so")
CAM_SO = "/etc/astra_probe.so"
CAM_PRELOAD = "/etc/ld.so.preload"


def main():
    data = SO.read_bytes()
    print(f"local so {len(data)} B sha256={hashlib.sha256(data).hexdigest()}", flush=True)

    sys.path.insert(0, "/root/a6600/pmca-vendor")
    from pmca.commands.usb import senserShellCommand

    def cb(cam):
        try:
            cam.deleteFile(CAM_PRELOAD)
        except Exception as exc:
            print(f"(no existing preload: {type(exc).__name__})", flush=True)
        try:
            cam.deleteFile(CAM_SO)
        except Exception:
            pass

        print("writing so...", flush=True)
        cam.writeFile(CAM_SO, data)
        back = cam.readFile(CAM_SO)
        print(f"readback so {len(back)} B match={back == data}", flush=True)

        print("writing ld.so.preload...", flush=True)
        cam.writeFile(CAM_PRELOAD, (CAM_SO + "\n").encode())
        pre = cam.readFile(CAM_PRELOAD)
        print(f"readback preload = {pre!r}", flush=True)

    senserShellCommand(driverName="libusb", complete=cb)


if __name__ == "__main__":
    main()
