#!/usr/bin/env python3
"""Force an exec inside the service shell, then read the probe log via file control."""
import re
import sys
import time


def main():
    sys.path.insert(0, "/root/a6600/pmca-vendor")
    from pmca.commands.usb import senserShellCommand

    def cb(cam):
        # 1) make the camera exec a dynamically linked binary (busybox)
        cam.setTerminalEnable(True)
        time.sleep(0.5)
        try:
            cam.dev.readTerminal()
        except Exception:
            pass
        for cmd in ("/bin/busybox true", "/bin/busybox ls /setting/mode"):
            cam.dev.writeTerminal(f"{cmd}\n".encode())
            time.sleep(0.6)
            try:
                out = cam.dev.readTerminal()
                print(f"[term] {cmd} -> {len(out)} bytes", flush=True)
            except Exception as exc:
                print(f"[term] {cmd} -> {type(exc).__name__}", flush=True)
        time.sleep(0.5)
        try:
            cam.setTerminalEnable(False)
        except Exception:
            pass

        # 2) read the logs via file control
        for path in ("/tmp/astra_probe.log", "/setting/mode/astra_probe.log"):
            try:
                data = cam.readFile(path)
                print(f"=== {path} ({len(data)} B) ===\n{data.decode('latin1', 'replace')}", flush=True)
            except Exception as exc:
                print(f"=== {path} -> {type(exc).__name__}: {exc}", flush=True)

    senserShellCommand(driverName="libusb", complete=cb)


if __name__ == "__main__":
    main()
