#!/usr/bin/env python3
"""Read probe logs via the Senser file-control protocol (no shell/terminal)."""
import sys


def main():
    sys.path.insert(0, "/root/a6600/pmca-vendor")
    from pmca.commands.usb import senserShellCommand

    def cb(cam):
        for path in ("/setting/mode/astra_probe.log", "/tmp/astra_probe.log"):
            try:
                data = cam.readFile(path)
                print(f"=== {path} ({len(data)} B) ===", flush=True)
                print(data.decode("latin1", "replace"), flush=True)
            except Exception as exc:
                print(f"=== {path} -> {type(exc).__name__}: {exc}", flush=True)
        for path in ("/etc/ld.so.preload", "/etc/astra_probe.so"):
            try:
                data = cam.readFile(path)
                print(f"=== {path} ({len(data)} B) ===", flush=True)
                print(data[:80], flush=True)
            except Exception as exc:
                print(f"=== {path} -> {type(exc).__name__}: {exc}", flush=True)

    senserShellCommand(driverName="libusb", complete=cb)


if __name__ == "__main__":
    main()
