#!/usr/bin/env python3
"""Remove /etc/ld.so.preload via the Senser file-control protocol (no shell needed)."""
import sys


def main():
    sys.path.insert(0, "/root/a6600/pmca-vendor")
    from pmca.commands.usb import senserShellCommand

    def cb(cam):
        for path in ("/etc/ld.so.preload", "/tmp/ld.so.preload"):
            try:
                cam.deleteFile(path)
                print(f"deleted {path}", flush=True)
            except Exception as exc:
                print(f"delete {path} failed: {type(exc).__name__}: {exc}", flush=True)

    senserShellCommand(driverName="libusb", complete=cb)


if __name__ == "__main__":
    main()
