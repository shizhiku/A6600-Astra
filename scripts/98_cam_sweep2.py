#!/usr/bin/env python3
"""ONE-SHOT read-only camera sweep #2 (fixed shell syntax).

Fixes:
  - use `basename`-free PID lookup (busybox ash supports ${p##*/})
  - avoid `head` (not present in this busybox build)
  - print /usr/lib listing in chunks with a counter

READ-ONLY: no writes to camera.
"""
import os
import pty
import select
import sys
import time

STUB = ("<WORKSPACE>/02-脚本/"
        "98_pmca_axml_stub.py")

BOOT_TEMPLATE = r'''
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location("axmlstub", "@STUB@")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

from pmca.commands.usb import importDriver, getDevice, listDevices
from pmca.usb.sony import (SonyMscExtCmdDevice, SonySenserAuthDevice,
                           SonySenserDevice, SonySenserCamera)
from pmca.platform import CameraShell
from pmca.platform.backend.senser import SenserPlatformBackend

with importDriver("libusb") as driver:
    dev0 = getDevice(driver)
    print("initial:", type(dev0).__name__ if dev0 else None, flush=True)
    if dev0 is None:
        sys.exit(1)
    if isinstance(dev0, SonyMscExtCmdDevice):
        print("switching to service mode...", flush=True)
        sw = SonySenserAuthDevice(dev0.driver)
        sw.start(); sw.authenticate()
        senser = None
        for i in range(60):
            time.sleep(1)
            try:
                found = [d for d in listDevices(driver, True)
                         if isinstance(d, SonySenserDevice)]
            except Exception:
                found = []
            if found:
                senser = found[0]
                print("service device after " + str(i+1) + "s", flush=True)
                break
        sw.stop()
        if senser is None:
            sys.exit("service device not found")
        target = senser
    elif isinstance(dev0, SonySenserDevice):
        target = dev0
    else:
        sys.exit("unexpected device")

    print("authenticating...", flush=True)
    dev = SonySenserAuthDevice(target.driver)
    dev.start(); dev.authenticate()
    try:
        cam = SonySenserCamera(target)
        shell = CameraShell(SenserPlatformBackend(cam))
        shell.run()
    finally:
        dev.stop()
'''


CMDS = [
    "echo @@PID@@",
    "P=$(/bin/busybox pidof im.elf); echo PID=$P; "
    "cat /proc/$P/status",
    "echo @@MAPS@@",
    "cat /proc/$P/maps",
    "echo @@USRLIB_N@@",
    "ls /usr/lib | wc -l",
    "echo @@USRLIB@@",
    "ls -l /usr/lib",
    "echo @@USRBIN@@",
    "ls -l /usr/bin",
    "echo @@END@@",
]


def main():
    boot = BOOT_TEMPLATE.replace("@STUB@", STUB)

    pid, fd = pty.fork()
    if pid == 0:
        os.chdir("/root/astra/Sony-PMCA-RE")
        os.execvp("python3", ["python3", "-c", boot])

    def drain(timeout):
        end = time.time() + timeout
        got = b""
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.3)
            if not r:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            got += chunk
        return got.decode("utf-8", "replace")

    text = drain(150)
    sys.stdout.write(text)
    sys.stdout.flush()
    if "platform shell" not in text:
        print("!! platform shell not reached", file=sys.stderr)
        return 1

    os.write(fd, b"shell\n")
    out = drain(30)
    sys.stdout.write(out)
    sys.stdout.flush()

    for c in CMDS:
        os.write(fd, (c + "\n").encode())
        out = drain(25)
        sys.stdout.write(out)
        sys.stdout.flush()

    os.write(fd, b"exit\n")
    drain(5)
    os.write(fd, b"exit\n")
    drain(5)
    try:
        os.close(fd)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
