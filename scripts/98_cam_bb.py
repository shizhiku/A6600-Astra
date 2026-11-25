#!/usr/bin/env python3
"""READ-ONLY camera BusyBox shell driver (handles both MSC and service mode).

Enters the camera's BusyBox shell via the platform shell's `shell` command,
then runs the given read-only commands, then exits cleanly.

Usage: 98_cam_bb.py "cmd1" "cmd2" ...
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
        sw.start()
        sw.authenticate()
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
                print("service device after " + str(i + 1) + "s", flush=True)
                break
        sw.stop()
        if senser is None:
            sys.exit("service device not found")
        target = senser
    elif isinstance(dev0, SonySenserDevice):
        print("already in service mode", flush=True)
        target = dev0
    else:
        sys.exit("unexpected device")

    print("authenticating...", flush=True)
    dev = SonySenserAuthDevice(target.driver)
    dev.start()
    dev.authenticate()
    try:
        cam = SonySenserCamera(target)
        backend = SenserPlatformBackend(cam)
        shell = CameraShell(backend)

        # Drive it ourselves so we can insert `shell` before user commands.
        import pmca.platform as P
        orig_run = CameraShell.run

        def run(self):
            self.backend.start()
            try:
                from pmca.shell import Shell
                import io
                # platform shell: run "shell" first (enters BusyBox terminal)
                self._commands["shell"].run(None)
                # now the camera terminal is bridged; feed subsequent lines
                for c in CMDS:
                    self.backend.dev.dev.writeTerminal((c + "\n").encode())
                    time.sleep(0.45)
                self.backend.dev.dev.writeTerminal(b"exit\n")
                time.sleep(0.6)
            finally:
                self.backend.stop()

        shell.run = run.__get__(shell, CameraShell)
        shell.run()
    finally:
        dev.stop()
'''


def main():
    cmds = sys.argv[1:]
    if not cmds:
        print("usage: 98_cam_bb.py cmd...", file=sys.stderr)
        return 2

    boot = ("CMDS = " + repr(cmds) + "\n"
            + BOOT_TEMPLATE.replace("@STUB@", STUB))

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

    text = drain(180)
    sys.stdout.write(text)
    sys.stdout.flush()
    try:
        os.close(fd)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
