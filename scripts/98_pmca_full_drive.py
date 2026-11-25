#!/usr/bin/env python3
"""Switch to service mode (auto-attach follows) and drive the platform shell
with a list of commands.  READ-ONLY unless the caller passes write commands.

Usage: 98_pmca_full_drive.py "cmd1" "cmd2" ...
"""
import importlib.util
import sys
import time

STUB = ("<WORKSPACE>/02-脚本/"
        "98_pmca_axml_stub.py")
spec = importlib.util.spec_from_file_location("axmlstub", STUB)
spec.loader.exec_module(importlib.util.module_from_spec(spec))

from pmca.commands.usb import importDriver, getDevice, listDevices
from pmca.usb.sony import (SonyMscExtCmdDevice, SonySenserAuthDevice,
                           SonySenserDevice, SonySenserCamera)
from pmca.platform import CameraShell
from pmca.platform.backend.senser import SenserPlatformBackend


def main():
    cmds = sys.argv[1:]
    with importDriver("libusb") as driver:
        device = getDevice(driver)
        print("initial device:", type(device).__name__ if device else None,
              flush=True)
        if device is None:
            return 1

        if isinstance(device, SonyMscExtCmdDevice):
            print("switching to service mode...", flush=True)
            dev = SonySenserAuthDevice(device.driver)
            dev.start()
            dev.authenticate()
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
                    print("service device appeared after %ds" % (i + 1),
                          flush=True)
                    break
            dev.stop()
            if senser is None:
                print("service device not found", flush=True)
                return 1
            device = senser
        elif not isinstance(device, SonySenserDevice):
            print("unexpected device type; abort", flush=True)
            return 1

        print("authenticating...", flush=True)
        dev = SonySenserAuthDevice(device.driver)
        dev.start()
        dev.authenticate()
        try:
            cam = SonySenserCamera(device)
            shell = CameraShell(SenserPlatformBackend(cam))
            # Feed commands through stdin by monkeypatching input() is fragile;
            # instead run the shell with our command list appended to stdin.
            import io
            sys.stdin = io.StringIO("\n".join(cmds) + "\nexit\n")
            shell.run()
        finally:
            dev.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
