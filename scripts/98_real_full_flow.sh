#!/bin/bash
# Full read-only flow with usbipd --auto-attach already watching:
#   switch to service mode -> (auto-attach follows) -> serviceshell -> pull files
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
OUT=/root/astra/realcam
mkdir -p "$OUT"

timeout 900 python3 - <<'PY' 2>&1 | grep -v SyntaxWarning | tail -60
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location(
    "axmlstub",
    "<WORKSPACE>/02-脚本/98_pmca_axml_stub.py")
spec.loader.exec_module(importlib.util.module_from_spec(spec))

from pmca.commands.usb import importDriver, getDevice, listDevices
from pmca.usb.sony import (SonyMscExtCmdDevice, SonySenserAuthDevice,
                           SonySenserDevice)
from pmca.platform import CameraShell
from pmca.platform.backend.senser import SenserPlatformBackend
from pmca.usb.sony import SonySenserCamera

with importDriver('libusb') as driver:
    device = getDevice(driver)
    print("initial:", type(device).__name__ if device else None, flush=True)
    if device is None:
        sys.exit("no device")

    if isinstance(device, SonyMscExtCmdDevice):
        print("switching to service mode...", flush=True)
        dev = SonySenserAuthDevice(device.driver)
        dev.start()
        dev.authenticate()
        print("waiting for re-enumeration (auto-attach active)...", flush=True)
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
                print("found service device after %ds" % (i + 1), flush=True)
                break
        dev.stop()
        if senser is None:
            sys.exit("service device not found")
        device = senser

    print("authenticating...", flush=True)
    dev = SonySenserAuthDevice(device.driver)
    dev.start()
    dev.authenticate()
    try:
        cam = SonySenserCamera(device)
        print("service shell ready", flush=True)
        # Non-interactive: drive CameraShell with our own stdin lines.
        shell = CameraShell(SenserPlatformBackend(cam))
        shell.run()
    finally:
        dev.stop()
PY
