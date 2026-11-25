#!/bin/bash
# Switch camera to service mode using PMCA's own logic (short-lived).
# It will report a timeout because usbipd can't auto-follow the re-enumeration;
# that is expected.  We only need the switch command to be delivered.
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
timeout 120 python3 - <<'PY' 2>&1 | tail -20
import importlib.util, sys, time
spec = importlib.util.spec_from_file_location(
    "axmlstub",
    "<WORKSPACE>/02-脚本/98_pmca_axml_stub.py")
spec.loader.exec_module(importlib.util.module_from_spec(spec))

from pmca.commands.usb import importDriver, getDevice
from pmca.usb.sony import SonyMscExtCmdDevice, SonySenserAuthDevice

with importDriver('libusb') as driver:
    device = getDevice(driver)
    print("device:", type(device).__name__)
    if not isinstance(device, SonyMscExtCmdDevice):
        print("not MSC"); sys.exit(1)
    dev = SonySenserAuthDevice(device.driver)
    dev.start()
    dev.authenticate()
    print("switch sent")
    time.sleep(5)
    dev.stop()
print("done")
PY
