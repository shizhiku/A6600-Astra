#!/bin/bash
# Step 1: switch camera (in MSC mode, already attached to WSL) to service mode.
# Only sends the Sony senser switch command; no flash writes.
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
python3 - <<'PY' 2>&1 | grep -v SyntaxWarning | tail -30
import importlib.util, sys
spec = importlib.util.spec_from_file_location(
    "axmlstub",
    "<WORKSPACE>/02-脚本/98_pmca_axml_stub.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

import time
from pmca.usb import *
from pmca.usb.sony import *
from pmca.platform.backend import *
from pmca.util import *

with importDriver('libusb') as driver:
    device = getDevice(driver)
    if not device:
        print("no device")
        sys.exit(1)
    print("device:", type(device).__name__)
    if not isinstance(device, SonyMscExtCmdDevice):
        print("not in MSC mode")
        sys.exit(1)
    print("Switching to service mode")
    dev = SonySenserAuthDevice(device.driver)
    dev.start()
    dev.authenticate()
    print("switch command sent")
    time.sleep(6)
    dev.stop()
print("done")
PY
