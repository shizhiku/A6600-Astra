#!/usr/bin/env python3
"""Run a list of shell commands (one per line, from a file) on the camera."""
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, "/root/a6600/probe")
from shell_run import run_cmd  # noqa: E402

CMDS = [ln.rstrip("\n") for ln in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.startswith("#")]


def main():
    sys.path.insert(0, "/root/a6600/pmca-vendor")
    from pmca.commands.usb import senserShellCommand

    def cb(cam):
        cam.setTerminalEnable(True)
        time.sleep(0.6)
        try:
            cam.dev.readTerminal()
        except Exception:
            pass
        try:
            for cmd in CMDS:
                out, rc = run_cmd(cam, cmd, timeout=25)
                print(f"$ {cmd}\n[rc={rc}]\n{out}\n", flush=True)
        finally:
            try:
                cam.setTerminalEnable(False)
            except Exception:
                pass

    senserShellCommand(driverName="libusb", complete=cb)


if __name__ == "__main__":
    main()
