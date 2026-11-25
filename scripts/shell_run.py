#!/usr/bin/env python3
"""Run arbitrary shell commands on the camera's Senser terminal (caller's responsibility)."""
import re
import sys
import time

CMD_TIMEOUT = float(__import__("os").environ.get("CAM_TIMEOUT", "20"))


def run_cmd(cam, cmd, timeout=CMD_TIMEOUT):
    dev = cam.dev
    pat = re.compile(rb"__PMCA_RC:(\d+)__")
    out = bytearray()
    rc = None
    try:
        dev.writeTerminal(b"\x03\n")
        time.sleep(0.15)
        dev.readTerminal()
    except Exception:
        pass
    dev.writeTerminal(f"{cmd}; printf '\\n__PMCA_RC:%s__\\n' $?\n".encode())
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            chunk = dev.readTerminal()
        except Exception:
            break
        if chunk:
            out.extend(chunk)
            m = pat.search(out)
            if m:
                rc = int(m.group(1))
                time.sleep(0.05)
                try:
                    more = dev.readTerminal()
                    if more:
                        out.extend(more)
                except Exception:
                    pass
                break
        else:
            time.sleep(0.01)
    return re.sub(r"__PMCA_RC:\d+__", "", bytes(out).decode("latin1", "replace")).strip(), rc


def main():
    cmds = sys.argv[1:]
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
            for cmd in cmds:
                out, rc = run_cmd(cam, cmd)
                print(f"$ {cmd}\n[rc={rc}]\n{out}\n", flush=True)
        finally:
            try:
                cam.setTerminalEnable(False)
            except Exception:
                pass

    senserShellCommand(driverName="libusb", complete=cb)


if __name__ == "__main__":
    main()
