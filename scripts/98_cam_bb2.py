#!/usr/bin/env python3
"""Drive the camera's BusyBox shell when the camera is ALREADY in service
mode (054c:0336) and attached.

Uses PMCA's own serviceshell code path with pty so we can inject `shell`
and then send commands.  READ-ONLY.

Usage: 98_cam_bb2.py "cmd1" "cmd2" ...
"""
import os
import pty
import select
import sys
import time

STUB = ("<WORKSPACE>/02-脚本/"
        "98_pmca_axml_stub.py")

BOOT_TEMPLATE = r'''
import importlib.util, sys, runpy
spec = importlib.util.spec_from_file_location("axmlstub", "@STUB@")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sys.argv = ["pmca-console.py", "serviceshell"]
runpy.run_path("pmca-console.py", run_name="__main__")
'''


def main():
    cmds = sys.argv[1:]
    if not cmds:
        print("usage: 98_cam_bb2.py cmd...", file=sys.stderr)
        return 2

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

    text = drain(120)
    sys.stdout.write(text)
    sys.stdout.flush()

    if "platform shell" not in text:
        print("!! platform shell not reached", file=sys.stderr)
        try:
            os.close(fd)
        except OSError:
            pass
        return 1

    # enter BusyBox terminal
    os.write(fd, b"shell\n")
    out = drain(30)
    sys.stdout.write(out)
    sys.stdout.flush()

    for cmd in cmds:
        os.write(fd, (cmd + "\n").encode())
        out = drain(12)
        sys.stdout.write(out)
        sys.stdout.flush()

    # clean exit from BusyBox + platform shell
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
