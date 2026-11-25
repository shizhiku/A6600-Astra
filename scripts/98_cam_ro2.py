#!/usr/bin/env python3
"""READ-ONLY camera inspection via PMCA service mode (clean exit).

Switches camera to service mode, authenticates, enters the BusyBox shell,
runs read-only commands, then exits the shell cleanly (no Ctrl+C) so the
camera returns to mass-storage mode without leaving a stale session.

Usage: 98_cam_ro2.py "cmd1" "cmd2" ...
"""
import importlib.util
import os
import pty
import select
import sys
import time

STUB = ("<WORKSPACE>/02-脚本/"
        "98_pmca_axml_stub.py")

BOOT = '''
import importlib.util, sys, runpy
spec = importlib.util.spec_from_file_location("axmlstub", %r)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sys.argv = ["pmca-console.py", "serviceshell"]
runpy.run_path("pmca-console.py", run_name="__main__")
''' % STUB


def main():
    cmds = sys.argv[1:]
    if not cmds:
        print("usage: 98_cam_ro2.py cmd...", file=sys.stderr)
        return 2

    pid, fd = pty.fork()
    if pid == 0:
        os.chdir("/root/astra/Sony-PMCA-RE")
        os.execvp("python3", ["python3", "-c", BOOT])

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
        try:
            os.close(fd)
        except OSError:
            pass
        return 1

    os.write(fd, b"shell\n")
    out = drain(30)
    sys.stdout.write(out)
    sys.stdout.flush()

    for cmd in cmds:
        os.write(fd, (cmd + "\n").encode())
        out = drain(15)
        sys.stdout.write(out)
        sys.stdout.flush()

    # Clean exit: leave the camera shell, then the platform shell, then PMCA.
    os.write(fd, b"exit\n")
    drain(6)
    os.write(fd, b"exit\n")
    drain(6)
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.waitpid(pid, os.WNOHANG)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
