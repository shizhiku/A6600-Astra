#!/usr/bin/env python3
"""Drive Sony-PMCA-RE's interactive serviceshell to run read-only commands.

Spawns pmca-console.py serviceshell with a pty, waits for the shell prompt,
sends each command, captures output.  NO writes are issued: all commands are
read-only system queries.

Usage:  python3 98_pmca_shell_drive.py "cmd1" "cmd2" ...
"""
import importlib.util
import os
import pty
import re
import select
import sys
import time

ROOT = "/root/astra/Sony-PMCA-RE"
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
        print("usage: 98_pmca_shell_drive.py cmd1 [cmd2 ...]", file=sys.stderr)
        return 2

    pid, fd = pty.fork()
    if pid == 0:                       # child
        os.chdir(ROOT)
        os.execvp("python3", ["python3", "-c", BOOT])

    buf = b""
    out = []

    def read_until(timeout):
        nonlocal buf
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.3)
            if not r:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return False
            if not chunk:
                return False
            buf += chunk
            out.append(chunk.decode("utf-8", "replace"))
        return True

    # wait for the service shell to come up (device switch takes a while)
    read_until(90)
    print("".join(out), flush=True)
    out.clear()

    for cmd in cmds:
        os.write(fd, (cmd + "\n").encode())
        read_until(12)
        print("".join(out), flush=True)
        out.clear()

    os.write(fd, b"exit\n")
    read_until(5)
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
