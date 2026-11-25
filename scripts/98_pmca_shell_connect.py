#!/usr/bin/env python3
"""Connect to the camera already in PMCA service mode and run read-only
commands through its serviceshell.  NO writes.

The camera must already be in service mode (054c:0336) and attached to WSL.
"""
import importlib.util
import os
import pty
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
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execvp("python3", ["python3", "-c", BOOT])

    buf = b""

    def drain(timeout):
        nonlocal buf
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
            buf += chunk
            got += chunk
        return got.decode("utf-8", "replace")

    text = drain(60)
    sys.stdout.write(text)
    sys.stdout.flush()

    for cmd in cmds:
        os.write(fd, (cmd + "\n").encode())
        out = drain(10)
        sys.stdout.write(out)
        sys.stdout.flush()

    os.write(fd, b"exit\n")
    drain(3)
    try:
        os.close(fd)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
