#!/usr/bin/env python3
"""One-shot: switch camera to service mode, authenticate, then read files
from the camera's filesystem using the platform shell's `pull` command.

READ-ONLY: no push, no flash writes.  Files are copied camera -> host.

Usage: 98_pmca_pull.py <remote_path> [<local_path>] [more_remote ...]
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

# Drive the real pmca-console serviceshell, which itself switches mode,
# authenticates and then opens the CameraShell with all backends enabled.
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

    text = drain(90)
    sys.stdout.write(text)
    sys.stdout.flush()

    if "platform shell" not in text:
        print("!! did not reach platform shell", file=sys.stderr)
        os.write(fd, b"exit\n")
        drain(3)
        return 1

    for cmd in cmds:
        os.write(fd, (cmd + "\n").encode())
        out = drain(20)
        sys.stdout.write(out)
        sys.stdout.flush()

    os.write(fd, b"exit\n")
    drain(5)
    try:
        os.close(fd)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
