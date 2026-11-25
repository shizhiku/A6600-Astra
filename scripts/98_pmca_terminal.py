#!/usr/bin/env python3
"""Open the camera's interactive root terminal (serviceshell `shell` command)
and run read-only commands over it.

The SenserPlatformBackend.interactiveShell() bridges the camera's terminal to a
socket; we drive it by feeding lines and reading output.

READ-ONLY: only inspection commands are sent.
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

    text = drain(120)
    sys.stdout.write(text)
    sys.stdout.flush()

    if "platform shell" not in text:
        print("!! no platform shell", file=sys.stderr)
        return 1

    # enter interactive camera terminal
    os.write(fd, b"shell\n")
    out = drain(25)
    sys.stdout.write(out)
    sys.stdout.flush()

    for cmd in cmds:
        os.write(fd, (cmd + "\n").encode())
        out = drain(12)
        sys.stdout.write(out)
        sys.stdout.flush()

    os.write(fd, b"\x03")   # break out of terminal
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
