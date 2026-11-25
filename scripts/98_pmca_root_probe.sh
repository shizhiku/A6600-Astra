#!/bin/bash
# Enter PMCA service mode and run a read-only serviceshell inspection.
# NO writes to the camera.  Commands are read-only system queries.
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
python3 - <<'PY' 2>&1 | grep -v SyntaxWarning | grep -v '^\s*m = self' | head -120
import importlib.util, sys
spec = importlib.util.spec_from_file_location(
    "axmlstub",
    "<WORKSPACE>/02-脚本/98_pmca_axml_stub.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

cmds = [
    "id",
    "cat /proc/mounts",
    "cat /proc/partitions",
    "cat /proc/cmdline",
]
sys.argv = ["pmca-console.py", "serviceshell"] + cmds
import runpy
try:
    runpy.run_path("pmca-console.py", run_name="__main__")
except SystemExit as e:
    print("exit", e.code)
PY
