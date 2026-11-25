#!/bin/bash
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
python3 - <<'PY' 2>&1 | grep -v SyntaxWarning | grep -v '^\s*m = self' | head -60
import importlib.util, sys
spec = importlib.util.spec_from_file_location(
    "axmlstub",
    "<WORKSPACE>/02-脚本/98_pmca_axml_stub.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sys.argv = ["pmca-console.py", "info"]
import runpy
try:
    runpy.run_path("pmca-console.py", run_name="__main__")
except SystemExit as e:
    print("exit", e.code)
PY
