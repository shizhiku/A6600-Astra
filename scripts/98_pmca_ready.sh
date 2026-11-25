#!/bin/bash
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
export PYTHONPATH="<WORKSPACE>/02-脚本:${PYTHONPATH:-}"
python3 - <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location(
    "axmlstub",
    "<WORKSPACE>/02-脚本/98_pmca_axml_stub.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for m in ("tlslite", "Cryptodome", "yaml", "certifi", "usb"):
    try:
        __import__(m)
        print("ok", m)
    except Exception as e:
        print("FAIL", m, type(e).__name__, e)
print("=== pmca commands ===")
sys.argv = ["pmca-console.py", "--help"]
import runpy
try:
    runpy.run_path("pmca-console.py", run_name="__main__")
except SystemExit:
    pass
PY
