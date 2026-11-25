#!/bin/bash
set -euo pipefail
BASE=<LEGACY_WORKSPACE>
export PYTHONPATH=/root/a6600/pmca-vendor:/root/a6600/probe
python3 "$BASE/bionz/tools/camera_debugger.py" ping
