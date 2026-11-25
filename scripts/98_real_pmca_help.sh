#!/bin/bash
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
echo "=== deps ==="
python3 -c 'import axmlparserpy, usb; print("deps ok")'
echo "=== help ==="
timeout 90 python3 pmca-console.py --help 2>&1 | head -50
