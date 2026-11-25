#!/bin/bash
# Try PMCA console: list what it detects on the attached camera (read-only).
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
echo "=== python deps ==="
python3 -c "import usb; print('pyusb ok')" 2>&1 | head -2
echo "=== pmca-console --help (head) ==="
timeout 60 python3 pmca-console.py --help 2>&1 | head -40
