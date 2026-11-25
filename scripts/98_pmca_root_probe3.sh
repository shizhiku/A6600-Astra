#!/bin/bash
# Read-only root probe through the service-mode shell (camera already in 0336).
set -u
CONN="<WORKSPACE>/02-脚本/98_pmca_shell_connect.py"
cd /root/astra/Sony-PMCA-RE || exit 1
python3 "$CONN" \
    "id" \
    "uname -a" \
    "cat /proc/partitions" \
    "cat /proc/mounts" 2>&1 | tail -100
