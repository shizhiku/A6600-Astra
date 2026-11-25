#!/bin/bash
# Read-only root probe via PMCA serviceshell.
set -u
DRV="<WORKSPACE>/02-脚本/98_pmca_shell_drive.py"
cd /root/astra/Sony-PMCA-RE || exit 1
python3 "$DRV" \
    "id" \
    "uname -a" \
    "cat /proc/partitions" \
    "cat /proc/mounts" 2>&1 | tail -80
