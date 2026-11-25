#!/bin/bash
# Read-only root verification inside the camera's busybox shell.
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
timeout 900 python3 '<WORKSPACE>/02-脚本/98_pmca_terminal.py' \
  'cat /proc/self/status | grep -E "Uid|Gid"' \
  'cat /proc/partitions' \
  'cat /proc/mounts' \
  'uname -a' \
  'ls /dev/nflasha* 2>/dev/null' \
  2>&1 | tail -80
