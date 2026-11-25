#!/bin/bash
# READ-ONLY verification: pull a small known file from the camera.
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
OUT=/root/astra/realcam
mkdir -p "$OUT"
timeout 21600 python3 '<WORKSPACE>/02-脚本/98_pmca_shell_connect.py' \
  'pull /proc/version /tmp/realcam_procversion.txt' \
  'pull /proc/mounts /tmp/realcam_mounts.txt' \
  'pull /proc/partitions /tmp/realcam_partitions.txt' \
  2>&1 | tail -40
echo "=== host side ==="
ls -la /tmp/realcam_*.txt 2>/dev/null
for f in /tmp/realcam_*.txt; do echo "--- $f"; head -30 "$f"; done
