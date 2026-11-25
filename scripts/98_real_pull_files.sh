#!/bin/bash
# Read-only pull of proc files via the service-mode platform shell.
# Requires: camera in MSC mode attached to WSL, usbipd --auto-attach watching.
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
DRV="<WORKSPACE>/02-脚本/98_pmca_full_drive.py"
mkdir -p /root/astra/realcam

timeout 1200 python3 "$DRV" \
  "pull /proc/version /tmp/rc_version.txt" \
  "pull /proc/mounts /tmp/rc_mounts.txt" \
  "pull /proc/partitions /tmp/rc_partitions.txt" \
  "pull /proc/cmdline /tmp/rc_cmdline.txt" \
  2>&1 | tail -60

echo "===== host side results ====="
for f in /tmp/rc_version.txt /tmp/rc_mounts.txt /tmp/rc_partitions.txt /tmp/rc_cmdline.txt; do
  if [ -f "$f" ]; then
    echo "--- $f ($(stat -c%s "$f") bytes)"
    head -25 "$f"
  else
    echo "--- $f MISSING"
  fi
done
