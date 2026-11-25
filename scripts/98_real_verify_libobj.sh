#!/bin/bash
# READ-ONLY: verify our offline-extracted a6600 libObj.so matches the real camera.
set -u
cd /root/astra/Sony-PMCA-RE || exit 1
DRV="<WORKSPACE>/02-脚本/98_cam_bb2.py"
timeout 900 python3 "$DRV" \
  'ls -l /usr/lib/libObj.so' \
  'sha256sum /usr/lib/libObj.so' \
  'ls /usr/lib/*.so | head -20' \
  'ls /usr/bin/im.elf /usr/bin/mwf_monio.elf' \
  2>&1 | tail -60
