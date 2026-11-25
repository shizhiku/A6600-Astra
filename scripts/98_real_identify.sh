#!/bin/bash
# Read-only identification of the attached ILCE-6600 storage LUNs.
for d in sde sdf; do
    echo "===== /dev/$d ====="
    if [ ! -b "/dev/$d" ]; then echo "absent"; continue; fi
    blockdev --getsize64 "/dev/$d" 2>/dev/null || echo "(size unknown)"
    echo "--- fdisk ---"
    fdisk -l "/dev/$d" 2>/dev/null | head -25
    echo "--- signature probes ---"
    # SDM table magic at 8 MiB (82461.00) per our offline analysis
    dd if="/dev/$d" bs=1M skip=8 count=1 status=none 2>/dev/null | od -An -tx1 -N8
    # ext2 magic at 1024+56
    dd if="/dev/$d" bs=1 count=2 skip=1080 status=none 2>/dev/null | od -An -tx1
    echo
done
