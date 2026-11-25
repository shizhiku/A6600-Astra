#!/bin/bash
# Read-only: inspect camera's 2 MiB FAT partition (INFO/LICENSE).
set -u
MNT=/mnt/cam2m
mkdir -p "$MNT"
if mount -o ro /dev/sdf1 "$MNT" 2>/dev/null; then
    echo "=== /INFO ==="
    ls -la "$MNT/INFO"
    for f in "$MNT"/INFO/*; do
        [ -f "$f" ] || continue
        echo "--- $f ---"
        head -c 400 "$f" | strings | head -12
    done
    umount "$MNT"
else
    echo "mount failed"
fi
