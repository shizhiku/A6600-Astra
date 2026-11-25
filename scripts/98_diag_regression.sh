#!/bin/bash
# Diagnose why previously-working images now fail at "bridge7 enter".
set -u
echo "=== emmc base (backing) ==="
ls -la /root/qemu_in/emmc.img
echo "expected mtime was Nov 20 22:32; sha prefix 8305fdf7"

echo
echo "=== SDM table check (magic at 8MiB) ==="
dd if=/root/qemu_in/emmc.img bs=1M skip=8 count=1 status=none | od -An -tx1 -N8

echo
echo "=== other qemu inputs ==="
ls -la /root/qemu_in/ | head -20

echo
echo "=== kernel / initrd / submicro ==="
for f in /root/qemu_in/nflasha3-Image /root/qemu_in/a6600-submicro-frames-20261121.bin; do
    ls -la "$f" 2>/dev/null || echo "MISSING $f"
done

echo
echo "=== recent run stderr (last control run) ==="
D=$(ls -d <WORKSPACE>/03-证据/ASTRA-97/m1-ctrl2-* 2>/dev/null | tail -1)
echo "dir: $D"
if [ -n "${D:-}" ]; then
    echo "--- serial tail ---"
    tail -25 "$D/serial.log" 2>/dev/null
    echo "--- stderr tail ---"
    tail -20 "$D/stderr.log" 2>/dev/null
fi
