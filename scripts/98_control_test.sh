#!/bin/bash
# Control test: run the UNPATCHED astra-m1-astra7.img twice.
# If it also fails 2/2 at "bridge7 enter", the problem is environmental
# (emmc base drift / overlay), not the fbrm patch.
set -u
cd "<WORKSPACE>" || exit 1

echo "=== emmc base ==="
ls -la /root/qemu_in/emmc.img
sha256sum /root/qemu_in/emmc.img 2>/dev/null | cut -c1-32

echo "=== disk ==="
df -h / | tail -1
df -h /mnt/c 2>/dev/null | tail -1

for i in 1 2; do
    echo "===== CONTROL $i (unpatched astra7) ====="
    python3 02-脚本/97_astra_trials.py \
        --image /root/astra/97/m1-verified/astra-m1-astra7.img \
        --label "m1-ctrl$i" --repeat 1 --wall 100 2>&1 | tail -1
done
