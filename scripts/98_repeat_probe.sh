#!/bin/bash
# Repeat the staircase probe 3 times to test whether the blocking point drifts
# (timing/race dependent) or is deterministic (deadlock).
set -u
cd "<WORKSPACE>" || exit 1
for i in 1 2 3; do
    echo "===== REPEAT $i ====="
    python3 02-脚本/97_astra_trials.py \
        --image /root/astra/97/m1-verified/astra-m1-astra7.img \
        --label "m1-rep$i" --repeat 1 --wall 95 \
        --preload 04-产物/libstair2.so 2>&1 | tail -2
done
