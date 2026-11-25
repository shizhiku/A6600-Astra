#!/bin/bash
# Long-run test WITHOUT probes (zero interference).
# Runs 600s and samples the display state / thread counts every 60s.
set -u
cd "<WORKSPACE>" || exit 1
export ASTRA97_CMD='for i in 1 2 3 4 5; do echo "SAMPLE $i"; grep -E "^Threads" /proc/144/status 2>/dev/null; for t in /proc/144/task/*; do cat $t/wchan 2>/dev/null; echo; done | sort | uniq -c | sort -rn | head -8; sleep 1; done'
python3 02-脚本/97_astra_trials.py \
    --image /root/astra/97/m1-verified/astra-m1-astra7.img \
    --label m1-long --repeat 1 --wall 300 \
    2>&1 | tail -3
