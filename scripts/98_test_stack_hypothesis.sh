#!/bin/bash
# Hypothesis: earlier successful runs used a preload with 6 MiB stack
# enlargement (libcrashtrace.so / libattrstack97.so).  The recent failing runs
# (control + fbrm2) had NO preload -> default 2 MiB pthread stack -> THREAD_APP
# stack overflow -> hits PROT_NONE guard page -> "page translation fault".
set -u
cd "<WORKSPACE>" || exit 1
PRE="$PWD/04-产物/libcrashtrace.so"
ls -la "$PRE" || exit 1

for i in 1 2; do
    echo "===== WITH STACK PRELOAD $i ====="
    python3 02-脚本/97_astra_trials.py \
        --image /root/astra/97/m1-verified/astra-m1-fbrm2.img \
        --label "m1-fbrm2-stk$i" --repeat 1 --wall 100 \
        --preload "$PRE" 2>&1 | tail -1
done
