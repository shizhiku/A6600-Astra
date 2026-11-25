#!/bin/bash
set -e
cd "<WORKSPACE>"
export ASTRA97_CMD='for t in /proc/144/task/*; do echo "THR $(basename $t) ST $(awk "{print \$3}" $t/stat 2>/dev/null) W $(cat $t/wchan 2>/dev/null)"; done; echo THREADS_DONE'
exec python3 02-脚本/97_astra_trials.py \
  --image /root/astra/97/m1-verified/astra-m1-rwx5.img \
  --label m1-threads --repeat 1 --wall 100 \
  --preload "$PWD/04-产物/libcrashtrace.so"
