#!/bin/bash
set -e
cd "<WORKSPACE>"
export ASTRA97_CMD='for t in /proc/144/task/*; do n=${t##*/}; echo "THR $n COMM $(cat $t/comm 2>/dev/null) ST $(cut -d" " -f3 $t/stat 2>/dev/null) W $(cat $t/wchan 2>/dev/null)"; done; echo THREADS_DONE'
exec python3 02-脚本/97_astra_trials.py \
  --image /root/astra/97/m1-verified/astra-m1-rwx5.img \
  --label m1-threads3 --repeat 1 --wall 100 \
  --preload "$PWD/04-产物/libcrashtrace.so"
