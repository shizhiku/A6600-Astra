#!/bin/bash
# Run the fbrm2-patched image 4x.  12% of runs die early with a loader crash;
# we only trust runs that reach the app.
set -u
cd "<WORKSPACE>" || exit 1
for i in 1 2 3 4; do
    echo "===== RUN $i ====="
    ASTRA97_GPE_TRACE=1 python3 02-脚本/97_astra_trials.py \
        --image /root/astra/97/m1-verified/astra-m1-fbrm2.img \
        --label "m1-fbrm2-r$i" --repeat 1 --wall 110 2>&1 | tail -1
done
