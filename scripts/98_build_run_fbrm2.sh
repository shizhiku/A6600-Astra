#!/bin/bash
# Build a new image with the reference-faithful fbrm patch and run it 4 times
# (to survive the ~12% random loader crash).  Records GPE trace + DMP counts.
set -u
cd "<WORKSPACE>" || exit 1

echo "===== BUILD IMAGE ====="
python3 02-脚本/98_swap_lib.py \
    --image /root/astra/97/m1-verified/astra-m1-astra7.img \
    --lib 03-证据/静态分析/97_abi/a5bObj_fbrm2.img.so \
    --path /lib/a5bObj.so \
    --output /root/astra/97/m1-verified/astra-m1-fbrm2.img || exit 1

for i in 1 2 3 4; do
    echo "===== RUN $i ====="
    ASTRA97_GPE_TRACE=1 python3 02-脚本/97_astra_trials.py \
        --image /root/astra/97/m1-verified/astra-m1-fbrm2.img \
        --label "m1-fbrm2-r$i" --repeat 1 --wall 110 2>&1 | tail -1
done
