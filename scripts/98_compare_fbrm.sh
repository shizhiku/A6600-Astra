#!/bin/bash
# Baseline restored (stack preload required).  Now compare unpatched vs
# fbrm2-patched image, with GPE trace on, to see whether forcing
# GRM_fbrmCheckUpdateFinished to 0 lets drawFramebuffer run.
set -u
cd "<WORKSPACE>" || exit 1
PRE="$PWD/04-产物/libcrashtrace.so"

for run in "unpatched:/root/astra/97/m1-verified/astra-m1-astra7.img" \
           "fbrm2:/root/astra/97/m1-verified/astra-m1-fbrm2.img"; do
    tag="${run%%:*}"
    img="${run#*:}"
    echo "===== $tag ====="
    ASTRA97_GPE_TRACE=1 python3 02-脚本/97_astra_trials.py \
        --image "$img" --label "m1-cmp-$tag" --repeat 1 --wall 100 \
        --preload "$PRE" 2>&1 | tail -1
done
