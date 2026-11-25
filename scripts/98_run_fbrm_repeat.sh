#!/bin/bash
# Run the fbrm-patched image several times; accept only runs that actually
# reach the app (has_appFw_mapping && no exception monitor) to work around the
# ~12% random loader crash.
set -u
cd "<WORKSPACE>" || exit 1
for i in 1 2 3 4; do
    echo "===== RUN $i ====="
    ASTRA97_GPE_TRACE=1 python3 02-脚本/97_astra_trials.py \
        --image /root/astra/97/m1-verified/astra-m1-fbrm.img \
        --label "m1-fbrm-r$i" --repeat 1 --wall 110 2>&1 | tail -1
done
