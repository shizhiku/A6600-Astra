#!/bin/bash
set -e
cd "<WORKSPACE>"
export ASTRA97_FRONT_BTN='0,0,0,0'
export ASTRA97_CMD="printf '40 40 0\n' > /tmp/touchcmd.new; mv /tmp/touchcmd.new /tmp/touchcmd"
exec python3 02-脚本/97_astra_trials.py \
  --image /root/astra/97/touchtest/usr-touchui.img \
  --label touch-cmd2 --repeat 1 --wall 95 \
  --preload "$PWD/04-产物/libtouchinject.so"
