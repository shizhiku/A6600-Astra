#!/bin/bash
# fwsearch_wsl_extra.sh —— 检查 WSL 实验目录（/root/astra 等）中是否另有“缺失库”文件或
# 是否已产生同名符号的运行时解析证据。只读，不删除/不修改任何文件。
set -u
EV="<WORKSPACE>/03-证据/静态分析/firmware_search"
OUT="$EV/symbols/probe_wsl_extra.txt"
mkdir -p "$(dirname "$OUT")"
: > "$OUT"
say() { echo "$@" | tee -a "$OUT"; }

say "===== WSL /root/astra 材料 ====="
say "-- /root/astra/stage 文件 --"
ls -l /root/astra/stage 2>/dev/null | tee -a "$OUT"
say "-- /root/astra/stage/libObj.so SHA-256（与工作区 gen5/libObj.so 对比） --"
sha256sum /root/astra/stage/libObj.so "<WORKSPACE>/05-原始固件/zv1m2_fw/gen5/libObj.so" 2>/dev/null | tee -a "$OUT"
say ""
say "===== WSL /root/astra/zvpart 中的 ZV 分区（与工作区证据对比） ====="
find /root/astra/zvpart -type f -printf '%s %p\n' 2>/dev/null | tee -a "$OUT"
sha256sum /root/astra/zvpart/0700_part_image/dev/nflasha3 /root/astra/zvpart/0700_part_image/dev/nflasha5 2>/dev/null | tee -a "$OUT"
say ""
say "===== WSL /root/astra/astra-usr.img 的 /lib（debugfs 只读） ====="
debugfs -R "ls -l /lib" /root/astra/astra-usr.img 2>/dev/null | grep -Ei 'Obj|IMDB|appFw|uxengine|grm|gpe|DDS|CoreSync|Ob5|InfraInput|SKD|MWF' | tee -a "$OUT"
say "-- 上述镜像 /lib 条目总数 --"
debugfs -R "ls -l /lib" /root/astra/astra-usr.img 2>/dev/null | tail -n +2 | wc -l | tee -a "$OUT"
say ""
say "===== 最近的 astra-gpetrace 运行日志中的符号解析/初始化记录（只读摘录） ====="
D=$(ls -dt /root/astra/97/astra-gpetrace-* 2>/dev/null | head -1)
say "DIR=$D"
if [ -n "$D" ] && [ -d "$D" ]; then
  ls -la "$D" 2>/dev/null | head -12 | tee -a "$OUT"
  for f in "$D"/serial.log "$D"/overlay.log "$D"/result.json; do
    [ -f "$f" ] || continue
    say "--- $f 关键行 ---"
    grep -a -m 40 -E 'GpeInit|grm_init|uxengine_init|core_sync|DDSUser|dlopen|dlsym|missing|not found|undefined symbol' "$f" 2>/dev/null | tee -a "$OUT"
  done
fi
say "WSL_EXTRA_DONE"
