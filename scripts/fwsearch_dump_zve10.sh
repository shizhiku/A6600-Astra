#!/bin/bash
# fwsearch_dump_zve10.sh —— 从 ZV-E10 v2.03 /usr、/usr 镜像的 /lib 中只读 dump 关键库到证据目录，
# 供离线 readelf/strings 复核（不修改原镜像）。
set -u
ROOT="<WORKSPACE>"
EV="$ROOT/03-证据/静态分析/firmware_search"
BASE="<LEGACY_WORKSPACE>/zve10_fw/extracted/0700_part_image/dev"
out="$EV/extracted_libs_zve10"
mkdir -p "$out"
IMG="$BASE/nflasha15"
for f in libIMDB.so libObj.so libInfraSKD.so libMWF.so libmpr.so; do
  debugfs -R "dump /lib/$f $out/$f" "$IMG" 2>&1 | grep -v '^debugfs' || true
done
echo "--- dumped ---"
ls -l "$out"
echo "--- sha256 ---"
sha256sum "$out"/* 2>/dev/null | sed "s|$out/||"
echo "--- libIMDB target strings ---"
strings -a "$out/libIMDB.so" 2>/dev/null | grep -E 'libInfraInput|libuxengine|libgrm|libgpe|libDDS|libCoreSync|GpeInit|grm_init|DDSUserInit|uxengine_init|infra_input_init|core_sync_user_init' | sort -u
echo "--- libObj target exports ---"
readelf -Ws "$out/libObj.so" 2>/dev/null | grep -v ' UND ' | grep -E 'infra_input|uxengine|grm_|Gpe|DDSUser|core_sync' | awk '{print $8}' | sort -u
echo "DONE"
