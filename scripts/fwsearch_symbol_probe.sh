#!/bin/bash
# fwsearch_symbol_probe.sh —— 只读核对：ZV-1M2 /lib 内的库与工作区 gen5/ 提取件是否同一文件，
# 以及 libIMDB 的加载方式、libObj 对目标符号的导出情况。
set -u
ROOT="<WORKSPACE>"
EV="$ROOT/03-证据/静态分析/firmware_search/symbols"
mkdir -p "$EV"
OUT="$EV/probe_symbols.txt"
: > "$OUT"

say() { echo "$@" | tee -a "$OUT"; }

mount_img() { # $1 = image, $2 = label
  local tmp="/tmp/fwsearch_probe_$2.img" mnt="/tmp/fwsearch_probe_mnt_$2"
  cp "$1" "$tmp" && mkdir -p "$mnt" && mount -o ro,loop "$tmp" "$mnt" && echo "$mnt"
}

say "===== ZV-1M2 /usr /lib 关键库 SHA-256（镜像内） ====="
ZVMNT=$(mount_img "$ROOT/05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha15" zvusr)
if [ -n "${ZVMNT:-}" ]; then
  for f in libObj.so libIMDB.so appFw.so appFwBoot.so libMWF.so libInfraSKD.so libsencore.so; do
    [ -f "$ZVMNT/lib/$f" ] && sha256sum "$ZVMNT/lib/$f" | sed "s|$ZVMNT||" | tee -a "$OUT"
  done
  say ""
  say "===== ZV-1M2 镜像内 /lib 与工作区 gen5/ 提取件逐一对比 ====="
  for f in libObj.so libIMDB.so appFw.so appFwBoot.so; do
    a=$(sha256sum "$ZVMNT/lib/$f" 2>/dev/null | cut -d' ' -f1)
    b=$(sha256sum "$ROOT/05-原始固件/zv1m2_fw/gen5/$f" 2>/dev/null | cut -d' ' -f1)
    say "$f  image=$a  gen5=$b  same=$([ "$a" = "$b" ] && echo YES || echo NO)"
  done
  say ""
  say "===== ZV libIMDB.so DT_NEEDED / SONAME ====="
  readelf -d "$ZVMNT/lib/libIMDB.so" | grep -E 'NEEDED|SONAME' | tee -a "$OUT"
  say ""
  say "===== ZV libIMDB.so 中的 dl* 字符串 ====="
  strings -a "$ZVMNT/lib/libIMDB.so" | grep -E '^dl(open|sym|error|close)' | sort -u | tee -a "$OUT"
  say ""
  say "===== ZV libObj.so / appFw.so 目标符号导出（defined） ====="
  for f in libObj.so appFw.so libMWF.so; do
    say "--- $f ---"
    readelf -Ws "$ZVMNT/lib/$f" 2>/dev/null | grep -E 'FUNC|OBJECT' | grep -v ' UND ' \
      | grep -E 'infra_input|uxengine|grm_|Gpe|DDSUser|core_sync' | awk '{print $8}' | sort -u | tee -a "$OUT"
  done
  say ""
  say "===== ZV libObj.so 中是否出现 Gpe / core_sync 相关字符串（含未导出） ====="
  strings -a "$ZVMNT/lib/libObj.so" | grep -E 'Gpe|core_sync' | sort -u | head -20 | tee -a "$OUT"
  say "(end)"
  umount "$ZVMNT" && rm -f "/tmp/fwsearch_probe_zvusr.img"
fi

say ""
say "===== a6600 /usr /lib/libObj.so 目标符号导出 ====="
A6MNT=$(mount_img "$ROOT/05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15" a6usr)
if [ -n "${A6MNT:-}" ]; then
  readelf -Ws "$A6MNT/lib/libObj.so" 2>/dev/null | grep -v ' UND ' \
    | grep -E 'infra_input|uxengine|grm_|Gpe|DDSUser|core_sync' | awk '{print $8}' | sort -u | tee -a "$OUT"
  say ""
  say "===== a6600 /usr /lib/libObj.so SHA-256 ====="
  sha256sum "$A6MNT/lib/libObj.so" | sed "s|$A6MNT||" | tee -a "$OUT"
  umount "$A6MNT" && rm -f "/tmp/fwsearch_probe_a6usr.img"
fi

say ""
say "===== ZV-1M2 与 ZV-E10 的 /rootfs /lib/libSTMcmdexecute.so 对比 ====="
for pair in "zv:<WORKSPACE>/05-原始固件/zv1m2_fw/extracted/0700_part_image/dev/nflasha7" \
            "zve10:<LEGACY_WORKSPACE>/zve10_fw/extracted/0700_part_image/dev/nflasha7"; do
  lab="${pair%%:*}"; img="${pair#*:}"
  m=$(mount_img "$img" "${lab}root")
  if [ -n "${m:-}" ]; then
    [ -f "$m/lib/libSTMcmdexecute.so" ] && sha256sum "$m/lib/libSTMcmdexecute.so" | sed "s|$m||" | sed "s|^|$lab |" | tee -a "$OUT"
    umount "$m" && rm -f "/tmp/fwsearch_probe_${lab}root.img"
  fi
done
say "PROBE DONE"
