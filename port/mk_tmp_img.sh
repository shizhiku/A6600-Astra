#!/bin/bash
# Build a /tmp (=/etc) vfat image carrying fonts + a chosen ld.so.preload.
# usage: mk_tmp_img.sh <preload-content> <out.img>
set -euo pipefail
IN='${RUN}/inputs-v2'
SRC="$IN/tmp-baseline.img"
OUT="${2:-$IN/tmp-preload.img}"
CONTENT="${1:-}"

cp -f "$SRC" "$OUT"
if [ -n "$CONTENT" ]; then
  echo "$CONTENT" > /tmp/ld.so.preload
  mcopy -o -i "$OUT" /tmp/ld.so.preload ::/ld.so.preload
fi
echo "--- contents ---"
mdir -i "$OUT" ::/ 2>/dev/null | head -20
echo "--- ld.so.preload ---"
mtype -i "$OUT" ::/ld.so.preload 2>/dev/null || echo "(absent)"
ls -l "$OUT" | awk '{print "  size:", $5}'
