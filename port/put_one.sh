#!/bin/bash
# usage: put_one.sh <src.img> <local-file> <path-in-image> <out.img>
set -euo pipefail
SRC="$1"; LOCAL="$2"; DSTPATH="$3"; OUT="$4"
cp -f "$SRC" "$OUT"
CMDS=$(mktemp)
{
  echo "rm $DSTPATH"
  echo "write $LOCAL $DSTPATH"
  echo "sif $DSTPATH mode 0100555"
} > "$CMDS"
debugfs -w -f "$CMDS" "$OUT" >/dev/null 2>&1
rm -f "$CMDS"
e2fsck -f -y "$OUT" >/dev/null 2>&1 || true

T=$(mktemp -d)
debugfs -R "dump $DSTPATH $T/x" "$OUT" >/dev/null 2>&1
if cmp -s "$T/x" "$LOCAL"; then echo "  $DSTPATH <- $(basename "$LOCAL") OK ($(stat -c %s "$LOCAL") B)"; else echo "  MISMATCH"; fi
rm -rf "$T"
q=$(dumpe2fs -h "$OUT" 2>/dev/null | awk -F: '/Free blocks/{gsub(/ /,"",$2); print $2}')
echo "  free blocks: ${q:-?}"
echo "  -> $OUT"
