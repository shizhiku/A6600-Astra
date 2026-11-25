#!/bin/bash
# Assemble the release package: /usr image + /etc(nflasha10) image + manifest.
set -euo pipefail
REPO='${REPO}'
OUT='${WORKSPACE}/04-产物/a6600-port/release'
IN='${RUN}/inputs-v2'
mkdir -p "$OUT"

cp -f "$REPO/build_out/a6600_v41_fnmenu.img" "$OUT/usr_astra_a6600.img"
cp -f "$IN/tmp-preload.img"               "$OUT/etc_nflasha10_preload.img"

{
  echo "# a6600 ASTRA package manifest"
  echo "# generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  for f in usr_astra_a6600.img etc_nflasha10_preload.img; do
    p="$OUT/$f"
    sz=$(stat -c %s "$p")
    sh=$(sha256sum "$p" | cut -d' ' -f1)
    printf "%-30s %12d B  %s\n" "$f" "$sz" "$sh"
  done
  echo
  echo "# expected target partitions (sectors, 512B)"
  echo "#   nflasha15 (/usr)  start=1490944  size=614400"
  echo "#   nflasha10 (/etc,/tmp) size=24576"
} > "$OUT/MANIFEST.txt"

cat "$OUT/MANIFEST.txt"
ls -l "$OUT"
