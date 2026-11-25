#!/bin/bash
# Boot the same image N times and measure how often the ASTRA widget system
# fails to initialise (the "startup race").
set -uo pipefail
N=${1:-5}
WALL=${2:-110}
USR='${REPO}/build_out/a6600_v34_final.img'
TMPIMG='${RUN}/inputs-v2/tmp-preload.img'
SUMM=${RUN}/boot_matrix.txt
: > "$SUMM"

for i in $(seq 1 "$N"); do
  tag="matrix$i"
  echo "=== boot $i/$N ($tag) ==="
  python3 '${WORKSPACE}/04-产物/a6600-port/scripts/boot_tmp.py' \
      "$USR" "$tag" "$WALL" 314572800 "$TMPIMG" >/dev/null 2>&1
  d=$(ls -dt ${RUN}/run-*"$tag" | head -1)
  s="$d/serial.log"
  nulls=$(grep -ac 'sys_getInstance 返回 NULL' "$s" 2>/dev/null); nulls=${nulls:-0}
  pipe=$(grep -ac 'WidgetSystem Pipeline' "$s" 2>/dev/null); pipe=${pipe:-0}
  menu=$(grep -ac 'ASTRA_OPEN_MENU_ACK status=switched' "$s" 2>/dev/null); menu=${menu:-0}
  tapp=$(grep -ac '模拟触控点击' "$s" 2>/dev/null); tapp=${tapp:-0}
  printf "%d %s %s %s %s\n" "$i" "$nulls" "$pipe" "$menu" "$tapp" >> "$SUMM"
  printf "  NULL=%-4s pipeline=%-4s menu=%-3s taps=%s\n" "$nulls" "$pipe" "$menu" "$tapp"
done

echo
echo "=========== summary ==========="
printf "%-4s %-6s %-10s %-6s %-6s\n" "run" "NULL" "pipeline" "menu" "taps"
ok=0
while read -r i nulls pipe menu tapp; do
  printf "%-4s %-6s %-10s %-6s %-6s\n" "$i" "$nulls" "$pipe" "$menu" "$tapp"
  [ "$pipe" -gt 0 ] && [ "$menu" -gt 0 ] && ok=$((ok+1))
done < "$SUMM"
echo
echo "successful boots (pipeline>0 AND menu>0): $ok / $N"
