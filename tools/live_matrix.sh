#!/bin/bash
# Boot matrix along the LIVE path (live_loop.py with QMP capture + touch mailbox).
# Tests whether the capture harness itself raises the failure rate.
set -uo pipefail
N=${1:-4}
WALL=${2:-100}
USR='${REPO}/build_out/a6600_v34_final.img'
TMPIMG='${RUN}/inputs-v2/tmp-preload.img'
OUT=${RUN}/livematrix
mkdir -p "$OUT"
: > "$OUT/summary.txt"

for i in $(seq 1 "$N"); do
  echo "=== live boot $i/$N ==="
  rm -f ${RUN}/live_overlay.qcow2 ${RUN}/live_serial.log
  timeout $((WALL + 60)) python3 \
    '${WORKSPACE}/04-产物/a6600-port/scripts/live_loop.py' \
    "$USR" "$TMPIMG" "$WALL" >/dev/null 2>&1
  pkill -f qemu-system-arm 2>/dev/null
  sleep 2
  s=${RUN}/live_serial.log
  if [ ! -f "$s" ]; then echo "  NO LOG"; echo "$i NA NA NA" >> "$OUT/summary.txt"; continue; fi
  cp -f "$s" "$OUT/serial_$i.log"
  nulls=$(grep -ac 'sys_getInstance 返回 NULL' "$s"); nulls=${nulls:-0}
  pipe=$(grep -ac 'WidgetSystem Pipeline' "$s"); pipe=${pipe:-0}
  menu=$(grep -ac 'ASTRA_OPEN_MENU_ACK status=switched' "$s"); menu=${menu:-0}
  touch=$(grep -ac 'TOUCH_HOST: injected ok' "$s"); touch=${touch:-0}
  echo "$i $nulls $pipe $menu $touch" >> "$OUT/summary.txt"
  printf "  NULL=%-4s pipeline=%-4s menu=%-3s touch=%s\n" "$nulls" "$pipe" "$menu" "$touch"
done

echo
echo "=== live path summary ==="
printf "%-4s %-6s %-10s %-6s %-6s\n" run NULL pipeline menu touch
ok=0; n=0
while read -r i a b c d; do
  [ "$a" = "NA" ] && continue
  n=$((n+1))
  printf "%-4s %-6s %-10s %-6s %-6s\n" "$i" "$a" "$b" "$c" "$d"
  [ "$b" -gt 0 ] && [ "$c" -gt 0 ] && ok=$((ok+1))
done < "$OUT/summary.txt"
echo
echo "successful live boots: $ok / $n"
