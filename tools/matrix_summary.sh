#!/bin/bash
# Summarise the boot matrix from existing runs (no re-run).
set -uo pipefail
echo "run  NULL  pipeline  menu  taps  verdict"
ok=0; n=0
for i in 1 2 3 4 5; do
  d=$(ls -dt ${RUN}/run-*"matrix$i" 2>/dev/null | head -1)
  [ -n "$d" ] || continue
  s="$d/serial.log"
  nulls=$(grep -ac 'sys_getInstance 返回 NULL' "$s" 2>/dev/null); nulls=${nulls:-0}
  pipe=$(grep -ac 'WidgetSystem Pipeline' "$s" 2>/dev/null); pipe=${pipe:-0}
  menu=$(grep -ac 'ASTRA_OPEN_MENU_ACK status=switched' "$s" 2>/dev/null); menu=${menu:-0}
  tapp=$(grep -ac '模拟触控点击' "$s" 2>/dev/null); tapp=${tapp:-0}
  n=$((n+1))
  if [ "$pipe" -gt 0 ] && [ "$menu" -gt 0 ]; then v="OK"; ok=$((ok+1)); else v="FAIL"; fi
  printf "%-4s %-5s %-9s %-5s %-5s %s\n" "$i" "$nulls" "$pipe" "$menu" "$tapp" "$v"
done
echo
echo "successful: $ok / $n"
