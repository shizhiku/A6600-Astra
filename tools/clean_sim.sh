#!/bin/bash
# Clean restart of the a6600 simulator.  Prints an explicit before/after report so
# the caller never has to interpret pgrep exit codes through PowerShell quoting.
set -u
Q=${RUN}

echo "=== before ==="
q=$(pgrep -f 'qemu-system-arm' | tr '\n' ' ')
l=$(pgrep -f 'live_loop' | tr '\n' ' ')
echo "qemu pids : ${q:-none}"
echo "loop pids : ${l:-none}"

for p in $q $l; do kill -9 "$p" 2>/dev/null; done
sleep 3

rm -f "$Q/live_overlay.qcow2" "$Q/live_serial.log" "$Q/live_qmp.sock" /tmp/live_dbg.log

echo "=== after kill ==="
q2=$(pgrep -f 'qemu-system-arm' | tr '\n' ' ')
l2=$(pgrep -f 'live_loop' | tr '\n' ' ')
echo "qemu pids : ${q2:-none}"
echo "loop pids : ${l2:-none}"
for f in live_overlay.qcow2 live_serial.log live_qmp.sock; do
  if [ -e "$Q/$f" ]; then echo "still present: $f"; else echo "removed: $f"; fi
done
