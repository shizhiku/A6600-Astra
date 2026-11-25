#!/bin/bash
# Report content stats for the frames of a run.
set -uo pipefail
d=$(ls -dt ${RUN}/run-*"${1:-rollback2}" | head -1)
echo "dir=$d"
for f in "$d"/fb.*.ppm; do
  [ -f "$f" ] || continue
  python3 - "$f" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1]); data = p.read_bytes()
i = 2; f = []
while len(f) < 3:
    while data[i:i+1].isspace(): i += 1
    s = i
    while not data[i:i+1].isspace(): i += 1
    f.append(int(data[s:i]))
i += 1
w, h, _ = f
px = data[i:i+w*h*3]
step = 3*37
nb = sum(1 for k in range(0, len(px), step) if px[k] or px[k+1] or px[k+2])
tot = len(px)//step or 1
cols = len({(px[k], px[k+1], px[k+2]) for k in range(0, len(px), step)})
print(f"  {p.name}: {w}x{h} colors={cols} nonblack={100.0*nb/tot:.1f}%")
PY
done
