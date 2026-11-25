#!/bin/bash
set -euo pipefail
BASE=<LEGACY_WORKSPACE>
R="$BASE/a6600_port/captures/boot-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$(dirname "$R")"
set +e
timeout --signal=TERM --kill-after=5s 120s python3 "$BASE/a6600_probe/capture_boot_files.py" --out "$R" > "$R.session.log" 2>&1
rc=$?
set -e
printf 'Capture directory: %s\nProcess exit: %s\n' "$R" "$rc"
printf '%s\n' "$rc" > "$R.process-exit.txt"
cat "$R.session.log"
exit "$rc"
