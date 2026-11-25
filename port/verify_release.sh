#!/bin/bash
# Verify the release package against MANIFEST.txt
set -uo pipefail
cd '${WORKSPACE}/04-产物/a6600-port/release' || exit 1
grep -E '^usr_astra|^etc_nflasha' MANIFEST.txt | awk '{print $4"  "$1}' > /tmp/sums.txt
cat /tmp/sums.txt
sha256sum -c /tmp/sums.txt
echo "--- sizes ---"
stat -c '%n %s B' usr_astra_a6600.img etc_nflasha10_preload.img
