#!/bin/bash
set -eu
printf 'Available analysis commands:\n'
for cmd in java node gdb-multiarch arm-linux-gnueabi-objdump; do command -v "$cmd" || true; done
printf 'Previously documented REA installation:\n'
for path in <HOME>/a6400-rea-tools /root/a6400-rea-tools; do
 if [ -d "$path" ]; then printf '%s\n' "$path"; fi
done
