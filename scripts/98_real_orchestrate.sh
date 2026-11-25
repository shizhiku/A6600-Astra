#!/bin/bash
# Orchestrate: attach MSC -> switch to service mode -> re-attach 0336 ->
# run serviceshell commands.  READ-ONLY except the Sony mode-switch command.
#
# Must run on the Windows side (usbipd) while WSL stays alive.
set -u
BUSID="${BUSID:-1-2}"
PULL_SCRIPT="<WORKSPACE>/02-脚本/98_pmca_shell_connect.py"
ARGS="$*"

wsl_run() { wsl.exe -d Ubuntu --exec bash -lc "$1"; }

echo "== current state =="
usbipd.exe list 2>/dev/null | grep -i "054c" || true

echo "== attach if needed =="
if ! usbipd.exe list 2>/dev/null | grep -qi "054c.*Attached"; then
    usbipd.exe attach --wsl --busid "$BUSID" >/dev/null 2>&1 || true
    sleep 6
fi
wsl_run "lsusb | grep -i 054c" || { echo "camera not visible in WSL"; exit 1; }
