#!/bin/bash
set -euo pipefail
BASE=<LEGACY_WORKSPACE>
D=/root/qemu_in
Q=/root/qemu-11.1.3/build
R=/root/a6600-emulation/stock-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$R"
cp "$BASE/a6600_fw/extracted/0700_part_image/dev/nflasha15" "$R/stock-usr.bin"
"$Q/qemu-img" create -q -f qcow2 -F raw -b "$D/emmc.img" "$R/overlay.qcow2"
(cd "$R"; "$Q/qemu-io" -f qcow2 -c 'write -s stock-usr.bin 771751936 215517184' overlay.qcow2 > overlay-write.log)
python3 - "$D/kemco.txt" "$R/cmdline.txt" <<'PY'
import pathlib,sys
s=' '.join(pathlib.Path(sys.argv[1]).read_text().split())
if s.startswith('kemco '): s=s[6:]
s=s.rstrip(' *').replace('console=ttynull','console=ttyAM0,115200n8 amba2.console=1')
pathlib.Path(sys.argv[2]).write_text(s)
PY
set +e
timeout --signal=TERM --kill-after=5s 90s "$Q/qemu-system-arm" \
 -M sony-a6400 -m 1G -display none -monitor none -serial stdio \
 -kernel "$D/nflasha3-Image" -initrd "$D/nflasha3-initrd" \
 -append "$(cat "$R/cmdline.txt")" \
 -drive if=sd,format=qcow2,file="$R/overlay.qcow2" \
 -device loader,file="$D/Backup.bin",addr=0x02E80000,force-raw=on \
 -device loader,file="$D/av-cam.bin",addr=0x035C6000,force-raw=on \
 -icount shift=0,sleep=on > "$R/serial.log" 2> "$R/stderr.log"
rc=$?
set -e
printf '%s\n' "$rc" > "$R/exit-code.txt"
DEST="$BASE/a6600_port/emulation/$(basename "$R")"
mkdir -p "$DEST"
cp "$R/cmdline.txt" "$R/serial.log" "$R/stderr.log" "$R/exit-code.txt" "$R/overlay-write.log" "$DEST/"
printf 'Stock control directory: %s\nExit code: %s\n' "$R" "$rc"
wc -c "$R/serial.log" "$R/stderr.log"
