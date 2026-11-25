#!/bin/bash
set -euo pipefail
BASE=<LEGACY_WORKSPACE>
D=/root/qemu_in
Q=/root/qemu-11.1.3/build
R=/root/a6600-emulation/$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$R"
cp "$BASE/qemu_in/nflasha3-Image" "$D/"
cp "$BASE/qemu_in/nflasha3-initrd" "$D/"
cp "$BASE/qemu_in/av-cam.bin" "$D/"
python3 - "$D" "$R" <<'PY'
import sys,pathlib,json,hashlib
src,out=map(pathlib.Path,sys.argv[1:])
cmd=' '.join((src/'kemco.txt').read_text().split())
if cmd.startswith('kemco '): cmd=cmd[6:]
cmd=cmd.rstrip(' *').replace('console=ttynull','console=ttyAM0,115200n8 amba2.console=1')
(out/'cmdline.txt').write_text(cmd)
r={'scope':'Offline update-package boot experiment; not a hardware compatibility validation', 'limitations':['Backup.bin is a fabricated zero-filled fixture with an address and cookie only; not camera settings','SDM is synthesized from update partinf.conf','Unacquired partitions are blank or absent','Patched usr retains original UI; no ASTRA UI port is installed'], 'inputs':{}}
for name in ['nflasha3-Image','nflasha3-initrd','av-cam.bin','Backup.bin','sdm.bin']:
 p=src/name; data=p.read_bytes(); r['inputs'][name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'first16':data[:16].hex()}
(out/'receipt.json').write_text(json.dumps(r,indent=2))
PY
"$Q/qemu-img" create -q -f qcow2 -F raw -b "$D/emmc.img" "$R/overlay.qcow2"
"$Q/qemu-system-arm" -version > "$R/qemu-version.txt"
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
cp "$R/receipt.json" "$R/cmdline.txt" "$R/qemu-version.txt" "$R/serial.log" "$R/stderr.log" "$R/exit-code.txt" "$DEST/"
printf 'Run directory: %s\nExit code: %s\n' "$R" "$rc"
wc -c "$R/serial.log" "$R/stderr.log"
