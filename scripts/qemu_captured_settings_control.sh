#!/bin/bash
# Offline stock firmware control using captured settings on a disposable overlay.
set -euo pipefail
BASE=<LEGACY_WORKSPACE>
CAP="$BASE/a6600_port/captures/boot-20261120T151656Z-26869"
D=/root/qemu_in
Q=/root/qemu-11.1.3/build
R=/root/a6600-emulation/captured-stock-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$R"
python3 - "$CAP" "$R" <<'PY'
import pathlib,json,hashlib,struct,sys
cap,r=map(pathlib.Path,sys.argv[1:])
receipt=json.loads((cap/'receipt.json').read_text())
for entry in receipt['files']:
 if entry['status']=='read':
  p=cap/entry['local']
  if hashlib.sha256(p.read_bytes()).hexdigest()!=entry['sha256']: raise RuntimeError('Capture changed')
for a,b in [('05-setting__Backup.bin','Backup.bin'),('06-setting__kemco.txt','kemco.txt'),('07-setting__ulogio.bin','ulogio.bin'),('08-setting__DmmConfig.bin','DmmConfig.bin')]:
 (r/b).write_bytes((cap/a).read_bytes())
backup=(r/'Backup.bin').read_bytes(); pa,cookie=struct.unpack_from('<II',backup)
if cookie!=0xaaaaaaaa or pa!=0x02e80000: raise RuntimeError('Unexpected backup header')
cmd=' '.join((r/'kemco.txt').read_text().split())
if cmd.startswith('kemco '): cmd=cmd[6:]
cmd=cmd.rstrip(' *').replace('console=ttynull','console=ttyAM0,115200n8 amba2.console=1')
(r/'cmdline.txt').write_text(cmd)
(r/'receipt.json').write_text(json.dumps({'scope':'Offline original usr with captured existing settings','capture_receipt':receipt,'limitations':['eMMC layout still synthesized from update-package partition table','Unacquired partitions remain blank/fixtures','No proof of matching all live installed firmware bytes','No synthetic success replacements or error suppression']},indent=2))
PY
cp "$D/part2.img" "$R/setting.img"
for name in Backup.bin kemco.txt ulogio.bin DmmConfig.bin; do
 mcopy -o -i "$R/setting.img" "$R/$name" "::$name"
done
cp "$BASE/a6600_fw/extracted/0700_part_image/dev/nflasha15" "$R/stock-usr.bin"
"$Q/qemu-img" create -q -f qcow2 -F raw -b "$D/emmc.img" "$R/overlay.qcow2"
(cd "$R"; "$Q/qemu-io" -f qcow2 -c 'write -s stock-usr.bin 771751936 215517184' -c 'write -s setting.img 16777216 20971520' overlay.qcow2 > overlay-write.log)
set +e
timeout --signal=TERM --kill-after=5s 90s "$Q/qemu-system-arm" \
 -M sony-a6400 -m 1G -display none -monitor none -serial stdio \
 -kernel "$D/nflasha3-Image" -initrd "$D/nflasha3-initrd" \
 -append "$(cat "$R/cmdline.txt")" \
 -drive if=sd,format=qcow2,file="$R/overlay.qcow2" \
 -device loader,file="$R/Backup.bin",addr=0x02E80000,force-raw=on \
 -device loader,file="$D/av-cam.bin",addr=0x035C6000,force-raw=on \
 -icount shift=0,sleep=on > "$R/serial.log" 2> "$R/stderr.log"
rc=$?
set -e
printf '%s\n' "$rc" > "$R/exit-code.txt"
DEST="$BASE/a6600_port/emulation/$(basename "$R")"
mkdir -p "$DEST"
cp "$R/receipt.json" "$R/cmdline.txt" "$R/serial.log" "$R/stderr.log" "$R/exit-code.txt" "$R/overlay-write.log" "$DEST/"
printf 'Run: %s\nExit: %s\n' "$R" "$rc"
wc -c "$R/serial.log" "$R/stderr.log"
