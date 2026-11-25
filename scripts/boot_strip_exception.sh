#!/bin/bash
# Boot with the camera av-cam, optionally stripping Sony exception-handler options
# from the kernel cmdline, to test whether an oops becomes non-fatal.
set -euo pipefail
BASE=<WORKSPACE>
Q=/root/qemu-11.1.3/build
CAP="$BASE/03-证据/相机采集/boot-20261120T151656Z-26869"
USR_IMG="${USR_IMG_OVERRIDE:-$BASE/05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15}"
LIVE_AVCAM="${AVCAM_IMG:-$BASE/05-原始固件/qemu_in/av-cam-live.bin}"
EMCC=/root/qemu_in/emmc.img
R=/root/a6600-emulation/cmdline-$(date -u +%Y%m%dT%H%M%SZ)-$$
mkdir -p "$R"

cp "${BACKUP_IMG:-$CAP/05-setting__Backup.bin}" "$R/Backup.bin"
cp "$CAP/06-setting__kemco.txt" "$R/kemco.txt"
cp "$CAP/07-setting__ulogio.bin" "$R/ulogio.bin"
cp "$CAP/08-setting__DmmConfig.bin" "$R/DmmConfig.bin"
cp "$USR_IMG" "$R/stock-usr.bin"
cp "$LIVE_AVCAM" "$R/av-cam-live.bin"

truncate -s 20M "$R/setting.img"
mkfs.vfat -F 16 "$R/setting.img" >/dev/null
for f in Backup.bin kemco.txt ulogio.bin DmmConfig.bin; do
  mcopy -o -i "$R/setting.img" "$R/$f" "::$f"
done

CMD=$(tr '\r\n' '  ' < "$R/kemco.txt" | sed 's/^kemco[[:space:]]*//' | tr -s ' ' \
      | sed 's/console=ttynull/console=ttyAM0,115200n8 amba2.console=1/')

if [ "${STRIP_EXC:-0}" = 1 ]; then
  CMD=$(printf '%s' "$CMD" | sed -E 's/ ?exception\.reboot=[^ ]+//g; s/ ?exception\.console_option=[^ ]+//g; s/ ?em_console=[^ ]+//g')
fi
CMD="$CMD ${CMDLINE_EXTRA:-}"
printf '%s' "$CMD" > "$R/cmdline.txt"

"$Q/qemu-img" create -q -f qcow2 -F raw -b "$EMCC" "$R/overlay.qcow2"
(cd "$R" && "$Q/qemu-io" -f qcow2 \
   -c 'write -s stock-usr.bin 771751936 215517184' \
   -c 'write -s setting.img 16777216 20971520' overlay.qcow2 > overlay.log 2>&1)

set +e
timeout --signal=TERM --kill-after=5s 120s "$Q/qemu-system-arm" \
  -M sony-a6400 -m 1G -display none -monitor none -serial stdio \
  -kernel /root/qemu_in/nflasha3-Image ${INITRD_IMG:--initrd /root/qemu_in/nflasha3-initrd} \
  -append "$CMD" \
  -drive if=sd,format=qcow2,file="$R/overlay.qcow2" \
  -device loader,file="$R/Backup.bin",addr=0x02E80000,force-raw=on \
  -device loader,file="$R/av-cam-live.bin",addr=0x035C6000,force-raw=on \
  -icount shift=0,sleep=on ${QEMU_EXTRA:-} > "$R/serial.log" 2> "$R/stderr.log"
rc=$?
set -e
printf '%s\n' "$rc" > "$R/exit-code.txt"

DEST="$BASE/03-证据/模拟器运行/$(basename "$R")"
mkdir -p "$DEST"
cp "$R/serial.log" "$R/stderr.log" "$R/exit-code.txt" "$R/cmdline.txt" "$DEST/" 2>/dev/null || true
printf 'Run: %s\nExit: %s\nSTRIP_EXC=%s\n' "$R" "$rc" "${STRIP_EXC:-0}"
printf 'faults: '; grep -c 'Unhandled fault' "$R/serial.log" || true
printf 'exception-monitor: '; grep -c 'Entering exception monitor' "$R/serial.log" || true
printf 'last guest time: '; grep -oE '^\[ *[0-9]+\.[0-9]+\]' "$R/serial.log" | tail -1 || true
