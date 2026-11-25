#!/bin/bash
# 把打好的补丁写回 a6600 的 /usr ext2 镜像
set -euo pipefail

BASE=<LEGACY_WORKSPACE>
WORK=/tmp/a6600img
IMG=$WORK/nflasha15.bin
SRC=$BASE/a6600_fw/extracted/0700_part_image/dev/nflasha15
PATCHED=$BASE/a6600_port/patched

rm -rf "$WORK"; mkdir -p "$WORK"
cp -f "$SRC" "$IMG"
echo "[*] 工作镜像 $IMG  $(stat -c%s "$IMG") B"

apply() {  # $1=host_file  $2=image_path
  local host="$1" path="$2"
  debugfs -w -R "rm $path" "$IMG" >/dev/null 2>&1 || true
  debugfs -w -R "write $host $path" "$IMG" >/dev/null
  debugfs -w -R "sif $path mode 0100755" "$IMG" >/dev/null
  debugfs -w -R "sif $path uid 57285" "$IMG" >/dev/null
  debugfs -w -R "sif $path gid 1000" "$IMG" >/dev/null
  local size
  size=$(debugfs -R "stat $path" "$IMG" 2>/dev/null | awk '/Size:/{print $2; exit}')
  echo "    $path  ->  $(stat -c%s "$host") B (镜像内 $size B)"
}

apply "$PATCHED/lib/libIMDB.so"  "/lib/libIMDB.so"
apply "$PATCHED/lib/libMWF.so"   "/lib/libMWF.so"
apply "$PATCHED/bin/im.elf"      "/bin/im.elf"
apply "$PATCHED/lib/appFwBoot.so" "/lib/appFwBoot.so"

echo "[*] e2fsck ..."
e2fsck -fn "$IMG" > "$WORK/fsck.log" 2>&1 || true
tail -5 "$WORK/fsck.log"
cp -f "$IMG" "$BASE/a6600_port/nflasha15_patched.bin"
echo "[+] 输出 $BASE/a6600_port/nflasha15_patched.bin  $(stat -c%s "$BASE/a6600_port/nflasha15_patched.bin") B"
