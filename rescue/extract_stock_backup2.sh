#!/bin/bash
# Extract stock /usr (from the offset it actually lives at in emmc.img) and /etc.
set -uo pipefail
EMMC=/root/qemu_in/emmc.img
OUT=${RUN}/rollback
mkdir -p "$OUT"

USR_OFF=771751936      # 0x2E000000 — verified by ext2 superblock magic
USR_LEN=314572800
ETC_OFF=188743680
ETC_LEN=12582912

echo "=== extract stock /usr @ 0x2E000000 ==="
dd if="$EMMC" of="$OUT/stock_usr.img" bs=512 skip=$((USR_OFF/512)) count=614400 status=none
printf "  %d B  %s\n" "$(stat -c %s "$OUT/stock_usr.img")" "$(sha256sum "$OUT/stock_usr.img" | cut -c1-16)"
e2fsck -fn "$OUT/stock_usr.img" >/dev/null 2>&1 && echo "  e2fsck: clean" || echo "  e2fsck: NOT clean"

echo "=== extract stock /etc @ sector 368640 ==="
dd if="$EMMC" of="$OUT/stock_etc.img" bs=512 skip=$((ETC_OFF/512)) count=24576 status=none
printf "  %d B  %s\n" "$(stat -c %s "$OUT/stock_etc.img")" "$(sha256sum "$OUT/stock_etc.img" | cut -c1-16)"
mdir -i "$OUT/stock_etc.img" ::/ 2>/dev/null | head -4 | sed 's/^/  /'

echo
echo "=== contents sanity ==="
for f in /bin/im.elf /lib/libObj.so /share/app; do
  debugfs -R "stat $f" "$OUT/stock_usr.img" 2>/dev/null | head -2 | tr '\n' ' ' | sed "s|^|  $f: |"; echo
done
debugfs -R "ls /share" "$OUT/stock_usr.img" 2>/dev/null | head -8 | sed 's/^/    /'
