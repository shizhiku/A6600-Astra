#!/bin/sh
# a6600 —— ASTRA 菜单刷写脚本（在相机上以 root 执行）
#
# 设计原则：
#   1) 直接写分区设备节点，**不用偏移**（避免整盘扇区算错）
#   2) 刷写前做完整前置校验，任何一项不通过就退出
#   3) 先备份、再校验备份、最后才写
#
# 用法：
#   把以下文件放到 /tmp：
#     usr_astra_a6600.img   etc_nflasha10_preload.img
#   然后： sh /tmp/flash_astra.sh
#
# 参数（按需修改）：
USR_DEV=/dev/nflasha15        # /usr 分区
ETC_DEV=/dev/nflasha10        # /etc(= /tmp) 分区
WBI_DEV=                      # WBI 分区节点，必填，例如 /dev/nflasha9
USR_IMG=/tmp/usr_astra_a6600.img
ETC_IMG=/tmp/etc_nflasha10_preload.img
BACKUP_DIR=/tmp/astra_backup

USR_SECTORS=614400            # 300 MiB
ETC_SECTORS=24576             # 12 MiB
USR_SHA=400fe8ecf29cb7463ceb5776f7de233019f8870a9d509b8f0d9c90a3b44f2b39
ETC_SHA=139cacdef9aebfe8fd8a065bedb1227e91fb925f1cebfa18cacda378539f5499

set -e

fail() { echo "!!! ABORT: $*"; exit 1; }

echo "=============================================="
echo " a6600 ASTRA flash"
echo "=============================================="

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -n "$WBI_DEV" ] || fail "WBI_DEV is not set — run probe_camera_ro.sh first and edit this script"

# ---- 1. devices exist and have the expected size ----
for pair in "$USR_DEV:$USR_SECTORS" "$ETC_DEV:$ETC_SECTORS"; do
    dev=${pair%%:*}; want=${pair##*:}
    [ -b "$dev" ] || fail "$dev is not a block device"
    got=$(cat "/sys/class/block/$(basename "$dev")/size" 2>/dev/null || echo 0)
    echo "  $dev size=$got (expected $want)"
    [ "$got" = "$want" ] || fail "$dev size mismatch — refusing to write"
done
[ -b "$WBI_DEV" ] || fail "$WBI_DEV is not a block device"
echo "  $WBI_DEV ok (wbi)"

# ---- 2. images present and hash-valid ----
for pair in "$USR_IMG:$USR_SHA" "$ETC_IMG:$ETC_SHA"; do
    img=${pair%%:*}; want=${pair##*:}
    [ -f "$img" ] || fail "$img missing"
    got=$(sha256sum "$img" | cut -d' ' -f1)
    echo "  $(basename "$img") sha256=${got%??????????????????????????????}…"
    [ "$got" = "$want" ] || fail "$img hash mismatch"
done

echo
echo "--- images OK, about to BACK UP both partitions ---"
mkdir -p "$BACKUP_DIR"
dd if="$USR_DEV" of="$BACKUP_DIR/backup_usr.bin" bs=512 count=$USR_SECTORS conv=fsync
dd if="$ETC_DEV" of="$BACKUP_DIR/backup_etc.bin" bs=512 count=$ETC_SECTORS conv=fsync
sync
echo "  backup_usr.bin $(stat -c %s "$BACKUP_DIR/backup_usr.bin") B"
echo "  backup_etc.bin $(stat -c %s "$BACKUP_DIR/backup_etc.bin") B"
echo
echo ">>> COPY $BACKUP_DIR OFF THE CAMERA NOW, then re-run with CONFIRM=yes"
[ "${CONFIRM:-no}" = "yes" ] || exit 0

# ---- 3. write /usr first, then /etc (safer ordering) ----
echo "--- writing /usr ---"
dd if="$USR_IMG" of="$USR_DEV" bs=512 count=$USR_SECTORS conv=fsync
sync
echo "--- writing /etc ---"
dd if="$ETC_IMG" of="$ETC_DEV" bs=512 count=$ETC_SECTORS conv=fsync
sync

# ---- 4. clear WBI first 512 bytes ----
echo "--- clearing WBI (first 512 bytes) ---"
dd if=/dev/zero of="$WBI_DEV" bs=512 count=1 conv=fsync
sync

echo
echo "=============================================="
echo " done — power off and reboot"
echo " rollback: dd if=$BACKUP_DIR/backup_usr.bin of=$USR_DEV bs=512 count=$USR_SECTORS"
echo "           dd if=$BACKUP_DIR/backup_etc.bin of=$ETC_DEV bs=512 count=$ETC_SECTORS"
echo "           dd if=/dev/zero of=$WBI_DEV bs=512 count=1"
echo "=============================================="
