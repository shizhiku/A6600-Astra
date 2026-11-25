#!/bin/sh
# a6600 —— 只读探测脚本（不做任何写入）
# 用途：在刷写前确认分区布局、WBI 节点、容量与写保护状态
# 用法：把本文件推到相机 /tmp 后  sh /tmp/probe_ro.sh

echo "=============================================="
echo " a6600 read-only partition probe"
echo "=============================================="
echo

echo "--- /proc/partitions ---"
cat /proc/partitions
echo

echo "--- nflasha* block devices (start sector / size in 512B sectors) ---"
for d in /sys/class/block/nflasha*; do
    [ -e "$d" ] || continue
    name=$(basename "$d")
    size=$(cat "$d/size" 2>/dev/null)
    start=$(cat "$d/start" 2>/dev/null)
    ro=$(cat "$d/ro" 2>/dev/null)
    if [ -n "$start" ]; then
        off=$((start * 512))
    else
        off="?"
    fi
    printf "  %-12s size=%-8s start=%-9s off=%-12s ro=%s\n" \
           "$name" "${size:-?}" "${start:-?}" "$off" "${ro:-?}"
done
echo

echo "--- block device nodes in /dev ---"
ls -l /dev/nflasha* 2>/dev/null
echo

echo "--- mounted partitions ---"
mount | grep -E 'nflasha|/usr|/tmp|/etc' 2>/dev/null
echo

echo "--- filesystem types (if blkid available) ---"
which blkid >/dev/null 2>&1 && blkid 2>/dev/null | grep nflasha
echo

echo "--- current /etc/ld.so.preload (empty = stock) ---"
if [ -f /etc/ld.so.preload ]; then
    echo "  present, size=$(wc -c < /etc/ld.so.preload 2>/dev/null)"
    cat /etc/ld.so.preload
else
    echo "  absent (stock)"
fi
echo

echo "--- /usr contents check ---"
ls -l /usr/lib/appFwBoot.so /usr/lib/appFw.so 2>/dev/null || echo "  (5th-gen libs absent = stock)"
echo

echo "--- kernel ---"
uname -a
echo

echo "--- free space ---"
df -k 2>/dev/null | head -10
echo

echo "=============================================="
echo " probe finished — nothing was written"
echo "=============================================="
