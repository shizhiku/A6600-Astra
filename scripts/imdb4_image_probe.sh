#!/bin/bash
# imdb4_image_probe.sh — 只读检查 ASTRA 镜像内 /lib /bin 的 ELF 事实（供 01-文档/111 引用）。
# 只读：debugfs dump 到 /tmp 后 hash/readelf，不写镜像、不运行目标。
set -u
IMG="${1:-/root/astra/97/m1-verified/astra-m1-rwx2.img}"
TMP=$(mktemp -d /tmp/imdb4probe.XXXXXX)
echo "# image: $IMG"
echo "# sha256(image)=$(sha256sum "$IMG" | cut -d' ' -f1)"
echo
for f in /lib/libIMDB.so /bin/im.elf /lib/libObj.so /lib/astra.so \
         /lib/a5bObj.so /lib/a5pFw.so /lib/a5pFwBoot.so /lib/a5bMWF.so \
         /lib/a5jChkConfig.so /lib/a5bUsbChargingApp.so; do
  name=$(echo "$f" | tr '/' '_')
  if debugfs -R "dump $f $TMP/$name" "$IMG" >/dev/null 2>&1 && [ -s "$TMP/$name" ]; then
    echo "== $f  size=$(stat -c%s "$TMP/$name")  sha256=$(sha256sum "$TMP/$name" | cut -d' ' -f1)"
    if [ "${f##*.}" = "so" ]; then
      echo "   NEEDED: $(readelf -d "$TMP/$name" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')"
      echo "   InfraInput/InputService UND: $(readelf --dyn-syms -W "$TMP/$name" 2>/dev/null | awk '$7=="UND" && ($8 ~ /InfraInput|InputService|initializeConfig|infra_input/) {print $8}' | sort | tr '\n' ' ')"
    fi
  else
    echo "== $f  MISSING"
  fi
done
echo
echo "# /lib/libIMDB.so 内记录 31 的原始字节（文件偏移 0x6128, 44B）:"
name=_lib_libIMDB.so
if [ -s "$TMP/$name" ]; then
  dd if="$TMP/$name" bs=1 skip=$((0x6128)) count=44 2>/dev/null | od -An -tx1 | tr -s ' '
fi
rm -rf "$TMP"
