#!/bin/bash
# fwsearch_fs_inventory.sh —— 对本地固件分区镜像做只读文件系统清单 + 目标库名/符号检索
# 用法: bash fwsearch_fs_inventory.sh [全部|ext2|vfat|wbi]
# 输出到 03-证据/静态分析/firmware_search/ ，镜像副本只放 /tmp，用完即删；不写任何原镜像。
set -u

ROOT="<WORKSPACE>"
EV="$ROOT/03-证据/静态分析/firmware_search"
mkdir -p "$EV/fs_inventory" "$EV/symbols" "$EV/fat_inventory" "$EV/wbi"

# 目标库名/符号（五代 IMDB 初始化表中引用、以及任务要求的关键字）
NAME_RE='libInfraInput|libuxengine|libgrm|libgpe|libDDS|libCoreSync|libOb5|libOb4|a5bObj|a5bFw|uxengine|GpeInit|grm_init|DDSUserInit|libInfraSKD|libSTMcmdexecute'
SYM_RE='infra_input_init|infra_input_sus|infra_input_res|core_sync_user_init|core_sync_user_sus|core_sync_user_res|grm_init|grm_sus|grm_res|GpeInit|GpeSus|GpeRes|DDSUserInit|DDSUserSus|DDSUserRes|uxengine_init|uxengine_sus|uxengine_res'

ZVBASE="$ROOT/05-原始固件/zv1m2_fw/extracted/0700_part_image/dev"
A6BASE="$ROOT/05-原始固件/a6600_fw/extracted/0700_part_image/dev"
OLDBASE="<LEGACY_WORKSPACE>"
ZVE10BASE="$OLDBASE/zve10_fw/extracted/0700_part_image/dev"

inventory_ext2() { # $1=label $2=image $3=releasenote
  local label="$1" img="$2" note="$3"
  local tmp="/tmp/fwsearch_${label}.img" mnt="/tmp/fwsearch_mnt_${label}"
  echo "===== [$label] $note ====="
  cp --reflink=auto "$img" "$tmp" || { echo "COPY_FAIL $label"; return 1; }
  mkdir -p "$mnt"
  if ! mount -o ro,loop "$tmp" "$mnt"; then echo "MOUNT_FAIL $label"; rm -f "$tmp"; return 1; fi

  # 1) 全量文件清单：类型 大小 路径
  find "$mnt" -printf '%y\t%s\t%p\n' 2>/dev/null | sed "s|$mnt||" \
      | sed 's|^\([a-z]\)\t|\1\t|' > "$EV/fs_inventory/${label}_filelist.tsv"
  local nfiles; nfiles=$(grep -c '^f' "$EV/fs_inventory/${label}_filelist.tsv" || true)
  echo "file_count=$nfiles"

  # 2) 文件名命中目标关键字
  grep -Ei "$NAME_RE" "$EV/fs_inventory/${label}_filelist.tsv" > "$EV/fs_inventory/${label}_name_hits.tsv" || true
  echo "name_hits=$(wc -l < "$EV/fs_inventory/${label}_name_hits.tsv")"

  # 3) 逐个 ELF/共享库：SHA256 + SONAME + 目标符号导出
  : > "$EV/symbols/${label}_so_index.tsv"
  printf 'path\tsize\tsha256\tsoname\n' >> "$EV/symbols/${label}_so_index.tsv"
  : > "$EV/symbols/${label}_symbol_hits.tsv"
  local f rel so sha
  while IFS= read -r f; do
    rel="${f#$mnt}"
    sha=$(sha256sum "$f" | cut -d' ' -f1)
    so=$(readelf -d "$f" 2>/dev/null | sed -n 's/.*SONAME.*\[\(.*\)\].*/\1/p' | head -1)
    printf '%s\t%s\t%s\t%s\n' "$rel" "$(stat -c %s "$f")" "$sha" "$so" >> "$EV/symbols/${label}_so_index.tsv"
    # 导出符号里找目标符号（只保留定义的行）
    readelf -Ws "$f" 2>/dev/null | awk -v re="$SYM_RE" '$4=="FUNC" && $7!="UND" && $8 ~ re {print $8}' | sort -u \
      | while IFS= read -r s; do printf '%s\t%s\t%s\n' "$rel" "$so" "$s" >> "$EV/symbols/${label}_symbol_hits.tsv"; done
    # SONAME 命中目标库名（真实文件名之外的另一种证据）
    if echo "$rel $so" | grep -Eqi "$NAME_RE"; then
      echo "SONAME_OR_PATH_HIT: $rel soname=$so" >> "$EV/symbols/${label}_soname_hits.txt"
    fi
  done < <(find "$mnt" -type f \( -name '*.so' -o -name '*.so.*' -o -perm -u+x \) 2>/dev/null)

  # 4) 文件内容（含普通文件）原始字节命中：库名/符号字符串
  grep -a -r -l -E "$NAME_RE|$SYM_RE" "$mnt" 2>/dev/null | sed "s|$mnt||" \
      > "$EV/fs_inventory/${label}_content_hits.txt" || true
  echo "content_hit_files=$(wc -l < "$EV/fs_inventory/${label}_content_hits.txt")"

  umount "$mnt" && rm -f "$tmp"
  echo "===== [$label] done ====="
}

inventory_vfat() { # FAT 镜像
  local label="$1" img="$2"
  local tmp="/tmp/fwsearch_${label}.img" mnt="/tmp/fwsearch_mnt_${label}"
  echo "===== [$label] vfat ====="
  cp --reflink=auto "$img" "$tmp" || return 1
  mkdir -p "$mnt"
  if ! mount -o ro,loop,fat=12 "$tmp" "$mnt" 2>/dev/null && ! mount -o ro,loop "$tmp" "$mnt"; then
    echo "MOUNT_FAIL $label"; rm -f "$tmp"; return 1
  fi
  find "$mnt" -printf '%y\t%s\t%p\n' | sed "s|$mnt||" > "$EV/fat_inventory/${label}_filelist.tsv"
  grep -Ei "$NAME_RE|$SYM_RE" "$EV/fat_inventory/${label}_filelist.tsv" > "$EV/fat_inventory/${label}_name_hits.tsv" || true
  echo "file_count=$(grep -c '^f' "$EV/fat_inventory/${label}_filelist.tsv")"
  grep -a -r -l -E "$NAME_RE|$SYM_RE" "$mnt" 2>/dev/null | sed "s|$mnt||" > "$EV/fat_inventory/${label}_content_hits.txt" || true
  umount "$mnt" && rm -f "$tmp"
  echo "===== [$label] done ====="
}

MODE="${1:-all}"
case "$MODE" in
  ext2|all|全部)
    inventory_ext2 zv1m2_usr   "$ZVBASE/nflasha15" "ZV-1M2 /usr (ext2, 530,345,984B)"
    inventory_ext2 zv1m2_rootfs "$ZVBASE/nflasha7" "ZV-1M2 /rootfs (ext2, 5,146,624B)"
    inventory_ext2 a6600_usr   "$A6BASE/nflasha15" "a6600 /usr (ext2, 215,517,184B)"
    inventory_ext2 a6600_rootfs "$A6BASE/nflasha7" "a6600 /rootfs (ext2, 4,921,344B)"
    ;;
esac
case "$MODE" in
  zve10|all|全部)
    inventory_ext2 zve10_usr   "$ZVE10BASE/nflasha15" "ZV-E10 /usr (ext2, 249,105,408B)"
    inventory_ext2 zve10_rootfs "$ZVE10BASE/nflasha7" "ZV-E10 /rootfs (ext2, 5,132,288B)"
    ;;
esac
case "$MODE" in
  vfat|all|全部)
    inventory_vfat zv1m2_system "$ROOT/03-证据/静态分析/firmware_search/extracted_partitions/0700_part_image/dev/nflasha3"
    inventory_vfat a6600_system "$A6BASE/nflasha3"
    inventory_vfat zve10_system "$ROOT/03-证据/静态分析/firmware_search/extracted_partitions/zve10/0700_part_image/dev/nflasha3"
    ;;
esac
echo "ALL DONE"
