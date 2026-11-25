#!/bin/bash
# fwsearch_all_elf_symbols.sh —— 对本机所有可枚举的 ELF 共享库/可执行文件做目标符号（已定义）扫描，
# 证明 GpeInit / core_sync_user_* 等符号在本机任何 ELF 中都未被定义。只读。
set -u
ROOT="<WORKSPACE>"
OLD="<LEGACY_WORKSPACE>"
EV="$ROOT/03-证据/静态分析/firmware_search/symbols"
OUT="$EV/all_elf_target_symbols.txt"
: > "$OUT"
SYM_RE='infra_input_init|infra_input_sus|infra_input_res|core_sync_user_init|core_sync_user_sus|core_sync_user_res|grm_init|grm_sus|grm_res|GpeInit|GpeSus|GpeRes|DDSUserInit|DDSUserSus|DDSUserRes|uxengine_init|uxengine_sus|uxengine_res|uxengine_init2'
count=0
find "$ROOT" "$OLD/zv1m2_fw" "$OLD/zve10_fw" "$OLD/a6600_fw" "$OLD/a6600_port" "$OLD/repo" \
  -xdev -type f \( -name '*.so' -o -name '*.so.*' -o -name '*.elf' -o -name '*.bin' \) \
  -not -path '*firmware_search*' 2>/dev/null | while IFS= read -r f; do
  head=$(head -c 4 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  [ "$head" = "7f454c46" ] || continue
  hits=$(readelf -Ws "$f" 2>/dev/null | awk '$7!="UND"' | grep -E "$SYM_RE" | awk '{print $8}' | sort -u | tr '\n' ' ')
  count=$((count+1))
  if [ -n "$hits" ]; then
    echo -e "$f\tDEFINED: $hits" >> "$OUT"
  fi
done
echo "---" >> "$OUT"
echo "扫描的 ELF 文件数: $(tail -n +1 "$OUT" | grep -c 'DEFINED:')" >> "$OUT"
# 汇总：打印每个符号首次出现的文件（用于人工核对）
echo "== defined symbol -> file ==" >> "$OUT"
grep 'DEFINED:' "$OUT" | awk -F'\t' '{print $2"\t"$1}' | sort -u >> "$OUT"
echo "DONE $OUT"
