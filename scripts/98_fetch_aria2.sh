#!/bin/bash
OUT="<WORKSPACE>/03-证据/静态分析/aria"
mkdir -p "$OUT"
cd "$OUT"
base="https://raw.githubusercontent.com/PCIEARIA/A6400-Extra-Menu/main"
for f in README.md docs/部署與操作規範.md docs/開發與架構細節.md docs/功能狀態.md docs/編譯與目錄.md tools/build_autoexec_hook.py tools/pmca_deploy_v3_clite.py camera/film_settings_start.S camera/native_ui_load_guard.c camera/native_ui_load_payload.c camera/film_menu_job_cli.c; do
  out=$(echo "$f" | tr '/' '_')
  for try in 1 2 3; do
    if timeout 40 curl -sSL --retry 2 "$base/$f" -o "$out"; then
      if [ -s "$out" ]; then echo "OK $f -> $out $(wc -c < "$out")"; break; fi
    fi
    sleep 2
  done
done
ls -la
