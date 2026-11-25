#!/bin/bash
set -e
OUT="<WORKSPACE>/03-证据/静态分析/aria"
mkdir -p "$OUT"
cd "$OUT"
timeout 60 curl -sSL "https://api.github.com/repos/PCIEARIA/A6400-Extra-Menu" -o repo.json
timeout 60 curl -sSL "https://api.github.com/repos/PCIEARIA/A6400-Extra-Menu/git/trees/HEAD?recursive=1" -o tree.json
python3 - <<'PY'
import json
d = json.load(open('tree.json'))
for e in d.get('tree', []):
    print(e['type'], e.get('size', ''), e['path'])
PY
timeout 60 curl -sSL "https://raw.githubusercontent.com/PCIEARIA/A6400-Extra-Menu/main/README.md" -o README.md || true
echo "==== README ===="
head -160 README.md || true
