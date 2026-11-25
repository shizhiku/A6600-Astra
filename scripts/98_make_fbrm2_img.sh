#!/bin/bash
# Build fbrm2 image.  Work around debugfs not handling non-ASCII source paths
# by copying the payload to /tmp first.
set -eu
R="<WORKSPACE>"
SRC=/root/astra/97/m1-verified/astra-m1-astra7.img
DST=/root/astra/97/m1-verified/astra-m1-fbrm2.img
LIB_SRC="$R/03-证据/静态分析/97_abi/a5bObj_fbrm2.img.so"
LIB=/tmp/a5bObj_fbrm2.so

cp "$LIB_SRC" "$LIB"
echo "payload: $(stat -c%s "$LIB") bytes  sha=$(sha256sum "$LIB" | cut -d' ' -f1)"

rm -f "$DST"
cp "$SRC" "$DST"
CMD=/tmp/fbrm2_cmds
printf 'rm /lib/a5bObj.so\nwrite %s /lib/a5bObj.so\nsif /lib/a5bObj.so mode 0100755\n' "$LIB" > "$CMD"
debugfs -w -f "$CMD" "$DST" > /tmp/fbrm2_debugfs.log 2>&1
cat /tmp/fbrm2_debugfs.log
echo "--- verify ---"
python3 - "$DST" "$LIB" <<'PY'
import sys
sys.path.insert(0, '<WORKSPACE>/02-脚本')
from importlib.machinery import SourceFileLoader
import hashlib
u = SourceFileLoader('u', '<WORKSPACE>/02-脚本/97_ext2.py').load_module()
f = u.Ext2(sys.argv[1])
idx = {p: i for p, i, d in f.walk() if not d}
if '/lib/a5bObj.so' not in idx:
    print('MISSING'); sys.exit(1)
b = f.read_file(idx['/lib/a5bObj.so'])
ref = open(sys.argv[2], 'rb').read()
print('size', len(b), 'match', hashlib.sha256(b).hexdigest() == hashlib.sha256(ref).hexdigest())
print('image sha', hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())
PY
