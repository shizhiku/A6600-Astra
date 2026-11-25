"""Check whether /usr carries its own libc and compare the fault-site bytes."""
from pathlib import Path
import importlib.util, hashlib

BASE = Path(r'<WORKSPACE>')
PART = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

for name in ('nflasha7', 'nflasha15'):
    img = PART / name
    if not img.exists():
        continue
    fs = m.Ext2(str(img))
    print(f'=== {name} ===')
    for path, ino, is_dir in fs.walk():
        if is_dir:
            continue
        base = path.rsplit('/', 1)[-1]
        if base in ('libc-2.11.2.so', 'libc.so.6'):
            data = fs.read_file(ino)
            seg = data[0x15790:0x157A0] if len(data) > 0x157A0 else b''
            print(f'  {path}  {len(data)} B  sha256={hashlib.sha256(data).hexdigest()[:16]}')
            print(f'    bytes@0x15796: {data[0x15796:0x1579A].hex(" ")}')
            out = BASE / f'03-证据/静态分析/{name}_{base}'
            out.write_bytes(data)
            print(f'    saved -> {out.name}')
