"""Find which /usr components reference fontlist.dat or the FONT_* identifiers."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

TERMS = [b'fontlist.dat', b'FONT_S_CHINESE', b'FONT_KOREAN', b'/tmp/images']
hits = {t.decode(): [] for t in TERMS}
files = 0
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    mode, size, _ = fs.inode(ino)
    if size == 0 or size > 60 * 1024 * 1024:
        continue
    data = fs.read_file(ino)
    files += 1
    for t in TERMS:
        if t in data:
            hits[t.decode()].append((path, size, data.count(t)))

print('files scanned:', files)
for term, rows in hits.items():
    print(f'--- {term}: {len(rows)} files ---')
    for p, s, c in rows[:10]:
        print(f'   {p}  size={s} count={c}')
