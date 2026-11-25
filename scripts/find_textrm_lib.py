"""Find which /usr library defines TextRM_loadFont."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

TERM = b'TextRM_loadFont'
hits = []
scanned = 0
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    if not path.endswith('.so'):
        continue
    mode, size, _ = fs.inode(ino)
    if size == 0 or size > 60 * 1024 * 1024:
        continue
    data = fs.read_file(ino)
    scanned += 1
    if TERM in data:
        hits.append((path, size, data.count(TERM)))

print('scanned .so files:', scanned)
for p, s, c in hits:
    print(f'  {p}  size={s} occurrences={c}')
