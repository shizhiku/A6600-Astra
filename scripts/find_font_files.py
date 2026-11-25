"""Locate font resources inside the /usr partition."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

hits = []
for path, ino, is_dir in fs.walk():
    low = path.lower()
    if '.ltt' in low or 'font' in low or 'yinghei' in low:
        mode, size, _ = fs.inode(ino)
        hits.append((path, is_dir, size, mode))

print('matches:', len(hits))
for p, d, s, mode in hits[:60]:
    kind = 'DIR ' if d else 'FILE'
    print(f'  {kind} {p}  size={s}')
