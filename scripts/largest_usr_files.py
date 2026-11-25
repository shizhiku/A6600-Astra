"""List the largest files in /usr and check them for the TextRM symbol."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

rows = []
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    mode, size, _ = fs.inode(ino)
    rows.append((size, path, ino))
rows.sort(reverse=True)

print('largest 15 files in /usr:')
for size, path, ino in rows[:15]:
    print(f'  {size:>12,}  {path}')

print('\nsearching files > 40MB for TextRM/loadFont ...')
for size, path, ino in rows:
    if size <= 40 * 1024 * 1024:
        break
    data = fs.read_file(ino)
    marks = [t for t in (b'TextRM', b'loadFont', b'TextRM_loadFont') if t in data]
    print(f'  {path} size={size}: {[x.decode() for x in marks]}')
