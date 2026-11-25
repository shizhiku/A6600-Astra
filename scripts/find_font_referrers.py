"""Find which files inside /usr reference the Chinese font or /tmp/images."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

TERMS = [b'MYingHeiC-GB18030', b'/tmp/images']
results = {}
scanned = 0
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    mode, size, _ = fs.inode(ino)
    if size == 0 or size > 40 * 1024 * 1024:
        continue
    try:
        data = fs.read_file(ino)
    except Exception:
        continue
    scanned += 1
    for t in TERMS:
        if t in data:
            results.setdefault(t.decode(), []).append((path, size, data.count(t)))

print('files scanned:', scanned)
for term, hits in results.items():
    print(f'--- {term} ({len(hits)} files) ---')
    for path, size, cnt in hits[:15]:
        print(f'   {path}  size={size} count={cnt}')
