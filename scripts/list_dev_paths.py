"""List every /dev/ path referenced by /usr binaries (static scan)."""
from pathlib import Path
import importlib.util, re

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

seen = {}
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    mode, size, _ = fs.inode(ino)
    if size == 0 or size > 60 * 1024 * 1024:
        continue
    data = fs.read_file(ino)
    for mm in re.finditer(rb'/dev/[A-Za-z0-9_.\-]{2,40}', data):
        s = mm.group(0).decode('latin1')
        seen.setdefault(s, set()).add(path)

print('device paths referenced:', len(seen))
for s in sorted(seen):
    files = sorted(seen[s])[:2]
    print(f'  {s:34s} {files}')
