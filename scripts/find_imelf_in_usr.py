"""Find im.elf (and related app binaries) inside the /usr ext2 partition."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

print('scanning /usr tree for executables named im.elf or similar...')
hits = []
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    name = path.rsplit('/', 1)[-1]
    if name in ('im.elf',) or name.startswith('im.') or name.endswith('.elf'):
        mode, size, _ = fs.inode(ino)
        hits.append((path, size))
for p, s in hits[:40]:
    print(f'  {p}  ({s} bytes)')
print('total matches:', len(hits))

# also list top-level dirs for orientation
print('\ntop-level entries:')
for name, child, ft in fs.listdir(2)[:40]:
    print('  ', name, ft)
