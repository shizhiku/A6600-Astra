"""Check whether the modules that failed to load exist in the /usr partition."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

want = {'sata_drv.ko', 'msen_drv.ko'}
found = {}
all_kmod = []
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    name = path.rsplit('/', 1)[-1]
    if path.startswith('/kmod/') or '/kmod/' in path:
        all_kmod.append(path)
    if name in want:
        mode, size, _ = fs.inode(ino)
        found[name] = (path, size)

print('kmod entries:', len(all_kmod))
for p in all_kmod[:25]:
    print('  ', p)
print()
for n in sorted(want):
    print(n, '->', found.get(n, 'MISSING'))
