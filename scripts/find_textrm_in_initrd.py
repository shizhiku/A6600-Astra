"""Search the initrd rootfs for the TextRM_loadFont implementation."""
from pathlib import Path
import importlib.util

BASE = Path(r'<WORKSPACE>')
INITRD = BASE / '05-原始固件/qemu_in/nflasha3-initrd'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

fs = m.Ext2(str(INITRD))
TERM = b'TextRM_loadFont'
hits = []
count = 0
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    mode, size, _ = fs.inode(ino)
    if size == 0:
        continue
    data = fs.read_file(ino)
    count += 1
    if TERM in data:
        hits.append((path, size, data.count(TERM)))

print('files scanned:', count)
for p, s, c in hits:
    print(f'  {p} size={s} occurrences={c}')

# also list the initrd tree briefly for orientation
print('\n--- initrd top-level ---')
for name, child, ft in fs.listdir(2)[:25]:
    print('  ', name, 'dir' if ft == 2 else 'file')
