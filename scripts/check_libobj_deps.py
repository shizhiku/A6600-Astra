"""Check whether every DT_NEEDED library of libObj exists in the /usr image."""
from pathlib import Path
import importlib.util
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
LIB = BASE / '03-证据/静态分析/libObj.so'
spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

# collect /usr file names with sizes
avail = {}
for path, ino, is_dir in fs.walk():
    if is_dir:
        continue
    mode, size, _ = fs.inode(ino)
    avail[path.rsplit('/', 1)[-1]] = (path, size)

with open(LIB, 'rb') as f:
    e = ELFFile(f)
    needed = [t.needed for t in e.get_section_by_name('.dynamic').iter_tags()
              if t.entry.d_tag == 'DT_NEEDED']

print('DT_NEEDED:', len(needed))
missing = []
for n in needed:
    if n in avail:
        p, s = avail[n]
        print(f'  OK      {n:28s} {s:>10,}  {p}')
    else:
        missing.append(n)
        print(f'  MISSING {n}')
print('\nmissing:', missing)
