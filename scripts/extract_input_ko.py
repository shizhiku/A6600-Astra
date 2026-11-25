"""Extract /kmod/input.ko and list key-related symbols."""
from pathlib import Path
import importlib.util

BASE = Path('<WORKSPACE>')
USR = BASE / '05-原始固件/a6600_fw/extracted/0700_part_image/dev/nflasha15'
OUT = BASE / '03-证据/静态分析/input.ko'

spec = importlib.util.spec_from_file_location('u', BASE / '02-脚本/a6600_usr.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fs = m.Ext2(str(USR))

blob = None
for path, ino, is_dir in fs.walk():
    if not is_dir and path.endswith('/input.ko'):
        blob = fs.read_file(ino)
        print('found', path, len(blob))
        break
if blob is None:
    raise SystemExit('input.ko not found')
OUT.write_bytes(blob)

from elftools.elf.elffile import ELFFile
with open(OUT, 'rb') as f:
    e = ELFFile(f)
    symtab = e.get_section_by_name('.symtab')
    rows = []
    for s in symtab.iter_symbols():
        if s.name and s.entry.st_size and s.entry.st_info.type == 'STT_FUNC':
            rows.append((s.entry.st_value, s.entry.st_size, s.name))
    rows.sort()
    print(f'\n{len(rows)} functions')
    for v, sz, n in rows:
        if any(k in n.lower() for k in ('key', 'adc', 'gpio', 'scan', 'poll', 'front')):
            print(f'  {v:#08x} size={sz:5d} {n}')
