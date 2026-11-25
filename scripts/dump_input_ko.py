"""Dump all functions and strings of input.ko."""
from pathlib import Path
import re
from elftools.elf.elffile import ELFFile

KO = Path(r'<WORKSPACE>/03-证据/静态分析/input.ko')
blob = KO.read_bytes()
with open(KO, 'rb') as f:
    e = ELFFile(f)
    symtab = e.get_section_by_name('.symtab')
    rows = []
    for s in symtab.iter_symbols():
        if s.name and s.entry.st_info.type == 'STT_FUNC':
            rows.append((s.entry.st_value, s.entry.st_size, s.name))
    rows.sort()
    print('functions:')
    for v, sz, n in rows:
        print(f'  {v:#08x} size={sz:5d} {n}')

print('\nstrings:')
for mm in re.finditer(rb'[ -~]{4,}', blob):
    print('  ', mm.group(0).decode('latin1')[:100])
