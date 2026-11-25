"""Resolve the real symbol called by the thunk at libObj 0x641910 (abort path)."""
from pathlib import Path
from elftools.elf.elffile import ELFFile

BASE = Path(r'<WORKSPACE>')
LIB = BASE / '03-证据/静态分析/libObj.so'
data = LIB.read_bytes()

THUNK = 0x641910
print('thunk bytes:', data[THUNK:THUNK + 12].hex(' '))
# literal right after the thunk
lit = THUNK + 0x10
print('literal area:', data[lit:lit + 8].hex(' '))
import struct
got = struct.unpack_from('<I', data, lit)[0]
print(f'GOT slot = {got:#x}')

with open(LIB, 'rb') as f:
    e = ELFFile(f)
    for secname in ('.rel.plt', '.rel.dyn', '.rela.plt', '.rela.dyn'):
        s = e.get_section_by_name(secname)
        if s is None:
            continue
        dynsym = e.get_section_by_name('.dynsym')
        for r in s.iter_relocations():
            if r['r_offset'] == got:
                sym = dynsym.get_symbol(r['r_info_sym'])
                print(f'  MATCH in {secname}: {sym.name}  (type {r["r_info_type"]})')
    # also check all relocations for that offset
    print('\n-- scanning all relocations for the slot --')
    for i, s in enumerate(e.iter_sections()):
        if s['sh_type'] not in ('SHT_REL', 'SHT_RELA'):
            continue
        dynsym = e.get_section_by_name('.dynsym')
        for r in s.iter_relocations():
            if r['r_offset'] == got:
                sym = dynsym.get_symbol(r['r_info_sym'])
                print(f'  {s.name}: {sym.name}')
