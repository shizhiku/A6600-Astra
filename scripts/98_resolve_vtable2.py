"""Resolve the vtable for the object built by 0x54D154, aligned properly.

GOT slots are 4-byte aligned.  base_a computed by "add r4, pc" is itself a
GOT base; the [r4, r3] load requires r4+r3 to be a slot address.  We snap to
4-byte alignment and then read the slot, then dump the vtable.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io
import struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb, td = text['sh_addr'], text.data()

funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(v & ~1, s.name)

reloc_names = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            reloc_names[r['r_offset']] = st.get_symbol(r['r_info_sym']).name


def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None


def read_u32(va):
    s = sec_of(va)
    if s is None:
        return None
    off = s['sh_offset'] + (va - s['sh_addr'])
    if off + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, off)[0]


# Try the whole family of plausible slot addresses around the computed value.
candidates = []
for delta in range(-8, 12, 4):
    candidates.append(0x37D95B6 + delta)
for va in candidates:
    s = sec_of(va)
    if s is None:
        continue
    raw = read_u32(va)
    name = reloc_names.get(va)
    print('%#010x sec=%-12s raw=%#010x reloc=%s'
          % (va, s.name, raw if raw is not None else 0, name))

print()
print('=== .data.rel.ro / .got ranges ===')
for s in e.iter_sections():
    if s.name in ('.got', '.data.rel.ro', '.data'):
        print('%-14s va=%#010x off=%#010x size=%#x'
              % (s.name, s['sh_addr'], s['sh_offset'], s['sh_size']))
