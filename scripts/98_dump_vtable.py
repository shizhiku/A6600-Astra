"""Dump the vtable at 0x0353C518 (global 0x0353C510 + 8) and resolve entries."""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
import io
import struct
import bisect

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))


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


funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                funcs.setdefault(v & ~1, s.name)
fa = sorted(funcs)
# relocation names (absolute pointers in .data.rel.ro are REL32 slots)
relocs = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            relocs[r['r_offset']] = st.get_symbol(r['r_info_sym']).name


def containing(va):
    i = bisect.bisect_right(fa, va) - 1
    if i < 0:
        return None
    return fa[i], funcs[fa[i]]


VT = 0x0353C518
print('=== vtable at %#010x (section %s) ==='
      % (VT, sec_of(VT).name if sec_of(VT) else '?'))
for i in range(32):
    a = VT + i * 4
    raw = read_u32(a)
    if raw is None:
        break
    reloc = relocs.get(a)
    c = containing(raw) if raw else None
    desc = ''
    if reloc:
        desc = 'RELOC->%s' % reloc
    elif c:
        desc = '%s+%#x' % (c[1], raw - c[0])
    secname = sec_of(raw).name if sec_of(raw) else '?'
    print('  vt[%2d] @ %#010x = %#010x  [%s]  %s'
          % (i, a, raw, secname, desc))
