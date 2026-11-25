"""Carefully decode 0x54D154's vtable setup.

Instructions (Thumb):
  54d154: push {r4,r5,r7,lr}
  54d156: add  r7, sp, #0
  54d158: ldr  r4, [pc, #0x14]      -> literal at 0x54d170
  54d15a: mov  r5, r0
  54d15c: bl   0x54d138
  54d160: ldr  r3, [pc, #0x10]      -> literal at 0x54d174
  54d162: add  r4, pc               -> r4 = 0x54d164 + lit[0x54d170]
  54d164: mov  r0, r5
  54d166: ldr  r3, [r4, r3]         -> r3 = *(u32*)(r4 + lit[0x54d174])
  54d168: adds r3, #8
  54d16a: str  r3, [r5]             -> obj->vtable = r3

For Thumb "add rX, pc", the PC reads as (address_of_this_insn + 4) with the
low bit cleared, i.e. ((0x54d162 + 4) & ~3) = 0x54d164.
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


def sec_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s
    return None


def read_u32(va):
    s = sec_of(va)
    if s is None or va < 0:
        return None
    off = s['sh_offset'] + (va - s['sh_addr'])
    if off + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, off)[0]


lit1 = read_u32(0x54D170)
lit2 = read_u32(0x54D174)
print('lit@54d170 = %#x' % lit1)
print('lit@54d174 = %#x' % lit2)

pc_val = (0x54D162 + 4) & ~3
r4_base = (pc_val + lit1) & 0xFFFFFFFF
print('pc=%#x  r4_base=%#x  section=%s'
      % (pc_val, r4_base, sec_of(r4_base).name if sec_of(r4_base) else None))

slot = (r4_base + lit2) & 0xFFFFFFFF
print('slot VA = %#x  section=%s'
      % (slot, sec_of(slot).name if sec_of(slot) else None))
print('slot value = %r' % (read_u32(slot),))

# The slot value + 8 should be the vtable address (in .data.rel.ro)
g = read_u32(slot)
if g:
    vt = (g + 8) & 0xFFFFFFFF
    print('vtable = %#x  section=%s'
          % (vt, sec_of(vt).name if sec_of(vt) else None))
    funcs = {}
    for sec in e.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for s in sec.iter_symbols():
                v = s['st_value']
                if v and s.name and s['st_info']['type'] == 'STT_FUNC':
                    funcs.setdefault(v & ~1, s.name)
    relocs = {}
    for sec in e.iter_sections():
        if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
            st = e.get_section(sec['sh_link'])
            for r in sec.iter_relocations():
                relocs[r['r_offset']] = st.get_symbol(r['r_info_sym']).name
    print('--- vtable entries ---')
    for i in range(12):
        a = vt + i * 4
        raw = read_u32(a)
        nm = relocs.get(a) or funcs.get((raw or 0) & ~1)
        print('  vt[%2d] @ %#010x = %#010x  %s'
              % (i, a, raw if raw is not None else 0, nm or ''))
