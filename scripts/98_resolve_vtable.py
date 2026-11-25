"""Statically resolve the vtable written by 0x54D154 and its vtable[0].

0x54EF74 later does:
    ldr r0, [r4, #0x10]     ; object at local+0x10 = the struct built by 0x54D154
    ldr r3, [r0]            ; object->vtable
    ldr r3, [r3]            ; vtable[0]
    blx r3                  ; <-- suspected blocking indirect call

0x54D154 sets that vtable:
    ldr r4, [pc, #0x14]  ; A
    ...
    ldr r3, [pc, #0x10]  ; B
    add r4, pc           ; r4 = A_base + A
    ldr r3, [r4, r3]     ; r3 = *(uint32*)(A_base + A + B)   -> global (GOT slot)
    adds r3, #8
    str r3, [r5]         ; object->vtable = global + 8

So this script:
  1. decodes the two pc-relative literals in 0x54D154,
  2. reads the GOT slot to obtain the vtable base (global + 8),
  3. dumps the first several vtable entries,
  4. maps each entry to a symbol / section.
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

# symbol maps
funcs = {}
for sec in e.iter_sections():
    if isinstance(sec, SymbolTableSection):
        for s in sec.iter_symbols():
            v = s['st_value']
            if v and s.name:
                key = v & ~1
                if s['st_info']['type'] == 'STT_FUNC':
                    funcs.setdefault(key, s.name)

# relocation name map (GOT slot VA -> symbol)
reloc_names = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            reloc_names[r['r_offset']] = st.get_symbol(r['r_info_sym']).name


def read_u32(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            off = s['sh_offset'] + (va - s['sh_addr'])
            return struct.unpack_from('<I', d, off)[0]
    return None


def section_of(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s.name
    return None


def decode_ldr_pc(va):
    """Decode a Thumb `ldr rX, [pc, #imm]` at va; returns (lit_va, imm)."""
    ins = struct.unpack_from('<H', d, va)[0]
    # 01001 Rt imm8
    if (ins & 0xF800) != 0x4800:
        return None
    rt = (ins >> 8) & 7
    imm = (ins & 0xFF) * 4
    lit = ((va + 4) & ~3) + imm
    return rt, lit, imm


for va in (0x54D158, 0x54D160):
    r = decode_ldr_pc(va)
    print('insn %#x -> rt=r%d lit=%#x imm=%#x' % (va, r[0], r[1], r[2]))

# A: literal at 0x54D158 -> value added to pc to form r4
rt_a, lit_a, _ = decode_ldr_pc(0x54D158)
val_a = read_u32(lit_a)
# r4 = (val of pc-relative add) : "add r4, pc" at 0x54D162 -> pc = 0x54D162+4 aligned
add_pc = (0x54D162 + 4) & ~3
base_a = add_pc + val_a
print('A: lit=%#x value=%#x add_pc=%#x -> r4 base=%#x'
      % (lit_a, val_a, add_pc, base_a))

# B: literal at 0x54D160 -> offset into [r4]
rt_b, lit_b, _ = decode_ldr_pc(0x54D160)
val_b = read_u32(lit_b)
print('B: lit=%#x value=%#x' % (lit_b, val_b))

# GOT slot address = base_a + val_b  (since ldr r3,[r4,r3])
slot_va = (base_a + val_b) & 0xFFFFFFFF
print('GOT slot VA = %#x  section=%s  reloc_name=%s'
      % (slot_va, section_of(slot_va),
         reloc_names.get(slot_va, '(none)')))
# The GOT slot value at rest (before relocation) is often 0 / addend.
slot_raw = read_u32(slot_va)
print('GOT slot raw value = %r' % (slot_raw,))
