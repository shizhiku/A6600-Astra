"""Resolve appFw's PLT stub 0x529684 (drawFramebuffer call site target) and
report which import it stands for, plus the GOT slot VMA.

Pattern for ARM-state veneer in this binary:
    ldr ip,[pc,#imm]; add ip,pc,ip; bx ip; .word delta
target = V + 12 + word   (verified earlier)

Doc 136 says PLT 0x529684 -> GOT VMA 0x377AFE0.
"""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from pathlib import Path
import io
import struct

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / '03-证据/静态分析/97_abi/a5pFw_upmfix_nonotify.so'
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
text = e.get_section_by_name('.text')
tb = text['sh_addr']
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


def file_offset(va):
    for s in e.iter_sections():
        if s['sh_type'] == 'SHT_NOBITS':
            continue
        if s['sh_addr'] <= va < s['sh_addr'] + s['sh_size']:
            return s['sh_offset'] + (va - s['sh_addr'])
    return None


def read_u32(va):
    o = file_offset(va)
    if o is None or o + 4 > len(d):
        return None
    return struct.unpack_from('<I', d, o)[0]


# relocation symbol names keyed by r_offset (GOT slot VA)
relocs = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
        st = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            relocs[r['r_offset']] = st.get_symbol(r['r_info_sym']).name

print('=== PLT stub 0x529684 (drawFramebuffer call target) ===')
raw = d[file_offset(0x529684):file_offset(0x529684) + 16]
print('raw bytes:', raw.hex(' '))
for ins in md.disasm(raw, 0x529684):
    print('  %08x  %-8s %s' % (ins.address, ins.mnemonic, ins.op_str))
    if ins.address > 0x529694:
        break

# decode: ldr ip,[pc,#4] ; add ip,pc,ip ; bx ip ; .word
word = struct.unpack_from('<i', d, file_offset(0x529684) + 12)[0]
tgt = (0x529684 + 12 + word) & 0xFFFFFFFF
print()
print('decoded target = %#x  (veneer formula V+12+word)' % tgt)
print('GOT slot value at that address =', hex(read_u32(tgt) or 0))
print('reloc symbol for that slot =', relocs.get(tgt, '(none)'))

print()
print('=== also resolve 0x528C5C (gfxeng) and 0x528D58 (processSystemMessage) ===')
for v in (0x528C5C, 0x528D58, 0x529684):
    if file_offset(v) is None:
        print('  %#x unmapped' % v)
        continue
    w = struct.unpack_from('<i', d, file_offset(v) + 12)[0]
    t = (v + 12 + w) & 0xFFFFFFFF
    print('  %#08x -> %#x  slot=%s  reloc=%s'
          % (v, t, hex(read_u32(t) or 0), relocs.get(t, '(none)')))
