"""Resolve ARM PLT stubs in gen5 appFw to imported symbol names."""
from elftools.elf.elffile import ELFFile
from capstone import *
from pathlib import Path
import io, struct

SRC = Path('03-证据/静态分析/97_abi/a5pFw_actual.so')
d = SRC.read_bytes()
e = ELFFile(io.BytesIO(d))
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

# map GOT slot VA -> symbol name
slot_to_name = {}
for sec in e.iter_sections():
    if sec['sh_type'] in ('SHT_REL', 'SHT_RELA') and 'plt' in sec.name:
        symtab = e.get_section(sec['sh_link'])
        for rel in sec.iter_relocations():
            sym = symtab.get_symbol(rel['r_info_sym'])
            slot_to_name[rel['r_offset']] = sym.name
print('plt relocs', len(slot_to_name))

text = e.get_section_by_name('.text')
tb = text['sh_addr']


def resolve_stub(addr):
    off = addr - tb
    insns = list(md.disasm(text.data()[off:off + 16], addr))
    got = None
    for i in insns:
        if i.mnemonic == 'ldr' and 'pc' in i.op_str:
            try:
                imm = int(i.op_str.split('#')[-1].rstrip(']'), 0)
                lit = ((i.address + 4) & ~3) + imm
                o = lit - tb
                if 0 <= o < len(text.data()):
                    got = struct.unpack_from('<I', text.data(), o)[0]
            except Exception:
                pass
    return slot_to_name.get(got), got


# calls inside 0x54F664
start = 0x54F664
insns = list(md.disasm(text.data()[start - tb:start - tb + 0x520], start))
import re
for i in insns:
    if i.mnemonic in ('bl', 'blx') and i.op_str.startswith('#'):
        tgt = int(i.op_str[1:], 16)
        if 0x5289d0 <= tgt < 0x52ab00:
            name, got = resolve_stub(tgt & ~1)
            print(f'{i.address:08x} -> PLT {tgt:08x} {name or "?"} (got {got and hex(got)})')
